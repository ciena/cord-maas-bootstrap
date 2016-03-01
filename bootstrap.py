#!/usr/bin/python

from __future__ import print_function
import sys
import json
import ipaddress
import requests
from optparse import OptionParser
from maasclient.auth import MaasAuth
from maasclient import MaasClient

# For some reason the maasclient doesn't provide a put method. So
# we will add it here
def put(client, url, params=None):
    return requests.put(url=client.auth.api_url + url,
                            auth=client._oauth(),
                            data=params)

def add_or_update_node_group_interface(client, ng, gw, foundIfc, ifcName, subnet):
    ip = ipaddress.IPv4Network(unicode(subnet, 'utf-8'))
    hosts = list(ip.hosts())

    # if the caller specified the default gateway then honor that, else used the default
    gw = gw or str(hosts[0])

    ifc = {
        "ip_range_high": str(hosts[-1]),
        "ip_range_low": str(hosts[2]),
        "management": 2,
        "name": ifcName,
        "router_ip" : gw,
        "gateway_ip" : gw,
        "ip": str(hosts[0]),
        "subnet_mask": str(ip.netmask),
        "broadcast_ip": str(ip.broadcast_address),
        "interface": ifcName,
    }

    if foundIfc is not None:
        print("WARN: network for specified interface, '%s', already exists" % (ifcName))

        # If the network already exists, update it with the information we want
        resp = put(client, '/nodegroups/' + ng['uuid'] + '/interfaces/' + ifcName + '/', ifc)
        if int(resp.status_code / 100) != 2:
            print("ERROR: unable to update specified network, '%s', on specified interface '%s', '%d : %s'"
                % (subnet, ifcName, resp.status_code, resp.text), file=sys.stderr)
        else:
            print("INFO: updated network, '%s', for interface '%s'" % (subnet, ifcName))

    else:
        # Add the operation
        ifc['op'] = 'new'

        resp = client.post('/nodegroups/' + ng['uuid'] + '/interfaces/', ifc)
        if int(resp.status_code / 100) != 2:
            print("ERROR: unable to create specified network, '%s', on specified interface '%s', '%d : %s'"
                % (subnet, ifcName, resp.status_code, resp.text), file=sys.stderr)
        else:
            print("INFO: created network, '%s', for interface '%s'" % (subnet, ifcName))

    # Add the first host to the subnet as the dns_server
    subnets = None
    resp = client.get('/subnets/', dict())
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to query subnets: '%d : %s'" % (resp.status_code, resp.text))
    else:
        subnets = json.loads(resp.text)

    id = None
    for sn in subnets:
        if sn['name'] == subnet:
            id = str(sn['id'])
            break

    if id == None:
        print("WARN: unable to find subnet entry for network '%s'" % (subnet))
    else:
        put(client, '/subnets/' + id + '/', dict(dns_servers=[hosts[0]]))

def main():
    parser = OptionParser()
    parser.add_option('-c', '--config', dest='config_file',
        help="specifies file from which configuration should be read", metavar='FILE')
    parser.add_option('-a', '--apikey', dest='apikey',
        help="specifies the API key to use when accessing MAAS")
    parser.add_option('-u', '--url', dest='url', default='http://localhost/MAAS/api/1.0',
        help="specifies the URL on which to contact MAAS")
    parser.add_option('-z', '--zone', dest='zone', default='administrative',
        help="specifies the zone to create for manually managed hosts")
    parser.add_option('-i', '--interface', dest='interface', default='eth0:1',
        help="the interface on which to set up DHCP for POD local hosts")
    parser.add_option('-n', '--network', dest='network', default='10.0.0.0/16',
        help="subnet to use for POD local DHCP")
    parser.add_option('-b', '--bridge', dest='bridge', default='mgmtbr',
        help="bridge to use for host local VM allocation")
    parser.add_option('-t', '--bridge-subnet', dest='bridge_subnet', default='172.18.0.0/16',
        help="subnet to assign from for bridged hosts")
    parser.add_option('-r', '--cluster', dest='cluster', default='Cluster master',
        help="name of cluster to user for POD / DHCP")
    parser.add_option('-s', '--sshkey', dest='sshkey', default=None,
        help="specifies public ssh key")
    parser.add_option('-d', '--domain', dest='domain', default='cord.lab',
        help="specifies the domain to configure in maas")
    parser.add_option('-g', '--gateway', dest='gw', default=None,
        help="specifies the gateway to configure for servers")
    (options, args) = parser.parse_args()

    if len(args) > 0:
        print("unknown command line arguments specified", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # If a config file was specified then read the config from that
    config = {}
    if options.config_file != None:
        with open(options.config_file) as config_file:
            config = json.load(config_file)

    # Override the config with any command line options
    if options.apikey == None:
        print("must specify a  MAAS API key", file=sys.stderr)
        sys.exit(1)
    else:
        config['key'] = options.apikey
    if options.url != None:
        config['url'] = options.url
    if options.zone != None:
        config['zone'] = options.zone
    if options.interface != None:
        config['interface'] = options.interface
    if options.network != None:
        config['network'] = options.network
    if options.bridge != None:
        config['bridge'] = options.bridge
    if options.bridge_subnet != None:
        config['bridge-subnet'] = options.bridge_subnet
    if options.cluster != None:
        config['cluster'] = options.cluster
    if options.domain != None:
        config['domain'] = options.domain
    if options.gw != None:
        config['gw'] = options.gw
    if not 'gw' in config.keys():
        config['gw'] = None
    if options.sshkey == None:
        print("must specify a SSH key to use for cord user", file=sys.stderr)
        sys.exit(1)
    else:
        config['sshkey'] = options.sshkey
    
    auth = MaasAuth(config['url'], config['key'])
    client = MaasClient(auth)

    # Add the SSH key to the user
    # POST /api/2.0/account/prefs/sshkeys/ op=new
    resp = client.post('/account/prefs/sshkeys/', dict(op='new', key=config['sshkey']))
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to add sshkey for user: '%d : %s'"
                % (resp.status_code, resp.text), file=sys.stderr)
        # TODO add exit back in
        #sys.exit(1)
    
    # Check to see if an "administrative" zone exists and if not
    # create one
    found = None
    zones = client.zones
    for zone in zones:
        if zone['name'] == config['zone']:
            found=zone
    
    if found is not None:
        print("WARN: administrative zone, '%s', already exists" % config['zone'], file=sys.stderr)
    else:
        if not client.zone_new(config['zone'], "Zone for manually administrated nodes"):
            print("ERROR: unable to create administrative zone '%s'" % config['zone'], file=sys.stderr)
            sys.exit(1)
        else:
            print("INFO: Zone '%s' created" % config['zone'])
    
    # If the interface doesn't already exist in the cluster then
    # create it. Look for the "Cluster Master" node group, but
    # if it is not found used the first one in the list, if the
    # list is empty, error out
    found = None
    ngs = client.nodegroups
    for ng in ngs:
        if ng['cluster_name'] == config['cluster']:
            found = ng
            break
    
    if found is None:
        print("ERROR: unable to find cluster with specified name, '%s'" % config['cluster'], file=sys.stderr)
        sys.exit(1)
    
    # Set the DNS domain name (zone) for the cluster
    resp = put(client, '/nodegroups/' + ng['uuid'] + '/', dict(name=config['domain']))
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to set the DNS domain name for the cluster with specified name, '%s': '%d : %s'"
            % (config['cluster'], resp.status_code, resp.text), file=sys.stderr)
    else:
        print("INFO: updated name of cluster to '%s' : %s" % (config['domain'], resp))
    
    found = None
    resp = client.get('/nodegroups/' + ng['uuid'] + '/interfaces/', dict(op='list'))
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to fetch interfaces for cluster with specified name, '%s': '%d : %s'"
            % (config['cluster'], resp.status_code, resp.text), file=sys.stderr)
        sys.exit(1)
    ifcs = json.loads(resp.text)

    localIfc = hostIfc = None 
    for ifc in ifcs:
        localIfc = ifc if ifc['name'] == config['interface'] else localIfc
        hostIfc = ifc if ifc['name'] == config['bridge'] else hostIfc

    add_or_update_node_group_interface(client, ng, config['gw'], localIfc, config['interface'], config['network'])
    add_or_update_node_group_interface(client, ng, config['gw'], hostIfc, config['bridge'], config['bridge-subnet'])

    # Update the server settings to upstream DNS request to Google
    # POST /api/2.0/maas/ op=set_config
    resp = client.post('/maas/', dict(op='set_config', name='upstream_dns', value='8.8.8.8 8.8.8.4'))
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to set the upstream DNS servers: '%d : %s'"
            % (resp.status_code, resp.text), file=sys.stderr)
    else:
        print("INFO: updated up stream DNS servers")

    # Start the download of boot images
    resp = client.post('/boot-resources/', dict(op='import'))
    if int(resp.status_code / 100) != 2:
        print("ERROR: unable to start image download: '%d : %s'" % (resp.status_code, resp.text), file=sys.stderr)
    else:
        print("INFO: Image download started")
    
if __name__ == '__main__':
    main()
