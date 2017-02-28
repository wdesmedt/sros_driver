# sros_driver

## What?
programmatic interface to SROS. This may evolve to a [NAPALM driver](https://github.com/napalm-automation/) but current methods 
of NAPALM drivers are geared towards datacenter functionality, rather than WAN-services, where SROS gets mainly deployed.

This driver interacts with a NOKIA node running SROS (7750SR service-routers) and currently supports:
- _getters_ : methods to get configuration and operational data from the network element
- _cli_command_: execute CLI command and return output

Since SROS in its latest release (14.0Rx) does not support netconf/yang or provides an API through e.g. a python library,
2 options remain for getting state/config data from the node:
- CLI screen-scraping
- SNMP

Due to the extensive SNMP-support on SROS and the large amount of configuration and operational data that can be queried, this driver
uses SNMP through the easysnmp library because:
- the SNMP-agent returns structured data as defined in the vendor-specific MIBs
- fast. Easysnmp uses the Net-SNMP packages for optimized processing and SNMP-transport is less demanding than SSH

CLI screen-scaping is error-prone and sensitive to changes between minor releases as command-syntax and CLI output may change

# Requirements
- Net-SNMP packages. See [EasySNMP installation](http://easysnmp.readthedocs.io/en/latest/) for package dependencies
- SROS MIBs - these get distributed with the SROS software and are also provided in this repo
- environment vars. MIBDIRS must be specified and set to the directory that holds the SROS MIBS, e.g.:
  `MIBDIRS=/usr/share/snmp/mibs:/home/vagrant/MIB`
- netmiko Python library: used for CLI over SSH interaction with the SROS-node. See https://github.com/ktbyers/netmiko
  
# Examples
```
$ python sros.py --help
Usage: sros.py [OPTIONS]

Options:
  -h, --host TEXT     hostname/IP of NOKIA 7750 node, multiple -h options
                      allowed
  --community TEXT    SNMPv2 community string with read-only access
  --username TEXT     CLI username
  --password TEXT     CLI password
  -g, --getter TEXT   getter function, e.g. get_facts
  -c, --command TEXT  command to execute on specified node
  --help              Show this message and exit.
```
List of supported getters:
```
$ python sros.py -h sros-1 -g blabla
Host: sros-1
Non-supported getter: blabla
list of supported getters: ['get_bgp_neighbors', 'get_facts', 'get_interfaces', 'get_lags', 'get_lldp_neighbors', 'get_ports', 'get_services', 'get_vrfs']
```

Get facts from 2 nodes:
```
$ python sros.py -h sros-1 -h sros-2 -g get_facts
Host: sros-1
{'fqdn': u'sros-1.lab.local',
 'hostname': u'sros-1',
 'interface_list': [u'1/1/1',
                    u'1/1/2',
                    u'1/1/3',
                    u'1/1/4',
                    u'1/1/5',
                    u'1/2/a.sap-sap',
                    u'1/2/b.sap-sap',
                    u'1/2/a.sap-net',
                    u'1/2/b.sap-net',
                    u'1/2/a.net-sap',
                    u'1/2/b.net-sap',
                    u'A/1',
                    u'B/1',
                    u'lag-11',
                    u'ccag-1.a',
                    u'ccag-1.b',
                    u'ccag-1.a.sap-net',
                    u'ccag-1.b.sap-net',
                    u'ccag-1.a.net-sap',
                    u'ccag-1.b.net-sap'],
 'model': u'7750 SR-12',
 'os_version': u'TiMOS-B-14.0.R7',
 'uptime': 7216,
 'vendor': u'NOKIA'}
Host: sros-2
{'fqdn': u'sros-2.',
 'hostname': u'sros-2',
 'interface_list': [u'1/1/1',
                    u'1/1/2',
                    u'1/1/3',
                    u'1/1/4',
                    u'1/1/5',
                    u'1/2/a.sap-sap',
                    u'1/2/b.sap-sap',
                    u'1/2/a.sap-net',
                    u'1/2/b.sap-net',
                    u'1/2/a.net-sap',
                    u'1/2/b.net-sap',
                    u'A/1',
                    u'B/1'],
 'model': u'7750 SR-12',
 'os_version': u'TiMOS-B-14.0.R7',
 'uptime': 7191,
 'vendor': u'NOKIA'}
```
Get BGP neighbors:
```
$ python sros.py -h sros-1 -g get_bgp_neighbors
Host: sros-1
{u'Base': {'ipv4': {u'192.168.255.2': {'bgp_last_event': 'receiveKeepalive',
                                       'description': u'',
                                       'is_up': True,
                                       'local_as': u'6774',
                                       'peer_as': u'6774',
                                       'peer_group': u'internal',
                                       'pfx_active': u'0',
                                       'pfx_rcvd': u'0',
                                       'pfx_sent': u'0',
                                       'shutdown': False,
                                       'v6_pfx_active': u'0',
                                       'v6_pfx_rcvd': u'0',
                                       'v6_pfx_sent': u'0',
                                       'vpn_pfx_active': u'1',
                                       'vpn_pfx_rcvd': u'1',
                                       'vpn_pfx_sent': u'3'}}},
 u'vprn3000': {'ipv4': {u'172.31.255.1': {'bgp_last_event': 'receiveKeepalive',
                                          'description': u'',
                                          'is_up': True,
                                          'local_as': u'6774',
                                          'peer_as': u'6848',
                                          'peer_group': u'ce',
                                          'pfx_active': u'1',
                                          'pfx_rcvd': u'2',
                                          'pfx_sent': u'1',
                                          'shutdown': False,
                                          'v6_pfx_active': u'0',
                                          'v6_pfx_rcvd': u'0',
                                          'v6_pfx_sent': u'0',
                                          'vpn_pfx_active': u'0',
                                          'vpn_pfx_rcvd': u'0',
                                          'vpn_pfx_sent': u'0'}},
               'ipv6': {u'2001:bad:beef:ffff::1': {'bgp_last_event': 'receiveKeepalive',
                                                   'description': u'',
                                                   'is_up': True,
                                                   'local_as': u'6774',
                                                   'peer_as': u'6848',
                                                   'peer_group': u'ce',
                                                   'pfx_active': u'0',
                                                   'pfx_rcvd': u'0',
                                                   'pfx_sent': u'0',
                                                   'shutdown': False,
                                                   'v6_pfx_active': u'0',
                                                   'v6_pfx_rcvd': u'1',
                                                   'v6_pfx_sent': u'0',
                                                   'vpn_pfx_active': u'0',
                                                   'vpn_pfx_rcvd': u'0',
                                                   'vpn_pfx_sent': u'0'}}},
 u'vprn9999': {'ipv4': {u'172.31.255.0': {'bgp_last_event': 'receiveKeepalive',
                                          'description': u'',
                                          'is_up': True,
                                          'local_as': u'6848',
                                          'peer_as': u'6774',
                                          'peer_group': u'pe',
                                          'pfx_active': u'0',
                                          'pfx_rcvd': u'1',
                                          'pfx_sent': u'2',
                                          'shutdown': False,
                                          'v6_pfx_active': u'0',
                                          'v6_pfx_rcvd': u'0',
                                          'v6_pfx_sent': u'0',
                                          'vpn_pfx_active': u'0',
                                          'vpn_pfx_rcvd': u'0',
                                          'vpn_pfx_sent': u'0'}},
               'ipv6': {u'2001:bad:beef:ffff::': {'bgp_last_event': 'receiveKeepalive',
                                                  'description': u'',
                                                  'is_up': True,
                                                  'local_as': u'6848',
                                                  'peer_as': u'6774',
                                                  'peer_group': u'pe',
                                                  'pfx_active': u'0',
                                                  'pfx_rcvd': u'0',
                                                  'pfx_sent': u'0',
                                                  'shutdown': False,
                                                  'v6_pfx_active': u'0',
                                                  'v6_pfx_rcvd': u'0',
                                                  'v6_pfx_sent': u'1',
                                                  'vpn_pfx_active': u'0',
                                                  'vpn_pfx_rcvd': u'0',
                                                  'vpn_pfx_sent': u'0'}}}}
```

