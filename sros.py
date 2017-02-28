from __future__ import print_function
#from __future__ import unicode_literals

from collections import defaultdict
from easysnmp import Session

import re
import os
import uuid
import tempfile
import ipaddress

import pprint

from netmiko import ConnectHandler

def decode_inet(inet_type_list):
    types = ['unknown', 'ipv4', 'ipv6']
    return [ types[int(x)] for x in inet_type_list ]

    return int(uni_string)

def to_int(uni_string):
    return int(uni_string)

def decode_mac(hex_string):
    return ':'.join( ['%02X' % ord(x) for x in hex_string ] )

def decode_preflen(len_list):
    return [ int(len) for len in len_list ]

def decode_ip(hex_string_list):
    decoded = []
    for string in hex_string_list:
        if len(string) == 4: # IPv4
            decoded.append('.'.join( [ '%d' % ord(x) for x in string ]) )
        elif len(string) == 16: # IPv6
            ipv6=[]
            for n in range(0,15,2) :
                b0, b1 = list(string[n:n+2])
                if ord(b0) != 0:
                    ipv6.append('%x' % ord(b0))
                    ipv6.append('%02x' % ord(b1))
                else:
                    ipv6.append('%x' % ord(b1))
                ipv6.append(':')
            decoded.append(unicode(ipaddress.ip_address(unicode(''.join(ipv6).strip(':')))))
    return decoded

def decode_rd(hex_string):
    ''' decodes a route-distinguisher of a VRF using a hex string as returned by the snmp-agent
    supports 'Type 1', ie <IP address>:<16bit value>,  and 'Type 0', ie <32-bit value>:<16-bit value> RD's
    as defined in RFC4364, section 4.2
    '''

    if ord(hex_string[1]) == 1:
        subfield1 = '.'.join([ "%s" %  ord(x) for x in hex_string[2:6] if ord(x) != 0 ] )
        subfield2 = ord(hex_string[6])*256 + ord(hex_string[7])
        rd_value = '%s:%d' % (subfield1, subfield2)
    else:
        subfield1 = ord(hex_string[2]) * 256 + ord(hex_string[3])
        subfield2 = ord(hex_string[4])*(2**24) + (ord(hex_string[5])*(2**16)) + (ord(hex_string[6])*(2**8)) + ord(hex_string[7])
        rd_value =   '%d:%d' % (subfield1, subfield2)
    return rd_value

SROS_OID_MAP = {
        'hostname':  'sysName.0',
        'uptime':   'sysUpTimeInstance',
        'version': 'sysDescr.0',
        'chassis_types': '.1.3.6.1.4.1.6527.3.1.2.2.1.6.1.2',
        'model_id': '.1.3.6.1.4.1.6527.3.1.2.2.1.3.1.4.1',
        'dns_domain': '.1.3.6.1.4.1.6527.3.1.2.1.11.19.0',
        'port': {
            'name': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.6',
            'is_enabled': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.37',
            'is_up': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.38',
            'port_mode': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.11',
            'port_encap': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.12',
            'port_transceiver_type': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.25',
            'port_lagid': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.13',
            'description': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.5',
            'port_transceiver_model': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.29',
            'port_sfp_equipped': '.1.3.6.1.4.1.6527.3.1.2.2.4.2.1.34',
            },
        'lldp': {
            'rem_name': '.1.3.6.1.4.1.6527.3.1.2.59.4.1.1.9',
#            'rem_desc': '.1.3.6.1.4.1.6527.3.1.2.59.4.1.1.10',
            'rem_port_desc': '.1.3.6.1.4.1.6527.3.1.2.59.4.1.1.8',
            'rem_port_id': '.1.3.6.1.4.1.6527.3.1.2.59.4.1.1.7',
            },
        'lag': {
            'lacp_enable': '.1.3.6.1.4.1.6527.3.1.2.15.2.1.6',
            'description': '.1.3.6.1.4.1.6527.3.1.2.15.2.1.7',
            'ifindex': '.1.3.6.1.4.1.6527.3.1.2.15.3.1.1',
            },
        'lag_members': '.1.3.6.1.4.1.6527.3.1.2.15.5.1.1',
        'vrf': {
            'name': '.1.3.6.1.4.1.6527.3.1.2.3.1.1.4',
            'svc_name': 'service:name@.1.3.6.1.4.1.6527.3.1.2.3.1.1.29',
            'svcid': '.1.3.6.1.4.1.6527.3.1.2.3.1.1.29',
            'as': '.1.3.6.1.4.1.6527.3.1.2.3.1.1.59',
            'routerid': '.1.3.6.1.4.1.6527.3.1.2.3.1.1.16',
            'rd': '.1.3.6.1.4.1.6527.3.1.2.3.1.1.19',
            },
        'service': {
            'name': '.1.3.6.1.4.1.6527.3.1.2.4.2.2.1.29',
            'svc_type': '.1.3.6.1.4.1.6527.3.1.2.4.2.2.1.3',
            'description': '.1.3.6.1.4.1.6527.3.1.2.4.2.2.1.6',
            'is_enabled': '.1.3.6.1.4.1.6527.3.1.2.4.2.2.1.8',
            'is_up': '.1.3.6.1.4.1.6527.3.1.2.4.2.2.1.9',
            },
        'vr_ifs': {
            'name': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.4',
            'port': 'port:name@.1.3.6.1.4.1.6527.3.1.2.3.4.1.5',
            'mac': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.11',
            'is_enabled': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.8',
            'is_up': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.9',
            'mtu': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.62',
            'description': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.34',
            'service_id': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.37',
            'global_ifindex': '.1.3.6.1.4.1.6527.3.1.2.3.4.1.63',
            'ip_address': 'vr_addr:address@_index',
            'pref_len': 'vr_addr:pref_len@_index',
#            'inet_type': 'vr_addr:inet_type@_index',
            },
        'vr_addr': {
            'address': '.1.3.6.1.4.1.6527.3.1.2.3.6.1.9',
            'pref_len': '.1.3.6.1.4.1.6527.3.1.2.3.6.1.10',
            'inet_type': '.1.3.6.1.4.1.6527.3.1.2.3.6.1.8',
            },
        'bgp_peers' : {
            'description':'.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.7',
            'peer_group': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.4',
            'shutdown': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.6',
            'is_up': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.42',
            'bgp_last_event': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.12',
            'local_as': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.65',
            'peer_as': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.66',
#            'af_safis': '.1.3.6.1.4.1.6527.3.1.2.14.4.7.1.53',
            'pfx_rcvd': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.5',
            'vpn_pfx_rcvd': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.13',
            'v6_pfx_rcvd': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.27',
            'pfx_sent': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.6',
            'vpn_pfx_sent': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.14',
            'v6_pfx_sent': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.28',
            'pfx_active': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.7',
            'v6_pfx_active': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.29',
            'vpn_pfx_active': '.1.3.6.1.4.1.6527.3.1.2.14.4.8.1.15',
            },

    }

SROS_OID_VALUE_DECODERS = {
        'rd':   decode_rd,
        'mac':  decode_mac,
        'ip_address':  decode_ip,
        'pref_len':  decode_preflen,
        'inet_type':  decode_inet,
        'service_id':  to_int,
        'mtu':  to_int,
        'global_ifindex':  to_int,
        }

SROS_OID_TYPES = {
        'service': {
            'is_enabled': {
                '1': True,
                '2': False,
                },
            'is_up' : {
                '1': True,
                '2': False,
                },
            },
        'bgp_peers': {
            'is_up': {
                '1': 'unknown',
                '2': True,
                '3': False,
                '4': 'transition',
                '5': 'disabled',
                },
            },
        'svc_type': {
            '0':    'unknown',
            '1':    'epipe',
            '3':    'vpls',
            '4':    'vprn',
            '5':    'ies',
            '6':    'mirror',
            },
        'lacp_enable': {
            '1':    True,
            '2':    False,
            },
        'shutdown': {
            '1':    True,
            '2':    False,
            },
        'is_enabled': {
            '1':    'noop',
            '2':    True,
            '3':    False,
            '4':    'diagnose',
            },
        'bgp_state': {
            '1':    'idle',
            '2':    'connect',
            '3':    'active',
            '4':    'opensent',
            '5':    'openconfirm',
            '6':    'established',
            },
        'bgp_last_event': {
            '0':    'none',
            '1':    'start',
            '2':    'stop',
            '3':    'open',
            '4':    'close',
            '5':    'openFail',
            '6':    'error',
            '7':    'connectionRetry',
            '8':    'holdtime',
            '9':    'keepalive',
            '10':   'receiveOpen',
            '11':   'receiveKeepalive',
            '12':   'receiveUpdate',
            '13':   'receiveNotify',
            '14':   'startPassive',
            '15':   'parseError',
            '16':   'outOfMemory',
            '17':   'rtLimitExceeded',
            '18':   'maxPfxLimitExceeded',
            '24':   'collisionResolution',
            '25':   'adminShutdown',
            '26':   'adminReset',
            '27':   'configChange',
            '28':   'peerTrackPolMismatch',
            '29':   'rcvdMalformedAttr',
            '30':   'adminResetHard',
            '31':   'peerDamping',
            },
        'is_up': {
            '1':    'unknown',
            '2':    True,
            '3':    False,
            '4':    'diagnose',
            '5':    'failed',
            },
        'port_mode': {
            '0':  'undefined',
            '1':  'access',
            '2':  'network',
            '3':  'hybrid',
            },
        'port_encap': {
            '0':  'unknown',
            '1':  'null',
            '2':  'dot1q',
            '3':  'mpls',
            '10': 'qinq',
            },
        'port_sfp_equipped': {
            '1':    True,
            '2':    False,
            },
        'port_transceiver_type': {
            '0':    'unknown',
            '1':    'gbic',
            '2':    'soldered',
            '3':    'sfp',
            '4':    'xbi',
            '6':    'xfp',
            '7':    'xff',
            '8':    'xfpe',
            '9':    'xpak',
            '11':   'dwdmsfp',
            '12':   'qsfp',
            '13':   'qsfp+',
            '14':   'cfp',
            '15':   'cxp',
            '17':   'cfp20rQsfp28',
            '18':   'cfp4',
            },
        'port_lagid': {
            '0':    'none',
            },
        }

class SrosDriver(object):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.snmp_version = optional_args.get('snmp_version', 2)
        self.snmp_community = optional_args.get('snmp_community','public')

        self.interface_map = {}
        self.snmp_device = None
        self.cli_device = None
        self.netmiko_optional_args={'global_delay_factor':2}

    def open(self):
        if 'MIBDIRS' not in os.environ:
            raise Exception('MIBDIRS not defined in ENVIRONMENT')
        if 'MIBS' not in os.environ:
            os.environ['MIBS'] = 'ALL'
        self.snmp_device = Session(hostname = self.hostname, community=self.snmp_community, version=self.snmp_version)
        sysdescr = self.snmp_device.get('sysDescr.0')
        if not re.search('nokia', sysdescr.value, flags=re.IGNORECASE):
            raise Exception('Not a NOKIA device!')
        model_id = self.snmp_device.get(SROS_OID_MAP['model_id'])
        if not model_id.oid_index:
            raise Exception('NOKIA MIBS not available. Check ' + os.environ['MIBDIRS'])


    def _build_dict(self, table, key):
        entries = dict()
        for attrib in SROS_OID_MAP[table]:
            m = re.search('^([^:]+):([^@]+)@(.+)$', SROS_OID_MAP[table][attrib] )
            if m:
                (f_table, f_key, oid) = m.groups()
                f_entries = self.snmp_device.walk(SROS_OID_MAP[f_table][f_key])
                entries[attrib] = []
                if oid == '_index':
                    ''' value of attrib in f_table, index from entry taken from key-attrib in param-list
                    remote entry's oid-index must contain oid_index of instances of local attribs in 'table'
                    '''
                    for entry in self.snmp_device.walk(SROS_OID_MAP[table][key]):
                        found_mach = False
                        f_matches = []
                        for f_entry in f_entries:
                            if entry.oid_index in f_entry.oid_index:
                                f_matches.append(f_entry.value)
                        entries[attrib].append(f_matches)
                else: # oid contains oid_index of foreign attribute f_key in f_table
                    for entry in self.snmp_device.walk(oid):
                        found_match = False
                        for f_entry in f_entries:
                            if f_entry.oid_index.endswith(entry.value):
                                entries[attrib].append(f_entry.value)
                                found_match = True
                                break
                        if not found_match:
                            entries[attrib].append([]) # append empty list to ensure order/quantity with 'native' table attribs
            else: # regular entry
                entries[attrib] = [ x.value for x in self.snmp_device.walk(SROS_OID_MAP[table][attrib]) ]

        info = defaultdict(dict)
        while (len(entries[key]) > 0):
            key_inst = entries[key].pop(0)
            for attrib in entries:
                if attrib == key: continue
                attrib_value = entries[attrib].pop(0)
                if attrib_value:
                    if attrib in SROS_OID_VALUE_DECODERS:
                        attrib_value = SROS_OID_VALUE_DECODERS[attrib](attrib_value)
                    elif table in SROS_OID_TYPES and attrib in SROS_OID_TYPES[table] and attrib_value in SROS_OID_TYPES[table][attrib]:
                        attrib_value = SROS_OID_TYPES[table][attrib][attrib_value]
                    elif attrib in SROS_OID_TYPES and attrib_value in SROS_OID_TYPES[attrib]:
                        attrib_value = SROS_OID_TYPES[attrib][attrib_value]
                info[key_inst][attrib] = attrib_value

        return dict(info)

    def close(self):
        if hasattr(self, 'cli_device'):
            if hasattr(self.cli_device, 'disconnect'):
                self.cli_device.disconnect()

    def _send_command(self, command):
        output = self.cli_device.send_command(command)
        return output


    def cli(self, commands):
        self.cli_device = ConnectHandler(device_type='alcatel_sros',
                                        ip=self.hostname,
                                        username=self.username,
                                        password=self.password,
                                        **self.netmiko_optional_args)
        cli_output = dict()
        if not isinstance(commands, list):
            commands = [ commands ]
        if isinstance(commands, list):
            for cmd in commands:
                output = self._send_command(cmd)
                cli_output.setdefault(cmd, {})
                cli_output[cmd] = output

        return cli_output

    def get_ports(self):
        return self._build_dict('port', 'name')

    def get_lags(self):
        entries = dict()
        for attrib in SROS_OID_MAP['lag']:
            entries[attrib] = self.snmp_device.walk(SROS_OID_MAP['lag'][attrib])
        lag_info = defaultdict(dict)
        for attrib in entries:
            for entry in entries[attrib]:
                lag_id = int(entry.oid_index.split('.')[-1])
                if attrib in SROS_OID_TYPES:
                    value = SROS_OID_TYPES[attrib][entry.value]
                else:
                    value = entry.value
                lag_info[lag_id][attrib] = value
        member_links = self.snmp_device.walk(SROS_OID_MAP['lag_members'])
        for link in member_links:
            lag_id = int(link.oid_index.split('.')[0])
            if 'members' not in lag_info[lag_id]:
                lag_info[lag_id]['members'] = []
            lag_info[lag_id]['members'].append(link.value)
        return dict(lag_info)

    def get_lldp_neighbors(self):
        port_names = self.snmp_device.walk(SROS_OID_MAP['port']['name'])
        entries = {}
        for attrib in SROS_OID_MAP['lldp']:
            entries[attrib] = self.snmp_device.walk(SROS_OID_MAP['lldp'][attrib])
        lldp_info={}
        for attrib in entries:
            for entry in entries[attrib]:
                m = re.search('^(\d+)\.(\d+)\.(\d+)\.(\d+)$', entry.oid_index)
                if not m:
                    raise Exception("Cannot decode oid_index: ", entry.oid_index)
                if_id = int(m.groups()[1])
                for port in port_names:
                    if int(port.oid_index.split('.')[-1]) == if_id:
                        port_name = port.value
                        break
                if port_name not in lldp_info:
                    lldp_info[port_name] = dict()
                lldp_info[port_name][attrib] = entry.value
        return lldp_info

    def get_services(self):
        return self._build_dict('service', 'name')

    def get_vrfs(self):
        return self._build_dict('vrf', 'name')

    def get_interfaces(self):
        return self._build_dict('vr_ifs', 'name')

    def get_bgp_neighbors(self):
        entries={}
        for attrib in SROS_OID_MAP['bgp_peers']:
            entries[attrib] = self.snmp_device.walk(SROS_OID_MAP['bgp_peers'][attrib])
        vrf_names = self.snmp_device.walk(SROS_OID_MAP['vrf']['name'])
        bgp_info = {}
        for attrib in entries:
            for entry in entries[attrib]:
                m = re.search('^(\d+)\.(\d+)\.(\d+)\.(.+)$', entry.oid_index)
                if not m:
                    raise Exception("Cannot decode oid_index", entry_oid_index)
                (rtr_id, bgp_inst_id, address_type, peer_address) = m.groups()
                if int(address_type) == 4: # IPv4
                    address_family = 'ipv4'
                elif int(address_type) == 16: # IPv6
                    address_family = 'ipv6'
                    byte_list = peer_address.split('.')
                    ipv6=[]
                    for n in range(0,16,2):
                        if int(byte_list[n]) != 0:
                            str = "%x%02x" % (int(byte_list[n]), int(byte_list[n+1]))
                        else:
                            str = "%x" % int(byte_list[n+1])
                        ipv6.append(str)
                    peer_address = ipaddress.ip_address(unicode(':'.join(ipv6))).compressed
                else:
                    address_family = 'unknown'

                vrf_name = ''.join( [ vrf.value for vrf in vrf_names if int(vrf.oid_index) == int(rtr_id) ] )
                if attrib in SROS_OID_TYPES:
                    value = SROS_OID_TYPES[attrib][entry.value]
                else:
                    value = entry.value
                if vrf_name not in bgp_info:
                    bgp_info[vrf_name] = {}
                if address_family not in bgp_info[vrf_name]:
                    bgp_info[vrf_name][address_family] = {}
                if peer_address not in bgp_info[vrf_name][address_family]:
                    bgp_info[vrf_name][address_family][peer_address] = {}
                if attrib not in bgp_info[vrf_name][address_family][peer_address]:
                    bgp_info[vrf_name][address_family][peer_address][attrib] = {}
                bgp_info[vrf_name][address_family][peer_address][attrib] = value
        return dict(bgp_info)

    def get_facts(self):

        facts = {
                'uptime':   -1,
                'vendor':   u'NOKIA',
                'os_version': u'n/a',
                'model': u'n/a',
                'hostname': u'n/a',
                'fqdn': u'n/a',
                'interface_list': [],
            }
        facts['uptime'] = int(self.snmp_device.get(SROS_OID_MAP['uptime']).value) / 100 # OID in ticks (10ms)
        facts['hostname'] = self.snmp_device.get(SROS_OID_MAP['hostname']).value
        facts['os_version'] = self.snmp_device.get(SROS_OID_MAP['version']).value.split(' ')[0]
        model_id = int(self.snmp_device.get(SROS_OID_MAP['model_id']).value)
        models = [ v.value for v in self.snmp_device.walk(SROS_OID_MAP['chassis_types']) if int(v.oid_index) == model_id ]
        if len(models) == 1:
            facts['model'] = models[0]
        facts['interface_list'] = [ port.value for port in self.snmp_device.walk(SROS_OID_MAP['port']['name']) ]
        facts['fqdn'] = facts['hostname'] + '.' + self.snmp_device.get(SROS_OID_MAP['dns_domain']).value

        return facts



import click

@click.command()
@click.option('--host','-h', multiple=True, help='hostname/IP of NOKIA 7750 node, multiple -h options allowed')
@click.option('--community', default='public', help='SNMPv2 community string with read-only access')
@click.option('--username', default='admin', help='CLI username')
@click.option('--password', default='admin', help='CLI password')
@click.option('--getter','-g', multiple=True, help='getter function, e.g. get_facts')
@click.option('--command','-c', help='command to execute on specified node' )
def sros(host, community, username, password, getter, command):
    if not host:
        print("host arg missing. Try --help")
        exit()
    args=dict()
    args['community'] = community
    for h in host:
        print('Host:', h)
        sros = SrosDriver(h, username, password, 20, args)
        sros.open()
        import pprint
        for g in getter:
            if hasattr(sros, g):
                out = getattr(sros, g)()
                pprint.pprint(out)
            else:
                print('Non-supported getter:', g)
                print('list of supported getters:', [ method for method in dir(sros) if callable(getattr(sros, method)) and method.startswith(('get_')) ])
                exit()
        if command:
            cli_cmd = command.split(';')
            out = sros.cli(cli_cmd)
            for cmd in out:
                print('Command:', cmd)
                print(out[cmd])
        sros.close()
if __name__ == '__main__' :
    sros()

