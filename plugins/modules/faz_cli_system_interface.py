#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021-2023 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: faz_cli_system_interface
short_description: Interface configuration.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        type: str
        choices:
            - set
            - update
            - add
    version_check:
        description:
            - If set to True, it will check whether the parameters used are supported by the corresponding version of FortiAnazlyer locally based on FNDN data.
            - A warning will be returned in version_check_warning if there is a mismatch.
            - This warning is only a suggestion and may not be accurate.
        type: bool
        default: true
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        elements: int
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object
        type: str
        required: true
        choices:
            - present
            - absent
    cli_system_interface:
        description: The top level parameters set.
        type: dict
        suboptions:
            alias:
                type: str
                description: Alias.
            allowaccess:
                description:
                 - Allow management access to interface.
                 - ping - PING access.
                 - https - HTTPS access.
                 - ssh - SSH access.
                 - snmp - SNMP access.
                 - http - HTTP access.
                 - webservice - Web service access.
                 - fgfm - FortiManager access.
                 - https-logging - Logging over HTTPS access.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'webservice'
                    - 'fgfm'
                    - 'https-logging'
                    - 'soc-fabric'
                    - 'fabric'
            description:
                type: str
                description: Description.
            ip:
                type: str
                description: IP address of interface.
            ipv6:
                description: no description
                type: dict
                suboptions:
                    ip6-address:
                        type: str
                        description: IPv6 address/prefix of interface.
                    ip6-allowaccess:
                        description:
                         - Allow management access to interface.
                         - ping - PING access.
                         - https - HTTPS access.
                         - ssh - SSH access.
                         - snmp - SNMP access.
                         - http - HTTP access.
                         - webservice - Web service access.
                         - fgfm - FortiManager access.
                         - https-logging - Logging over HTTPS access.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'https'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'webservice'
                            - 'fgfm'
                            - 'https-logging'
                            - 'fabric'
                    ip6-autoconf:
                        type: str
                        description:
                         - Enable/disable address auto config
                         - disable - Disable setting.
                         - enable - Enable setting.
                        choices:
                            - 'disable'
                            - 'enable'
            mtu:
                type: int
                description: Maximum transportation unit
            name:
                type: str
                description: Interface name.
            speed:
                type: str
                description:
                 - Speed.
                 - auto - Auto adjust speed.
                 - 10full - 10M full-duplex.
                 - 10half - 10M half-duplex.
                 - 100full - 100M full-duplex.
                 - 100half - 100M half-duplex.
                 - 1000full - 1000M full-duplex.
                 - 10000full - 10000M full-duplex.
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '10000full'
                    - '1g/full'
                    - '2.5g/full'
                    - '5g/full'
                    - '10g/full'
                    - '14g/full'
                    - '20g/full'
                    - '25g/full'
                    - '40g/full'
                    - '50g/full'
                    - '56g/full'
                    - '100g/full'
                    - '1g/half'
            status:
                type: str
                description:
                 - Interface status.
                 - down - Interface down.
                 - up - Interface up.
                choices:
                    - 'down'
                    - 'up'
                    - 'disable'
                    - 'enable'
            aggregate:
                type: str
                description: Aggregate interface.
            lacp-mode:
                type: str
                description:
                 - LACP mode.
                 - active - Actively use LACP to negotiate 802.3ad aggregation.
                choices:
                    - 'active'
            lacp-speed:
                type: str
                description:
                 - How often the interface sends LACP messages.
                 - slow - Send LACP message every 30 seconds.
                 - fast - Send LACP message every second.
                choices:
                    - 'slow'
                    - 'fast'
            link-up-delay:
                type: int
                description: Number of milliseconds to wait before considering a link is up.
            member:
                description: no description
                type: list
                elements: dict
                suboptions:
                    interface-name:
                        type: str
                        description: Physical interface name.
            min-links:
                type: int
                description: Minimum number of aggregated ports that must be up.
            min-links-down:
                type: str
                description:
                 - Action to take when less than the configured minimum number of links are active.
                 - operational - Set the aggregate operationally down.
                 - administrative - Set the aggregate administratively down.
                choices:
                    - 'operational'
                    - 'administrative'
            type:
                type: str
                description:
                 - Set type of interface
                 - physical - Physical interface.
                 - aggregate - Aggregate interface.
                choices:
                    - 'physical'
                    - 'aggregate'
                    - 'vlan'
            interface:
                type: str
                description: Underlying interface name.
            vlan-protocol:
                type: str
                description:
                 - Ethernet protocol of VLAN.
                 - 8021q - IEEE 802.1Q.
                 - 8021ad - IEEE 802.1AD.
                choices:
                    - '8021q'
                    - '8021ad'
            vlanid:
                type: int
                description: VLAN ID
            lldp:
                type: str
                description:
                 - Enable/disable LLDP
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            defaultgw:
                type: str
                description:
                 - Enable/disable default gateway.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-client-identifier:
                type: str
                description: DHCP client identifier.
            dns-server-override:
                type: str
                description:
                 - Enable/disable use DNS acquired by DHCP or PPPoE.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            mode:
                type: str
                description:
                 - Addressing mode
                 - static - Static setting.
                 - dhcp - External DHCP client mode.
                choices:
                    - 'static'
                    - 'dhcp'
            mtu-override:
                type: str
                description:
                 - Enable/disable use MTU acquired by DHCP or PPPoE.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Physical interfaces that belong to the aggregate or redundant interface.
      fortinet.fortianalyzer.faz_cli_system_interface:
        state: present
        cli_system_interface:
          name: fooaggregate
          status: up
          type: aggregate
    - name: Create faz_cli_system_interface_member.
      fortinet.fortianalyzer.faz_cli_system_interface_member:
        cli_system_interface_member:
          interface_name: port4
        interface: fooaggregate
        state: present
  vars:
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false

- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Interface configuration.
      fortinet.fortianalyzer.faz_cli_system_interface:
        cli_system_interface:
          allowaccess:
            - ping
            - https
            - ssh
            - snmp
            - http
            - webservice
            - fgfm
            - https-logging
            - soc-fabric
          description: second port
          ip: 22.22.22.222 255.255.255.0
          name: port2
          status: down
          # type: physical
        state: present
  vars:
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current fortianalyzer version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    jrpc_urls = [
        '/cli/global/system/interface'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/interface/{interface}'
    ]

    url_params = []
    module_primary_key = 'name'
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'cli_system_interface': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'alias': {'type': 'str'},
                'allowaccess': {
                    'type': 'list',
                    'choices': ['ping', 'https', 'ssh', 'snmp', 'http', 'webservice', 'fgfm', 'https-logging', 'soc-fabric', 'fabric'],
                    'elements': 'str'
                },
                'description': {'type': 'str'},
                'ip': {'type': 'str'},
                'ipv6': {
                    'type': 'dict',
                    'options': {
                        'ip6-address': {'type': 'str'},
                        'ip6-allowaccess': {
                            'type': 'list',
                            'choices': ['ping', 'https', 'ssh', 'snmp', 'http', 'webservice', 'fgfm', 'https-logging', 'fabric'],
                            'elements': 'str'
                        },
                        'ip6-autoconf': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'mtu': {'type': 'int'},
                'name': {'type': 'str'},
                'speed': {
                    'choices': [
                        'auto', '10full', '10half', '100full', '100half', '1000full', '10000full', '1g/full', '2.5g/full', '5g/full', '10g/full',
                        '14g/full', '20g/full', '25g/full', '40g/full', '50g/full', '56g/full', '100g/full', '1g/half'
                    ],
                    'type': 'str'
                },
                'status': {'choices': ['down', 'up', 'disable', 'enable'], 'type': 'str'},
                'aggregate': {'v_range': [['6.4.9', '']], 'type': 'str'},
                'lacp-mode': {'v_range': [['6.4.9', '']], 'choices': ['active'], 'type': 'str'},
                'lacp-speed': {'v_range': [['6.4.9', '']], 'choices': ['slow', 'fast'], 'type': 'str'},
                'link-up-delay': {'v_range': [['6.4.9', '']], 'type': 'int'},
                'member': {
                    'v_range': [['6.4.9', '']],
                    'type': 'list',
                    'options': {'interface-name': {'v_range': [['6.4.9', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'min-links': {'v_range': [['6.4.9', '']], 'type': 'int'},
                'min-links-down': {'v_range': [['6.4.9', '']], 'choices': ['operational', 'administrative'], 'type': 'str'},
                'type': {'v_range': [['6.4.9', '']], 'choices': ['physical', 'aggregate', 'vlan'], 'type': 'str'},
                'interface': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'vlan-protocol': {'v_range': [['7.2.0', '']], 'choices': ['8021q', '8021ad'], 'type': 'str'},
                'vlanid': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'lldp': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'defaultgw': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-client-identifier': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dns-server-override': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mode': {'v_range': [['7.4.2', '']], 'choices': ['static', 'dhcp'], 'type': 'str'},
                'mtu-override': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_interface'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
