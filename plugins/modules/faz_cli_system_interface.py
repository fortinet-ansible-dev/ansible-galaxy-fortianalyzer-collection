#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021 Fortinet, Inc.
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

version_added: "2.11"
author:
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    cli_system_interface:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            alias:
                type: str
                description: 'Alias.'
            allowaccess:
                description: no description
                type: list
                choices:
                 - ping
                 - https
                 - ssh
                 - snmp
                 - http
                 - webservice
                 - fgfm
                 - https-logging
                 - soc-fabric
            description:
                type: str
                description: 'Description.'
            ip:
                type: str
                default: '0.0.0.0 0.0.0.0'
                description: 'IP address of interface.'
            ipv6:
                description: no description
                type: dict
                required: false
                suboptions:
                    ip6-address:
                        type: str
                        default: '::/0'
                        description: 'IPv6 address/prefix of interface.'
                    ip6-allowaccess:
                        description: no description
                        type: list
                        choices:
                         - ping
                         - https
                         - ssh
                         - snmp
                         - http
                         - webservice
                         - fgfm
                         - https-logging
                    ip6-autoconf:
                        type: str
                        default: 'enable'
                        description:
                         - 'Enable/disable address auto config (SLAAC).'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            mtu:
                type: int
                default: 1500
                description: 'Maximum transportation unit(68 - 9000).'
            name:
                type: str
                description: 'Interface name.'
            speed:
                type: str
                default: 'auto'
                description:
                 - 'Speed.'
                 - 'auto - Auto adjust speed.'
                 - '10full - 10M full-duplex.'
                 - '10half - 10M half-duplex.'
                 - '100full - 100M full-duplex.'
                 - '100half - 100M half-duplex.'
                 - '1000full - 1000M full-duplex.'
                 - '10000full - 10000M full-duplex.'
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '10000full'
            status:
                type: str
                default: 'up'
                description:
                 - 'Interface status.'
                 - 'down - Interface down.'
                 - 'up - Interface up.'
                choices:
                    - 'down'
                    - 'up'
                    - 'disable'
                    - 'enable'
            aggregate:
                type: str
                description: 'Aggregate interface.'
            lacp-mode:
                type: str
                default: 'active'
                description:
                 - 'LACP mode.'
                 - 'active - Actively use LACP to negotiate 802.3ad aggregation.'
                choices:
                    - 'active'
            lacp-speed:
                type: str
                default: 'slow'
                description:
                 - 'How often the interface sends LACP messages.'
                 - 'slow - Send LACP message every 30 seconds.'
                 - 'fast - Send LACP message every second.'
                choices:
                    - 'slow'
                    - 'fast'
            link-up-delay:
                type: int
                default: 50
                description: 'Number of milliseconds to wait before considering a link is up.'
            member:
                description: no description
                type: list
                suboptions:
                    interface-name:
                        type: str
                        description: 'Physical interface name.'
            min-links:
                type: int
                default: 1
                description: 'Minimum number of aggregated ports that must be up.'
            min-links-down:
                type: str
                default: 'operational'
                description:
                 - 'Action to take when less than the configured minimum number of links are active.'
                 - 'operational - Set the aggregate operationally down.'
                 - 'administrative - Set the aggregate administratively down.'
                choices:
                    - 'operational'
                    - 'administrative'
            type:
                type: str
                default: 'physical'
                description:
                 - 'Set type of interface (physical/aggregate).'
                 - 'physical - Physical interface.'
                 - 'aggregate - Aggregate interface.'
                choices:
                    - 'physical'
                    - 'aggregate'
                    - 'vlan'
            interface:
                type: str
                description: 'Underlying interface name.'
            vlan-protocol:
                type: str
                default: '8021q'
                description:
                 - 'Ethernet protocol of VLAN.'
                 - '8021q - IEEE 802.1Q.'
                 - '8021ad - IEEE 802.1AD.'
                choices:
                    - '8021q'
                    - '8021ad'
            vlanid:
                type: int
                default: 0
                description: 'VLAN ID (1 - 4094).'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_interface:
         state: present
         cli_system_interface:
          name: fooaggregate
          status: up
          type: aggregate
   - faz_cli_system_interface_member:
       cli_system_interface_member:
         interface-name: port4
       interface: fooaggregate
       state: present
     name: Physical interfaces that belong to the aggregate or redundant interface.
   vars:
     ansible_httpapi_port: 443
     ansible_httpapi_use_ssl: true
     ansible_httpapi_validate_certs: false

 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_interface:
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
         #type: physical
       state: present
     name: Interface configuration.
   vars:
     ansible_httpapi_port: 443
     ansible_httpapi_use_ssl: true
     ansible_httpapi_validate_certs: false

'''

RETURN = '''
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
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass


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
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'cli_system_interface': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'alias': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'allowaccess': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'ping',
                        'https',
                        'ssh',
                        'snmp',
                        'http',
                        'webservice',
                        'fgfm',
                        'https-logging',
                        'soc-fabric'
                    ]
                },
                'description': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ip': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'ip6-address': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ip6-allowaccess': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'ping',
                                'https',
                                'ssh',
                                'snmp',
                                'http',
                                'webservice',
                                'fgfm',
                                'https-logging'
                            ]
                        },
                        'ip6-autoconf': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mtu': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'speed': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'auto',
                        '10full',
                        '10half',
                        '100full',
                        '100half',
                        '1000full',
                        '10000full'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'down',
                        'up',
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'aggregate': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'lacp-mode': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'active'
                    ],
                    'type': 'str'
                },
                'lacp-speed': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'slow',
                        'fast'
                    ],
                    'type': 'str'
                },
                'link-up-delay': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'member': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'interface-name': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'min-links': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'min-links-down': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'operational',
                        'administrative'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'physical',
                        'aggregate',
                        'vlan'
                    ],
                    'type': 'str'
                },
                'interface': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vlan-protocol': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        '8021q',
                        '8021ad'
                    ],
                    'type': 'str'
                },
                'vlanid': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_interface'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
