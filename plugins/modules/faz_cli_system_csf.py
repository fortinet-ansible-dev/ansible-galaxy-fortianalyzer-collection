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
module: faz_cli_system_csf
short_description: Add this device to a Security Fabric or set up a new Security Fabric on this device.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.3.0"
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
        required: false
        type: str
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        required: false
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        type: str
        required: false
        choices:
            - set
            - update
            - add
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
        elements: int
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
        required: false
    cli_system_csf:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            accept-auth-by-cert:
                type: str
                description:
                 - 'Accept connections with unknown certificates and ask admin for approval.'
                 - 'disable - Do not accept SSL connections with unknown certificates.'
                 - 'enable - Accept SSL connections without automatic certificate verification.'
                choices:
                    - 'disable'
                    - 'enable'
            authorization-request-type:
                type: str
                description:
                 - 'Authorization request type.'
                 - 'certificate - Request verification by certificate.'
                 - 'serial - Request verification by serial number.'
                choices:
                    - 'certificate'
                    - 'serial'
            certificate:
                type: str
                description: 'Certificate.'
            configuration-sync:
                type: str
                description:
                 - 'Configuration sync mode.'
                 - 'default - Synchronize configuration for IPAM, FortiAnalyzer, FortiSandbox, and Central Management to root node.'
                 - 'local - Do not synchronize configuration with root node.'
                choices:
                    - 'default'
                    - 'local'
            downstream-access:
                type: str
                description:
                 - 'Enable/disable downstream device access to this devices configuration and data.'
                 - 'disable - Disable downstream device access to this devices configuration and data.'
                 - 'enable - Enable downstream device access to this devices configuration and data.'
                choices:
                    - 'disable'
                    - 'enable'
            downstream-accprofile:
                type: str
                description: 'Default access profile for requests from downstream devices.'
            fabric-connector:
                description: no description
                type: list
                elements: dict
                suboptions:
                    accprofile:
                        type: str
                        description: 'Override access profile.'
                    configuration-write-access:
                        type: str
                        description:
                         - 'Enable/disable downstream device write access to configuration.'
                         - 'disable - Disable downstream device write access to configuration.'
                         - 'enable - Enable downstream device write access to configuration.'
                        choices:
                            - 'disable'
                            - 'enable'
                    serial:
                        type: str
                        description: 'Serial.'
            fabric-object-unification:
                type: str
                description:
                 - 'Fabric CMDB Object Unification.'
                 - 'local - Global CMDB objects will not be synchronized to and from this device.'
                 - 'default - Global CMDB objects will be synchronized in Security Fabric.'
                choices:
                    - 'local'
                    - 'default'
            fabric-workers:
                type: int
                description: 'Number of worker processes for Security Fabric daemon.'
            file-mgmt:
                type: str
                description:
                 - 'Enable/disable Security Fabric daemon file management.'
                 - 'disable - Disable daemon file management.'
                 - 'enable - Enable daemon file management.'
                choices:
                    - 'disable'
                    - 'enable'
            file-quota:
                type: int
                description: 'Maximum amount of memory that can be used by the daemon files (in bytes).'
            file-quota-warning:
                type: int
                description: 'Warn when the set percentage of quota has been used.'
            fixed-key:
                description: no description
                type: str
            forticloud-account-enforcement:
                type: str
                description:
                 - 'Fabric FortiCloud account unification.'
                 - 'disable - Disable FortiCloud accound ID matching for Security Fabric.'
                 - 'enable - Enable FortiCloud account ID matching for Security Fabric.'
                choices:
                    - 'disable'
                    - 'enable'
            group-name:
                type: str
                description: 'Security Fabric group name. All FortiGates in a Security Fabric must have the same group name.'
            group-password:
                description: no description
                type: str
            log-unification:
                type: str
                description:
                 - 'Enable/disable broadcast of discovery messages for log unification.'
                 - 'disable - Disable broadcast of discovery messages for log unification.'
                 - 'enable - Enable broadcast of discovery messages for log unification.'
                choices:
                    - 'disable'
                    - 'enable'
            saml-configuration-sync:
                type: str
                description:
                 - 'SAML setting configuration synchronization.'
                 - 'local - Do not apply SAML configuration generated by root.'
                 - 'default - SAML setting for fabric members is created by fabric root.'
                choices:
                    - 'local'
                    - 'default'
            status:
                type: str
                description:
                 - 'Enable/disable Security Fabric.'
                 - 'disable - Disable Security Fabric.'
                 - 'enable - Enable Security Fabric.'
                choices:
                    - 'disable'
                    - 'enable'
            trusted-list:
                description: no description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description:
                         - 'Security fabric authorization action.'
                         - 'accept - Accept authorization request.'
                         - 'deny - Deny authorization request.'
                        choices:
                            - 'accept'
                            - 'deny'
                    authorization-type:
                        type: str
                        description:
                         - 'Authorization type.'
                         - 'serial - Verify downstream by serial number.'
                         - 'certificate - Verify downstream by certificate.'
                        choices:
                            - 'serial'
                            - 'certificate'
                    certificate:
                        type: str
                        description: 'Certificate.'
                    downstream-authorization:
                        type: str
                        description:
                         - 'Trust authorizations by this nodes administrator.'
                         - 'disable - Disable downstream authorization.'
                         - 'enable - Enable downstream authorization.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ha-members:
                        type: str
                        description: 'HA members.'
                    index:
                        type: int
                        description: 'Index of the downstream in tree.'
                    name:
                        type: str
                        description: 'Name.'
                    serial:
                        type: str
                        description: 'Serial.'
            upstream:
                type: str
                description: 'IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.'
            upstream-port:
                type: int
                description: 'The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric (default = 8013).'

'''

EXAMPLES = '''
- hosts: fortianalyzer_inventory
  collections:
    - fortinet.fortianalyzer
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
    - name: Add this device to a Security Fabric or set up a new Security Fabric on this device.
      faz_cli_system_csf:
        bypass_validation: False
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        cli_system_csf:
          accept-auth-by-cert: <value in [disable, enable]>
          authorization-request-type: <value in [certificate, serial]>
          certificate: <value of string>
          configuration-sync: <value in [default, local]>
          downstream-access: <value in [disable, enable]>
          downstream-accprofile: <value of string>
          fabric-connector:
            -
              accprofile: <value of string>
              configuration-write-access: <value in [disable, enable]>
              serial: <value of string>
          fabric-object-unification: <value in [local, default]>
          fabric-workers: <value of integer>
          file-mgmt: <value in [disable, enable]>
          file-quota: <value of integer>
          file-quota-warning: <value of integer>
          fixed-key: <value of string>
          forticloud-account-enforcement: <value in [disable, enable]>
          group-name: <value of string>
          group-password: <value of string>
          log-unification: <value in [disable, enable]>
          saml-configuration-sync: <value in [local, default]>
          status: <value in [disable, enable]>
          trusted-list:
            -
              action: <value in [accept, deny]>
              authorization-type: <value in [serial, certificate]>
              certificate: <value of string>
              downstream-authorization: <value in [disable, enable]>
              ha-members: <value of string>
              index: <value of integer>
              name: <value of string>
              serial: <value of string>
          upstream: <value of string>
          upstream-port: <value of integer>

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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass, remove_revision


def main():
    jrpc_urls = [
        '/cli/global/system/csf'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/csf/{csf}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'log_path': {
            'type': 'str',
            'required': False,
            'default': '/tmp/fortianalyzer.ansible.log'
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
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'cli_system_csf': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.4.1': True
            },
            'options': {
                'accept-auth-by-cert': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'authorization-request-type': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'certificate',
                        'serial'
                    ],
                    'type': 'str'
                },
                'certificate': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'configuration-sync': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'default',
                        'local'
                    ],
                    'type': 'str'
                },
                'downstream-access': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'downstream-accprofile': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'fabric-connector': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'options': {
                        'accprofile': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'configuration-write-access': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'serial': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'local',
                        'default'
                    ],
                    'type': 'str'
                },
                'fabric-workers': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'file-mgmt': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'file-quota': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'file-quota-warning': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'fixed-key': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'no_log': True,
                    'type': 'str'
                },
                'forticloud-account-enforcement': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'group-name': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'group-password': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'no_log': True,
                    'type': 'str'
                },
                'log-unification': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'saml-configuration-sync': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'local',
                        'default'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trusted-list': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'accept',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'authorization-type': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'serial',
                                'certificate'
                            ],
                            'type': 'str'
                        },
                        'certificate': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'downstream-authorization': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ha-members': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'index': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'serial': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'upstream': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'upstream-port': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    module = AnsibleModule(argument_spec=remove_revision(check_parameter_bypass(module_arg_spec, 'cli_system_csf')),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
