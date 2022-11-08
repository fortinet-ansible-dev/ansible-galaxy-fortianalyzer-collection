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
module: faz_cli_system_log_ratelimit
short_description: Logging rate limit.
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
    cli_system_log_ratelimit:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            device:
                description: no description
                type: list
                suboptions:
                    device:
                        type: str
                        description: 'Device(s) filter according to filter-type setting, wildcard expression supported.'
                    filter-type:
                        type: str
                        default: 'devid'
                        description:
                         - 'Device filter type.'
                         - 'devid - Device ID.'
                        choices:
                            - 'devid'
                    id:
                        type: int
                        default: 0
                        description: 'Device filter ID.'
                    ratelimit:
                        type: int
                        default: 0
                        description: 'Maximum device log rate limit.'
            device-ratelimit-default:
                type: int
                default: 0
                description: 'Default maximum device log rate limit.'
            mode:
                type: str
                default: 'disable'
                description:
                 - 'Logging rate limit mode.'
                 - 'disable - Logging rate limit function disabled.'
                 - 'manual - System rate limit and device rate limit both configurable, no limit if not configured.'
                choices:
                    - 'disable'
                    - 'manual'
            system-ratelimit:
                type: int
                default: 0
                description: 'Maximum system log rate limit.'
            ratelimits:
                description: no description
                type: list
                suboptions:
                    filter:
                        type: str
                        description: 'Device or ADOM filter according to filter-type setting, wildcard expression supported.'
                    filter-type:
                        type: str
                        default: 'devid'
                        description:
                         - 'Device filter type.'
                         - 'devid - Device ID.'
                         - 'adom - ADOM name.'
                        choices:
                            - 'devid'
                            - 'adom'
                    id:
                        type: int
                        default: 0
                        description: 'Filter ID.'
                    ratelimit:
                        type: int
                        default: 0
                        description: 'Maximum log rate limit.'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_log_ratelimit:
       cli_system_log_ratelimit:
         device:
         - device: port4
           filter-type: devid
           id: 1
           ratelimit: 5
         device-ratelimit-default: 0
         mode: disable
         system-ratelimit: 0
     name: Logging rate limit.
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
        '/cli/global/system/log/ratelimit'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log/ratelimit/{ratelimit}'
    ]

    url_params = []
    module_primary_key = None
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
        'cli_system_log_ratelimit': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'device': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'type': 'list',
                    'options': {
                        'device': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'filter-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': False
                            },
                            'choices': [
                                'devid'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': False
                            },
                            'type': 'int'
                        },
                        'ratelimit': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': False
                            },
                            'type': 'int'
                        }
                    }
                },
                'device-ratelimit-default': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'mode': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'manual'
                    ],
                    'type': 'str'
                },
                'system-ratelimit': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ratelimits': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'filter': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'filter-type': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'devid',
                                'adom'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ratelimit': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_log_ratelimit'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
