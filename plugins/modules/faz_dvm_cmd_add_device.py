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
module: faz_dvm_cmd_add_device
short_description: Add a device to the Device Manager database.
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
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    dvm_cmd_add_device:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: 'Name or ID of the ADOM where the command is to be executed on.'
            device:
                description: no description
                type: dict
                required: false
                suboptions:
                    adm_pass:
                        description: no description
                        type: str
                    adm_usr:
                        type: str
                        description: '<i>add real and promote device</i>.'
                    desc:
                        type: str
                        description: '<i>available for all operations</i>.'
                    device action:
                        type: str
                        description:
                         - 'Specify add device operations, or leave blank to add real device:'
                         - '"add_model" - add a model device.'
                         - '"promote_unreg" - promote an unregistered device to be managed by FortiManager using information from database.'
                    faz.quota:
                        type: int
                        description: '<i>available for all operations</i>.'
                    ip:
                        type: str
                        description: '<i>add real device only</i>. Add device will probe with this IP using the log in credential specified.'
                    meta fields:
                        type: str
                        description: '<i>add real and model device</i>.'
                    mgmt_mode:
                        type: str
                        description: '<i>add real and model device</i>.'
                        choices:
                            - 'unreg'
                            - 'fmg'
                            - 'faz'
                            - 'fmgfaz'
                    mr:
                        type: int
                        description: '<i>add model device only</i>.'
                    name:
                        type: str
                        description: '<i>required for all operations</i>. Unique name for the device.'
                    os_type:
                        type: str
                        description: '<i>add model device only</i>.'
                        choices:
                            - 'unknown'
                            - 'fos'
                            - 'fsw'
                            - 'foc'
                            - 'fml'
                            - 'faz'
                            - 'fwb'
                            - 'fch'
                            - 'fct'
                            - 'log'
                            - 'fmg'
                            - 'fsa'
                            - 'fdd'
                            - 'fac'
                    os_ver:
                        type: str
                        description: '<i>add model device only</i>.'
                        choices:
                            - 'unknown'
                            - '0.0'
                            - '1.0'
                            - '2.0'
                            - '3.0'
                            - '4.0'
                            - '5.0'
                    patch:
                        type: int
                        description: '<i>add model device only</i>.'
                    platform_str:
                        type: str
                        description: '<i>add model device only</i>. Required for determine the platform for VM platforms.'
                    sn:
                        type: str
                        description: '<i>add model device only</i>. This attribute will be used to determine the device platform, except for VM platforms, w...'
            flags:
                description: no description
                type: list
                choices:
                 - none
                 - create_task
                 - nonblocking
            groups:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_dvm_cmd_add_device:
       dvm_cmd_add_device:
         adom: root
         device:
           adm_pass: 'ca$hc0w'
           adm_usr: admin
           desc: 'The device is added via FortiAnalyzer Ansible'
           device action: <value of string>
           ip: 192.168.190.132
           mgmt_mode: faz
           name: foodevice
           sn: FGVM02TM20012347
         flags:
         - create_task
         - nonblocking
     name: Add a device to the Device Manager database.
     register: installing_task
   - name: poll the task
     faz_fact:
         facts:
             selector: 'task_task'
             params:
                 task: '{{installing_task.meta.response_data.taskid}}'
     register: taskinfo
     until: taskinfo.meta.response_data.percent == 100
     retries: 30
     delay: 5
     failed_when: taskinfo.meta.response_data.state == 'error' and 'devsnexist' not in taskinfo.meta.response_data.line[0].detail
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
        '/dvm/cmd/add/device'
    ]

    perobject_jrpc_urls = [
        '/dvm/cmd/add/device/{device}'
    ]

    url_params = []
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'dvm_cmd_add_device': {
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
                'adom': {
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
                'device': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'adm_pass': {
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
                        'adm_usr': {
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
                        'desc': {
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
                        'device action': {
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
                        'faz.quota': {
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
                        'meta fields': {
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
                        'mgmt_mode': {
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
                                'unreg',
                                'fmg',
                                'faz',
                                'fmgfaz'
                            ],
                            'type': 'str'
                        },
                        'mr': {
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
                        'os_type': {
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
                                'unknown',
                                'fos',
                                'fsw',
                                'foc',
                                'fml',
                                'faz',
                                'fwb',
                                'fch',
                                'fct',
                                'log',
                                'fmg',
                                'fsa',
                                'fdd',
                                'fac'
                            ],
                            'type': 'str'
                        },
                        'os_ver': {
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
                                'unknown',
                                '0.0',
                                '1.0',
                                '2.0',
                                '3.0',
                                '4.0',
                                '5.0'
                            ],
                            'type': 'str'
                        },
                        'patch': {
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
                        'platform_str': {
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
                        'sn': {
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
                        }
                    }
                },
                'flags': {
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
                        'none',
                        'create_task',
                        'nonblocking'
                    ]
                },
                'groups': {
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
                    'options': {
                        'name': {
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
                        'vdom': {
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
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvm_cmd_add_device'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, None, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_exec(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
