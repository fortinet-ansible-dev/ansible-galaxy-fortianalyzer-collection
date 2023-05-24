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
module: faz_um_image_upgrade
short_description: The older API for updating the firmware of specific device.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.1.0"
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        required: false
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
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
    workspace_locking_adom:
        description: no description
        type: str
        required: false
    workspace_locking_timeout:
        description: no description
        type: int
        required: false
        default: 300
    um_image_upgrade:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: no description
            create_task:
                type: str
                description: no description
            device:
                description: no description
                type: list
                elements: dict
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            flags:
                type: str
                description: no description
                choices:
                    - 'f_boot_alt_partition'
                    - 'f_skip_retrieve'
                    - 'f_skip_multi_steps'
                    - 'f_skip_fortiguard_img'
                    - 'f_preview'
            image:
                description: no description
                type: dict
                required: false
                suboptions:
                    build:
                        type: str
                        description: no description
                    id:
                        description: no description
                        type: str
                    model:
                        type: str
                        description: no description
                    release:
                        type: str
                        description: no description
            schedule_time:
                type: str
                description: no description

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
    - name: The older API for updating the firmware of specific device.
      faz_um_image_upgrade:
        bypass_validation: False
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        um_image_upgrade:
          adom: <value of string>
          create_task: <value of string>
          device:
            -
              name: <value of string>
              vdom: <value of string>
          flags: <value in [f_boot_alt_partition, f_skip_retrieve, f_skip_multi_steps, ...]>
          image:
            build: <value of string>
            id: <value of string>
            model: <value of string>
            release: <value of string>
          schedule_time: <value of string>

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
        '/um/image/upgrade'
    ]

    perobject_jrpc_urls = [
        '/um/image/upgrade/{upgrade}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'log_path': {
            'type': 'str',
            'required': False,
            'default': '/tmp/fortianalyzer.ansible.log'
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'um_image_upgrade': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.1': True,
                '7.2.2': True
            },
            'options': {
                'adom': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'str'
                },
                'create_task': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'str'
                },
                'device': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        },
                        'vdom': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'flags': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'f_boot_alt_partition',
                        'f_skip_retrieve',
                        'f_skip_multi_steps',
                        'f_skip_fortiguard_img',
                        'f_preview'
                    ],
                    'type': 'str'
                },
                'image': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'build': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        },
                        'model': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        },
                        'release': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'schedule_time': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=remove_revision(check_parameter_bypass(module_arg_spec, 'um_image_upgrade')),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='exec')
    faz.validate_parameters(params_validation_blob)
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
