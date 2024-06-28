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
module: faz_um_image_upgrade_ext
short_description: Update the firmware of specific device.
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
    um_image_upgrade_ext:
        description: The top level parameters set.
        type: dict
        suboptions:
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
                type: str
                description: Support version with a build number.
            schedule_time:
                type: str
                description: no description
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
  tasks:
    - name: Update the firmware of specific device.
      fortinet.fortianalyzer.faz_um_image_upgrade_ext:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        um_image_upgrade_ext:
          create_task: <value of string>
          device:
            - name: <value of string>
              vdom: <value of string>
          flags: <value in [f_boot_alt_partition, f_skip_retrieve, f_skip_multi_steps, ...]>
          image: <value of string>
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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    jrpc_urls = [
        '/um/image/upgrade/ext'
    ]

    perobject_jrpc_urls = [
        '/um/image/upgrade/ext/{ext}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'um_image_upgrade_ext': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'create_task': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'device': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.2.1', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.2.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'flags': {
                    'v_range': [['7.2.1', '']],
                    'choices': ['f_boot_alt_partition', 'f_skip_retrieve', 'f_skip_multi_steps', 'f_skip_fortiguard_img', 'f_preview'],
                    'type': 'str'
                },
                'image': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'schedule_time': {'v_range': [['7.2.1', '']], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'um_image_upgrade_ext'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='exec')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
