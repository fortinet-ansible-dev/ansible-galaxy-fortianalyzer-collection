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
module: faz_dvm_cmd_add_devlist
short_description: Add multiple devices to the Device Manager database.
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
    dvm_cmd_add_devlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add-dev-list:
                description: no description
                type: list
                elements: dict
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
                            - '6.0'
                            - '7.0'
                            - '8.0'
                    patch:
                        type: int
                        description: '<i>add model device only</i>.'
                    platform_str:
                        type: str
                        description: '<i>add model device only</i>. Required for determine the platform for VM platforms.'
                    sn:
                        type: str
                        description: '<i>add model device only</i>. This attribute will be used to determine the device platform, except for VM platforms, w...'
            adom:
                type: str
                description: 'Name or ID of the ADOM where the command is to be executed on.'
            flags:
                description: no description
                type: list
                elements: str
                choices:
                    - 'none'
                    - 'create_task'
                    - 'nonblocking'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Add multiple devices to the Device Manager database.
      fortinet.fortianalyzer.faz_dvm_cmd_add_devlist:
        dvm_cmd_add_devlist:
          add_dev_list:
            - adm_pass: "ca$hc0w"
              adm_usr: admin
              ip: 192.168.190.132
              mgmt_mode: faz
              # sn: <value of string>
          adom: root
          flags:
            - create_task
            - nonblocking
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
        '/dvm/cmd/add/dev-list'
    ]

    perobject_jrpc_urls = [
        '/dvm/cmd/add/dev-list/{dev-list}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'dvm_cmd_add_devlist': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'add-dev-list': {
                    'type': 'list',
                    'options': {
                        'adm_pass': {'no_log': True, 'type': 'str'},
                        'adm_usr': {'type': 'str'},
                        'desc': {'type': 'str'},
                        'device action': {'type': 'str'},
                        'faz.quota': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'meta fields': {'type': 'str'},
                        'mgmt_mode': {'choices': ['unreg', 'fmg', 'faz', 'fmgfaz'], 'type': 'str'},
                        'mr': {'type': 'int'},
                        'name': {'type': 'str'},
                        'os_type': {
                            'choices': ['unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac'],
                            'type': 'str'
                        },
                        'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0'], 'type': 'str'},
                        'patch': {'type': 'int'},
                        'platform_str': {'type': 'str'},
                        'sn': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'adom': {'type': 'str'},
                'flags': {'type': 'list', 'choices': ['none', 'create_task', 'nonblocking'], 'elements': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'dvm_cmd_add_devlist'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='exec')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
