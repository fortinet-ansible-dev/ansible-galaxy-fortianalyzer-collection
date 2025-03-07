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
    - This module supports check mode.
version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Beginning with version 2.0.0, all input arguments must adhere to the underscore naming convention (snake_case).
      Please convert any arguments from "var-name", "var.name" or "var name" to "var_name".
      While legacy argument names will continue to function, they will trigger deprecation warnings.
      These warnings can be suppressed by setting deprecation_warnings=False in ansible.cfg.
    - Normally, running one module can fail when a non-zero rc is returned.
      However, you can override the conditions to fail or succeed with parameters rc_failed and rc_succeeded.
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
    dvm_cmd_add_devlist:
        description: The top level parameters set.
        type: dict
        suboptions:
            add_dev_list:
                aliases: ['add-dev-list']
                description: A list of device objects to be added.
                type: list
                elements: dict
                suboptions:
                    adm_pass:
                        description: add real and promote device.
                        type: str
                    adm_usr:
                        type: str
                        description: add real and promote device.
                    desc:
                        type: str
                        description: available for all operations.
                    device_action:
                        aliases: ['device action']
                        type: str
                        description:
                         - 'Specify add device operations, or leave blank to add real device:'
                         - add_model - add a model device.
                         - promote_unreg - promote an unregistered device to be managed by FortiManager using information from database.
                    faz_quota:
                        aliases: ['faz.quota']
                        type: int
                        description: available for all operations.
                    ip:
                        type: str
                        description: add real device only.
                    meta_fields:
                        aliases: ['meta fields']
                        type: str
                        description: add real and model device.
                    mgmt_mode:
                        type: str
                        description: add real and model device.
                        choices: ['unreg', 'fmg', 'faz', 'fmgfaz']
                    mr:
                        type: int
                        description: add model device only.
                    name:
                        type: str
                        description: required for all operations.
                    os_type:
                        type: str
                        description: add model device only.
                        choices: ['unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac']
                    os_ver:
                        type: str
                        description: add model device only.
                        choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0']
                    patch:
                        type: int
                        description: add model device only.
                    platform_str:
                        type: str
                        description: add model device only.
                    sn:
                        type: str
                        description: add model device only.
            adom:
                type: str
                description: Name or ID of the ADOM where the command is to be executed on.
            flags:
                description:
                 - create_task - Create a new task in task manager database.
                 - nonblocking - The API will return immediately in for non-blocking call.
                type: list
                elements: str
                choices: ['none', 'create_task', 'nonblocking']
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
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import FortiAnalyzerAnsible
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    urls_list = [
        '/dvm/cmd/add/dev-list'
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
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='exec')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
