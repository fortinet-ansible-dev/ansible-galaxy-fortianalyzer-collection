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
module: faz_cli_system_log_ratelimit
short_description: Logging rate limit.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
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
    cli_system_log_ratelimit:
        description: The top level parameters set.
        type: dict
        suboptions:
            device:
                description: no description
                type: list
                elements: dict
                suboptions:
                    device:
                        type: str
                        description: Device
                    filter_type:
                        type: str
                        description:
                         - Device filter type.
                         - devid - Device ID.
                        choices:
                            - 'devid'
                    id:
                        type: int
                        description: Device filter ID.
                    ratelimit:
                        type: int
                        description: Maximum device log rate limit.
            device_ratelimit_default:
                type: int
                description: Default maximum device log rate limit.
            mode:
                type: str
                description:
                 - Logging rate limit mode.
                 - disable - Logging rate limit function disabled.
                 - manual - System rate limit and device rate limit both configurable, no limit if not configured.
                choices:
                    - 'disable'
                    - 'manual'
            system_ratelimit:
                type: int
                description: Maximum system log rate limit.
            ratelimits:
                description: no description
                type: list
                elements: dict
                suboptions:
                    filter:
                        type: str
                        description: Device or ADOM filter according to filter-type setting, wildcard expression supported.
                    filter_type:
                        type: str
                        description:
                         - Device filter type.
                         - devid - Device ID.
                         - adom - ADOM name.
                        choices:
                            - 'devid'
                            - 'adom'
                    id:
                        type: int
                        description: Filter ID.
                    ratelimit:
                        type: int
                        description: Maximum log rate limit.
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Logging rate limit.
      fortinet.fortianalyzer.faz_cli_system_log_ratelimit:
        cli_system_log_ratelimit:
          device:
            - device: port4
              filter_type: devid
              id: 1
              ratelimit: 5
          device_ratelimit_default: 0
          mode: disable
          system_ratelimit: 0
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
        '/cli/global/system/log/ratelimit'
    ]

    url_params = []
    module_primary_key = None
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
        'cli_system_log_ratelimit': {
            'type': 'dict',
            'v_range': [['6.4.8', '']],
            'options': {
                'device': {
                    'v_range': [['6.4.8', '7.0.2']],
                    'type': 'list',
                    'options': {
                        'device': {'v_range': [['6.4.8', '7.0.2']], 'type': 'str'},
                        'filter-type': {'v_range': [['6.4.8', '7.0.2']], 'choices': ['devid'], 'type': 'str'},
                        'id': {'v_range': [['6.4.8', '7.0.2']], 'type': 'int'},
                        'ratelimit': {'v_range': [['6.4.8', '7.0.2']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'device-ratelimit-default': {'v_range': [['6.4.8', '']], 'type': 'int'},
                'mode': {'v_range': [['6.4.8', '']], 'choices': ['disable', 'manual'], 'type': 'str'},
                'system-ratelimit': {'v_range': [['6.4.8', '']], 'type': 'int'},
                'ratelimits': {
                    'v_range': [['7.0.3', '']],
                    'type': 'list',
                    'options': {
                        'filter': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'filter-type': {'v_range': [['7.0.3', '']], 'choices': ['devid', 'adom'], 'type': 'str'},
                        'id': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'ratelimit': {'v_range': [['7.0.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_log_ratelimit'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
