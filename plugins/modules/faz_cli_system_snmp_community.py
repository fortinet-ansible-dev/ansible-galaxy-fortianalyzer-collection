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
module: faz_cli_system_snmp_community
short_description: SNMP community configuration.
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
    - To create or update an object, set the state argument to present. To delete an object, set the state argument to absent.
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
    state:
        description: The directive to create, update or delete an object
        type: str
        required: true
        choices:
            - present
            - absent
    cli_system_snmp_community:
        description: The top level parameters set.
        type: dict
        suboptions:
            events:
                description:
                 - SNMP trap events.
                 - disk_low - Disk usage too high.
                 - intf_ip_chg - Interface IP address changed.
                 - sys_reboot - System reboot.
                 - cpu_high - CPU usage too high.
                 - mem_low - Available memory is low.
                 - log-alert - Log base alert message.
                 - log-rate - High incoming log rate detected.
                 - log-data-rate - High incoming log data rate detected.
                 - lic-gbday - High licensed log GB/day detected.
                 - lic-dev-quota - High licensed device quota detected.
                 - cpu-high-exclude-nice - CPU usage exclude NICE threshold.
                type: list
                elements: str
                choices:
                    - 'disk_low'
                    - 'intf_ip_chg'
                    - 'sys_reboot'
                    - 'cpu_high'
                    - 'mem_low'
                    - 'log-alert'
                    - 'log-rate'
                    - 'log-data-rate'
                    - 'lic-gbday'
                    - 'lic-dev-quota'
                    - 'cpu-high-exclude-nice'
            hosts:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: Host entry ID.
                    interface:
                        type: str
                        description: Allow interface name.
                    ip:
                        type: str
                        description: Allow host IP address.
            hosts6:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: Host entry ID.
                    interface:
                        type: str
                        description: Allow interface name.
                    ip:
                        type: str
                        description: Allow host IP address.
            id:
                type: int
                description: Community ID.
            name:
                type: str
                description: Community name.
            query_v1_port:
                type: int
                description: SNMP v1 query port.
            query_v1_status:
                type: str
                description:
                 - Enable/disable SNMP v1 query.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            query_v2c_port:
                type: int
                description: SNMP v2c query port.
            query_v2c_status:
                type: str
                description:
                 - Enable/disable SNMP v2c query.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            status:
                type: str
                description:
                 - Enable/disable community.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            trap_v1_rport:
                type: int
                description: SNMP v1 trap remote port.
            trap_v1_status:
                type: str
                description:
                 - Enable/disable SNMP v1 trap.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            trap_v2c_rport:
                type: int
                description: SNMP v2c trap remote port.
            trap_v2c_status:
                type: str
                description:
                 - Enable/disable SNMP v2c trap.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: SNMP community configuration.
      fortinet.fortianalyzer.faz_cli_system_snmp_community:
        cli_system_snmp_community:
          id: 1
          name: foosnmpcommunity
          status: disable
        state: present
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
        '/cli/global/system/snmp/community'
    ]

    url_params = []
    module_primary_key = 'id'
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
        'cli_system_snmp_community': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'events': {
                    'type': 'list',
                    'choices': [
                        'disk_low', 'intf_ip_chg', 'sys_reboot', 'cpu_high', 'mem_low', 'log-alert', 'log-rate', 'log-data-rate', 'lic-gbday',
                        'lic-dev-quota', 'cpu-high-exclude-nice'
                    ],
                    'elements': 'str'
                },
                'hosts': {'type': 'list', 'options': {'id': {'type': 'int'}, 'interface': {'type': 'str'}, 'ip': {'type': 'str'}}, 'elements': 'dict'},
                'hosts6': {'type': 'list', 'options': {'id': {'type': 'int'}, 'interface': {'type': 'str'}, 'ip': {'type': 'str'}}, 'elements': 'dict'},
                'id': {'type': 'int'},
                'name': {'type': 'str'},
                'query_v1_port': {'type': 'int'},
                'query_v1_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query_v2c_port': {'type': 'int'},
                'query_v2c_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'trap_v1_rport': {'type': 'int'},
                'trap_v1_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'trap_v2c_rport': {'type': 'int'},
                'trap_v2c_status': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_snmp_community'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
