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
module: faz_cli_system_admin_user_dashboard
short_description: Custom dashboard widgets.
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
    user:
        description: The parameter (user) in requested url.
        type: str
        required: true
    cli_system_admin_user_dashboard:
        description: The top level parameters set.
        type: dict
        suboptions:
            column:
                type: int
                description: Widgets column ID.
            diskio_content_type:
                aliases: ['diskio-content-type']
                type: str
                description:
                 - Disk I/O Monitor widgets chart type.
                 - util - bandwidth utilization.
                 - iops - the number of I/O requests.
                 - blks - the amount of data of I/O requests.
                choices: ['util', 'iops', 'blks']
            diskio_period:
                aliases: ['diskio-period']
                type: str
                description:
                 - Disk I/O Monitor widgets data period.
                 - 1hour - 1 hour.
                 - 8hour - 8 hour.
                 - 24hour - 24 hour.
                choices: ['1hour', '8hour', '24hour']
            log_rate_period:
                aliases: ['log-rate-period']
                type: str
                description:
                 - Log receive monitor widgets data period.
                 - 2min  - 2 minutes.
                 - 1hour - 1 hour.
                 - 6hours - 6 hours.
                choices: ['2min ', '1hour', '6hours']
            log_rate_topn:
                aliases: ['log-rate-topn']
                type: str
                description:
                 - Log receive monitor widgets number of top items to display.
                 - 1 - Top 1.
                 - 2 - Top 2.
                 - 3 - Top 3.
                 - 4 - Top 4.
                 - 5 - Top 5.
                choices: ['1', '2', '3', '4', '5']
            log_rate_type:
                aliases: ['log-rate-type']
                type: str
                description:
                 - Log receive monitor widgets statistics breakdown options.
                 - log - Show log rates for each log type.
                 - device - Show log rates for each device.
                choices: ['log', 'device']
            moduleid:
                type: int
                description: Widget ID.
            name:
                type: str
                description: Widget name.
            num_entries:
                aliases: ['num-entries']
                type: int
                description: Number of entries.
            refresh_interval:
                aliases: ['refresh-interval']
                type: int
                description: Widgets refresh interval.
            res_cpu_display:
                aliases: ['res-cpu-display']
                type: str
                description:
                 - Widgets CPU display type.
                 - average  - Average usage of CPU.
                 - each - Each usage of CPU.
                choices: ['average ', 'each']
            res_period:
                aliases: ['res-period']
                type: str
                description:
                 - Widgets data period.
                 - 10min  - Last 10 minutes.
                 - hour - Last hour.
                 - day - Last day.
                choices: ['10min ', 'hour', 'day']
            res_view_type:
                aliases: ['res-view-type']
                type: str
                description:
                 - Widgets data view type.
                 - real-time  - Real-time view.
                 - history - History view.
                choices: ['real-time ', 'history']
            status:
                type: str
                description:
                 - Widgets opened/closed state.
                 - close - Widget closed.
                 - open - Widget opened.
                choices: ['close', 'open']
            tabid:
                type: int
                description: ID of tab where widget is displayed.
            time_period:
                aliases: ['time-period']
                type: str
                description:
                 - Log Database Monitor widgets data period.
                 - 1hour - 1 hour.
                 - 8hour - 8 hour.
                 - 24hour - 24 hour.
                choices: ['1hour', '8hour', '24hour']
            widget_type:
                aliases: ['widget-type']
                type: str
                description:
                 - Widget type.
                 - top-lograte - Log Receive Monitor.
                 - sysres - System resources.
                 - sysinfo - System Information.
                 - licinfo - License Information.
                 - jsconsole - CLI Console.
                 - sysop - Unit Operation.
                 - alert - Alert Message Console.
                 - statistics - Statistics.
                 - rpteng - Report Engine.
                 - raid - Disk Monitor.
                 - logrecv - Logs/Data Received.
                 - devsummary - Device Summary.
                 - logdb-perf - Log Database Performance Monitor.
                 - logdb-lag - Log Database Lag Time.
                 - disk-io - Disk I/O.
                 - log-rcvd-fwd - Log receive and forwarding Monitor.
                choices:
                    - 'top-lograte'
                    - 'sysres'
                    - 'sysinfo'
                    - 'licinfo'
                    - 'jsconsole'
                    - 'sysop'
                    - 'alert'
                    - 'statistics'
                    - 'rpteng'
                    - 'raid'
                    - 'logrecv'
                    - 'devsummary'
                    - 'logdb-perf'
                    - 'logdb-lag'
                    - 'disk-io'
                    - 'log-rcvd-fwd'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Custom dashboard widgets.
      fortinet.fortianalyzer.faz_cli_system_admin_user_dashboard:
        cli_system_admin_user_dashboard:
          name: foodashboard
          res_view_type: history
          status: open
          tabid: 1
          time_period: 1hour
          widget_type: top-lograte
        state: present
        user: fooadminuser
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
        '/cli/global/system/admin/user/{user}/dashboard'
    ]

    url_params = ['user']
    module_primary_key = 'tabid'
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
        'user': {'required': True, 'type': 'str'},
        'cli_system_admin_user_dashboard': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'column': {'type': 'int'},
                'diskio-content-type': {'choices': ['util', 'iops', 'blks'], 'type': 'str'},
                'diskio-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                'log-rate-period': {'choices': ['2min ', '1hour', '6hours'], 'type': 'str'},
                'log-rate-topn': {'choices': ['1', '2', '3', '4', '5'], 'type': 'str'},
                'log-rate-type': {'choices': ['log', 'device'], 'type': 'str'},
                'moduleid': {'type': 'int'},
                'name': {'type': 'str'},
                'num-entries': {'type': 'int'},
                'refresh-interval': {'type': 'int'},
                'res-cpu-display': {'choices': ['average ', 'each'], 'type': 'str'},
                'res-period': {'choices': ['10min ', 'hour', 'day'], 'type': 'str'},
                'res-view-type': {'choices': ['real-time ', 'history'], 'type': 'str'},
                'status': {'choices': ['close', 'open'], 'type': 'str'},
                'tabid': {'type': 'int'},
                'time-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                'widget-type': {
                    'choices': [
                        'top-lograte', 'sysres', 'sysinfo', 'licinfo', 'jsconsole', 'sysop', 'alert', 'statistics', 'rpteng', 'raid', 'logrecv',
                        'devsummary', 'logdb-perf', 'logdb-lag', 'disk-io', 'log-rcvd-fwd'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_user_dashboard'),
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
