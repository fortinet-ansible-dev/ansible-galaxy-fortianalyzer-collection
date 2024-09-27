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
module: faz_report_config_schedule
short_description: Config schedule.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.5.0"
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
        default: false
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    report_config_schedule:
        description: The top level parameters set.
        type: dict
        suboptions:
            description:
                type: str
                description: no description
            devices:
                description: 'reference: /report/adom/<adom-name>/config/schedule/<schedule_name>/devices'
                type: list
                elements: dict
                suboptions:
                    devices_name:
                        type: str
                        description: no description
                    interfaces:
                        description: 'reference: /sql-report/schedule/devices/interfaces'
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                type: str
                                description: no description
            filter:
                description: 'reference: /report/adom/<adom-name>/config/schedule/<schedule_name>/filter'
                type: list
                elements: dict
                suboptions:
                    description:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    opcode:
                        type: str
                        description: no description
                        choices:
                            - 'not_equal'
                            - 'equal'
                    status:
                        type: int
                        description: no description
                    value:
                        type: str
                        description: no description
            name:
                type: str
                description: no description
            report_layout:
                description: 'reference: /report/adom/<adom-name>/config/schedule/<schedule_name>/report-layout'
                type: list
                elements: dict
                suboptions:
                    layout_id:
                        type: int
                        description: no description
                    is_global:
                        type: int
                        description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            admin_user:
                type: str
                description: no description
            auto_hcache:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            date_format:
                type: str
                description: no description
            dev_type:
                type: str
                description: no description
                choices:
                    - 'FortiSandbox'
                    - 'FortiWeb'
                    - 'Fabric'
                    - 'Syslog'
                    - 'FortiCache'
                    - 'FortiAuthenticator'
                    - 'FortiMail'
                    - 'FortiProxy'
                    - 'FortiManager'
                    - 'FortiNAC'
                    - 'FortiAnalyzer'
                    - 'FortiClient'
                    - 'FortiDDoS'
                    - 'FortiGate'
                    - 'FortiFirewall'
            device_list_type:
                type: str
                description: no description
                choices:
                    - 'compact'
                    - 'count'
                    - 'detailed'
                    - 'none'
            display_device_by:
                type: str
                description: no description
                choices:
                    - 'device-id'
                    - 'device-name'
            display_table_contents:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            email_report_per_device:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            filter_logic:
                type: str
                description: no description
                choices:
                    - 'all'
                    - 'any'
            filter_type:
                type: str
                description: no description
                choices:
                    - 'srcip'
                    - 'none'
                    - 'hostname'
                    - 'group'
                    - 'user'
            include_coverpage:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            include_other:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - 'enable'
                    - 'disable'
            language:
                type: str
                description: no description
            ldap_query:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            ldap_server:
                type: str
                description: no description
            ldap_user_case_change:
                type: str
                description: no description
                choices:
                    - 'upper'
                    - 'lower'
                    - 'disable'
            max_reports:
                type: int
                description: no description
            obfuscate_user:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            orientation:
                type: str
                description: no description
                choices:
                    - 'portrait'
                    - 'landscape'
            output_format:
                type: str
                description: no description
                choices:
                    - 'xml'
                    - 'rtf'
                    - 'connectwise'
                    - 'html'
                    - 'pdf'
                    - 'mht'
                    - 'txt'
                    - 'csv'
            output_profile:
                type: str
                description: no description
            period_end:
                description: no description
                type: list
                elements: dict
            period_last_n:
                type: int
                description: no description
            period_opt:
                type: str
                description: no description
                choices:
                    - 'faz'
                    - 'dev'
            period_start:
                description: no description
                type: list
                elements: dict
            print_report_filters:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            report_per_device:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            resolve_hostname:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            schedule_color:
                type: str
                description: no description
            schedule_frequency:
                type: int
                description: no description
            schedule_type:
                type: str
                description: no description
                choices:
                    - 'every-n-days'
                    - 'every-n-months'
                    - 'every-n-hours'
                    - 'on-demand'
                    - 'every-n-weeks'
            schedule_valid_end:
                type: str
                description: no description
            schedule_valid_start:
                type: str
                description: no description
            time_period:
                type: str
                description: no description
                choices:
                    - 'last-n-weeks'
                    - 'last-month'
                    - 'last-7-days'
                    - 'last-week'
                    - 'yesterday'
                    - 'this-month'
                    - 'this-week'
                    - 'last-30-days'
                    - 'last-quarter'
                    - 'last-2-weeks'
                    - 'this-quarter'
                    - 'last-n-days'
                    - 'last-14-days'
                    - 'this-year'
                    - 'other'
                    - 'today'
                    - 'last-n-hours'
            week_start:
                type: str
                description: no description
                choices:
                    - 'wed'
                    - 'sun'
                    - 'fri'
                    - 'thr'
                    - 'mon'
                    - 'tue'
                    - 'sat'
            address_filter:
                description: 'reference: /report/adom/<adom-name>/config/schedule/<schedule_name>/address-filter'
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: no description
                    include_option:
                        type: str
                        description: no description
                    address_type:
                        type: str
                        description: no description
            soc_cust_filters:
                description: 'reference: /sql-report/schedule/soc-cust-filters'
                type: list
                elements: dict
                suboptions:
                    name:
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
    - name: Config schedule.
      fortinet.fortianalyzer.faz_report_config_schedule:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        report_config_schedule:
          description: <value of string>
          devices:
            - devices_name: <value of string>
              interfaces:
                - name: <value of string>
          filter:
            - description: <value of string>
              name: <value of string>
              opcode: <value in [not_equal, equal]>
              status: <value of integer>
              value: <value of string>
          name: <value of string>
          report_layout:
            - layout_id: <value of integer>
              is_global: <value of integer>
          status: <value in [enable, disable]>
          admin_user: <value of string>
          auto_hcache: <value in [enable, disable]>
          date_format: <value of string>
          dev_type: <value in [FortiSandbox, FortiWeb, Fabric, ...]>
          device_list_type: <value in [compact, count, detailed, ...]>
          display_device_by: <value in [device-id, device-name]>
          display_table_contents: <value in [enable, disable]>
          email_report_per_device: <value in [enable, disable]>
          filter_logic: <value in [all, any]>
          filter_type: <value in [srcip, none, hostname, ...]>
          include_coverpage: <value in [enable, disable]>
          include_other: <value in [auto, enable, disable]>
          language: <value of string>
          ldap_query: <value in [enable, disable]>
          ldap_server: <value of string>
          ldap_user_case_change: <value in [upper, lower, disable]>
          max_reports: <value of integer>
          obfuscate_user: <value in [enable, disable]>
          orientation: <value in [portrait, landscape]>
          output_format: <value in [xml, rtf, connectwise, ...]>
          output_profile: <value of string>
          period_end: <value of dict>
          period_last_n: <value of integer>
          period_opt: <value in [faz, dev]>
          period_start: <value of dict>
          print_report_filters: <value in [enable, disable]>
          report_per_device: <value in [enable, disable]>
          resolve_hostname: <value in [enable, disable]>
          schedule_color: <value of string>
          schedule_frequency: <value of integer>
          schedule_type: <value in [every-n-days, every-n-months, every-n-hours, ...]>
          schedule_valid_end: <value of string>
          schedule_valid_start: <value of string>
          time_period: <value in [last-n-weeks, last-month, last-7-days, ...]>
          week_start: <value in [wed, sun, fri, ...]>
          address_filter:
            - id: <value of integer>
              include_option: <value of string>
              address_type: <value of string>
          soc_cust_filters:
            - name: <value of string>
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
        '/report/adom/{adom}/config/schedule'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'version_check': {'type': 'bool', 'default': 'false'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'adom': {'required': True, 'type': 'str'},
        'report_config_schedule': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'description': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'devices': {
                    'type': 'list',
                    'options': {
                        'devices-name': {'type': 'str'},
                        'interfaces': {
                            'v_range': [['6.4.3', '']],
                            'type': 'list',
                            'options': {'name': {'v_range': [['6.4.3', '']], 'type': 'str'}},
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'filter': {
                    'type': 'list',
                    'options': {
                        'description': {'type': 'str'},
                        'name': {'type': 'str'},
                        'opcode': {'choices': ['not_equal', 'equal'], 'type': 'str'},
                        'status': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'value': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'report-layout': {
                    'type': 'list',
                    'options': {'layout-id': {'v_range': [['6.2.1', '7.4.2']], 'type': 'int'}, 'is-global': {'v_range': [['7.4.2', '']], 'type': 'int'}},
                    'elements': 'dict'
                },
                'status': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'admin-user': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                'auto-hcache': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'date-format': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'dev-type': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': [
                        'FortiSandbox', 'FortiWeb', 'Fabric', 'Syslog', 'FortiCache', 'FortiAuthenticator', 'FortiMail', 'FortiProxy', 'FortiManager',
                        'FortiNAC', 'FortiAnalyzer', 'FortiClient', 'FortiDDoS', 'FortiGate', 'FortiFirewall'
                    ],
                    'type': 'str'
                },
                'device-list-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['compact', 'count', 'detailed', 'none'], 'type': 'str'},
                'display-device-by': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['device-id', 'device-name'], 'type': 'str'},
                'display-table-contents': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'email-report-per-device': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'filter-logic': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['all', 'any'], 'type': 'str'},
                'filter-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['srcip', 'none', 'hostname', 'group', 'user'], 'type': 'str'},
                'include-coverpage': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'include-other': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['auto', 'enable', 'disable'], 'type': 'str'},
                'language': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'ldap-query': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'ldap-server': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'ldap-user-case-change': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['upper', 'lower', 'disable'], 'type': 'str'},
                'max-reports': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'obfuscate-user': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'orientation': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['portrait', 'landscape'], 'type': 'str'},
                'output-format': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': ['xml', 'rtf', 'connectwise', 'html', 'pdf', 'mht', 'txt', 'csv'],
                    'type': 'str'
                },
                'output-profile': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'period-end': {'v_range': [['6.2.2', '6.2.12']], 'type': 'list', 'elements': 'dict'},
                'period-last-n': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'period-opt': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['faz', 'dev'], 'type': 'str'},
                'period-start': {'v_range': [['6.2.2', '6.2.12']], 'type': 'list', 'elements': 'dict'},
                'print-report-filters': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'report-per-device': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'resolve-hostname': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'schedule-color': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'schedule-frequency': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'schedule-type': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': ['every-n-days', 'every-n-months', 'every-n-hours', 'on-demand', 'every-n-weeks'],
                    'type': 'str'
                },
                'schedule-valid-end': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'schedule-valid-start': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'time-period': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': [
                        'last-n-weeks', 'last-month', 'last-7-days', 'last-week', 'yesterday', 'this-month', 'this-week', 'last-30-days', 'last-quarter',
                        'last-2-weeks', 'this-quarter', 'last-n-days', 'last-14-days', 'this-year', 'other', 'today', 'last-n-hours'
                    ],
                    'type': 'str'
                },
                'week-start': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['wed', 'sun', 'fri', 'thr', 'mon', 'tue', 'sat'], 'type': 'str'},
                'address-filter': {
                    'v_range': [['6.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.4.3', '7.4.2']], 'type': 'int'},
                        'include-option': {'v_range': [['6.4.3', '7.4.2']], 'type': 'str'},
                        'address-type': {'v_range': [['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'soc-cust-filters': {
                    'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_schedule'),
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
