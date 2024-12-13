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
module: faz_report_config_layout_component
short_description: Config component.
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
    layout-id:
        description: Deprecated, please use "layout_id"
        type: str
    layout_id:
        description: The parameter (layout-id) in requested url.
        type: str
    report_config_layout_component:
        description: The top level parameters set.
        type: dict
        suboptions:
            component_id:
                aliases: ['component-id']
                type: int
                description: no description
            type:
                type: str
                description: no description
                choices: ['graphic', 'column-break', 'macro', 'section', 'chart', 'heading2', 'heading3', 'heading1', 'page-break', 'text']
            variable:
                description: 'reference: /report/adom/<adom-name>/config/layout/<layout-id>/component/<component-id>/variable'
                type: list
                elements: dict
                suboptions:
                    not:
                        type: str
                        description: no description
                        choices: ['enable', 'disable']
                    var:
                        type: str
                        description: no description
                    var_value:
                        aliases: ['var-value']
                        type: str
                        description: no description
                    description:
                        type: str
                        description: no description
                    drilldown_flag:
                        aliases: ['drilldown-flag']
                        type: str
                        description: no description
                        choices: ['enable', 'disable']
                    status:
                        type: str
                        description: no description
                        choices: ['enable', 'disable']
                    var_expression:
                        aliases: ['var-expression']
                        type: str
                        description: no description
                    var_type:
                        aliases: ['var-type']
                        type: str
                        description: no description
                        choices: ['ip', 'integer', 'string', 'datetime']
                    view_mask:
                        type: int
                        description: no description
            alignment:
                type: int
                description: no description
            bg_color:
                aliases: ['bg-color']
                type: str
                description: no description
            category:
                type: str
                description: no description
            chart:
                type: str
                description: no description
            chart_option:
                aliases: ['chart-option']
                type: str
                description: no description
                choices: ['calc-average', 'none']
            column:
                type: str
                description: no description
                choices: ['1', '2']
            customized:
                type: int
                description: no description
            device_mode:
                aliases: ['device-mode']
                type: str
                description: no description
                choices: ['variable', 'specify']
            devices:
                type: str
                description: no description
            drill_down_report:
                aliases: ['drill-down-report']
                type: str
                description: no description
                choices: ['enable', 'disable']
            filter_logic:
                aliases: ['filter-logic']
                type: str
                description: no description
                choices: ['all', 'any']
            filter_mode:
                aliases: ['filter-mode']
                type: str
                description: no description
                choices: ['override', 'inherit']
            font_color:
                aliases: ['font-color']
                type: str
                description: no description
            font_family:
                aliases: ['font-family']
                type: str
                description: no description
            font_size:
                aliases: ['font-size']
                type: int
                description: no description
            font_type:
                aliases: ['font-type']
                type: str
                description: no description
                choices: ['bold-italic', 'bold', 'undefined', 'italic', 'normal']
            graphic:
                type: str
                description: no description
            include_other:
                aliases: ['include-other']
                type: str
                description: no description
                choices: ['enable', 'disable']
            ldap_query:
                aliases: ['ldap-query']
                type: str
                description: no description
                choices: ['auto', 'enable', 'disable']
            ldap_server:
                aliases: ['ldap-server']
                type: str
                description: no description
            ldap_user_case_change:
                aliases: ['ldap-user-case-change']
                type: str
                description: no description
                choices: ['upper', 'lower', 'disable']
            left_margin:
                aliases: ['left-margin']
                type: int
                description: no description
            macro:
                type: str
                description: no description
            not_vdom:
                aliases: ['not-vdom']
                type: str
                description: no description
                choices: ['enable', 'disable']
            period_end:
                aliases: ['period-end']
                description: no description
                type: list
                elements: dict
            period_last_n:
                aliases: ['period-last-n']
                type: int
                description: no description
            period_mode:
                aliases: ['period-mode']
                type: str
                description: no description
                choices: ['variable', 'specify']
            period_opt:
                aliases: ['period-opt']
                type: str
                description: no description
                choices: ['faz', 'dev']
            period_start:
                aliases: ['period-start']
                description: no description
                type: list
                elements: dict
            right_margin:
                aliases: ['right-margin']
                type: int
                description: no description
            table_color:
                aliases: ['table-color']
                type: str
                description: no description
                choices: ['default', 'blue', 'green', 'red']
            text:
                type: str
                description: no description
            time_period:
                aliases: ['time-period']
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
            title:
                type: str
                description: no description
            vdom:
                type: str
                description: no description
            week_start:
                aliases: ['week-start']
                type: str
                description: no description
                choices: ['wed', 'sun', 'fri', 'thr', 'mon', 'tue', 'sat']
            width:
                type: int
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
    - name: Config component.
      fortinet.fortianalyzer.faz_report_config_layout_component:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        layout_id: <your own value>
        state: <value in [present, absent]>
        report_config_layout_component:
          component_id: <value of integer>
          type: <value in [graphic, column-break, macro, ...]>
          variable:
            - not: <value in [enable, disable]>
              var: <value of string>
              var_value: <value of string>
              description: <value of string>
              drilldown_flag: <value in [enable, disable]>
              status: <value in [enable, disable]>
              var_expression: <value of string>
              var_type: <value in [ip, integer, string, ...]>
              view_mask: <value of integer>
          alignment: <value of integer>
          bg_color: <value of string>
          category: <value of string>
          chart: <value of string>
          chart_option: <value in [calc-average, none]>
          column: <value in [1, 2]>
          customized: <value of integer>
          device_mode: <value in [variable, specify]>
          devices: <value of string>
          drill_down_report: <value in [enable, disable]>
          filter_logic: <value in [all, any]>
          filter_mode: <value in [override, inherit]>
          font_color: <value of string>
          font_family: <value of string>
          font_size: <value of integer>
          font_type: <value in [bold-italic, bold, undefined, ...]>
          graphic: <value of string>
          include_other: <value in [enable, disable]>
          ldap_query: <value in [auto, enable, disable]>
          ldap_server: <value of string>
          ldap_user_case_change: <value in [upper, lower, disable]>
          left_margin: <value of integer>
          macro: <value of string>
          not_vdom: <value in [enable, disable]>
          period_end: <value of dict>
          period_last_n: <value of integer>
          period_mode: <value in [variable, specify]>
          period_opt: <value in [faz, dev]>
          period_start: <value of dict>
          right_margin: <value of integer>
          table_color: <value in [default, blue, green, ...]>
          text: <value of string>
          time_period: <value in [last-n-weeks, last-month, last-7-days, ...]>
          title: <value of string>
          vdom: <value of string>
          week_start: <value in [wed, sun, fri, ...]>
          width: <value of integer>
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
        '/report/adom/{adom}/config/layout/{layout-id}/component'
    ]

    url_params = ['adom', 'layout-id']
    module_primary_key = 'component_id'
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
        'layout-id': {'type': 'str', 'api_name': 'layout_id'},
        'layout_id': {'type': 'str'},
        'report_config_layout_component': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'component-id': {'v_range': [['6.2.1', '7.4.2']], 'type': 'int'},
                'type': {
                    'v_range': [['6.2.1', '7.4.2']],
                    'choices': ['graphic', 'column-break', 'macro', 'section', 'chart', 'heading2', 'heading3', 'heading1', 'page-break', 'text'],
                    'type': 'str'
                },
                'variable': {
                    'type': 'list',
                    'options': {
                        'not': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'var': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'var-value': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'description': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'type': 'str'},
                        'drilldown-flag': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'var-expression': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'var-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['ip', 'integer', 'string', 'datetime'], 'type': 'str'},
                        'view_mask': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'alignment': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'type': 'int'},
                'bg-color': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'type': 'str'},
                'category': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'type': 'str'},
                'chart': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'type': 'str'},
                'chart-option': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'choices': ['calc-average', 'none'], 'type': 'str'},
                'column': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['1', '2'], 'type': 'str'},
                'customized': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'device-mode': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['variable', 'specify'], 'type': 'str'},
                'devices': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'drill-down-report': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'filter-logic': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['all', 'any'], 'type': 'str'},
                'filter-mode': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['override', 'inherit'], 'type': 'str'},
                'font-color': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'font-family': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'font-size': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'font-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['bold-italic', 'bold', 'undefined', 'italic', 'normal'], 'type': 'str'},
                'graphic': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'include-other': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'ldap-query': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['auto', 'enable', 'disable'], 'type': 'str'},
                'ldap-server': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'ldap-user-case-change': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['upper', 'lower', 'disable'], 'type': 'str'},
                'left-margin': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'macro': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'not-vdom': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'period-end': {'v_range': [['6.2.2', '6.2.13']], 'type': 'list', 'elements': 'dict'},
                'period-last-n': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'period-mode': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['variable', 'specify'], 'type': 'str'},
                'period-opt': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['faz', 'dev'], 'type': 'str'},
                'period-start': {'v_range': [['6.2.2', '6.2.13']], 'type': 'list', 'elements': 'dict'},
                'right-margin': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'table-color': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['default', 'blue', 'green', 'red'], 'type': 'str'},
                'text': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'time-period': {
                    'v_range': [['6.2.2', '6.2.13']],
                    'choices': [
                        'last-n-weeks', 'last-month', 'last-7-days', 'last-week', 'yesterday', 'this-month', 'this-week', 'last-30-days', 'last-quarter',
                        'last-2-weeks', 'this-quarter', 'last-n-days', 'last-14-days', 'this-year', 'other', 'today', 'last-n-hours'
                    ],
                    'type': 'str'
                },
                'title': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'vdom': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'week-start': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['wed', 'sun', 'fri', 'thr', 'mon', 'tue', 'sat'], 'type': 'str'},
                'width': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_layout_component'),
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
