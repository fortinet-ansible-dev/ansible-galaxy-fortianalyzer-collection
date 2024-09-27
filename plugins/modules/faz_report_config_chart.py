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
module: faz_report_config_chart
short_description: Config chart.
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
    report_config_chart:
        description: The top level parameters set.
        type: dict
        suboptions:
            category:
                type: str
                description: no description
            description:
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
            disp_name:
                type: str
                description: no description
            drill_down_table:
                description: 'reference: /report/adom/<adom-name>/config/chart/<chart_name>/drill-down-table'
                type: list
                elements: dict
                suboptions:
                    chart:
                        type: str
                        description: no description
                    flag:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    table_id:
                        type: int
                        description: no description
                    chart_group:
                        type: str
                        description: no description
                    page_break_after:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    show_title:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
            name:
                type: str
                description: no description
            table_columns:
                description: 'reference: /report/adom/<adom-name>/config/chart/<chart_name>/table-columns'
                type: list
                elements: dict
                suboptions:
                    data_type:
                        type: str
                        description: no description
                        choices:
                            - 'aggregate'
                            - 'raw'
                            - 'drilldown'
                    header:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    column_attr:
                        type: str
                        description: no description
                        choices:
                            - 'app-id'
                            - 'email-recver'
                            - 'timespan'
                            - 'obf-url'
                            - 'cal-percent'
                            - 'vuln'
                            - 'bandwidth'
                            - 'dev-type'
                            - 'severity'
                            - 'percent'
                            - 'trend'
                            - 'attack'
                            - 'html'
                            - 'ipsec-tunnel'
                            - 'web-cat'
                            - 'ip-country'
                            - 'email-sender'
                            - 'search'
                            - 'virus'
                            - 'user'
                            - 'state-icon'
                            - 'count'
                            - 'none'
                            - 'dst-country'
                            - 'url'
                            - 'appcat'
                            - 'time'
                            - 'kbps'
                    column_graph_type:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'bar'
                            - 'line-down'
                            - 'line-up'
                    column_num:
                        type: int
                        description: no description
                    column_span:
                        type: int
                        description: no description
                    column_width:
                        type: int
                        description: no description
                    data_binding:
                        type: str
                        description: no description
                    data_top:
                        type: int
                        description: no description
                    legend:
                        type: str
                        description: no description
            variable_template:
                description: 'reference: /report/adom/<adom-name>/config/chart/<chart_name>/variable-template'
                type: list
                elements: dict
                suboptions:
                    not:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    var:
                        type: str
                        description: no description
                    var_value:
                        type: str
                        description: no description
                    description:
                        type: str
                        description: no description
                    drilldown_flag:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    var_expression:
                        type: str
                        description: no description
                    var_type:
                        type: str
                        description: no description
                        choices:
                            - 'ip'
                            - 'integer'
                            - 'string'
                            - 'datetime'
                    view_mask:
                        type: int
                        description: no description
            chart_type:
                type: str
                description: no description
                choices:
                    - 'map'
                    - 'none'
                    - 'chord'
                    - 'bar'
                    - 'area'
                    - 'pie'
                    - 'donut'
                    - 'radar'
                    - 'table'
                    - 'line'
            dataset:
                type: str
                description: no description
            drill_down_agg:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            drill_down_desc:
                type: str
                description: no description
            drill_down_title:
                type: str
                description: no description
            favorite:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            hidden:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            include_other:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            line_subtype:
                type: str
                description: no description
                choices:
                    - 'back-to-back'
                    - 'stacked'
                    - 'basic'
            order_by:
                type: str
                description: no description
            order_desc:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            protected:
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
            resolve_hostname_mode:
                type: str
                description: no description
                choices:
                    - 'variable'
                    - 'specify'
            scale:
                type: int
                description: no description
            show_table:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            x_axis_data_binding:
                type: str
                description: no description
            x_axis_data_top:
                type: int
                description: no description
            x_axis_include_other:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            x_axis_label:
                type: str
                description: no description
            y_axis_data_binding:
                type: str
                description: no description
            y_axis_group:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            y_axis_group_by:
                type: str
                description: no description
            y_axis_group_top:
                type: int
                description: no description
            y_axis_label:
                type: str
                description: no description
            y2_axis_data_binding:
                type: str
                description: no description
            y2_axis_label:
                type: str
                description: no description
            tags:
                type: str
                description: no description
            chart_style:
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
    - name: Config chart.
      fortinet.fortianalyzer.faz_report_config_chart:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        report_config_chart:
          category: <value of string>
          description: <value of string>
          dev_type: <value in [FortiSandbox, FortiWeb, Fabric, ...]>
          disp_name: <value of string>
          drill_down_table:
            - chart: <value of string>
              flag: <value in [enable, disable]>
              table_id: <value of integer>
              chart_group: <value of string>
              page_break_after: <value in [enable, disable]>
              show_title: <value in [enable, disable]>
          name: <value of string>
          table_columns:
            - data_type: <value in [aggregate, raw, drilldown]>
              header: <value of string>
              id: <value of integer>
              column_attr: <value in [app-id, email-recver, timespan, ...]>
              column_graph_type: <value in [none, bar, line-down, ...]>
              column_num: <value of integer>
              column_span: <value of integer>
              column_width: <value of integer>
              data_binding: <value of string>
              data_top: <value of integer>
              legend: <value of string>
          variable_template:
            - not: <value in [enable, disable]>
              var: <value of string>
              var_value: <value of string>
              description: <value of string>
              drilldown_flag: <value in [enable, disable]>
              status: <value in [enable, disable]>
              var_expression: <value of string>
              var_type: <value in [ip, integer, string, ...]>
              view_mask: <value of integer>
          chart_type: <value in [map, none, chord, ...]>
          dataset: <value of string>
          drill_down_agg: <value in [enable, disable]>
          drill_down_desc: <value of string>
          drill_down_title: <value of string>
          favorite: <value in [enable, disable]>
          hidden: <value in [enable, disable]>
          include_other: <value in [enable, disable]>
          line_subtype: <value in [back-to-back, stacked, basic]>
          order_by: <value of string>
          order_desc: <value in [enable, disable]>
          protected: <value in [enable, disable]>
          resolve_hostname: <value in [enable, disable]>
          resolve_hostname_mode: <value in [variable, specify]>
          scale: <value of integer>
          show_table: <value in [enable, disable]>
          x_axis_data_binding: <value of string>
          x_axis_data_top: <value of integer>
          x_axis_include_other: <value in [enable, disable]>
          x_axis_label: <value of string>
          y_axis_data_binding: <value of string>
          y_axis_group: <value in [enable, disable]>
          y_axis_group_by: <value of string>
          y_axis_group_top: <value of integer>
          y_axis_label: <value of string>
          y2_axis_data_binding: <value of string>
          y2_axis_label: <value of string>
          tags: <value of string>
          chart_style: <value of string>
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
        '/report/adom/{adom}/config/chart'
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
        'report_config_chart': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'category': {'type': 'str'},
                'description': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'dev-type': {
                    'v_range': [['6.2.1', '7.4.2']],
                    'choices': [
                        'FortiSandbox', 'FortiWeb', 'Fabric', 'Syslog', 'FortiCache', 'FortiAuthenticator', 'FortiMail', 'FortiProxy', 'FortiManager',
                        'FortiNAC', 'FortiAnalyzer', 'FortiClient', 'FortiDDoS', 'FortiGate', 'FortiFirewall'
                    ],
                    'type': 'str'
                },
                'disp-name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'drill-down-table': {
                    'type': 'list',
                    'options': {
                        'chart': {'type': 'str'},
                        'flag': {'choices': ['enable', 'disable'], 'type': 'str'},
                        'table-id': {'v_range': [['6.2.1', '7.4.2']], 'type': 'int'},
                        'chart-group': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'page-break-after': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'show-title': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'table-columns': {
                    'type': 'list',
                    'options': {
                        'data-type': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['aggregate', 'raw', 'drilldown'], 'type': 'str'},
                        'header': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'id': {'v_range': [['6.2.1', '7.4.2']], 'type': 'int'},
                        'column-attr': {
                            'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']],
                            'choices': [
                                'app-id', 'email-recver', 'timespan', 'obf-url', 'cal-percent', 'vuln', 'bandwidth', 'dev-type', 'severity', 'percent',
                                'trend', 'attack', 'html', 'ipsec-tunnel', 'web-cat', 'ip-country', 'email-sender', 'search', 'virus', 'user',
                                'state-icon', 'count', 'none', 'dst-country', 'url', 'appcat', 'time', 'kbps'
                            ],
                            'type': 'str'
                        },
                        'column-graph-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['none', 'bar', 'line-down', 'line-up'], 'type': 'str'},
                        'column-num': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'column-span': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'column-width': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'data-binding': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'data-top': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'legend': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'variable-template': {
                    'type': 'list',
                    'options': {
                        'not': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'var': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'var-value': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'description': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'drilldown-flag': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'var-expression': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'var-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['ip', 'integer', 'string', 'datetime'], 'type': 'str'},
                        'view_mask': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'chart-type': {
                    'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']],
                    'choices': ['map', 'none', 'chord', 'bar', 'area', 'pie', 'donut', 'radar', 'table', 'line'],
                    'type': 'str'
                },
                'dataset': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'drill-down-agg': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'drill-down-desc': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'drill-down-title': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'favorite': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'hidden': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'include-other': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'line-subtype': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['back-to-back', 'stacked', 'basic'], 'type': 'str'},
                'order-by': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'order-desc': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'protected': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'resolve-hostname': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'resolve-hostname-mode': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['variable', 'specify'], 'type': 'str'},
                'scale': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'show-table': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'x-axis-data-binding': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'x-axis-data-top': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'x-axis-include-other': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'x-axis-label': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'y-axis-data-binding': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'y-axis-group': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'y-axis-group-by': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'y-axis-group-top': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'y-axis-label': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'y2-axis-data-binding': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'y2-axis-label': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'tags': {'v_range': [['6.4.3', '7.4.2']], 'type': 'str'},
                'chart-style': {'v_range': [['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_chart'),
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
