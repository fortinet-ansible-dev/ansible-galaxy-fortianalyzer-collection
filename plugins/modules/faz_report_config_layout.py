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
module: faz_report_config_layout
short_description: Config layout.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.5.0"
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
    report_config_layout:
        description: The top level parameters set.
        type: dict
        suboptions:
            body:
                type: str
                description: no description
            component:
                description: 'reference: /report/adom/<adom-name>/config/layout/<layout-id>/component'
                type: list
                elements: dict
                suboptions:
                    component-id:
                        type: int
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'graphic'
                            - 'column-break'
                            - 'macro'
                            - 'section'
                            - 'chart'
                            - 'heading2'
                            - 'heading3'
                            - 'heading1'
                            - 'page-break'
                            - 'text'
                    variable:
                        description: 'reference: /report/adom/<adom-name>/config/layout/<layout-id>/component/<component-id>/variable'
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
                            var-value:
                                type: str
                                description: no description
                            description:
                                type: str
                                description: no description
                            drilldown-flag:
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
                            var-expression:
                                type: str
                                description: no description
                            var-type:
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
                    alignment:
                        type: int
                        description: no description
                    bg-color:
                        type: str
                        description: no description
                    category:
                        type: str
                        description: no description
                    chart:
                        type: str
                        description: no description
                    chart-option:
                        type: str
                        description: no description
                        choices:
                            - 'calc-average'
                            - 'none'
                    column:
                        type: str
                        description: no description
                        choices:
                            - '1'
                            - '2'
                    customized:
                        type: int
                        description: no description
                    device-mode:
                        type: str
                        description: no description
                        choices:
                            - 'variable'
                            - 'specify'
                    devices:
                        type: str
                        description: no description
                    drill-down-report:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    filter-logic:
                        type: str
                        description: no description
                        choices:
                            - 'all'
                            - 'any'
                    filter-mode:
                        type: str
                        description: no description
                        choices:
                            - 'override'
                            - 'inherit'
                    font-color:
                        type: str
                        description: no description
                    font-family:
                        type: str
                        description: no description
                    font-size:
                        type: int
                        description: no description
                    font-type:
                        type: str
                        description: no description
                        choices:
                            - 'bold-italic'
                            - 'bold'
                            - 'undefined'
                            - 'italic'
                            - 'normal'
                    graphic:
                        type: str
                        description: no description
                    include-other:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    ldap-query:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'enable'
                            - 'disable'
                    ldap-server:
                        type: str
                        description: no description
                    ldap-user-case-change:
                        type: str
                        description: no description
                        choices:
                            - 'upper'
                            - 'lower'
                            - 'disable'
                    left-margin:
                        type: int
                        description: no description
                    macro:
                        type: str
                        description: no description
                    not-vdom:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    period-end:
                        description: no description
                        type: list
                        elements: dict
                    period-last-n:
                        type: int
                        description: no description
                    period-mode:
                        type: str
                        description: no description
                        choices:
                            - 'variable'
                            - 'specify'
                    period-opt:
                        type: str
                        description: no description
                        choices:
                            - 'faz'
                            - 'dev'
                    period-start:
                        description: no description
                        type: list
                        elements: dict
                    right-margin:
                        type: int
                        description: no description
                    table-color:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'blue'
                            - 'green'
                            - 'red'
                    text:
                        type: str
                        description: no description
                    time-period:
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
                    week-start:
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
                    width:
                        type: int
                        description: no description
            description:
                type: str
                description: no description
            footer:
                description: 'reference: /report/adom/<adom-name>/config/layout/<layout-id>/footer'
                type: list
                elements: dict
                suboptions:
                    footer-id:
                        type: int
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'text'
                            - 'graphic'
                            - 'minicover'
                    graphic:
                        type: str
                        description: no description
                    text:
                        type: str
                        description: no description
            header:
                description: 'reference: /report/adom/<adom-name>/config/layout/<layout-id>/header'
                type: list
                elements: dict
                suboptions:
                    header-id:
                        type: int
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'text'
                            - 'graphic'
                            - 'minicover'
                    graphic:
                        type: str
                        description: no description
                    text:
                        type: str
                        description: no description
            language:
                type: str
                description: no description
            layout-id:
                type: int
                description: no description
            subtitle:
                type: str
                description: no description
            title:
                type: str
                description: no description
            alignment:
                type: str
                description: no description
                choices:
                    - 'right'
                    - 'center'
                    - 'left'
            bg-color:
                type: str
                description: no description
            category:
                type: str
                description: no description
            chart-heading-level:
                type: int
                description: no description
            chart-info-display:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            coverpage-background-image:
                type: str
                description: no description
            coverpage-bottom-image:
                type: str
                description: no description
            coverpage-custom-text1:
                type: str
                description: no description
            coverpage-custom-text2:
                type: str
                description: no description
            coverpage-enable-create-time:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            coverpage-enable-time-period:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            coverpage-footer-bgcolor:
                type: str
                description: no description
            coverpage-footer-left:
                type: str
                description: no description
            coverpage-footer-right:
                type: str
                description: no description
            coverpage-text-color:
                type: str
                description: no description
            coverpage-title:
                type: str
                description: no description
            coverpage-top-image:
                type: str
                description: no description
            coverpage-top-image-position:
                type: str
                description: no description
                choices:
                    - 'right'
                    - 'center'
                    - 'left'
            dev-type:
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
            folder-id:
                type: int
                description: no description
            font-color:
                type: str
                description: no description
            font-family:
                type: str
                description: no description
            font-size:
                type: int
                description: no description
            font-type:
                type: str
                description: no description
                choices:
                    - 'bold-italic'
                    - 'bold'
                    - 'undefined'
                    - 'italic'
                    - 'normal'
            footer-bgcolor:
                type: str
                description: no description
            header-bgcolor:
                type: str
                description: no description
            hide-report-title:
                type: int
                description: no description
            hide-rowid:
                type: int
                description: no description
            include-empty-charts:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            is-template:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            left-margin:
                type: int
                description: no description
            protected:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            report-tag:
                type: str
                description: no description
            right-margin:
                type: int
                description: no description
            folders:
                description: 'reference: /sql-report/layout/folders'
                type: list
                elements: dict
                suboptions:
                    folder-id:
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
    - name: Config layout.
      fortinet.fortianalyzer.faz_report_config_layout:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        report_config_layout:
          body: <value of string>
          component:
            - component_id: <value of integer>
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
          description: <value of string>
          footer:
            - footer_id: <value of integer>
              type: <value in [text, graphic, minicover]>
              graphic: <value of string>
              text: <value of string>
          header:
            - header_id: <value of integer>
              type: <value in [text, graphic, minicover]>
              graphic: <value of string>
              text: <value of string>
          language: <value of string>
          layout_id: <value of integer>
          subtitle: <value of string>
          title: <value of string>
          alignment: <value in [right, center, left]>
          bg_color: <value of string>
          category: <value of string>
          chart_heading_level: <value of integer>
          chart_info_display: <value in [enable, disable]>
          coverpage_background_image: <value of string>
          coverpage_bottom_image: <value of string>
          coverpage_custom_text1: <value of string>
          coverpage_custom_text2: <value of string>
          coverpage_enable_create_time: <value in [enable, disable]>
          coverpage_enable_time_period: <value in [enable, disable]>
          coverpage_footer_bgcolor: <value of string>
          coverpage_footer_left: <value of string>
          coverpage_footer_right: <value of string>
          coverpage_text_color: <value of string>
          coverpage_title: <value of string>
          coverpage_top_image: <value of string>
          coverpage_top_image_position: <value in [right, center, left]>
          dev_type: <value in [FortiSandbox, FortiWeb, Fabric, ...]>
          folder_id: <value of integer>
          font_color: <value of string>
          font_family: <value of string>
          font_size: <value of integer>
          font_type: <value in [bold-italic, bold, undefined, ...]>
          footer_bgcolor: <value of string>
          header_bgcolor: <value of string>
          hide_report_title: <value of integer>
          hide_rowid: <value of integer>
          include_empty_charts: <value in [enable, disable]>
          is_template: <value in [enable, disable]>
          left_margin: <value of integer>
          protected: <value in [enable, disable]>
          report_tag: <value of string>
          right_margin: <value of integer>
          folders:
            - folder_id: <value of integer>
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
        '/report/adom/{adom}/config/layout'
    ]

    perobject_jrpc_urls = [
        '/report/adom/{adom}/config/layout/{layout}'
    ]

    url_params = ['adom']
    module_primary_key = 'layout_id'
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
        'report_config_layout': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'body': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'component': {
                    'type': 'list',
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
                                'description': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'drilldown-flag': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                                'status': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                                'var-expression': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                                'var-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['ip', 'integer', 'string', 'datetime'], 'type': 'str'},
                                'view_mask': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'alignment': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'bg-color': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'category': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'chart': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'chart-option': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['calc-average', 'none'], 'type': 'str'},
                        'column': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['1', '2'], 'type': 'str'},
                        'customized': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'device-mode': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['variable', 'specify'], 'type': 'str'},
                        'devices': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'drill-down-report': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'filter-logic': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['all', 'any'], 'type': 'str'},
                        'filter-mode': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['override', 'inherit'], 'type': 'str'},
                        'font-color': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'font-family': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'font-size': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'font-type': {
                            'v_range': [['6.2.2', '6.2.12']],
                            'choices': ['bold-italic', 'bold', 'undefined', 'italic', 'normal'],
                            'type': 'str'
                        },
                        'graphic': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'include-other': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'ldap-query': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['auto', 'enable', 'disable'], 'type': 'str'},
                        'ldap-server': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'ldap-user-case-change': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['upper', 'lower', 'disable'], 'type': 'str'},
                        'left-margin': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'macro': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'not-vdom': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'period-end': {'v_range': [['6.2.2', '6.2.12']], 'type': 'list', 'elements': 'dict'},
                        'period-last-n': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'period-mode': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['variable', 'specify'], 'type': 'str'},
                        'period-opt': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['faz', 'dev'], 'type': 'str'},
                        'period-start': {'v_range': [['6.2.2', '6.2.12']], 'type': 'list', 'elements': 'dict'},
                        'right-margin': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                        'table-color': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['default', 'blue', 'green', 'red'], 'type': 'str'},
                        'text': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'time-period': {
                            'v_range': [['6.2.2', '6.2.12']],
                            'choices': [
                                'last-n-weeks', 'last-month', 'last-7-days', 'last-week', 'yesterday', 'this-month', 'this-week', 'last-30-days',
                                'last-quarter', 'last-2-weeks', 'this-quarter', 'last-n-days', 'last-14-days', 'this-year', 'other', 'today',
                                'last-n-hours'
                            ],
                            'type': 'str'
                        },
                        'title': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'vdom': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                        'week-start': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['wed', 'sun', 'fri', 'thr', 'mon', 'tue', 'sat'], 'type': 'str'},
                        'width': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'description': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'footer': {
                    'type': 'list',
                    'options': {
                        'footer-id': {'type': 'int'},
                        'type': {'choices': ['text', 'graphic', 'minicover'], 'type': 'str'},
                        'graphic': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'text': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'header': {
                    'type': 'list',
                    'options': {
                        'header-id': {'type': 'int'},
                        'type': {'choices': ['text', 'graphic', 'minicover'], 'type': 'str'},
                        'graphic': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'text': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'language': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'layout-id': {'v_range': [['6.2.1', '7.4.2']], 'type': 'int'},
                'subtitle': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'title': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'alignment': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['right', 'center', 'left'], 'type': 'str'},
                'bg-color': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'category': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'chart-heading-level': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'chart-info-display': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'coverpage-background-image': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-bottom-image': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-custom-text1': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-custom-text2': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-enable-create-time': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'coverpage-enable-time-period': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'coverpage-footer-bgcolor': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-footer-left': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-footer-right': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-text-color': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-title': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-top-image': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'coverpage-top-image-position': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['right', 'center', 'left'], 'type': 'str'},
                'dev-type': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': [
                        'FortiSandbox', 'FortiWeb', 'Fabric', 'Syslog', 'FortiCache', 'FortiAuthenticator', 'FortiMail', 'FortiProxy', 'FortiManager',
                        'FortiNAC', 'FortiAnalyzer', 'FortiClient', 'FortiDDoS', 'FortiGate', 'FortiFirewall'
                    ],
                    'type': 'str'
                },
                'folder-id': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'font-color': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'font-family': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'font-size': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'font-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['bold-italic', 'bold', 'undefined', 'italic', 'normal'], 'type': 'str'},
                'footer-bgcolor': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'header-bgcolor': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'hide-report-title': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'hide-rowid': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'include-empty-charts': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'is-template': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'left-margin': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'protected': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'report-tag': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'right-margin': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'},
                'folders': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {'folder-id': {'v_range': [['7.0.0', '']], 'type': 'int'}},
                    'elements': 'dict'
                }
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_layout'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
