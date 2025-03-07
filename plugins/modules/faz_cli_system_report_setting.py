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
module: faz_cli_system_report_setting
short_description: Report settings.
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
    cli_system_report_setting:
        description: The top level parameters set.
        type: dict
        suboptions:
            aggregate_report:
                aliases: ['aggregate-report']
                type: str
                description:
                 - Enable/disable including a group report along with the per-device reports.
                 - disable - Exclude a group report along with the per-device reports.
                 - enable - Include a group report along with the per-device reports.
                choices: ['disable', 'enable']
            capwap_port:
                aliases: ['capwap-port']
                type: int
                description: Exclude capwap traffic by port.
            capwap_service:
                aliases: ['capwap-service']
                type: str
                description: Exclude capwap traffic by service.
            exclude_capwap:
                aliases: ['exclude-capwap']
                type: str
                description:
                 - Exclude capwap traffic.
                 - disable - Disable.
                 - by-port - By port.
                 - by-service - By service.
                choices: ['disable', 'by-port', 'by-service']
            hcache_lossless:
                aliases: ['hcache-lossless']
                type: str
                description:
                 - Usableness of ready-with-loss hcaches.
                 - disable - Use ready-with-loss hcaches.
                 - enable - Do not use ready-with-loss hcaches.
                choices: ['disable', 'enable']
            ldap_cache_timeout:
                aliases: ['ldap-cache-timeout']
                type: int
                description: LDAP cache timeout in minutes, default 60, 0 means not use cache.
            max_table_rows:
                aliases: ['max-table-rows']
                type: int
                description: Maximum number of rows can be generated in a single table.
            report_priority:
                aliases: ['report-priority']
                type: str
                description:
                 - Priority of sql report.
                 - high - High
                 - low - Low
                 - auto - Auto
                choices: ['high', 'low', 'auto']
            template_auto_install:
                aliases: ['template-auto-install']
                type: str
                description:
                 - The language used for new ADOMs
                 - default - Default.
                 - english - English.
                choices: ['default', 'english']
            week_start:
                aliases: ['week-start']
                type: str
                description:
                 - Day of the week on which the week starts.
                 - sun - Sunday.
                 - mon - Monday.
                choices: ['sun', 'mon']
            max_rpt_pdf_rows:
                aliases: ['max-rpt-pdf-rows']
                type: int
                description: Maximum number of rows can be generated in a single pdf.
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
    - name: Report settings.
      fortinet.fortianalyzer.faz_cli_system_report_setting:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        cli_system_report_setting:
          # aggregate_report: <value in [disable, enable]>
          # capwap_port: <value of integer>
          # capwap_service: <value of string>
          # exclude_capwap: <value in [disable, by-port, by-service]>
          # hcache_lossless: <value in [disable, enable]>
          # ldap_cache_timeout: <value of integer>
          # max_table_rows: <value of integer>
          # report_priority: <value in [high, low, auto]>
          # template_auto_install: <value in [default, english]>
          # week_start: <value in [sun, mon]>
          # max_rpt_pdf_rows: <value of integer>
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
        '/cli/global/system/report/setting'
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
        'cli_system_report_setting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'aggregate-report': {'choices': ['disable', 'enable'], 'type': 'str'},
                'capwap-port': {'type': 'int'},
                'capwap-service': {'type': 'str'},
                'exclude-capwap': {'choices': ['disable', 'by-port', 'by-service'], 'type': 'str'},
                'hcache-lossless': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-cache-timeout': {'type': 'int'},
                'max-table-rows': {'type': 'int'},
                'report-priority': {'choices': ['high', 'low', 'auto'], 'type': 'str'},
                'template-auto-install': {'choices': ['default', 'english'], 'type': 'str'},
                'week-start': {'choices': ['sun', 'mon'], 'type': 'str'},
                'max-rpt-pdf-rows': {'v_range': [['7.0.4', '']], 'type': 'int'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_report_setting'),
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
