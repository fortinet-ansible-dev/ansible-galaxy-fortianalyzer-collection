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
module: faz_cli_system_alertevent
short_description: Alert events.
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
    cli_system_alertevent:
        description: The top level parameters set.
        type: dict
        suboptions:
            alert_destination:
                aliases: ['alert-destination']
                description: no description
                type: list
                elements: dict
                suboptions:
                    from:
                        type: str
                        description: Sender email address to use in alert emails.
                    smtp_name:
                        aliases: ['smtp-name']
                        type: str
                        description: SMTP server name.
                    snmp_name:
                        aliases: ['snmp-name']
                        type: str
                        description: SNMP trap name.
                    syslog_name:
                        aliases: ['syslog-name']
                        type: str
                        description: Syslog server name.
                    to:
                        type: str
                        description: Recipient email address to use in alert emails.
                    type:
                        type: str
                        description:
                         - Destination type.
                         - mail - Send email alert.
                         - snmp - Send SNMP trap.
                         - syslog - Send syslog message.
                        choices: ['mail', 'snmp', 'syslog']
            enable_generic_text:
                aliases: ['enable-generic-text']
                description:
                 - Enable/disable generic text match.
                 - enable - Enable setting.
                 - disable - Disable setting.
                type: list
                elements: str
                choices: ['enable', 'disable']
            enable_severity_filter:
                aliases: ['enable-severity-filter']
                description:
                 - Enable/disable alert severity filter.
                 - enable - Enable setting.
                 - disable - Disable setting.
                type: list
                elements: str
                choices: ['enable', 'disable']
            event_time_period:
                aliases: ['event-time-period']
                type: str
                description:
                 - Time period
                 - 0.5 - 30 minutes.
                 - 1 - 1 hour.
                 - 3 - 3 hours.
                 - 6 - 6 hours.
                 - 12 - 12 hours.
                 - 24 - 1 day.
                 - 72 - 3 days.
                 - 168 - 1 week.
                choices: ['0.5', '1', '3', '6', '12', '24', '72', '168']
            generic_text:
                aliases: ['generic-text']
                type: str
                description: Text that must be contained in a log to trigger alert.
            name:
                type: str
                description: Alert name.
            num_events:
                aliases: ['num-events']
                type: str
                description:
                 - Minimum number of events required within time period.
                 - 1 - 1 event.
                 - 5 - 5 events.
                 - 10 - 10 events.
                 - 50 - 50 events.
                 - 100 - 100 events.
                choices: ['1', '5', '10', '50', '100']
            severity_filter:
                aliases: ['severity-filter']
                type: str
                description:
                 - Required log severity to trigger alert.
                 - high - High level alert.
                 - medium-high - Medium-high level alert.
                 - medium - Medium level alert.
                 - medium-low - Medium-low level alert.
                 - low - Low level alert.
                choices: ['high', 'medium-high', 'medium', 'medium-low', 'low']
            severity_level_comp:
                aliases: ['severity-level-comp']
                description: Log severity threshold comparison criterion.
                type: list
                elements: str
                choices: ['>=', '=', '<=']
            severity_level_logs:
                aliases: ['severity-level-logs']
                description:
                 - Log severity threshold level.
                 - no-check - Do not check severity level for this log type.
                 - information - Information level.
                 - notify - Notify level.
                 - warning - Warning level.
                 - error - Error level.
                 - critical - Critical level.
                 - alert - Alert level.
                 - emergency - Emergency level.
                type: list
                elements: str
                choices: ['no-check', 'information', 'notify', 'warning', 'error', 'critical', 'alert', 'emergency']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Alert events.
      fortinet.fortianalyzer.faz_cli_system_alertevent:
        cli_system_alertevent:
          event_time_period: 1
          generic_text: "an event aleryed"
          name: fooevent
          num_events: 5
          severity_filter: high
          severity_level_comp:
            - ">="
          severity_level_logs:
            - no-check
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
        '/cli/global/system/alert-event'
    ]

    url_params = []
    module_primary_key = 'name'
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
        'cli_system_alertevent': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'alert-destination': {
                    'type': 'list',
                    'options': {
                        'from': {'type': 'str'},
                        'smtp-name': {'type': 'str'},
                        'snmp-name': {'type': 'str'},
                        'syslog-name': {'type': 'str'},
                        'to': {'type': 'str'},
                        'type': {'choices': ['mail', 'snmp', 'syslog'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enable-generic-text': {'type': 'list', 'choices': ['enable', 'disable'], 'elements': 'str'},
                'enable-severity-filter': {'type': 'list', 'choices': ['enable', 'disable'], 'elements': 'str'},
                'event-time-period': {'choices': ['0.5', '1', '3', '6', '12', '24', '72', '168'], 'type': 'str'},
                'generic-text': {'type': 'str'},
                'name': {'type': 'str'},
                'num-events': {'choices': ['1', '5', '10', '50', '100'], 'type': 'str'},
                'severity-filter': {'choices': ['high', 'medium-high', 'medium', 'medium-low', 'low'], 'type': 'str'},
                'severity-level-comp': {'type': 'list', 'choices': ['>=', '=', '<='], 'elements': 'str'},
                'severity-level-logs': {
                    'type': 'list',
                    'choices': ['no-check', 'information', 'notify', 'warning', 'error', 'critical', 'alert', 'emergency'],
                    'elements': 'str'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_alertevent'),
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
