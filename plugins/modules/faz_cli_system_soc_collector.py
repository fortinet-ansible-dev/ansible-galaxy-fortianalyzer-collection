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
module: faz_cli_system_soc_collector
short_description: FAZ SOC collector settings.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.11.0"
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
        description:
            - Enable/Disable logging for task.
            - If omitted, use environment variable ANSIBLE_FORTIANALYZER_ENABLE_LOG. Defaults to false.
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
    cli_system_soc_collector:
        description: The top level parameters set.
        type: dict
        suboptions:
            client_id:
                aliases: ['client-id']
                type: str
                description: SIEM client ID.
            client_secret:
                aliases: ['client-secret']
                description: SIEM client secret.
                type: str
            log_level:
                aliases: ['log-level']
                description: no description
                type: dict
                suboptions:
                    all:
                        type: str
                        description:
                         - Set the log level for all.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phAgentManager:
                        type: str
                        description:
                         - Set the log level for phAgentManager.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phDiscover:
                        type: str
                        description:
                         - Set the log level for phDiscover.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phEventForwarder:
                        type: str
                        description:
                         - Set the log level for phEventForwarder.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phEventHandler:
                        type: str
                        description:
                         - Set the log level for phEventHandler.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phEventPackager:
                        type: str
                        description:
                         - Set the log level for phEventPackager.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phMonitor:
                        type: str
                        description:
                         - Set the log level for phMonitor.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phParser:
                        type: str
                        description:
                         - Set the log level for phParser.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
                    phPerfMonitor:
                        type: str
                        description:
                         - Set the log level for phPerfMonitor.
                         - none - NONE.
                         - critical - CRITICAL.
                         - error - ERROR.
                         - warning - WARNING.
                         - notification - NOTIF.
                         - info - INFO.
                         - debug - DEBUG.
                        choices: ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug']
            log_queue:
                aliases: ['log-queue']
                description: no description
                type: dict
                suboptions:
                    config_queue_file_count_limit:
                        aliases: ['config-queue-file-count-limit']
                        type: int
                        description: Set the maximum number of device-config files that can be queued by soc collector processes.
                    config_queue_size_limit_mb:
                        aliases: ['config-queue-size-limit-mb']
                        type: int
                        description: Set the maximum total size of device config files that can be queued by soc collector processes.
                    linux_queue_file_count_limit:
                        aliases: ['linux-queue-file-count-limit']
                        type: int
                        description: Set the maximum number of linux event files that can be queued by soc collector processes.
                    linux_queue_size_limit_mb:
                        aliases: ['linux-queue-size-limit-mb']
                        type: int
                        description: Set the maximum total size of linux event files that can be queued by soc collector processes.
                    logs_queue_file_count_limit:
                        aliases: ['logs-queue-file-count-limit']
                        type: int
                        description: Set the maximum number of other
                    logs_queue_size_limit_mb:
                        aliases: ['logs-queue-size-limit-mb']
                        type: int
                        description: Set the maximum total size of other
                    win_queue_file_count_limit:
                        aliases: ['win-queue-file-count-limit']
                        type: int
                        description: Set the maximum number of windows event files that can be queued by soc collector processes.
                    win_queue_size_limit_mb:
                        aliases: ['win-queue-size-limit-mb']
                        type: int
                        description: Set the maximum total size of windows event files that can be queued by soc collector processes.
            name:
                type: str
                description: SIEM collector name.
            org_name:
                aliases: ['org-name']
                type: str
                description: organization name.
            perf_mode:
                aliases: ['perf-mode']
                type: str
                description:
                 - Set the resource limitation profile for soc collector processes.
                 - minimum - Restrict system resources for the SIEM collector.
                 - balanced - Moderate resource usage for balanced performance of the SIEM collector.
                 - aggressive - Allow more system resources for peak performance of the SIEM collector.
                choices: ['minimum', 'balanced', 'aggressive']
            status:
                type: str
                description:
                 - Enable or Disable SIEM collector.
                 - disable - Disable SIEM collector.
                 - enable - Enable SIEM collector.
                choices: ['disable', 'enable']
            super_addr:
                aliases: ['super-addr']
                type: str
                description: SIEM supervisor IP/FQDN.
            super_port:
                aliases: ['super-port']
                type: int
                description: SIEM supervisor port
            verify_ssl:
                aliases: ['verify-ssl']
                type: str
                description:
                 - Enable or Disable verify-ssl on SIEM collector connection.
                 - disable - Disable verify-ssl on connection.
                 - enable - Enable verify-ssl on connection.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
  tasks:
    - name: FAZ SOC collector settings.
      fortinet.fortianalyzer.faz_cli_system_soc_collector:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        cli_system_soc_collector:
          # client_id: <value of string>
          # client_secret: <value of string>
          # log_level:
          #   all: <value in [none, critical, error, ...]>
          #   phAgentManager: <value in [none, critical, error, ...]>
          #   phDiscover: <value in [none, critical, error, ...]>
          #   phEventForwarder: <value in [none, critical, error, ...]>
          #   phEventHandler: <value in [none, critical, error, ...]>
          #   phEventPackager: <value in [none, critical, error, ...]>
          #   phMonitor: <value in [none, critical, error, ...]>
          #   phParser: <value in [none, critical, error, ...]>
          #   phPerfMonitor: <value in [none, critical, error, ...]>
          # log_queue:
          #   config_queue_file_count_limit: <value of integer>
          #   config_queue_size_limit_mb: <value of integer>
          #   linux_queue_file_count_limit: <value of integer>
          #   linux_queue_size_limit_mb: <value of integer>
          #   logs_queue_file_count_limit: <value of integer>
          #   logs_queue_size_limit_mb: <value of integer>
          #   win_queue_file_count_limit: <value of integer>
          #   win_queue_size_limit_mb: <value of integer>
          # name: <value of string>
          # org_name: <value of string>
          # perf_mode: <value in [minimum, balanced, aggressive]>
          # status: <value in [disable, enable]>
          # super_addr: <value of string>
          # super_port: <value of integer>
          # verify_ssl: <value in [disable, enable]>
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
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import FortiAnalyzerAnsible
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    urls_list = [
        '/cli/global/system/soc/collector'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False, 'fallback': (env_fallback, ['ANSIBLE_FORTIANALYZER_ENABLE_LOG'])},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_system_soc_collector': {
            'type': 'dict',
            'v_range': [['8.0.1', '']],
            'options': {
                'client-id': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'client-secret': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'str'},
                'log-level': {
                    'v_range': [['8.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'all': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phAgentManager': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phDiscover': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phEventForwarder': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phEventHandler': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phEventPackager': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phMonitor': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phParser': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        },
                        'phPerfMonitor': {
                            'v_range': [['8.0.1', '']],
                            'choices': ['none', 'critical', 'error', 'warning', 'notification', 'info', 'debug'],
                            'type': 'str'
                        }
                    }
                },
                'log-queue': {
                    'v_range': [['8.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'config-queue-file-count-limit': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'config-queue-size-limit-mb': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'linux-queue-file-count-limit': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'linux-queue-size-limit-mb': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'logs-queue-file-count-limit': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'logs-queue-size-limit-mb': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'win-queue-file-count-limit': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'win-queue-size-limit-mb': {'v_range': [['8.0.1', '']], 'type': 'int'}
                    }
                },
                'name': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'org-name': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'perf-mode': {'v_range': [['8.0.1', '']], 'choices': ['minimum', 'balanced', 'aggressive'], 'type': 'str'},
                'status': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'super-addr': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'super-port': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'verify-ssl': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_soc_collector'),
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
