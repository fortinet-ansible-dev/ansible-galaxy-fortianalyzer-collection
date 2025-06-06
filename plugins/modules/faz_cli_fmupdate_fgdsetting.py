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
module: faz_cli_fmupdate_fgdsetting
short_description: Cli fmupdate fgd setting
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.9.0"
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
    cli_fmupdate_fgdsetting:
        description: The top level parameters set.
        type: dict
        suboptions:
            as_cache:
                aliases: ['as-cache']
                type: int
                description: no description
            as_log:
                aliases: ['as-log']
                type: str
                description: no description
                choices: ['disable', 'nospam', 'all']
            as_preload:
                aliases: ['as-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            av_cache:
                aliases: ['av-cache']
                type: int
                description: no description
            av_log:
                aliases: ['av-log']
                type: str
                description: no description
                choices: ['disable', 'novirus', 'all']
            av_preload:
                aliases: ['av-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            av2_cache:
                aliases: ['av2-cache']
                type: int
                description: no description
            av2_log:
                aliases: ['av2-log']
                type: str
                description: no description
                choices: ['disable', 'noav2', 'all']
            av2_preload:
                aliases: ['av2-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            eventlog_query:
                aliases: ['eventlog-query']
                type: str
                description: no description
                choices: ['disable', 'enable']
            fgd_pull_interval:
                aliases: ['fgd-pull-interval']
                type: int
                description: no description
            fq_cache:
                aliases: ['fq-cache']
                type: int
                description: no description
            fq_log:
                aliases: ['fq-log']
                type: str
                description: no description
                choices: ['disable', 'nofilequery', 'all']
            fq_preload:
                aliases: ['fq-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            iot_cache:
                aliases: ['iot-cache']
                type: int
                description: no description
            iot_log:
                aliases: ['iot-log']
                type: str
                description: no description
                choices: ['disable', 'noiot', 'all']
            iot_preload:
                aliases: ['iot-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            iotv_preload:
                aliases: ['iotv-preload']
                type: str
                description: no description
                choices: ['disable', 'enable']
            linkd_log:
                aliases: ['linkd-log']
                type: str
                description: no description
                choices: ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable']
            max_client_worker:
                aliases: ['max-client-worker']
                type: int
                description: no description
            max_log_quota:
                aliases: ['max-log-quota']
                type: int
                description: no description
            max_unrated_site:
                aliases: ['max-unrated-site']
                type: int
                description: no description
            restrict_as1_dbver:
                aliases: ['restrict-as1-dbver']
                type: str
                description: no description
            restrict_as2_dbver:
                aliases: ['restrict-as2-dbver']
                type: str
                description: no description
            restrict_as4_dbver:
                aliases: ['restrict-as4-dbver']
                type: str
                description: no description
            restrict_av_dbver:
                aliases: ['restrict-av-dbver']
                type: str
                description: no description
            restrict_av2_dbver:
                aliases: ['restrict-av2-dbver']
                type: str
                description: no description
            restrict_fq_dbver:
                aliases: ['restrict-fq-dbver']
                type: str
                description: no description
            restrict_iots_dbver:
                aliases: ['restrict-iots-dbver']
                type: str
                description: no description
            restrict_wf_dbver:
                aliases: ['restrict-wf-dbver']
                type: str
                description: no description
            server_override:
                aliases: ['server-override']
                description: no description
                type: dict
                suboptions:
                    servlist:
                        description: no description
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: no description
                            ip:
                                type: str
                                description: no description
                            ip6:
                                type: str
                                description: no description
                            port:
                                type: int
                                description: no description
                            service_type:
                                aliases: ['service-type']
                                type: str
                                description: no description
                                choices: ['fgd', 'fsa', 'fgfq', 'geoip', 'iot-collect']
                    status:
                        type: str
                        description: no description
                        choices: ['disable', 'enable']
            stat_log:
                aliases: ['stat-log']
                type: str
                description: no description
                choices: ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable']
            stat_log_interval:
                aliases: ['stat-log-interval']
                type: int
                description: no description
            stat_sync_interval:
                aliases: ['stat-sync-interval']
                type: int
                description: no description
            update_interval:
                aliases: ['update-interval']
                type: int
                description: no description
            update_log:
                aliases: ['update-log']
                type: str
                description: no description
                choices: ['disable', 'enable']
            wf_cache:
                aliases: ['wf-cache']
                type: int
                description: no description
            wf_dn_cache_expire_time:
                aliases: ['wf-dn-cache-expire-time']
                type: int
                description: no description
            wf_dn_cache_max_number:
                aliases: ['wf-dn-cache-max-number']
                type: int
                description: no description
            wf_log:
                aliases: ['wf-log']
                type: str
                description: no description
                choices: ['disable', 'nourl', 'all']
            wf_preload:
                aliases: ['wf-preload']
                type: str
                description: no description
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
    - name: Cli fmupdate fgd setting
      fortinet.fortianalyzer.faz_cli_fmupdate_fgdsetting:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        cli_fmupdate_fgdsetting:
          # as_cache: <value of integer>
          # as_log: <value in [disable, nospam, all]>
          # as_preload: <value in [disable, enable]>
          # av_cache: <value of integer>
          # av_log: <value in [disable, novirus, all]>
          # av_preload: <value in [disable, enable]>
          # av2_cache: <value of integer>
          # av2_log: <value in [disable, noav2, all]>
          # av2_preload: <value in [disable, enable]>
          # eventlog_query: <value in [disable, enable]>
          # fgd_pull_interval: <value of integer>
          # fq_cache: <value of integer>
          # fq_log: <value in [disable, nofilequery, all]>
          # fq_preload: <value in [disable, enable]>
          # iot_cache: <value of integer>
          # iot_log: <value in [disable, noiot, all]>
          # iot_preload: <value in [disable, enable]>
          # iotv_preload: <value in [disable, enable]>
          # linkd_log: <value in [emergency, alert, critical, ...]>
          # max_client_worker: <value of integer>
          # max_log_quota: <value of integer>
          # max_unrated_site: <value of integer>
          # restrict_as1_dbver: <value of string>
          # restrict_as2_dbver: <value of string>
          # restrict_as4_dbver: <value of string>
          # restrict_av_dbver: <value of string>
          # restrict_av2_dbver: <value of string>
          # restrict_fq_dbver: <value of string>
          # restrict_iots_dbver: <value of string>
          # restrict_wf_dbver: <value of string>
          # server_override:
          #   servlist:
          #     - id: <value of integer>
          #       ip: <value of string>
          #       ip6: <value of string>
          #       port: <value of integer>
          #       service_type: <value in [fgd, fsa, fgfq, ...]>
          #   status: <value in [disable, enable]>
          # stat_log: <value in [emergency, alert, critical, ...]>
          # stat_log_interval: <value of integer>
          # stat_sync_interval: <value of integer>
          # update_interval: <value of integer>
          # update_log: <value in [disable, enable]>
          # wf_cache: <value of integer>
          # wf_dn_cache_expire_time: <value of integer>
          # wf_dn_cache_max_number: <value of integer>
          # wf_log: <value in [disable, nourl, all]>
          # wf_preload: <value in [disable, enable]>
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
        '/cli/global/fmupdate/fgd-setting'
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
        'cli_fmupdate_fgdsetting': {
            'type': 'dict',
            'v_range': [['7.6.3', '']],
            'options': {
                'as-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'as-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'nospam', 'all'], 'type': 'str'},
                'as-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'av-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'novirus', 'all'], 'type': 'str'},
                'av-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av2-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'av2-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'noav2', 'all'], 'type': 'str'},
                'av2-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eventlog-query': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgd-pull-interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'fq-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'fq-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'nofilequery', 'all'], 'type': 'str'},
                'fq-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iot-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'iot-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'noiot', 'all'], 'type': 'str'},
                'iot-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iotv-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'linkd-log': {
                    'v_range': [['7.6.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'],
                    'type': 'str'
                },
                'max-client-worker': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'max-log-quota': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'max-unrated-site': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'restrict-as1-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-as2-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-as4-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-av-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-av2-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-fq-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-iots-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'restrict-wf-dbver': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'server-override': {
                    'v_range': [['7.6.3', '']],
                    'type': 'dict',
                    'options': {
                        'servlist': {
                            'v_range': [['7.6.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.6.3', '']], 'type': 'str'},
                                'ip6': {'v_range': [['7.6.3', '']], 'type': 'str'},
                                'port': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'service-type': {'v_range': [['7.6.3', '']], 'choices': ['fgd', 'fsa', 'fgfq', 'geoip', 'iot-collect'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'stat-log': {
                    'v_range': [['7.6.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'],
                    'type': 'str'
                },
                'stat-log-interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'stat-sync-interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'update-interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'update-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wf-cache': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'wf-dn-cache-expire-time': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'wf-dn-cache-max-number': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'wf-log': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'nourl', 'all'], 'type': 'str'},
                'wf-preload': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_fgdsetting'),
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
