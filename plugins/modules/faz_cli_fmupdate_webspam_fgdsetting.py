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
module: faz_cli_fmupdate_webspam_fgdsetting
short_description: Configure the FortiGuard run parameters.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
        required: false
        type: str
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        required: false
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        type: str
        required: false
        choices:
            - set
            - update
            - add
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
        elements: int
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
        required: false
    cli_fmupdate_webspam_fgdsetting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            as-cache:
                type: int
                description: 'Antispam service maximum memory usage in megabytes (Maximum = Physical memory-1024, 0: no limit, default = 300).'
            as-log:
                type: str
                description:
                 - 'Antispam log setting (default = nospam).'
                 - 'disable - Disable spam log.'
                 - 'nospam - Log non-spam events.'
                 - 'all - Log all spam lookups.'
                choices:
                    - 'disable'
                    - 'nospam'
                    - 'all'
            as-preload:
                type: str
                description:
                 - 'Enable/disable preloading antispam database to memory (default = disable).'
                 - 'disable - Disable antispam database preload.'
                 - 'enable - Enable antispam database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            av-cache:
                type: int
                description: 'Antivirus service maximum memory usage, in megabytes (100 - 500, default = 300).'
            av-log:
                type: str
                description:
                 - 'Antivirus log setting (default = novirus).'
                 - 'disable - Disable virus log.'
                 - 'novirus - Log non-virus events.'
                 - 'all - Log all virus lookups.'
                choices:
                    - 'disable'
                    - 'novirus'
                    - 'all'
            av-preload:
                type: str
                description:
                 - 'Enable/disable preloading antivirus database to memory (default = disable).'
                 - 'disable - Disable antivirus database preload.'
                 - 'enable - Enable antivirus database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            av2-cache:
                type: int
                description: 'Antispam service maximum memory usage in megabytes (Maximum = Physical memory-1024, 0: no limit, default = 800).'
            av2-log:
                type: str
                description:
                 - 'Outbreak prevention log setting (default = noav2).'
                 - 'disable - Disable av2 log.'
                 - 'noav2 - Log non-av2 events.'
                 - 'all - Log all av2 lookups.'
                choices:
                    - 'disable'
                    - 'noav2'
                    - 'all'
            av2-preload:
                type: str
                description:
                 - 'Enable/disable preloading outbreak prevention database to memory (default = disable).'
                 - 'disable - Disable outbreak prevention database preload.'
                 - 'enable - Enable outbreak prevention database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            eventlog-query:
                type: str
                description:
                 - 'Enable/disable record query to event-log besides fgd-log (default = disable).'
                 - 'disable - Record query to event-log besides fgd-log.'
                 - 'enable - Do not log to event-log.'
                choices:
                    - 'disable'
                    - 'enable'
            fgd-pull-interval:
                type: int
                description: 'Fgd pull interval setting, in minutes (1 - 1440, default = 10).'
            fq-cache:
                type: int
                description: 'File query service maximum memory usage, in megabytes (100 - 500, default = 300).'
            fq-log:
                type: str
                description:
                 - 'File query log setting (default = nofilequery).'
                 - 'disable - Disable file query log.'
                 - 'nofilequery - Log non-file query events.'
                 - 'all - Log all file query events.'
                choices:
                    - 'disable'
                    - 'nofilequery'
                    - 'all'
            fq-preload:
                type: str
                description:
                 - 'Enable/disable preloading file query database to memory (default = disable).'
                 - 'disable - Disable file query db preload.'
                 - 'enable - Enable file query db preload.'
                choices:
                    - 'disable'
                    - 'enable'
            linkd-log:
                type: str
                description:
                 - 'Linkd log setting (default = debug).'
                 - 'emergency - The unit is unusable.'
                 - 'alert - Immediate action is required'
                 - 'critical - Functionality is affected.'
                 - 'error - Functionality is probably affected.'
                 - 'warn - Functionality might be affected.'
                 - 'notice - Information about normal events.'
                 - 'info - General information.'
                 - 'debug - Debug information.'
                 - 'disable - Linkd logging is disabled.'
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warn'
                    - 'notice'
                    - 'info'
                    - 'debug'
                    - 'disable'
            max-client-worker:
                type: int
                description: 'max worker for tcp client connection (0~16: 0 means use cpu number up to 4).'
            max-log-quota:
                type: int
                description: 'Maximum log quota setting, in megabytes (100 - 20480, default = 6144).'
            max-unrated-site:
                type: int
                description: 'Maximum number of unrated site in memory, in kilobytes(10 - 5120, default = 500).'
            restrict-as1-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(1) database version (character limit = 127).'
            restrict-as2-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(2) database version (character limit = 127).'
            restrict-as4-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(4) database version (character limit = 127).'
            restrict-av-dbver:
                type: str
                description: 'Restrict system update to indicated antivirus database version (character limit = 127).'
            restrict-av2-dbver:
                type: str
                description: 'Restrict system update to indicated outbreak prevention database version (character limit = 127).'
            restrict-fq-dbver:
                type: str
                description: 'Restrict system update to indicated file query database version (character limit = 127).'
            restrict-wf-dbver:
                type: str
                description: 'Restrict system update to indicated web filter database version (character limit = 127).'
            server-override:
                description: no description
                type: dict
                required: false
                suboptions:
                    servlist:
                        description: no description
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: 'Override server ID (1 - 10).'
                            ip:
                                type: str
                                description: 'IPv4 address of the override server.'
                            ip6:
                                type: str
                                description: 'IPv6 address of the override server.'
                            port:
                                type: int
                                description: 'Port number to use when contacting FortiGuard (1 - 65535, default = 443).'
                            service-type:
                                type: str
                                description:
                                 - 'Override service type.'
                                 - 'fgd - Server override config for fgd'
                                 - 'fgc - Server override config for fgc'
                                 - 'fsa - Server override config for fsa'
                                choices:
                                    - 'fgd'
                                    - 'fgc'
                                    - 'fsa'
                                    - 'fgfq'
                                    - 'geoip'
                                    - 'iot-collect'
                    status:
                        type: str
                        description:
                         - 'Override status.'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            stat-log-interval:
                type: int
                description: 'Statistic log interval setting, in minutes (1 - 1440, default = 60).'
            stat-sync-interval:
                type: int
                description: 'Synchronization interval for statistic of unrated site in minutes (1 - 60, default = 60).'
            update-interval:
                type: int
                description: 'FortiGuard database update wait time if not enough delta files, in hours (2 - 24, default = 6).'
            update-log:
                type: str
                description:
                 - 'Enable/disable update log setting (default = enable).'
                 - 'disable - Disable update log.'
                 - 'enable - Enable update log.'
                choices:
                    - 'disable'
                    - 'enable'
            wf-cache:
                type: int
                description: 'Web filter service maximum memory usage, in megabytes (maximum = Physical memory-1024, 0 = no limit, default = 600).'
            wf-dn-cache-expire-time:
                type: int
                description: 'Web filter DN cache expire time, in minutes (1 - 1440, 0 = never, default = 30).'
            wf-dn-cache-max-number:
                type: int
                description: 'Maximum number of Web filter DN cache (0 = disable, default = 10000).'
            wf-log:
                type: str
                description:
                 - 'Web filter log setting (default = nour1)'
                 - 'disable - Disable URL log.'
                 - 'nourl - Log non-URL events.'
                 - 'all - Log all URL lookups.'
                choices:
                    - 'disable'
                    - 'nourl'
                    - 'all'
            wf-preload:
                type: str
                description:
                 - 'Enable/disable preloading the web filter database into memory (default = disable).'
                 - 'disable - Disable web filter database preload.'
                 - 'enable - Enable web filter database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            iot-cache:
                type: int
                description: 'IoT service maximum memory usage, in megabytes (100 - 500, default = 300).'
            iot-log:
                type: str
                description:
                 - 'IoT log setting (default = nofilequery).'
                 - 'disable - Disable IoT log.'
                 - 'nofilequery - Log non-IoT events.'
                 - 'all - Log all IoT events.'
                choices:
                    - 'disable'
                    - 'nofilequery'
                    - 'all'
            iot-preload:
                type: str
                description:
                 - 'Enable/disable preloading IoT database to memory (default = disable).'
                 - 'disable - Disable IoT db preload.'
                 - 'enable - Enable IoT db preload.'
                choices:
                    - 'disable'
                    - 'enable'
            restrict-iots-dbver:
                type: str
                description: 'Restrict system update to indicated file query database version (character limit = 127).'
            stat-log:
                type: str
                description:
                 - 'stat log setting (default = disable).'
                 - 'emergency - The unit is unusable(0).'
                 - 'alert - Immediate action is required(1)'
                 - 'critical - Functionality is affected(2).'
                 - 'error - Functionality is probably affected(3).'
                 - 'warn - Functionality might be affected(4).'
                 - 'notice - Information about normal events(5).'
                 - 'info - General information(6).'
                 - 'debug - Debug information(7).'
                 - 'disable - Linkd logging is disabled.'
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warn'
                    - 'notice'
                    - 'info'
                    - 'debug'
                    - 'disable'
            iotv-preload:
                type: str
                description:
                 - 'Enable/disable preloading IoT-Vulnerability database to memory (default = disable).'
                 - 'disable - Disable IoT-Vulnerability db preload.'
                 - 'enable - Enable IoT-Vulnerability db preload.'
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Configure the FortiGuard run parameters.
      fortinet.fortianalyzer.faz_cli_fmupdate_webspam_fgdsetting:
        cli_fmupdate_webspam_fgdsetting:
          as_preload: disable
          av_preload: disable
          av2_preload: disable
          eventlog_query: disable
          fq_preload: disable
          update_log: disable
          wf_preload: disable
  vars:
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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    jrpc_urls = [
        '/cli/global/fmupdate/web-spam/fgd-setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/web-spam/fgd-setting/{fgd-setting}'
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
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_fmupdate_webspam_fgdsetting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'as-cache': {'type': 'int'},
                'as-log': {'choices': ['disable', 'nospam', 'all'], 'type': 'str'},
                'as-preload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'av-cache': {'type': 'int'},
                'av-log': {'choices': ['disable', 'novirus', 'all'], 'type': 'str'},
                'av-preload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'av2-cache': {'type': 'int'},
                'av2-log': {'choices': ['disable', 'noav2', 'all'], 'type': 'str'},
                'av2-preload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eventlog-query': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgd-pull-interval': {'type': 'int'},
                'fq-cache': {'type': 'int'},
                'fq-log': {'choices': ['disable', 'nofilequery', 'all'], 'type': 'str'},
                'fq-preload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'linkd-log': {'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'], 'type': 'str'},
                'max-client-worker': {'type': 'int'},
                'max-log-quota': {'type': 'int'},
                'max-unrated-site': {'type': 'int'},
                'restrict-as1-dbver': {'type': 'str'},
                'restrict-as2-dbver': {'type': 'str'},
                'restrict-as4-dbver': {'type': 'str'},
                'restrict-av-dbver': {'type': 'str'},
                'restrict-av2-dbver': {'type': 'str'},
                'restrict-fq-dbver': {'type': 'str'},
                'restrict-wf-dbver': {'type': 'str'},
                'server-override': {
                    'type': 'dict',
                    'options': {
                        'servlist': {
                            'type': 'list',
                            'options': {
                                'id': {'type': 'int'},
                                'ip': {'type': 'str'},
                                'ip6': {'type': 'str'},
                                'port': {'type': 'int'},
                                'service-type': {'choices': ['fgd', 'fgc', 'fsa', 'fgfq', 'geoip', 'iot-collect'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'stat-log-interval': {'type': 'int'},
                'stat-sync-interval': {'type': 'int'},
                'update-interval': {'type': 'int'},
                'update-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wf-cache': {'type': 'int'},
                'wf-dn-cache-expire-time': {'type': 'int'},
                'wf-dn-cache-max-number': {'type': 'int'},
                'wf-log': {'choices': ['disable', 'nourl', 'all'], 'type': 'str'},
                'wf-preload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'iot-cache': {'v_range': [['6.4.6', '6.4.14'], ['7.0.1', '']], 'type': 'int'},
                'iot-log': {'v_range': [['6.4.6', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'nofilequery', 'all'], 'type': 'str'},
                'iot-preload': {'v_range': [['6.4.6', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restrict-iots-dbver': {'v_range': [['6.4.6', '6.4.14'], ['7.0.1', '']], 'type': 'str'},
                'stat-log': {
                    'v_range': [['7.0.10', '7.0.11'], ['7.4.2', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'],
                    'type': 'str'
                },
                'iotv-preload': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_webspam_fgdsetting'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
