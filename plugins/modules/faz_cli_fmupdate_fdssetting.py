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
module: faz_cli_fmupdate_fdssetting
short_description: Configure FortiGuard settings.
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
    cli_fmupdate_fdssetting:
        description: The top level parameters set.
        type: dict
        suboptions:
            User_Agent:
                aliases: ['User-Agent']
                type: str
                description: Configure the user agent string.
            fds_clt_ssl_protocol:
                aliases: ['fds-clt-ssl-protocol']
                type: str
                description:
                 - The SSL protocols version for connecting fds server
                 - sslv3 - set SSLv3 as the client version.
                 - tlsv1.0 - set TLSv1.0 as the client version.
                 - tlsv1.1 - set TLSv1.1 as the client version.
                 - tlsv1.2 - set TLSv1.2 as the client version
                 - tlsv1.3 - set TLSv1.3 as the client version.
                choices: ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3']
            fds_ssl_protocol:
                aliases: ['fds-ssl-protocol']
                type: str
                description:
                 - The SSL protocols version for receiving fgt connection
                 - sslv3 - set SSLv3 as the lowest version.
                 - tlsv1.0 - set TLSv1.0 as the lowest version.
                 - tlsv1.1 - set TLSv1.1 as the lowest version.
                 - tlsv1.2 - set TLSv1.2 as the lowest version
                 - tlsv1.3 - set TLSv1.3 as the lowest version.
                choices: ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3']
            fmtr_log:
                aliases: ['fmtr-log']
                type: str
                description:
                 - fmtr log level
                 - emergency - Log level - emergency
                 - alert - Log level - alert
                 - critical - Log level - critical
                 - error - Log level - error
                 - warn - Log level - warn
                 - notice - Log level - notice
                 - info - Log level - info
                 - debug - Log level - debug
                 - disable - Disable linkd log
                choices: ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable']
            fortiguard_anycast:
                aliases: ['fortiguard-anycast']
                type: str
                description:
                 - Enable/disable use of FortiGuards anycast network
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            fortiguard_anycast_source:
                aliases: ['fortiguard-anycast-source']
                type: str
                description:
                 - Configure which of Fortinets servers to provide FortiGuard services in FortiGuards anycast network.
                 - fortinet - Use Fortinets servers to provide FortiGuard services in FortiGuards anycast network.
                 - aws - Use Fortinets AWS servers to provide FortiGuard services in FortiGuards anycast network.
                choices: ['fortinet', 'aws']
            linkd_log:
                aliases: ['linkd-log']
                type: str
                description:
                 - The linkd log level
                 - emergency - Log level - emergency
                 - alert - Log level - alert
                 - critical - Log level - critical
                 - error - Log level - error
                 - warn - Log level - warn
                 - notice - Log level - notice
                 - info - Log level - info
                 - debug - Log level - debug
                 - disable - Disable linkd log
                choices: ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable']
            max_av_ips_version:
                aliases: ['max-av-ips-version']
                type: int
                description: The maximum number of downloadable, full version AV/IPS packages
            max_work:
                aliases: ['max-work']
                type: int
                description: The maximum number of worker processing download requests
            push_override:
                aliases: ['push-override']
                description: no description
                type: dict
                suboptions:
                    ip:
                        type: str
                        description: External or virtual IP address of the NAT device that will forward push messages to the FortiManager unit.
                    port:
                        type: int
                        description: Receiving port number on the NAT device
                    status:
                        type: str
                        description:
                         - Enable/disable push updates for clients
                         - disable - Disable setting.
                         - enable - Enable setting.
                        choices: ['disable', 'enable']
            push_override_to_client:
                aliases: ['push-override-to-client']
                description: no description
                type: dict
                suboptions:
                    announce_ip:
                        aliases: ['announce-ip']
                        description: no description
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: ID of the announce IP address
                            ip:
                                type: str
                                description: Announce IPv4 address.
                            port:
                                type: int
                                description: Announce IP port
                    status:
                        type: str
                        description:
                         - Enable/disable push updates
                         - disable - Disable setting.
                         - enable - Enable setting.
                        choices: ['disable', 'enable']
            send_report:
                type: str
                description:
                 - send report/fssi to fds server.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            send_setup:
                type: str
                description:
                 - forward setup to fds server.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
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
                                description: Override server ID
                            ip:
                                type: str
                                description: IPv4 address of the override server.
                            ip6:
                                type: str
                                description: IPv6 address of the override server.
                            port:
                                type: int
                                description: Port number to use when contacting FortiGuard
                            service_type:
                                aliases: ['service-type']
                                type: str
                                description:
                                 - Override service type.
                                 - fct - Server override config for fct
                                 - fds - Server override config for fds
                                choices: ['fct', 'fds', 'fai']
                    status:
                        type: str
                        description:
                         - Override status.
                         - disable - Disable setting.
                         - enable - Enable setting.
                        choices: ['disable', 'enable']
            system_support_fct:
                aliases: ['system-support-fct']
                description:
                 - Supported FortiClient versions.
                 - 4.x - Support version 4.x
                 - 5.0 - Support version 5.0
                 - 5.2 - Support version 5.2
                 - 5.4 - Support version 5.4
                 - 5.6 - Support version 5.6
                 - 6.0 - Support version 6.0
                 - 6.2 - Support version 6.2
                type: list
                elements: str
                choices: ['4.x', '5.0', '5.2', '5.4', '5.6', '6.0', '6.2', '6.4', '7.0', '7.2', '7.4']
            system_support_fgt:
                aliases: ['system-support-fgt']
                description:
                 - Supported FortiOS versions.
                 - 5.4 - Support version 5.4
                 - 5.6 - Support version 5.6
                 - 6.0 - Support version 6.0
                 - 6.2 - Support version 6.2
                 - 6.4 - Support version 6.4
                type: list
                elements: str
                choices: ['5.4', '5.6', '6.0', '6.2', '6.4', '7.0', '7.2', '7.4', '7.6']
            system_support_fml:
                aliases: ['system-support-fml']
                description:
                 - Supported FortiMail versions.
                 - 4.x - Support version 4.x
                 - 5.x - Support version 5.x
                 - 6.x - Support version 6.x
                type: list
                elements: str
                choices: ['4.x', '5.x', '6.x', '6.0', '6.2', '6.4', '7.0', '7.2', '7.x']
            system_support_fsa:
                aliases: ['system-support-fsa']
                description:
                 - Supported FortiSandbox versions.
                 - 1.x - Support version 1.x
                 - 2.x - Support version 2.x
                 - 3.x - Support version 3.x
                type: list
                elements: str
                choices: ['1.x', '2.x', '3.x', '3.0', '3.1', '3.2', '4.x']
            system_support_fsw:
                aliases: ['system-support-fsw']
                description:
                 - Supported FortiSwitch versions.
                 - 4.x - Support version 4.x
                 - 5.0 - Support version 5.0
                 - 5.2 - Support version 5.2
                 - 5.4 - Support version 5.4
                 - 5.6 - Support version 5.6
                 - 6.0 - Support version 6.0
                 - 6.2 - Support version 6.2
                type: list
                elements: str
                choices: ['4.x', '5.0', '5.2', '5.4', '5.6', '6.0', '6.2', '6.4']
            umsvc_log:
                aliases: ['umsvc-log']
                type: str
                description:
                 - The um_service log level
                 - emergency - Log level - emergency
                 - alert - Log level - alert
                 - critical - Log level - critical
                 - error - Log level - error
                 - warn - Log level - warn
                 - notice - Log level - notice
                 - info - Log level - info
                 - debug - Log level - debug
                 - disable - Disable linkd log
                choices: ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable']
            unreg_dev_option:
                aliases: ['unreg-dev-option']
                type: str
                description:
                 - set the option for unregister devices
                 - ignore - Ignore all unregistered devices.
                 - svc-only - Allow update requests without adding the device.
                 - add-service - Add unregistered devices and allow update request.
                choices: ['ignore', 'svc-only', 'add-service']
            update_schedule:
                aliases: ['update-schedule']
                description: no description
                type: dict
                suboptions:
                    day:
                        type: str
                        description:
                         - Configure the day the update will occur, if the freqnecy is weekly
                         - Sunday - Update every Sunday.
                         - Monday - Update every Monday.
                         - Tuesday - Update every Tuesday.
                         - Wednesday - Update every Wednesday.
                         - Thursday - Update every Thursday.
                         - Friday - Update every Friday.
                         - Saturday - Update every Saturday.
                        choices: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
                    frequency:
                        type: str
                        description:
                         - 'Configure update frequency: every - time interval, daily - once a day, weekly - once a week'
                         - every - Time interval.
                         - daily - Every day.
                         - weekly - Every week.
                        choices: ['every', 'daily', 'weekly']
                    status:
                        type: str
                        description:
                         - Enable/disable scheduled updates.
                         - disable - Disable setting.
                         - enable - Enable setting.
                        choices: ['disable', 'enable']
                    time:
                        description: Time interval between updates, or the hour and minute when the update occurs
                        type: str
            wanip_query_mode:
                aliases: ['wanip-query-mode']
                type: str
                description:
                 - public ip query mode
                 - disable - Do not query public ip
                 - 'ipify - Get public IP through https://api.ipify.org'
                choices: ['disable', 'ipify']
            system_support_fdc:
                aliases: ['system-support-fdc']
                description:
                 - Supported FortiDeceptor versions.
                 - 3.x - Support version 3.x
                type: list
                elements: str
                choices: ['3.x', '4.x', '5.x', '6.x']
            system_support_fts:
                aliases: ['system-support-fts']
                description:
                 - Supported FortiTester versions.
                 - 4.x - Support version 4.x
                type: list
                elements: str
                choices: ['4.x', '3.x', '7.x']
            system_support_faz:
                aliases: ['system-support-faz']
                description:
                 - Supported FortiAnalyzer versions.
                 - 6.x - Support version 6.x
                 - 7.x - Support version 7.x
                type: list
                elements: str
                choices: ['6.x', '7.x']
            system_support_fis:
                aliases: ['system-support-fis']
                description:
                 - Supported FortiIsolator versions.
                 - 1.x - Support version 1.x
                 - 2.x - Support version 2.x
                type: list
                elements: str
                choices: ['1.x', '2.x']
            system_support_fai:
                aliases: ['system-support-fai']
                description:
                 - Supported FortiNDR versions.
                 - 7.x - Support version 7.x
                type: list
                elements: str
                choices: ['7.x']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Configure FortiGuard settings.
      fortinet.fortianalyzer.faz_cli_fmupdate_fdssetting:
        cli_fmupdate_fdssetting:
          umsvc_log: emergency
          wanip_query_mode: disable
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
        '/cli/global/fmupdate/fds-setting'
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
        'cli_fmupdate_fdssetting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'User-Agent': {'type': 'str'},
                'fds-clt-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'fds-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'fmtr-log': {'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'], 'type': 'str'},
                'fortiguard-anycast': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-anycast-source': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['fortinet', 'aws'], 'type': 'str'},
                'linkd-log': {'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'], 'type': 'str'},
                'max-av-ips-version': {'type': 'int'},
                'max-work': {'type': 'int'},
                'push-override': {
                    'type': 'dict',
                    'options': {'ip': {'type': 'str'}, 'port': {'type': 'int'}, 'status': {'choices': ['disable', 'enable'], 'type': 'str'}}
                },
                'push-override-to-client': {
                    'type': 'dict',
                    'options': {
                        'announce-ip': {
                            'type': 'list',
                            'options': {'id': {'type': 'int'}, 'ip': {'type': 'str'}, 'port': {'type': 'int'}},
                            'elements': 'dict'
                        },
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'send_report': {'choices': ['disable', 'enable'], 'type': 'str'},
                'send_setup': {'choices': ['disable', 'enable'], 'type': 'str'},
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
                                'service-type': {'choices': ['fct', 'fds', 'fai'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'system-support-fct': {
                    'type': 'list',
                    'choices': ['4.x', '5.0', '5.2', '5.4', '5.6', '6.0', '6.2', '6.4', '7.0', '7.2', '7.4'],
                    'elements': 'str'
                },
                'system-support-fgt': {'type': 'list', 'choices': ['5.4', '5.6', '6.0', '6.2', '6.4', '7.0', '7.2', '7.4', '7.6'], 'elements': 'str'},
                'system-support-fml': {'type': 'list', 'choices': ['4.x', '5.x', '6.x', '6.0', '6.2', '6.4', '7.0', '7.2', '7.x'], 'elements': 'str'},
                'system-support-fsa': {'type': 'list', 'choices': ['1.x', '2.x', '3.x', '3.0', '3.1', '3.2', '4.x'], 'elements': 'str'},
                'system-support-fsw': {
                    'v_range': [['6.2.1', '6.4.5'], ['7.0.0', '7.0.0']],
                    'type': 'list',
                    'choices': ['4.x', '5.0', '5.2', '5.4', '5.6', '6.0', '6.2', '6.4'],
                    'elements': 'str'
                },
                'umsvc-log': {'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'], 'type': 'str'},
                'unreg-dev-option': {'choices': ['ignore', 'svc-only', 'add-service'], 'type': 'str'},
                'update-schedule': {
                    'type': 'dict',
                    'options': {
                        'day': {'choices': ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'], 'type': 'str'},
                        'frequency': {'choices': ['every', 'daily', 'weekly'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'time': {'type': 'str'}
                    }
                },
                'wanip-query-mode': {'choices': ['disable', 'ipify'], 'type': 'str'},
                'system-support-fdc': {
                    'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'choices': ['3.x', '4.x', '5.x', '6.x'],
                    'elements': 'str'
                },
                'system-support-fts': {
                    'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'choices': ['4.x', '3.x', '7.x'],
                    'elements': 'str'
                },
                'system-support-faz': {'v_range': [['7.0.7', '7.0.13'], ['7.2.2', '']], 'type': 'list', 'choices': ['6.x', '7.x'], 'elements': 'str'},
                'system-support-fis': {'v_range': [['7.4.0', '']], 'type': 'list', 'choices': ['1.x', '2.x'], 'elements': 'str'},
                'system-support-fai': {'v_range': [['7.6.0', '']], 'type': 'list', 'choices': ['7.x'], 'elements': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_fdssetting'),
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
