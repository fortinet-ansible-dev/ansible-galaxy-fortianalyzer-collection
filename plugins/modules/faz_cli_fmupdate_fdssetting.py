#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021 Fortinet, Inc.
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

version_added: "2.11"
author:
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    cli_fmupdate_fdssetting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            User-Agent:
                type: str
                default: 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
                description: 'Configure the user agent string.'
            fds-clt-ssl-protocol:
                type: str
                default: 'tlsv1.2'
                description:
                 - 'The SSL protocols version for connecting fds server (default = tlsv1.2).'
                 - 'sslv3 - set SSLv3 as the client version.'
                 - 'tlsv1.0 - set TLSv1.0 as the client version.'
                 - 'tlsv1.1 - set TLSv1.1 as the client version.'
                 - 'tlsv1.2 - set TLSv1.2 as the client version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the client version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            fds-ssl-protocol:
                type: str
                default: 'tlsv1.2'
                description:
                 - 'The SSL protocols version for receiving fgt connection (default = tlsv1.2).'
                 - 'sslv3 - set SSLv3 as the lowest version.'
                 - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                 - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                 - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the lowest version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            fmtr-log:
                type: str
                default: 'info'
                description:
                 - 'fmtr log level'
                 - 'emergency - Log level - emergency'
                 - 'alert - Log level - alert'
                 - 'critical - Log level - critical'
                 - 'error - Log level - error'
                 - 'warn - Log level - warn'
                 - 'notice - Log level - notice'
                 - 'info - Log level - info'
                 - 'debug - Log level - debug'
                 - 'disable - Disable linkd log'
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
            fortiguard-anycast:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable use of FortiGuards anycast network'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            fortiguard-anycast-source:
                type: str
                default: 'fortinet'
                description:
                 - 'Configure which of Fortinets servers to provide FortiGuard services in FortiGuards anycast network. Default is Fortinet'
                 - 'fortinet - Use Fortinets servers to provide FortiGuard services in FortiGuards anycast network.'
                 - 'aws - Use Fortinets AWS servers to provide FortiGuard services in FortiGuards anycast network.'
                choices:
                    - 'fortinet'
                    - 'aws'
            linkd-log:
                type: str
                default: 'info'
                description:
                 - 'The linkd log level (default = info).'
                 - 'emergency - Log level - emergency'
                 - 'alert - Log level - alert'
                 - 'critical - Log level - critical'
                 - 'error - Log level - error'
                 - 'warn - Log level - warn'
                 - 'notice - Log level - notice'
                 - 'info - Log level - info'
                 - 'debug - Log level - debug'
                 - 'disable - Disable linkd log'
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
            max-av-ips-version:
                type: int
                default: 20
                description: 'The maximum number of downloadable, full version AV/IPS packages (1 - 1000, default = 20).'
            max-work:
                type: int
                default: 1
                description: 'The maximum number of worker processing download requests (1 - 32, default = 1).'
            push-override:
                description: no description
                type: dict
                required: false
                suboptions:
                    ip:
                        type: str
                        default: '0.0.0.0'
                        description: 'External or virtual IP address of the NAT device that will forward push messages to the FortiManager unit.'
                    port:
                        type: int
                        default: 9443
                        description: 'Receiving port number on the NAT device (1 - 65535, default = 9443).'
                    status:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable push updates for clients (default = disable).'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            push-override-to-client:
                description: no description
                type: dict
                required: false
                suboptions:
                    announce-ip:
                        description: no description
                        type: list
                        suboptions:
                            id:
                                type: int
                                default: 0
                                description: 'ID of the announce IP address (1 - 10).'
                            ip:
                                type: str
                                default: '0.0.0.0'
                                description: 'Announce IPv4 address.'
                            port:
                                type: int
                                default: 8890
                                description: 'Announce IP port (1 - 65535, default = 8890).'
                    status:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable push updates (default = disable).'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            send_report:
                type: str
                default: 'enable'
                description:
                 - 'send report/fssi to fds server.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            send_setup:
                type: str
                default: 'disable'
                description:
                 - 'forward setup to fds server.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            server-override:
                description: no description
                type: dict
                required: false
                suboptions:
                    servlist:
                        description: no description
                        type: list
                        suboptions:
                            id:
                                type: int
                                default: 0
                                description: 'Override server ID (1 - 10).'
                            ip:
                                type: str
                                default: '0.0.0.0'
                                description: 'IPv4 address of the override server.'
                            ip6:
                                type: str
                                default: '::'
                                description: 'IPv6 address of the override server.'
                            port:
                                type: int
                                default: 443
                                description: 'Port number to use when contacting FortiGuard (1 - 65535, default = 443).'
                            service-type:
                                type: str
                                default: 'fds'
                                description:
                                 - 'Override service type.'
                                 - 'fct - Server override config for fct'
                                 - 'fds - Server override config for fds'
                                choices:
                                    - 'fct'
                                    - 'fds'
                    status:
                        type: str
                        default: 'disable'
                        description:
                         - 'Override status.'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            system-support-fct:
                description: no description
                type: list
                choices:
                 - 4.x
                 - 5.0
                 - 5.2
                 - 5.4
                 - 5.6
                 - 6.0
                 - 6.2
                 - 6.4
                 - 7.0
            system-support-fgt:
                description: no description
                type: list
                choices:
                 - 5.4
                 - 5.6
                 - 6.0
                 - 6.2
                 - 6.4
                 - 7.0
                 - 7.2
            system-support-fml:
                description: no description
                type: list
                choices:
                 - 4.x
                 - 5.x
                 - 6.x
                 - 6.0
                 - 6.2
                 - 6.4
                 - 7.0
            system-support-fsa:
                description: no description
                type: list
                choices:
                 - 1.x
                 - 2.x
                 - 3.x
                 - 4.x
                 - 3.0
                 - 3.1
                 - 3.2
            system-support-fsw:
                description: no description
                type: list
                choices:
                 - 4.x
                 - 5.0
                 - 5.2
                 - 5.4
                 - 5.6
                 - 6.0
                 - 6.2
                 - 6.4
            umsvc-log:
                type: str
                default: 'info'
                description:
                 - 'The um_service log level (default = info).'
                 - 'emergency - Log level - emergency'
                 - 'alert - Log level - alert'
                 - 'critical - Log level - critical'
                 - 'error - Log level - error'
                 - 'warn - Log level - warn'
                 - 'notice - Log level - notice'
                 - 'info - Log level - info'
                 - 'debug - Log level - debug'
                 - 'disable - Disable linkd log'
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
            unreg-dev-option:
                type: str
                default: 'add-service'
                description:
                 - 'set the option for unregister devices'
                 - 'ignore - Ignore all unregistered devices.'
                 - 'svc-only - Allow update requests without adding the device.'
                 - 'add-service - Add unregistered devices and allow update request.'
                choices:
                    - 'ignore'
                    - 'svc-only'
                    - 'add-service'
            update-schedule:
                description: no description
                type: dict
                required: false
                suboptions:
                    day:
                        type: str
                        default: 'Monday'
                        description:
                         - 'Configure the day the update will occur, if the freqnecy is weekly (Sunday - Saturday, default = Monday).'
                         - 'Sunday - Update every Sunday.'
                         - 'Monday - Update every Monday.'
                         - 'Tuesday - Update every Tuesday.'
                         - 'Wednesday - Update every Wednesday.'
                         - 'Thursday - Update every Thursday.'
                         - 'Friday - Update every Friday.'
                         - 'Saturday - Update every Saturday.'
                        choices:
                            - 'Sunday'
                            - 'Monday'
                            - 'Tuesday'
                            - 'Wednesday'
                            - 'Thursday'
                            - 'Friday'
                            - 'Saturday'
                    frequency:
                        type: str
                        default: 'every'
                        description:
                         - 'Configure update frequency: every - time interval, daily - once a day, weekly - once a week (default = every).'
                         - 'every - Time interval.'
                         - 'daily - Every day.'
                         - 'weekly - Every week.'
                        choices:
                            - 'every'
                            - 'daily'
                            - 'weekly'
                    status:
                        type: str
                        default: 'enable'
                        description:
                         - 'Enable/disable scheduled updates.'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
                    time:
                        description: no description
                        type: str
            wanip-query-mode:
                type: str
                default: 'disable'
                description:
                 - 'public ip query mode'
                 - 'disable - Do not query public ip'
                 - 'ipify - Get public IP through https://api.ipify.org'
                choices:
                    - 'disable'
                    - 'ipify'
            system-support-fdc:
                description: no description
                type: list
                choices:
                 - 3.x
                 - 4.x
            system-support-fts:
                description: no description
                type: list
                choices:
                 - 3.x
                 - 4.x
                 - 7.x

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_fmupdate_fdssetting:
       cli_fmupdate_fdssetting:
         umsvc-log: emergency
         wanip-query-mode: disable
     name: Configure FortiGuard settings.
   vars:
     ansible_httpapi_port: 443
     ansible_httpapi_use_ssl: true
     ansible_httpapi_validate_certs: false

'''

RETURN = '''
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
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/cli/global/fmupdate/fds-setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/fds-setting/{fds-setting}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'cli_fmupdate_fdssetting': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'User-Agent': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'fds-clt-ssl-protocol': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'fds-ssl-protocol': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'fmtr-log': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'emergency',
                        'alert',
                        'critical',
                        'error',
                        'warn',
                        'notice',
                        'info',
                        'debug',
                        'disable'
                    ],
                    'type': 'str'
                },
                'fortiguard-anycast': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.2.6': False,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fortiguard-anycast-source': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.2.6': False,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'fortinet',
                        'aws'
                    ],
                    'type': 'str'
                },
                'linkd-log': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'emergency',
                        'alert',
                        'critical',
                        'error',
                        'warn',
                        'notice',
                        'info',
                        'debug',
                        'disable'
                    ],
                    'type': 'str'
                },
                'max-av-ips-version': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'max-work': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'push-override': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'push-override-to-client': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'announce-ip': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'port': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                }
                            }
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'send_report': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'send_setup': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'server-override': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'servlist': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ip6': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'port': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'service-type': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.2': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.2.6': True,
                                        '6.4.1': True,
                                        '6.4.2': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'fct',
                                        'fds'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'system-support-fct': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '4.x',
                        '5.0',
                        '5.2',
                        '5.4',
                        '5.6',
                        '6.0',
                        '6.2',
                        '6.4',
                        '7.0'
                    ]
                },
                'system-support-fgt': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '5.4',
                        '5.6',
                        '6.0',
                        '6.2',
                        '6.4',
                        '7.0',
                        '7.2'
                    ]
                },
                'system-support-fml': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '4.x',
                        '5.x',
                        '6.x',
                        '6.0',
                        '6.2',
                        '6.4',
                        '7.0'
                    ]
                },
                'system-support-fsa': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '1.x',
                        '2.x',
                        '3.x',
                        '4.x',
                        '3.0',
                        '3.1',
                        '3.2'
                    ]
                },
                'system-support-fsw': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'type': 'list',
                    'choices': [
                        '4.x',
                        '5.0',
                        '5.2',
                        '5.4',
                        '5.6',
                        '6.0',
                        '6.2',
                        '6.4'
                    ]
                },
                'umsvc-log': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'emergency',
                        'alert',
                        'critical',
                        'error',
                        'warn',
                        'notice',
                        'info',
                        'debug',
                        'disable'
                    ],
                    'type': 'str'
                },
                'unreg-dev-option': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'ignore',
                        'svc-only',
                        'add-service'
                    ],
                    'type': 'str'
                },
                'update-schedule': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'day': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'Sunday',
                                'Monday',
                                'Tuesday',
                                'Wednesday',
                                'Thursday',
                                'Friday',
                                'Saturday'
                            ],
                            'type': 'str'
                        },
                        'frequency': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'every',
                                'daily',
                                'weekly'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'time': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'wanip-query-mode': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'ipify'
                    ],
                    'type': 'str'
                },
                'system-support-fdc': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '3.x',
                        '4.x'
                    ]
                },
                'system-support-fts': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        '3.x',
                        '4.x',
                        '7.x'
                    ]
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_fmupdate_fdssetting'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
