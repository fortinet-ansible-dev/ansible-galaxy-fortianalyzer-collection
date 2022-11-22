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
module: faz_cli_system_admin_user_dashboard
short_description: Custom dashboard widgets.
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
    user:
        description: the parameter (user) in requested url
        type: str
        required: true
    cli_system_admin_user_dashboard:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            column:
                type: int
                default: 0
                description: 'Widgets column ID.'
            diskio-content-type:
                type: str
                default: 'util'
                description:
                 - 'Disk I/O Monitor widgets chart type.'
                 - 'util - bandwidth utilization.'
                 - 'iops - the number of I/O requests.'
                 - 'blks - the amount of data of I/O requests.'
                choices:
                    - 'util'
                    - 'iops'
                    - 'blks'
            diskio-period:
                type: str
                default: '1hour'
                description:
                 - 'Disk I/O Monitor widgets data period.'
                 - '1hour - 1 hour.'
                 - '8hour - 8 hour.'
                 - '24hour - 24 hour.'
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            log-rate-period:
                type: str
                description:
                 - 'Log receive monitor widgets data period.'
                 - '2min  - 2 minutes.'
                 - '1hour - 1 hour.'
                 - '6hours - 6 hours.'
                choices:
                    - '2min '
                    - '1hour'
                    - '6hours'
            log-rate-topn:
                type: str
                default: '5'
                description:
                 - 'Log receive monitor widgets number of top items to display.'
                 - '1 - Top 1.'
                 - '2 - Top 2.'
                 - '3 - Top 3.'
                 - '4 - Top 4.'
                 - '5 - Top 5.'
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
            log-rate-type:
                type: str
                default: 'device'
                description:
                 - 'Log receive monitor widgets statistics breakdown options.'
                 - 'log - Show log rates for each log type.'
                 - 'device - Show log rates for each device.'
                choices:
                    - 'log'
                    - 'device'
            moduleid:
                type: int
                default: 0
                description: 'Widget ID.'
            name:
                type: str
                description: 'Widget name.'
            num-entries:
                type: int
                default: 10
                description: 'Number of entries.'
            refresh-interval:
                type: int
                default: 300
                description: 'Widgets refresh interval.'
            res-cpu-display:
                type: str
                default: 'average '
                description:
                 - 'Widgets CPU display type.'
                 - 'average  - Average usage of CPU.'
                 - 'each - Each usage of CPU.'
                choices:
                    - 'average '
                    - 'each'
            res-period:
                type: str
                default: '10min '
                description:
                 - 'Widgets data period.'
                 - '10min  - Last 10 minutes.'
                 - 'hour - Last hour.'
                 - 'day - Last day.'
                choices:
                    - '10min '
                    - 'hour'
                    - 'day'
            res-view-type:
                type: str
                default: 'history'
                description:
                 - 'Widgets data view type.'
                 - 'real-time  - Real-time view.'
                 - 'history - History view.'
                choices:
                    - 'real-time '
                    - 'history'
            status:
                type: str
                default: 'open'
                description:
                 - 'Widgets opened/closed state.'
                 - 'close - Widget closed.'
                 - 'open - Widget opened.'
                choices:
                    - 'close'
                    - 'open'
            tabid:
                type: int
                default: 0
                description: 'ID of tab where widget is displayed.'
            time-period:
                type: str
                default: '1hour'
                description:
                 - 'Log Database Monitor widgets data period.'
                 - '1hour - 1 hour.'
                 - '8hour - 8 hour.'
                 - '24hour - 24 hour.'
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            widget-type:
                type: str
                description:
                 - 'Widget type.'
                 - 'top-lograte - Log Receive Monitor.'
                 - 'sysres - System resources.'
                 - 'sysinfo - System Information.'
                 - 'licinfo - License Information.'
                 - 'jsconsole - CLI Console.'
                 - 'sysop - Unit Operation.'
                 - 'alert - Alert Message Console.'
                 - 'statistics - Statistics.'
                 - 'rpteng - Report Engine.'
                 - 'raid - Disk Monitor.'
                 - 'logrecv - Logs/Data Received.'
                 - 'devsummary - Device Summary.'
                 - 'logdb-perf - Log Database Performance Monitor.'
                 - 'logdb-lag - Log Database Lag Time.'
                 - 'disk-io - Disk I/O.'
                 - 'log-rcvd-fwd - Log receive and forwarding Monitor.'
                choices:
                    - 'top-lograte'
                    - 'sysres'
                    - 'sysinfo'
                    - 'licinfo'
                    - 'jsconsole'
                    - 'sysop'
                    - 'alert'
                    - 'statistics'
                    - 'rpteng'
                    - 'raid'
                    - 'logrecv'
                    - 'devsummary'
                    - 'logdb-perf'
                    - 'logdb-lag'
                    - 'disk-io'
                    - 'log-rcvd-fwd'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_admin_user_dashboard:
       cli_system_admin_user_dashboard:
         name: foodashboard
         res-view-type: history
         status: open
         tabid: 1
         time-period: 1hour
         widget-type: top-lograte
       state: present
       user: fooadminuser
     name: Custom dashboard widgets.
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
        '/cli/global/system/admin/user/{user}/dashboard'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
    ]

    url_params = ['user']
    module_primary_key = 'tabid'
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
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'user': {
            'required': True,
            'type': 'str'
        },
        'cli_system_admin_user_dashboard': {
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
                'column': {
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
                'diskio-content-type': {
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
                        'util',
                        'iops',
                        'blks'
                    ],
                    'type': 'str'
                },
                'diskio-period': {
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
                        '1hour',
                        '8hour',
                        '24hour'
                    ],
                    'type': 'str'
                },
                'log-rate-period': {
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
                        '2min ',
                        '1hour',
                        '6hours'
                    ],
                    'type': 'str'
                },
                'log-rate-topn': {
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
                        '1',
                        '2',
                        '3',
                        '4',
                        '5'
                    ],
                    'type': 'str'
                },
                'log-rate-type': {
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
                        'log',
                        'device'
                    ],
                    'type': 'str'
                },
                'moduleid': {
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
                'name': {
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
                'num-entries': {
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
                'refresh-interval': {
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
                'res-cpu-display': {
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
                        'average ',
                        'each'
                    ],
                    'type': 'str'
                },
                'res-period': {
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
                        '10min ',
                        'hour',
                        'day'
                    ],
                    'type': 'str'
                },
                'res-view-type': {
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
                        'real-time ',
                        'history'
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
                        'close',
                        'open'
                    ],
                    'type': 'str'
                },
                'tabid': {
                    'required': True,
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
                'time-period': {
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
                        '1hour',
                        '8hour',
                        '24hour'
                    ],
                    'type': 'str'
                },
                'widget-type': {
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
                        'top-lograte',
                        'sysres',
                        'sysinfo',
                        'licinfo',
                        'jsconsole',
                        'sysop',
                        'alert',
                        'statistics',
                        'rpteng',
                        'raid',
                        'logrecv',
                        'devsummary',
                        'logdb-perf',
                        'logdb-lag',
                        'disk-io',
                        'log-rcvd-fwd'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_admin_user_dashboard'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
