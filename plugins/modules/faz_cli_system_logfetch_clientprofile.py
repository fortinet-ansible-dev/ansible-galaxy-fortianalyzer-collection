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
module: faz_cli_system_logfetch_clientprofile
short_description: Log-fetch client profile settings.
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
    state:
        description: The directive to create, update or delete an object
        type: str
        required: true
        choices:
            - present
            - absent
    cli_system_logfetch_clientprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            client-adom:
                type: str
                description: 'Log-fetch client sides adom name.'
            data-range:
                type: str
                description:
                 - 'Data-range for fetched logs.'
                 - 'custom - Specify some other date and time range.'
                choices:
                    - 'custom'
            data-range-value:
                type: int
                description: 'Last n days or hours.'
            device-filter:
                description: no description
                type: list
                elements: dict
                suboptions:
                    adom:
                        type: str
                        description: 'Adom name.'
                    device:
                        type: str
                        description: 'Device name or Serial number.'
                    id:
                        type: int
                        description: 'Add or edit a device filter.'
                    vdom:
                        type: str
                        description: 'Vdom filters.'
            end-time:
                description: no description
                type: str
            id:
                type: int
                description: 'Log-fetch client profile ID.'
            index-fetch-logs:
                type: str
                description:
                 - 'Enable/Disable indexing logs automatically after fetching logs.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            log-filter:
                description: no description
                type: list
                elements: dict
                suboptions:
                    field:
                        type: str
                        description: 'Field name.'
                    id:
                        type: int
                        description: 'Log filter ID.'
                    oper:
                        type: str
                        description:
                         - 'Field filter operator.'
                         - '&lt; - =Less than or equal to'
                         - '&gt; - =Greater than or equal to'
                         - 'contain - Contain'
                         - 'not-contain - Not contain'
                         - 'match - Match (expression)'
                        choices:
                            - '='
                            - '!='
                            - '<'
                            - '>'
                            - '<='
                            - '>='
                            - 'contain'
                            - 'not-contain'
                            - 'match'
                    value:
                        type: str
                        description: 'Field filter operand or free-text matching expression.'
            log-filter-logic:
                type: str
                description:
                 - 'And/Or logic for log-filters.'
                 - 'and - Logic And.'
                 - 'or - Logic Or.'
                choices:
                    - 'and'
                    - 'or'
            log-filter-status:
                type: str
                description:
                 - 'Enable/Disable log-filter.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'Name of log-fetch client profile.'
            password:
                description: no description
                type: str
            secure-connection:
                type: str
                description:
                 - 'Enable/Disable protecting log-fetch connection with TLS/SSL.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            server-adom:
                type: str
                description: 'Log-fetch server sides adom name.'
            server-ip:
                type: str
                description: 'Log-fetch server IP address.'
            start-time:
                description: no description
                type: str
            sync-adom-config:
                type: str
                description:
                 - 'Enable/Disable sync adom related config.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            user:
                type: str
                description: 'Log-fetch server login username.'
            peer-cert-cn:
                type: str
                description: 'Certificate common name of log-fetch server.'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Log-fetch client profile settings.
      fortinet.fortianalyzer.faz_cli_system_logfetch_clientprofile:
        cli_system_logfetch_clientprofile:
          id: 1
          index_fetch_logs: disable
          log_filter_status: disable
          secure_connection: disable
          sync_adom_config: disable
          server_ip: 34.54.65.75
          name: fooclientprofile
          user: "admin"
          password: "password"
        state: present
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
        '/cli/global/system/log-fetch/client-profile'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log-fetch/client-profile/{client-profile}'
    ]

    url_params = []
    module_primary_key = 'id'
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'cli_system_logfetch_clientprofile': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'client-adom': {'type': 'str'},
                'data-range': {'choices': ['custom'], 'type': 'str'},
                'data-range-value': {'type': 'int'},
                'device-filter': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'device': {'type': 'str'}, 'id': {'type': 'int'}, 'vdom': {'type': 'str'}},
                    'elements': 'dict'
                },
                'end-time': {'type': 'str'},
                'id': {'type': 'int'},
                'index-fetch-logs': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-filter': {
                    'type': 'list',
                    'options': {
                        'field': {'type': 'str'},
                        'id': {'type': 'int'},
                        'oper': {'choices': ['=', '!=', '<', '>', '<=', '>=', 'contain', 'not-contain', 'match'], 'type': 'str'},
                        'value': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'log-filter-logic': {'choices': ['and', 'or'], 'type': 'str'},
                'log-filter-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'type': 'str'},
                'password': {'no_log': True, 'type': 'str'},
                'secure-connection': {'choices': ['disable', 'enable'], 'type': 'str'},
                'server-adom': {'type': 'str'},
                'server-ip': {'type': 'str'},
                'start-time': {'type': 'str'},
                'sync-adom-config': {'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'type': 'str'},
                'peer-cert-cn': {'v_range': [['7.0.3', '']], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_logfetch_clientprofile'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
