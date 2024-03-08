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
module: faz_cli_fmupdate_serveraccesspriorities
short_description: Configure priorities for FortiGate units accessing antivirus updates and web filtering services.
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
    cli_fmupdate_serveraccesspriorities:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access-public:
                type: str
                description:
                 - 'Enable/disable FortiGates to Access Public FortiGuard Servers when Private Servers are Unavailable (default = disable).'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            av-ips:
                type: str
                description:
                 - 'Enable/disable Antivirus and IPS Update Service for Private Server(default = disable).'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            private-server:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: 'Private server ID (1 - 10).'
                    ip:
                        type: str
                        description: 'IPv4 address of the FortiManager unit or private server.'
                    ip6:
                        type: str
                        description: 'IPv6 address of the FortiManager unit or private server.'
                    time_zone:
                        type: int
                        description: 'Time zone of the private server (-24 = local time zone, default = -24).'
            web-spam:
                type: str
                description:
                 - 'Enable/disable Web Filter and Email Filter Update Service for Private Server (default = enable).'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name:
        Configure priorities for FortiGate units accessing antivirus updates and
        web filtering services.
      fortinet.fortianalyzer.faz_cli_fmupdate_serveraccesspriorities:
        cli_fmupdate_serveraccesspriorities:
          access_public: disable
          av_ips: disable
          web_spam: disable
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
        '/cli/global/fmupdate/server-access-priorities'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/server-access-priorities/{server-access-priorities}'
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
        'cli_fmupdate_serveraccesspriorities': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'access-public': {'choices': ['disable', 'enable'], 'type': 'str'},
                'av-ips': {'choices': ['disable', 'enable'], 'type': 'str'},
                'private-server': {
                    'type': 'list',
                    'options': {'id': {'type': 'int'}, 'ip': {'type': 'str'}, 'ip6': {'type': 'str'}, 'time_zone': {'type': 'int'}},
                    'elements': 'dict'
                },
                'web-spam': {'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_serveraccesspriorities'),
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
