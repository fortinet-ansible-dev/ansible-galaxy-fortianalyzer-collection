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
module: faz_generic
short_description: Build and send generic FortiAnalyzer API request.
description:
    - This module is for generic fortianalyzer requests. it receives raw json-rpc
      data, and sends it to fortianalyzer, finally returns the response to users.
    - This module also rely on fortianalyzer httpapi plugin as the transport.
    - the payload doesn't include session, the httpapi plugin will automatically
      fill the session later.
    - the username and password is not managed by the module, but by the plugin.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Link Zheng (@zhengl)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - two parameters schemes are supported, either in raw json format or in
      ansible recognnizable top-level parameters format.
    - json is defined as string, user is response for make it json-formatted
    - method and params should be specified by users if 'json' is not present
    - if all three parameters are provided, the 'json' is preferred.
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
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
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
    method:
        description:
            - The method of the json-rpc
            - It must be in [get, add, set, update, delete, move, clone, exec]
        type: str
    params:
        description:
            - The parameter collection.
        type: list
        elements: dict
    json:
        description:
            - The raw json-formatted payload to send to fortianalyzer
        type: str
    jsonrpc:
        description:
            - Some APIs may require jsonrpc set as 2.0 (such as fortiview, report, etc.)
        type: str
        choices:
            - '2.0'
            - ''
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    adom: "root"
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Login a user
      fortinet.fortianalyzer.faz_generic:
        method: "exec"
        params:
          - url: "sys/login/user"
            data:
              - user: "APIUser"
                passwd: "Fortinet1!e"
    - name: Login another user
      fortinet.fortianalyzer.faz_generic:
        json: |
          {
           "method":"exec",
           "params":[
            {
                 "url":"sys/login/user",
                 "data":[
                    {
                       "user":"APIUser",
                       "passwd":"Fortinet1!"
                    }
                  ]
             }
            ]
          }
'''

RETURN = """
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
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
import json


def main():
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'rc_succeeded': {'elements': 'int', 'type': 'list'},
        'rc_failed': {'elements': 'int', 'type': 'list'},
        'method': {'type': 'str'},
        'params': {'type': 'list', 'elements': 'dict'},
        'json': {'type': 'str'},
        'jsonrpc': {'type': 'str', 'choices': ['2.0', '']}
    }

    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    if not module._socket_path:
        module.fail_json(msg='Only Httpapi plugin is supported in this module.')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    fmgr = NAPIManager(None, None, None, None, module, connection)
    method = None
    params = None

    if module.params['json']:
        raw_json_params = None
        try:
            raw_json_params = json.loads(module.params['json'])
            method = raw_json_params['method']
            params = raw_json_params['params']
        except Exception as e:
            module.fail_json(msg='invalid json content: %s' % (e))
    else:
        if not module.params['method'] or not module.params['params']:
            raise AssertionError('method and params must be given!')
        method = module.params['method']
        params = module.params['params']

    if method not in ['get', 'add', 'set', 'update', 'delete', 'move', 'clone', 'exec']:
        module.fail_json(msg='method:%s not supported' % (method))

    if not isinstance(params, list):
        module.fail_json(msg='parameter:params must be an array')
    for param_block in params:
        if 'url' not in param_block:
            module.fail_json(msg='url must be specified in params')
    try:
        fmgr.process_generic(method, params, module.params['jsonrpc'])
    except Exception as e:
        module.fail_json(msg='error sending request: %s' % (e))


if __name__ == '__main__':
    main()
