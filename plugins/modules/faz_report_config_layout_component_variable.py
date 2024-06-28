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
module: faz_report_config_layout_component_variable
short_description: Config variable.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.5.0"
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
        default: false
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    component-id:
        description: Deprecated, please use "component_id"
        type: str
    component_id:
        description: The parameter (component-id) in requested url.
        type: str
    layout-id:
        description: Deprecated, please use "layout_id"
        type: str
    layout_id:
        description: The parameter (layout-id) in requested url.
        type: str
    report_config_layout_component_variable:
        description: The top level parameters set.
        type: dict
        suboptions:
            not:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            var:
                type: str
                description: no description
            var-value:
                type: str
                description: no description
            description:
                type: str
                description: no description
            drilldown-flag:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            status:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            var-expression:
                type: str
                description: no description
            var-type:
                type: str
                description: no description
                choices:
                    - 'ip'
                    - 'integer'
                    - 'string'
                    - 'datetime'
            view_mask:
                type: int
                description: no description
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
  tasks:
    - name: Config variable.
      fortinet.fortianalyzer.faz_report_config_layout_component_variable:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        component_id: <your own value>
        layout_id: <your own value>
        state: <value in [present, absent]>
        report_config_layout_component_variable:
          not: <value in [enable, disable]>
          var: <value of string>
          var_value: <value of string>
          description: <value of string>
          drilldown_flag: <value in [enable, disable]>
          status: <value in [enable, disable]>
          var_expression: <value of string>
          var_type: <value in [ip, integer, string, ...]>
          view_mask: <value of integer>
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
        '/report/adom/{adom}/config/layout/{layout-id}/component/{component-id}/variable'
    ]

    perobject_jrpc_urls = [
        '/report/adom/{adom}/config/layout/{layout-id}/component/{component-id}/variable/{variable}'
    ]

    url_params = ['adom', 'component-id', 'layout-id']
    module_primary_key = 'var'
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'version_check': {'type': 'bool', 'default': 'false'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'adom': {'required': True, 'type': 'str'},
        'component-id': {'type': 'str', 'api_name': 'component_id'},
        'component_id': {'type': 'str'},
        'layout-id': {'type': 'str', 'api_name': 'layout_id'},
        'layout_id': {'type': 'str'},
        'report_config_layout_component_variable': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'not': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'var': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'var-value': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'description': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'type': 'str'},
                'drilldown-flag': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'status': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'var-expression': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'},
                'var-type': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['ip', 'integer', 'string', 'datetime'], 'type': 'str'},
                'view_mask': {'v_range': [['6.2.2', '6.2.12']], 'type': 'int'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_layout_component_variable'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
