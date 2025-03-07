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
module: faz_eventmgmt_config_trigger_filter
short_description: Filter
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.8.0"
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
    - To create or update an object, set the state argument to present. To delete an object, set the state argument to absent.
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
    trigger_id:
        description: The parameter (trigger_id) in requested url.
        type: str
        required: true
    eventmgmt_config_trigger_filter:
        description: The top level parameters set.
        type: dict
        suboptions:
            dev_type:
                aliases: ['dev-type']
                type: raw
                description: no description
            id:
                type: int
                description: no description
            rule:
                description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/filter/<filter_id>/rule'
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: no description
                    key:
                        type: str
                        description: no description
                    value:
                        type: str
                        description: no description
                    value_type:
                        aliases: ['value-type']
                        type: int
                        description: no description
                    oper:
                        type: str
                        description: no description
                        choices: ['less-than', 'not-contain', 'less-or-equal', 'equal', 'great-or-equal', 'not-equal', 'contain', 'great-than']
            subject:
                type: str
                description: no description
            tag:
                type: str
                description: no description
            enable:
                type: str
                description: no description
                choices: ['enable', 'disable']
            eventstatus:
                type: str
                description: no description
            eventtype:
                type: str
                description: no description
            extrainfo:
                type: str
                description: no description
            extrainfo_type:
                aliases: ['extrainfo-type']
                type: str
                description: no description
                choices: ['default', 'custom']
            filter_expr:
                aliases: ['filter-expr']
                type: str
                description: no description
            groupby1:
                type: str
                description: no description
            groupby2:
                type: str
                description: no description
            logtype:
                type: str
                description: no description
            rule_relation:
                aliases: ['rule-relation']
                type: int
                description: no description
            severity:
                type: str
                description: no description
                choices: ['high', 'medium', 'critical', 'low']
            thres_count:
                aliases: ['thres-count']
                type: int
                description: no description
            thres_duration:
                aliases: ['thres-duration']
                type: int
                description: no description
            utmevent:
                type: str
                description: no description
            indicator:
                description: 'reference: /log-alert/trigger/filter/indicator'
                type: list
                elements: dict
                suboptions:
                    count:
                        type: int
                        description: no description
                    name:
                        type: str
                        description: no description
                    type:
                        type: str
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
    - name: Filter
      fortinet.fortianalyzer.faz_eventmgmt_config_trigger_filter:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        trigger_id: <your own value>
        state: present # <value in [present, absent]>
        eventmgmt_config_trigger_filter:
          id: 0 # Required variable, integer
          # dev_type: <any type of data>
          # rule:
          #   - id: <value of integer>
          #     key: <value of string>
          #     value: <value of string>
          #     value_type: <value of integer>
          #     oper: <value in [less-than, not-contain, less-or-equal, ...]>
          # subject: <value of string>
          # tag: <value of string>
          # enable: <value in [enable, disable]>
          # eventstatus: <value of string>
          # eventtype: <value of string>
          # extrainfo: <value of string>
          # extrainfo_type: <value in [default, custom]>
          # filter_expr: <value of string>
          # groupby1: <value of string>
          # groupby2: <value of string>
          # logtype: <value of string>
          # rule_relation: <value of integer>
          # severity: <value in [high, medium, critical, ...]>
          # thres_count: <value of integer>
          # thres_duration: <value of integer>
          # utmevent: <value of string>
          # indicator:
          #   - count: <value of integer>
          #     name: <value of string>
          #     type: <value of string>
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
        '/eventmgmt/adom/{adom}/config/trigger/{trigger_id}/filter'
    ]

    url_params = ['adom', 'trigger_id']
    module_primary_key = 'id'
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
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'adom': {'required': True, 'type': 'str'},
        'trigger_id': {'required': True, 'type': 'str'},
        'eventmgmt_config_trigger_filter': {
            'type': 'dict',
            'v_range': [['6.2.1', '7.2.1']],
            'options': {
                'dev-type': {'v_range': [['6.2.1', '7.2.1']], 'type': 'raw'},
                'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                'rule': {
                    'v_range': [['6.2.1', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                        'key': {'v_range': [['6.2.1', '7.2.1']], 'no_log': False, 'type': 'str'},
                        'value': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                        'value-type': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                        'oper': {
                            'v_range': [['6.2.2', '6.2.13']],
                            'choices': ['less-than', 'not-contain', 'less-or-equal', 'equal', 'great-or-equal', 'not-equal', 'contain', 'great-than'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'subject': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                'tag': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                'enable': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'eventstatus': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'eventtype': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'extrainfo': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'extrainfo-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['default', 'custom'], 'type': 'str'},
                'filter-expr': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'groupby1': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'groupby2': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'logtype': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'rule-relation': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'severity': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['high', 'medium', 'critical', 'low'], 'type': 'str'},
                'thres-count': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'thres-duration': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'utmevent': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'indicator': {
                    'v_range': [['7.0.3', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'count': {'v_range': [['7.0.3', '7.2.1']], 'type': 'int'},
                        'name': {'v_range': [['7.0.3', '7.2.1']], 'type': 'str'},
                        'type': {'v_range': [['7.0.3', '7.2.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'eventmgmt_config_trigger_filter'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
