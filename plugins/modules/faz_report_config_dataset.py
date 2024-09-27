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
module: faz_report_config_dataset
short_description: Config dataset.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.5.0"
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
    report_config_dataset:
        description: The top level parameters set.
        type: dict
        suboptions:
            description:
                type: str
                description: no description
            dev_type:
                type: str
                description: no description
                choices:
                    - 'FortiSandbox'
                    - 'FortiWeb'
                    - 'Fabric'
                    - 'Syslog'
                    - 'FortiCache'
                    - 'FortiAuthenticator'
                    - 'FortiMail'
                    - 'FortiProxy'
                    - 'FortiManager'
                    - 'FortiNAC'
                    - 'FortiAnalyzer'
                    - 'FortiClient'
                    - 'FortiDDoS'
                    - 'FortiGate'
                    - 'FortiFirewall'
            name:
                type: str
                description: no description
            variable:
                description: 'reference: /report/adom/<adom-name>/config/dataset/<dataset_name>/variable'
                type: list
                elements: dict
                suboptions:
                    var:
                        type: str
                        description: no description
                    var_expression:
                        type: str
                        description: no description
                    var_name:
                        type: str
                        description: no description
                    var_type:
                        type: str
                        description: no description
                        choices:
                            - 'ip'
                            - 'integer'
                            - 'string'
                            - 'datetime'
                    drilldown_flag:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                    var_array:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
            dev_drilldown:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            hcache:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            hidden:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            log_type:
                type: str
                description: no description
                choices:
                    - 'netscan'
                    - 'webfilter'
                    - 'event'
                    - 'fct-traffic'
                    - 'content'
                    - 'generic'
                    - 'waf'
                    - 'gtp'
                    - 'attack'
                    - 'dlp'
                    - 'dns'
                    - 'fct-event'
                    - 'ssl'
                    - 'virus'
                    - 'traffic'
                    - 'ssh'
                    - 'file-filter'
                    - 'voip'
                    - 'app-ctrl'
                    - 'emailfilter'
                    - 'local-event'
                    - 'sniffer'
                    - 'fct-netscan'
                    - 'history'
                    - 'asset'
            protected:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
            query:
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
    - name: Config dataset.
      fortinet.fortianalyzer.faz_report_config_dataset:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        report_config_dataset:
          description: <value of string>
          dev_type: <value in [FortiSandbox, FortiWeb, Fabric, ...]>
          name: <value of string>
          variable:
            - var: <value of string>
              var_expression: <value of string>
              var_name: <value of string>
              var_type: <value in [ip, integer, string, ...]>
              drilldown_flag: <value in [enable, disable]>
              var_array: <value in [enable, disable]>
          dev_drilldown: <value in [enable, disable]>
          hcache: <value in [enable, disable]>
          hidden: <value in [enable, disable]>
          log_type: <value in [netscan, webfilter, event, ...]>
          protected: <value in [enable, disable]>
          query: <value of string>
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
        '/report/adom/{adom}/config/dataset'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'report_config_dataset': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'description': {'type': 'str'},
                'dev-type': {
                    'v_range': [['6.2.1', '7.4.2']],
                    'choices': [
                        'FortiSandbox', 'FortiWeb', 'Fabric', 'Syslog', 'FortiCache', 'FortiAuthenticator', 'FortiMail', 'FortiProxy', 'FortiManager',
                        'FortiNAC', 'FortiAnalyzer', 'FortiClient', 'FortiDDoS', 'FortiGate', 'FortiFirewall'
                    ],
                    'type': 'str'
                },
                'name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'variable': {
                    'type': 'list',
                    'options': {
                        'var': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'var-expression': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'var-name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                        'var-type': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['ip', 'integer', 'string', 'datetime'], 'type': 'str'},
                        'drilldown-flag': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'var-array': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'dev-drilldown': {'v_range': [['6.2.2', '6.2.12'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'hcache': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'hidden': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'log-type': {
                    'v_range': [['6.2.2', '6.2.12']],
                    'choices': [
                        'netscan', 'webfilter', 'event', 'fct-traffic', 'content', 'generic', 'waf', 'gtp', 'attack', 'dlp', 'dns', 'fct-event', 'ssl',
                        'virus', 'traffic', 'ssh', 'file-filter', 'voip', 'app-ctrl', 'emailfilter', 'local-event', 'sniffer', 'fct-netscan', 'history',
                        'asset'
                    ],
                    'type': 'str'
                },
                'protected': {'v_range': [['6.2.2', '6.2.12']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'query': {'v_range': [['6.2.2', '6.2.12']], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_dataset'),
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
