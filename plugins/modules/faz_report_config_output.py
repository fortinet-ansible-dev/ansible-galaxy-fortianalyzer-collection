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
module: faz_report_config_output
short_description: Config output.
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
    report_config_output:
        description: The top level parameters set.
        type: dict
        suboptions:
            description:
                type: str
                description: no description
            email_recipients:
                aliases: ['email-recipients']
                description: 'reference: /report/adom/<adom-name>/config/output/<output-name>/email-recipients'
                type: list
                elements: dict
                suboptions:
                    address:
                        type: str
                        description: no description
                    email_from:
                        aliases: ['email-from']
                        type: str
                        description: no description
                    email_server:
                        aliases: ['email-server']
                        type: str
                        description: no description
            name:
                type: str
                description: no description
            output_format:
                aliases: ['output-format']
                type: str
                description: no description
                choices: ['xml', 'rtf', 'connectwise', 'html', 'pdf', 'mht', 'txt', 'csv']
            email:
                type: str
                description: no description
                choices: ['enable', 'disable']
            email_attachment_compress:
                aliases: ['email-attachment-compress']
                type: str
                description: no description
                choices: ['enable', 'disable']
            email_attachment_name:
                aliases: ['email-attachment-name']
                type: str
                description: no description
            email_body:
                aliases: ['email-body']
                type: str
                description: no description
            email_subject:
                aliases: ['email-subject']
                type: str
                description: no description
            upload:
                type: str
                description: no description
                choices: ['enable', 'disable']
            upload_delete:
                aliases: ['upload-delete']
                type: str
                description: no description
                choices: ['enable', 'disable']
            upload_dir:
                aliases: ['upload-dir']
                type: str
                description: no description
            upload_pass:
                aliases: ['upload-pass']
                type: str
                description: no description
            upload_server:
                aliases: ['upload-server']
                type: str
                description: no description
            upload_server_type:
                aliases: ['upload-server-type']
                type: str
                description: no description
                choices: ['ftp', 'scp', 'sftp']
            upload_user:
                aliases: ['upload-user']
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
    - name: Config output.
      fortinet.fortianalyzer.faz_report_config_output:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        report_config_output:
          description: <value of string>
          email_recipients:
            - address: <value of string>
              email_from: <value of string>
              email_server: <value of string>
          name: <value of string>
          output_format: <value in [xml, rtf, connectwise, ...]>
          email: <value in [enable, disable]>
          email_attachment_compress: <value in [enable, disable]>
          email_attachment_name: <value of string>
          email_body: <value of string>
          email_subject: <value of string>
          upload: <value in [enable, disable]>
          upload_delete: <value in [enable, disable]>
          upload_dir: <value of string>
          upload_pass: <value of string>
          upload_server: <value of string>
          upload_server_type: <value in [ftp, scp, sftp]>
          upload_user: <value of string>
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
        '/report/adom/{adom}/config/output'
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
        'report_config_output': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'description': {'type': 'str'},
                'email-recipients': {
                    'type': 'list',
                    'options': {'address': {'type': 'str'}, 'email-from': {'type': 'str'}, 'email-server': {'type': 'str'}},
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.2.1', '7.4.2']], 'type': 'str'},
                'output-format': {
                    'v_range': [['6.2.1', '7.4.2']],
                    'choices': ['xml', 'rtf', 'connectwise', 'html', 'pdf', 'mht', 'txt', 'csv'],
                    'type': 'str'
                },
                'email': {'v_range': [['6.2.2', '6.2.13'], ['7.4.3', '']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'email-attachment-compress': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'email-attachment-name': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'email-body': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'email-subject': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'upload': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'upload-delete': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'upload-dir': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'upload-pass': {'v_range': [['6.2.2', '6.2.13']], 'no_log': False, 'type': 'str'},
                'upload-server': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'upload-server-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['ftp', 'scp', 'sftp'], 'type': 'str'},
                'upload-user': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'report_config_output'),
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
