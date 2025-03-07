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
module: faz_cli_system_admin_ldap
short_description: LDAP server entry configuration.
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
    cli_system_admin_ldap:
        description: The top level parameters set.
        type: dict
        suboptions:
            adom:
                description: no description
                type: list
                elements: dict
                suboptions:
                    adom_name:
                        aliases: ['adom-name']
                        type: str
                        description: Admin domain names.
            adom_attr:
                aliases: ['adom-attr']
                type: str
                description: Attribute used to retrieve adom
            attributes:
                type: str
                description: Attributes used for group searching.
            ca_cert:
                aliases: ['ca-cert']
                type: str
                description: CA certificate name.
            cnid:
                type: str
                description: Common Name Identifier
            connect_timeout:
                aliases: ['connect-timeout']
                type: int
                description: LDAP connection timeout
            dn:
                type: str
                description: Distinguished Name.
            filter:
                type: str
                description: Filter used for group searching.
            group:
                type: str
                description: Full base DN used for group searching.
            memberof_attr:
                aliases: ['memberof-attr']
                type: str
                description: Attribute used to retrieve memeberof.
            name:
                type: str
                description: LDAP server entry name.
            password:
                description: Password for initial binding.
                type: str
            port:
                type: int
                description: Port number of LDAP server
            profile_attr:
                aliases: ['profile-attr']
                type: str
                description: Attribute used to retrieve admin profile.
            secondary_server:
                aliases: ['secondary-server']
                type: str
                description: no description
            secure:
                type: str
                description:
                 - SSL connection.
                 - disable - No SSL.
                 - starttls - Use StartTLS.
                 - ldaps - Use LDAPS.
                choices: ['disable', 'starttls', 'ldaps']
            server:
                type: str
                description: no description
            tertiary_server:
                aliases: ['tertiary-server']
                type: str
                description: no description
            type:
                type: str
                description:
                 - Type of LDAP binding.
                 - simple - Simple password authentication without search.
                 - anonymous - Bind using anonymous user search.
                 - regular - Bind using username/password and then search.
                choices: ['simple', 'anonymous', 'regular']
            username:
                type: str
                description: Username
            adom_access:
                aliases: ['adom-access']
                type: str
                description:
                 - set all or specify adom access type.
                 - all - All ADOMs access.
                 - specify - Specify ADOMs access.
                choices: ['all', 'specify']
            ssl_protocol:
                aliases: ['ssl-protocol']
                type: str
                description:
                 - set the lowest SSL protocol version for connection to ldap server.
                 - follow-global-ssl-protocol - Follow system.global.global-ssl-protocol setting
                 - sslv3 - set SSLv3 as the lowest version.
                 - tlsv1.0 - set TLSv1.0 as the lowest version.
                 - tlsv1.1 - set TLSv1.1 as the lowest version.
                 - tlsv1.2 - set TLSv1.2 as the lowest version.
                 - tlsv1.3 - set TLSv1.3 as the lowest version.
                choices: ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: LDAP server entry configuration.
      fortinet.fortianalyzer.faz_cli_system_admin_ldap:
        cli_system_admin_ldap:
          name: fooldap
          password: foopasscode
          port: 10443
          server: 192.11.1.11
          type: simple
          username: fooldap
        state: present
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
        '/cli/global/system/admin/ldap'
    ]

    url_params = []
    module_primary_key = 'name'
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
        'cli_system_admin_ldap': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'adom': {'type': 'list', 'options': {'adom-name': {'type': 'str'}}, 'elements': 'dict'},
                'adom-attr': {'type': 'str'},
                'attributes': {'type': 'str'},
                'ca-cert': {'type': 'str'},
                'cnid': {'type': 'str'},
                'connect-timeout': {'v_range': [['6.2.1', '7.2.9'], ['7.4.0', '7.4.2']], 'type': 'int'},
                'dn': {'type': 'str'},
                'filter': {'type': 'str'},
                'group': {'type': 'str'},
                'memberof-attr': {'type': 'str'},
                'name': {'type': 'str'},
                'password': {'no_log': True, 'type': 'str'},
                'port': {'type': 'int'},
                'profile-attr': {'type': 'str'},
                'secondary-server': {'type': 'str'},
                'secure': {'choices': ['disable', 'starttls', 'ldaps'], 'type': 'str'},
                'server': {'type': 'str'},
                'tertiary-server': {'type': 'str'},
                'type': {'choices': ['simple', 'anonymous', 'regular'], 'type': 'str'},
                'username': {'type': 'str'},
                'adom-access': {'v_range': [['7.0.3', '']], 'choices': ['all', 'specify'], 'type': 'str'},
                'ssl-protocol': {
                    'v_range': [['7.4.4', '7.4.6'], ['7.6.2', '']],
                    'choices': ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'],
                    'type': 'str'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_ldap'),
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
