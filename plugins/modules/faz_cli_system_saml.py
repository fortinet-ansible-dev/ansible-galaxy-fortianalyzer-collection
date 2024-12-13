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
module: faz_cli_system_saml
short_description: Global settings for SAML authentication.
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
    cli_system_saml:
        description: The top level parameters set.
        type: dict
        suboptions:
            acs_url:
                aliases: ['acs-url']
                type: str
                description: SP ACS
            cert:
                type: str
                description: Certificate name.
            default_profile:
                aliases: ['default-profile']
                type: str
                description: Default Profile Name.
            entity_id:
                aliases: ['entity-id']
                type: str
                description: SP entity ID.
            fabric_idp:
                aliases: ['fabric-idp']
                description: no description
                type: list
                elements: dict
                suboptions:
                    dev_id:
                        aliases: ['dev-id']
                        type: str
                        description: IDP Device ID.
                    idp_cert:
                        aliases: ['idp-cert']
                        type: str
                        description: IDP Certificate name.
                    idp_entity_id:
                        aliases: ['idp-entity-id']
                        type: str
                        description: IDP entity ID.
                    idp_single_logout_url:
                        aliases: ['idp-single-logout-url']
                        type: str
                        description: IDP single logout url.
                    idp_single_sign_on_url:
                        aliases: ['idp-single-sign-on-url']
                        type: str
                        description: IDP single sign-on URL.
                    idp_status:
                        aliases: ['idp-status']
                        type: str
                        description:
                         - Enable/disable SAML authentication
                         - disable - Disable SAML authentication.
                         - enable - Enabld SAML authentication.
                        choices: ['disable', 'enable']
            idp_cert:
                aliases: ['idp-cert']
                type: str
                description: IDP Certificate name.
            idp_entity_id:
                aliases: ['idp-entity-id']
                type: str
                description: IDP entity ID.
            idp_single_logout_url:
                aliases: ['idp-single-logout-url']
                type: str
                description: IDP single logout url.
            idp_single_sign_on_url:
                aliases: ['idp-single-sign-on-url']
                type: str
                description: IDP single sign-on URL.
            login_auto_redirect:
                aliases: ['login-auto-redirect']
                type: str
                description:
                 - Enable/Disable auto redirect to IDP login page.
                 - disable - Disable auto redirect to IDP Login Page.
                 - enable - Enable auto redirect to IDP Login Page.
                choices: ['disable', 'enable']
            role:
                type: str
                description:
                 - SAML role.
                 - IDP - IDentiy Provider.
                 - SP - Service Provider.
                 - FAB-SP - Fabric Service Provider.
                choices: ['IDP', 'SP', 'FAB-SP']
            server_address:
                aliases: ['server-address']
                type: str
                description: server address.
            service_providers:
                aliases: ['service-providers']
                description: no description
                type: list
                elements: dict
                suboptions:
                    idp_entity_id:
                        aliases: ['idp-entity-id']
                        type: str
                        description: IDP Entity ID.
                    idp_single_logout_url:
                        aliases: ['idp-single-logout-url']
                        type: str
                        description: IDP single logout url.
                    idp_single_sign_on_url:
                        aliases: ['idp-single-sign-on-url']
                        type: str
                        description: IDP single sign-on URL.
                    name:
                        type: str
                        description: Name.
                    prefix:
                        type: str
                        description: Prefix.
                    sp_cert:
                        aliases: ['sp-cert']
                        type: str
                        description: SP certificate name.
                    sp_entity_id:
                        aliases: ['sp-entity-id']
                        type: str
                        description: SP Entity ID.
                    sp_single_logout_url:
                        aliases: ['sp-single-logout-url']
                        type: str
                        description: SP single logout URL.
                    sp_single_sign_on_url:
                        aliases: ['sp-single-sign-on-url']
                        type: str
                        description: SP single sign-on URL.
                    sp_adom:
                        aliases: ['sp-adom']
                        type: str
                        description: SP adom name.
                    sp_profile:
                        aliases: ['sp-profile']
                        type: str
                        description: SP profile name.
            sls_url:
                aliases: ['sls-url']
                type: str
                description: SP SLS
            status:
                type: str
                description:
                 - Enable/disable SAML authentication
                 - disable - Disable SAML authentication.
                 - enable - Enabld SAML authentication.
                choices: ['disable', 'enable']
            forticloud_sso:
                aliases: ['forticloud-sso']
                type: str
                description:
                 - Enable/disable FortiCloud SSO
                 - disable - Disable Forticloud SSO.
                 - enable - Enabld Forticloud SSO.
                choices: ['disable', 'enable']
            user_auto_create:
                aliases: ['user-auto-create']
                type: str
                description:
                 - Enable/disable user auto creation
                 - disable - Disable auto create user.
                 - enable - Enable auto create user.
                choices: ['disable', 'enable']
            auth_request_signed:
                aliases: ['auth-request-signed']
                type: str
                description:
                 - Enable/Disable auth request signed.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            want_assertions_signed:
                aliases: ['want-assertions-signed']
                type: str
                description:
                 - Enable/Disable want assertions signed.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Global settings for SAML authentication.
      fortinet.fortianalyzer.faz_cli_system_saml:
        cli_system_saml:
          # forticloud_sso: disable
          login_auto_redirect: disable
          status: disable
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
        '/cli/global/system/saml'
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
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_system_saml': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'acs-url': {'type': 'str'},
                'cert': {'type': 'str'},
                'default-profile': {'v_range': [['6.2.1', '6.2.1'], ['6.2.5', '']], 'type': 'str'},
                'entity-id': {'type': 'str'},
                'fabric-idp': {
                    'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
                    'type': 'list',
                    'options': {
                        'dev-id': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'type': 'str'},
                        'idp-cert': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'type': 'str'},
                        'idp-entity-id': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'type': 'str'},
                        'idp-single-logout-url': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'type': 'str'},
                        'idp-single-sign-on-url': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'type': 'str'},
                        'idp-status': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'idp-cert': {'type': 'str'},
                'idp-entity-id': {'type': 'str'},
                'idp-single-logout-url': {'type': 'str'},
                'idp-single-sign-on-url': {'type': 'str'},
                'login-auto-redirect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'role': {'choices': ['IDP', 'SP', 'FAB-SP'], 'type': 'str'},
                'server-address': {'type': 'str'},
                'service-providers': {
                    'type': 'list',
                    'options': {
                        'idp-entity-id': {'type': 'str'},
                        'idp-single-logout-url': {'type': 'str'},
                        'idp-single-sign-on-url': {'type': 'str'},
                        'name': {'type': 'str'},
                        'prefix': {'type': 'str'},
                        'sp-cert': {'type': 'str'},
                        'sp-entity-id': {'type': 'str'},
                        'sp-single-logout-url': {'type': 'str'},
                        'sp-single-sign-on-url': {'type': 'str'},
                        'sp-adom': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'sp-profile': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'sls-url': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'forticloud-sso': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-auto-create': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-request-signed': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'want-assertions-signed': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_saml'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
