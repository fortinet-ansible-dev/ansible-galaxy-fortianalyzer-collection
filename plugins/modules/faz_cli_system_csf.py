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
module: faz_cli_system_csf
short_description: Add this device to a Security Fabric or set up a new Security Fabric on this device.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.3.0"
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
    cli_system_csf:
        description: The top level parameters set.
        type: dict
        suboptions:
            accept_auth_by_cert:
                type: str
                description:
                 - Accept connections with unknown certificates and ask admin for approval.
                 - disable - Do not accept SSL connections with unknown certificates.
                 - enable - Accept SSL connections without automatic certificate verification.
                choices:
                    - 'disable'
                    - 'enable'
            authorization_request_type:
                type: str
                description:
                 - Authorization request type.
                 - certificate - Request verification by certificate.
                 - serial - Request verification by serial number.
                choices:
                    - 'certificate'
                    - 'serial'
            certificate:
                type: str
                description: Certificate.
            configuration_sync:
                type: str
                description:
                 - Configuration sync mode.
                 - default - Synchronize configuration for IPAM, FortiAnalyzer, FortiSandbox, and Central Management to root node.
                 - local - Do not synchronize configuration with root node.
                choices:
                    - 'default'
                    - 'local'
            downstream_access:
                type: str
                description:
                 - Enable/disable downstream device access to this devices configuration and data.
                 - disable - Disable downstream device access to this devices configuration and data.
                 - enable - Enable downstream device access to this devices configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            downstream_accprofile:
                type: str
                description: Default access profile for requests from downstream devices.
            fabric_connector:
                description: no description
                type: list
                elements: dict
                suboptions:
                    accprofile:
                        type: str
                        description: Override access profile.
                    configuration_write_access:
                        type: str
                        description:
                         - Enable/disable downstream device write access to configuration.
                         - disable - Disable downstream device write access to configuration.
                         - enable - Enable downstream device write access to configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    serial:
                        type: str
                        description: Serial.
            fabric_object_unification:
                type: str
                description:
                 - Fabric CMDB Object Unification.
                 - local - Global CMDB objects will not be synchronized to and from this device.
                 - default - Global CMDB objects will be synchronized in Security Fabric.
                choices:
                    - 'local'
                    - 'default'
            fabric_workers:
                type: int
                description: Number of worker processes for Security Fabric daemon.
            file_mgmt:
                type: str
                description:
                 - Enable/disable Security Fabric daemon file management.
                 - disable - Disable daemon file management.
                 - enable - Enable daemon file management.
                choices:
                    - 'disable'
                    - 'enable'
            file_quota:
                type: int
                description: Maximum amount of memory that can be used by the daemon files
            file_quota_warning:
                type: int
                description: Warn when the set percentage of quota has been used.
            fixed_key:
                description: Auto-generated fixed key used when this device is the root.
                type: str
            forticloud_account_enforcement:
                type: str
                description:
                 - Fabric FortiCloud account unification.
                 - disable - Disable FortiCloud accound ID matching for Security Fabric.
                 - enable - Enable FortiCloud account ID matching for Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            group_name:
                type: str
                description: Security Fabric group name.
            group_password:
                description: Security Fabric group password.
                type: str
            log_unification:
                type: str
                description:
                 - Enable/disable broadcast of discovery messages for log unification.
                 - disable - Disable broadcast of discovery messages for log unification.
                 - enable - Enable broadcast of discovery messages for log unification.
                choices:
                    - 'disable'
                    - 'enable'
            saml_configuration_sync:
                type: str
                description:
                 - SAML setting configuration synchronization.
                 - local - Do not apply SAML configuration generated by root.
                 - default - SAML setting for fabric members is created by fabric root.
                choices:
                    - 'local'
                    - 'default'
            status:
                type: str
                description:
                 - Enable/disable Security Fabric.
                 - disable - Disable Security Fabric.
                 - enable - Enable Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            trusted_list:
                description: no description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description:
                         - Security fabric authorization action.
                         - accept - Accept authorization request.
                         - deny - Deny authorization request.
                        choices:
                            - 'accept'
                            - 'deny'
                    authorization_type:
                        type: str
                        description:
                         - Authorization type.
                         - serial - Verify downstream by serial number.
                         - certificate - Verify downstream by certificate.
                        choices:
                            - 'serial'
                            - 'certificate'
                    certificate:
                        type: str
                        description: Certificate.
                    downstream_authorization:
                        type: str
                        description:
                         - Trust authorizations by this nodes administrator.
                         - disable - Disable downstream authorization.
                         - enable - Enable downstream authorization.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha_members:
                        type: str
                        description: HA members.
                    index:
                        type: int
                        description: Index of the downstream in tree.
                    name:
                        type: str
                        description: Name.
                    serial:
                        type: str
                        description: Serial.
            upstream:
                type: str
                description: IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
            upstream_port:
                type: int
                description: The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric
            upstream_confirm:
                type: str
                description:
                 - Upstream authorization confirm.
                 - discover - Discover upstream devices info.
                 - confirm - Confirm upstream devices access.
                choices:
                    - 'discover'
                    - 'confirm'
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
    - name: Add this device to a Security Fabric or set up a new Security Fabric on this device.
      fortinet.fortianalyzer.faz_cli_system_csf:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        cli_system_csf:
          accept_auth_by_cert: <value in [disable, enable]>
          authorization_request_type: <value in [certificate, serial]>
          certificate: <value of string>
          configuration_sync: <value in [default, local]>
          downstream_access: <value in [disable, enable]>
          downstream_accprofile: <value of string>
          fabric_connector:
            - accprofile: <value of string>
              configuration_write_access: <value in [disable, enable]>
              serial: <value of string>
          fabric_object_unification: <value in [local, default]>
          fabric_workers: <value of integer>
          file_mgmt: <value in [disable, enable]>
          file_quota: <value of integer>
          file_quota_warning: <value of integer>
          fixed_key: <value of string>
          forticloud_account_enforcement: <value in [disable, enable]>
          group_name: <value of string>
          group_password: <value of string>
          log_unification: <value in [disable, enable]>
          saml_configuration_sync: <value in [local, default]>
          status: <value in [disable, enable]>
          trusted_list:
            - action: <value in [accept, deny]>
              authorization_type: <value in [serial, certificate]>
              certificate: <value of string>
              downstream_authorization: <value in [disable, enable]>
              ha_members: <value of string>
              index: <value of integer>
              name: <value of string>
              serial: <value of string>
          upstream: <value of string>
          upstream_port: <value of integer>
          upstream_confirm: <value in [discover, confirm]>
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
        '/cli/global/system/csf'
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
        'cli_system_csf': {
            'type': 'dict',
            'v_range': [['7.4.1', '']],
            'options': {
                'accept-auth-by-cert': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authorization-request-type': {'v_range': [['7.4.1', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                'certificate': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'configuration-sync': {'v_range': [['7.4.1', '7.4.3']], 'choices': ['default', 'local'], 'type': 'str'},
                'downstream-access': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'downstream-accprofile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'fabric-connector': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'accprofile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'configuration-write-access': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'serial': {'v_range': [['7.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {'v_range': [['7.4.1', '7.4.3']], 'choices': ['local', 'default'], 'type': 'str'},
                'fabric-workers': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'file-mgmt': {'v_range': [['7.4.1', '7.4.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-quota': {'v_range': [['7.4.1', '7.4.3']], 'type': 'int'},
                'file-quota-warning': {'v_range': [['7.4.1', '7.4.3']], 'type': 'int'},
                'fixed-key': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'str'},
                'forticloud-account-enforcement': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'group-password': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'str'},
                'log-unification': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-configuration-sync': {'v_range': [['7.4.1', '7.4.3']], 'choices': ['local', 'default'], 'type': 'str'},
                'status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-list': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.1', '']], 'choices': ['accept', 'deny'], 'type': 'str'},
                        'authorization-type': {'v_range': [['7.4.1', '']], 'choices': ['serial', 'certificate'], 'type': 'str'},
                        'certificate': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'downstream-authorization': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-members': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'index': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'serial': {'v_range': [['7.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'upstream': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'upstream-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'upstream-confirm': {'v_range': [['7.6.0', '']], 'choices': ['discover', 'confirm'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_csf'),
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
