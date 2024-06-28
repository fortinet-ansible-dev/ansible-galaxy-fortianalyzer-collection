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
module: faz_cli_system_snmp_user
short_description: SNMP user configuration.
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
    cli_system_snmp_user:
        description: The top level parameters set.
        type: dict
        suboptions:
            auth-proto:
                type: str
                description:
                 - Authentication protocol.
                 - md5 - HMAC-MD5-96 authentication protocol.
                 - sha - HMAC-SHA-96 authentication protocol.
                choices:
                    - 'md5'
                    - 'sha'
            auth-pwd:
                description: Password for authentication protocol.
                type: str
            events:
                description:
                 - SNMP notifications
                 - disk_low - Disk usage too high.
                 - intf_ip_chg - Interface IP address changed.
                 - sys_reboot - System reboot.
                 - cpu_high - CPU usage too high.
                 - mem_low - Available memory is low.
                 - log-alert - Log base alert message.
                 - log-rate - High incoming log rate detected.
                 - log-data-rate - High incoming log data rate detected.
                 - lic-gbday - High licensed log GB/day detected.
                 - lic-dev-quota - High licensed device quota detected.
                 - cpu-high-exclude-nice - CPU usage exclude NICE threshold.
                type: list
                elements: str
                choices:
                    - 'disk_low'
                    - 'intf_ip_chg'
                    - 'sys_reboot'
                    - 'cpu_high'
                    - 'mem_low'
                    - 'log-alert'
                    - 'log-rate'
                    - 'log-data-rate'
                    - 'lic-gbday'
                    - 'lic-dev-quota'
                    - 'cpu-high-exclude-nice'
            name:
                type: str
                description: SNMP user name.
            notify-hosts:
                type: str
                description: Hosts to send notifications
            notify-hosts6:
                type: str
                description: IPv6 hosts to send notifications
            priv-proto:
                type: str
                description:
                 - Privacy
                 - aes - CFB128-AES-128 symmetric encryption protocol.
                 - des - CBC-DES symmetric encryption protocol.
                choices:
                    - 'aes'
                    - 'des'
            priv-pwd:
                description: Password for privacy
                type: str
            queries:
                type: str
                description:
                 - Enable/disable queries for this user.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            query-port:
                type: int
                description: SNMPv3 query port.
            security-level:
                type: str
                description:
                 - Security level for message authentication and encryption.
                 - no-auth-no-priv - Message with no authentication and no privacy
                 - auth-no-priv - Message with authentication but no privacy
                 - auth-priv - Message with authentication and privacy
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: SNMP user configuration.
      fortinet.fortianalyzer.faz_cli_system_snmp_user:
        cli_system_snmp_user:
          # auth_proto: <value in [md5, sha]>
          # auth_pwd: <value of string>
          events:
            - disk_low
            - intf_ip_chg
            - sys_reboot
            - cpu_high
            - mem_low
            - log-alert
            - log-rate
            - log-data-rate
            - lic-gbday
            - lic-dev-quota
            - cpu-high-exclude-nice
          name: foosnmpuser
          # notify_hosts: <value of string>
          # notify_hosts6: <value of string>
          priv_proto: aes
          priv_pwd: foopass
          queries: disable
          # query_port: <value of integer>
          # security_level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
        state: present
  vars:
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false

- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Create snap user.
      fortinet.fortianalyzer.faz_cli_system_snmp_user:
        state: present
        cli_system_snmp_user:
          name: foosnmp
          auth_proto: md5
          auth_pwd: foopwd
    - name: Alert destination.
      fortinet.fortianalyzer.faz_cli_system_alertevent_alertdestination:
        alert_event: fooevent
        cli_system_alertevent_alertdestination:
          type: snmp
          snmp_name: foosnmp
        state: present
      when: false
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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import modify_argument_spec


def main():
    jrpc_urls = [
        '/cli/global/system/snmp/user'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/snmp/user/{user}'
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
        'cli_system_snmp_user': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'auth-proto': {'choices': ['md5', 'sha'], 'type': 'str'},
                'auth-pwd': {'no_log': True, 'type': 'str'},
                'events': {
                    'type': 'list',
                    'choices': [
                        'disk_low', 'intf_ip_chg', 'sys_reboot', 'cpu_high', 'mem_low', 'log-alert', 'log-rate', 'log-data-rate', 'lic-gbday',
                        'lic-dev-quota', 'cpu-high-exclude-nice'
                    ],
                    'elements': 'str'
                },
                'name': {'type': 'str'},
                'notify-hosts': {'type': 'str'},
                'notify-hosts6': {'type': 'str'},
                'priv-proto': {'choices': ['aes', 'des'], 'type': 'str'},
                'priv-pwd': {'no_log': True, 'type': 'str'},
                'queries': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-port': {'type': 'int'},
                'security-level': {'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_snmp_user'),
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
