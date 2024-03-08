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
module: faz_cli_system_sniffer
short_description: Interface sniffer.
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
    state:
        description: The directive to create, update or delete an object
        type: str
        required: true
        choices:
            - present
            - absent
    cli_system_sniffer:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            host:
                type: str
                description: 'Hosts to filter for in sniffer traffic'
            id:
                type: int
                description: 'Sniffer ID.'
            interface:
                type: str
                description: 'Interface.'
            ipv6:
                type: str
                description:
                 - 'Enable/disable sniffing IPv6 packets.'
                 - 'disable - Disable sniffer for IPv6 packets.'
                 - 'enable - Enable sniffer for IPv6 packets.'
                choices:
                    - 'disable'
                    - 'enable'
            max-packet-count:
                type: int
                description: 'Maximum packet count (1000000, default = 4000).'
            non-ip:
                type: str
                description:
                 - 'Enable/disable sniffing non-IP packets.'
                 - 'disable - Disable sniffer for non-IP packets.'
                 - 'enable - Enable sniffer for non-IP packets.'
                choices:
                    - 'disable'
                    - 'enable'
            port:
                type: str
                description: 'Ports to sniff (Format examples: 10, 100-200).'
            protocol:
                type: str
                description: 'Integer value for the protocol type as defined by IANA (0 - 255).'
            vlan:
                type: str
                description: 'List of VLANs to sniff.'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Interface sniffer.
      fortinet.fortianalyzer.faz_cli_system_sniffer:
        cli_system_sniffer:
          host: 2.3.4.53
          id: 1
          interface: port1
          ipv6: disable
          max_packet_count: 100
          non_ip: disable
          port: 22
          protocol: 1
          vlan: 0
        state: present
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
        '/cli/global/system/sniffer'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/sniffer/{sniffer}'
    ]

    url_params = []
    module_primary_key = 'id'
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'cli_system_sniffer': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'host': {'type': 'str'},
                'id': {'type': 'int'},
                'interface': {'type': 'str'},
                'ipv6': {'choices': ['disable', 'enable'], 'type': 'str'},
                'max-packet-count': {'type': 'int'},
                'non-ip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'type': 'str'},
                'protocol': {'type': 'str'},
                'vlan': {'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_sniffer'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='full crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
