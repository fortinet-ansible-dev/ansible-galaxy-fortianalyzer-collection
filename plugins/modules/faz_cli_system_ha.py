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
module: faz_cli_system_ha
short_description: HA configuration.
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
    cli_system_ha:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            group-id:
                type: int
                description: 'HA group ID (1 - 255).'
            group-name:
                type: str
                description: 'HA group name.'
            hb-interface:
                type: str
                description: 'Interface for heartbeat.'
            hb-interval:
                type: int
                description: 'Heartbeat interval (1 - 20).'
            healthcheck:
                description: no description
                type: list
                elements: str
                choices:
                    - 'DB'
                    - 'fault-test'
            initial-sync:
                type: str
                description:
                 - 'Need to sync data from master before up as an HA member.'
                 - 'false - False.'
                 - 'true - True.'
                choices:
                    - 'false'
                    - 'true'
            initial-sync-threads:
                type: int
                description: 'Number of threads used for initial sync (1-15).'
            load-balance:
                type: str
                description:
                 - 'Load balance to slaves.'
                 - 'disable - Disable load-balance to slaves.'
                 - 'round-robin - Round-Robin mode.'
                choices:
                    - 'disable'
                    - 'round-robin'
            log-sync:
                type: str
                description:
                 - 'Sync logs to backup FortiAnalyzer.'
                 - 'disable - Disable.'
                 - 'enable - Enable.'
                choices:
                    - 'disable'
                    - 'enable'
            mode:
                type: str
                description:
                 - 'Standalone or HA (a-p) mode'
                 - 'standalone - Standalone mode.'
                 - 'a-p - Active-Passive mode.'
                choices:
                    - 'standalone'
                    - 'a-p'
                    - 'a-a'
            password:
                description: no description
                type: str
            peer:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: 'Id.'
                    ip:
                        type: str
                        description: 'IP address of peer for management and data.'
                    ip-hb:
                        type: str
                        description: 'IP address of peers VIP interface for heartbeat, set if different from ip. (needed only when using unicast)'
                    serial-number:
                        type: str
                        description: 'Serial number of peer.'
                    status:
                        type: str
                        description:
                         - 'Peer enabled status.'
                         - 'disable - Disable.'
                         - 'enable - Enable.'
                        choices:
                            - 'disable'
                            - 'enable'
            preferred-role:
                type: str
                description:
                 - 'Preferred role, runtime role may be different.'
                 - 'slave - Prefer slave mode, FAZ can only become master after data-sync is done.'
                 - 'master - Prefer master mode, FAZ can become master if theres no existing master.'
                choices:
                    - 'slave'
                    - 'master'
                    - 'secondary'
                    - 'primary'
            priority:
                type: int
                description: 'Set the runtime priority between 80 (lowest) - 120 (highest).'
            private-clusterid:
                type: int
                description: 'Cluster ID range (1 - 64).'
            private-file-quota:
                type: int
                description: 'File quota in MB (2048 - 20480).'
            private-hb-interval:
                type: int
                description: 'Heartbeat interval (1 - 255).'
            private-hb-lost-threshold:
                type: int
                description: 'Heartbeat lost threshold (1 - 255).'
            private-mode:
                type: str
                description:
                 - 'Mode.'
                 - 'standalone - Standalone.'
                 - 'master - Master.'
                 - 'slave - Slave.'
                choices:
                    - 'standalone'
                    - 'master'
                    - 'slave'
                    - 'primary'
                    - 'secondary'
            private-password:
                description: no description
                type: str
            private-peer:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: 'Id.'
                    ip:
                        type: str
                        description: 'IP address of peer.'
                    ip6:
                        type: str
                        description: 'IP address (V6) of peer.'
                    serial-number:
                        type: str
                        description: 'Serial number of peer.'
                    status:
                        type: str
                        description:
                         - 'Peer admin status.'
                         - 'disable - Disable.'
                         - 'enable - Enable.'
                        choices:
                            - 'disable'
                            - 'enable'
            unicast:
                type: str
                description:
                 - 'Use unicast for HA heartbeat.'
                 - 'disable - HA heartbeat through multicast.'
                 - 'enable - HA heartbeat through unicast.'
                choices:
                    - 'disable'
                    - 'enable'
            vip:
                type: str
                description: 'Virtual IP address for the HA'
            vip-interface:
                type: str
                description: 'Interface for configuring virtual IP address'
            private-local-cert:
                type: str
                description: 'set the ha local certificate.'
            cfg-sync-hb-interval:
                type: int
                description: 'Config sync heartbeat interval (1 - 80).'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: HA configuration.
      fortinet.fortianalyzer.faz_cli_system_ha:
        cli_system_ha:
          log_sync: disable
          mode: standalone
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
        '/cli/global/system/ha'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/ha/{ha}'
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
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_system_ha': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'group-id': {'type': 'int'},
                'group-name': {'type': 'str'},
                'hb-interface': {'type': 'str'},
                'hb-interval': {'type': 'int'},
                'healthcheck': {'type': 'list', 'choices': ['DB', 'fault-test'], 'elements': 'str'},
                'initial-sync': {'choices': ['false', 'true'], 'type': 'str'},
                'initial-sync-threads': {'type': 'int'},
                'load-balance': {'choices': ['disable', 'round-robin'], 'type': 'str'},
                'log-sync': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mode': {'choices': ['standalone', 'a-p', 'a-a'], 'type': 'str'},
                'password': {'no_log': True, 'type': 'str'},
                'peer': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'ip-hb': {'type': 'str'},
                        'serial-number': {'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'preferred-role': {'choices': ['slave', 'master', 'secondary', 'primary'], 'type': 'str'},
                'priority': {'type': 'int'},
                'private-clusterid': {'type': 'int'},
                'private-file-quota': {'type': 'int'},
                'private-hb-interval': {'type': 'int'},
                'private-hb-lost-threshold': {'type': 'int'},
                'private-mode': {'choices': ['standalone', 'master', 'slave', 'primary', 'secondary'], 'type': 'str'},
                'private-password': {'no_log': True, 'type': 'str'},
                'private-peer': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'ip6': {'type': 'str'},
                        'serial-number': {'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'unicast': {'choices': ['disable', 'enable'], 'type': 'str'},
                'vip': {'type': 'str'},
                'vip-interface': {'v_range': [['6.2.1', '7.0.4']], 'type': 'str'},
                'private-local-cert': {'v_range': [['6.2.7', '6.2.12']], 'type': 'str'},
                'cfg-sync-hb-interval': {'v_range': [['6.4.8', '6.4.14'], ['7.0.3', '']], 'type': 'int'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_ha'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
