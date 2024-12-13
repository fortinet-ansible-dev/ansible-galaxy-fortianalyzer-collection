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
    cli_system_ha:
        description: The top level parameters set.
        type: dict
        suboptions:
            group_id:
                aliases: ['group-id']
                type: int
                description: HA group ID
            group_name:
                aliases: ['group-name']
                type: str
                description: HA group name.
            hb_interface:
                aliases: ['hb-interface']
                type: str
                description: Interface for heartbeat.
            hb_interval:
                aliases: ['hb-interval']
                type: int
                description: Heartbeat interval
            healthcheck:
                description:
                 - Healthchecking options.
                 - DB - Check database is running
                 - fault-test - temp fault test
                type: list
                elements: str
                choices: ['DB', 'fault-test']
            initial_sync:
                aliases: ['initial-sync']
                type: str
                description:
                 - Need to sync data from master before up as an HA member.
                 - false - False.
                 - true - True.
                choices: ['false', 'true']
            initial_sync_threads:
                aliases: ['initial-sync-threads']
                type: int
                description: Number of threads used for initial sync
            load_balance:
                aliases: ['load-balance']
                type: str
                description:
                 - Load balance to slaves.
                 - disable - Disable load-balance to slaves.
                 - round-robin - Round-Robin mode.
                choices: ['disable', 'round-robin']
            log_sync:
                aliases: ['log-sync']
                type: str
                description:
                 - Sync logs to backup FortiAnalyzer.
                 - disable - Disable.
                 - enable - Enable.
                choices: ['disable', 'enable']
            mode:
                type: str
                description:
                 - Standalone or HA
                 - standalone - Standalone mode.
                 - a-p - Active-Passive mode.
                choices: ['standalone', 'a-p', 'a-a']
            password:
                description: HA group password.
                type: str
            peer:
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: IP address of peer for management and data.
                    ip_hb:
                        aliases: ['ip-hb']
                        type: str
                        description: IP address of peers VIP interface for heartbeat, set if different from ip.
                    serial_number:
                        aliases: ['serial-number']
                        type: str
                        description: Serial number of peer.
                    status:
                        type: str
                        description:
                         - Peer enabled status.
                         - disable - Disable.
                         - enable - Enable.
                        choices: ['disable', 'enable']
                    addr:
                        type: str
                        description: Address of peer for management and data.
                    addr_hb:
                        aliases: ['addr-hb']
                        type: str
                        description: Address of peers interface for heartbeat, set if different from ip.
            preferred_role:
                aliases: ['preferred-role']
                type: str
                description:
                 - Preferred role, runtime role may be different.
                 - slave - Prefer slave mode, FAZ can only become master after data-sync is done.
                 - master - Prefer master mode, FAZ can become master if theres no existing master.
                choices: ['slave', 'master', 'secondary', 'primary']
            priority:
                type: int
                description: Set the runtime priority between 80
            private_clusterid:
                aliases: ['private-clusterid']
                type: int
                description: Cluster ID range
            private_file_quota:
                aliases: ['private-file-quota']
                type: int
                description: File quota in MB
            private_hb_interval:
                aliases: ['private-hb-interval']
                type: int
                description: Heartbeat interval
            private_hb_lost_threshold:
                aliases: ['private-hb-lost-threshold']
                type: int
                description: Heartbeat lost threshold
            private_mode:
                aliases: ['private-mode']
                type: str
                description:
                 - Mode.
                 - standalone - Standalone.
                 - master - Master.
                 - slave - Slave.
                choices: ['standalone', 'master', 'slave', 'primary', 'secondary']
            private_password:
                aliases: ['private-password']
                description: Group password.
                type: str
            private_peer:
                aliases: ['private-peer']
                description: no description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: IP address of peer.
                    ip6:
                        type: str
                        description: IP address
                    serial_number:
                        aliases: ['serial-number']
                        type: str
                        description: Serial number of peer.
                    status:
                        type: str
                        description:
                         - Peer admin status.
                         - disable - Disable.
                         - enable - Enable.
                        choices: ['disable', 'enable']
            unicast:
                type: str
                description:
                 - Use unicast for HA heartbeat.
                 - disable - HA heartbeat through multicast.
                 - enable - HA heartbeat through unicast.
                choices: ['disable', 'enable']
            vip:
                type: str
                description: Virtual IP address for the HA
            vip_interface:
                aliases: ['vip-interface']
                type: str
                description: Interface for configuring virtual IP address
            private_local_cert:
                aliases: ['private-local-cert']
                type: str
                description: set the ha local certificate.
            cfg_sync_hb_interval:
                aliases: ['cfg-sync-hb-interval']
                type: int
                description: Config sync heartbeat interval
            local_cert:
                aliases: ['local-cert']
                type: str
                description: set the ha local certificate.
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
        '/cli/global/system/ha'
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
                        'ip': {'v_range': [['6.2.1', '7.4.3']], 'type': 'str'},
                        'ip-hb': {'v_range': [['6.2.1', '7.4.3']], 'type': 'str'},
                        'serial-number': {'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'addr': {'v_range': [['7.4.4', '']], 'type': 'str'},
                        'addr-hb': {'v_range': [['7.4.4', '']], 'type': 'str'}
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
                'private-local-cert': {'v_range': [['6.2.7', '6.2.13']], 'type': 'str'},
                'cfg-sync-hb-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'local-cert': {'v_range': [['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_ha'),
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
