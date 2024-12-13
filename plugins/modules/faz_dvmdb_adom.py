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
module: faz_dvmdb_adom
short_description: ADOM table, most attributes are read-only and can only be changed internally.
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
    dvmdb_adom:
        description: The top level parameters set.
        type: dict
        suboptions:
            desc:
                type: str
                description: no description
            flags:
                description: no description
                type: list
                elements: str
                choices:
                    - 'migration'
                    - 'db_export'
                    - 'no_vpn_console'
                    - 'backup'
                    - 'other_devices'
                    - 'central_sdwan'
                    - 'is_autosync'
                    - 'per_device_wtp'
                    - 'policy_check_on_install'
                    - 'install_on_policy_check_fail'
                    - 'auto_push_cfg'
                    - 'per_device_fsw'
                    - 'install_deselect_all'
            log_db_retention_hours:
                type: int
                description: no description
            log_disk_quota:
                type: int
                description: no description
            log_disk_quota_alert_thres:
                type: int
                description: no description
            log_disk_quota_split_ratio:
                type: int
                description: no description
            log_file_retention_hours:
                type: int
                description: no description
            meta_fields:
                aliases: ['meta fields']
                description: no description
                type: dict
            mig_mr:
                type: int
                description: no description
            mig_os_ver:
                type: str
                description: no description
                choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0']
            mode:
                type: str
                description:
                 - ems -
                 - provider - Global database.
                choices: ['ems', 'gms', 'provider']
            mr:
                type: int
                description: no description
            name:
                type: str
                description: no description
            os_ver:
                type: str
                description: no description
                choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0']
            restricted_prds:
                description: no description
                type: list
                elements: str
                choices:
                    - 'fos'
                    - 'foc'
                    - 'fml'
                    - 'fch'
                    - 'fwb'
                    - 'log'
                    - 'fct'
                    - 'faz'
                    - 'fsa'
                    - 'fsw'
                    - 'fmg'
                    - 'fdd'
                    - 'fac'
                    - 'fpx'
                    - 'fna'
                    - 'fdc'
                    - 'ffw'
                    - 'fsr'
                    - 'fad'
                    - 'fts'
                    - 'fap'
                    - 'fxt'
                    - 'fai'
                    - 'fwc'
            state:
                type: int
                description: no description
            uuid:
                type: str
                description: no description
            create_time:
                type: int
                description: no description
            workspace_mode:
                type: int
                description: no description
            tz:
                type: int
                description: no description
            lock_override:
                type: int
                description: no description
            primary_dns_ip4:
                type: str
                description: no description
            primary_dns_ip6_1:
                type: int
                description: no description
            primary_dns_ip6_2:
                type: int
                description: no description
            primary_dns_ip6_3:
                type: int
                description: no description
            primary_dns_ip6_4:
                type: int
                description: no description
            secondary_dns_ip4:
                type: str
                description: no description
            secondary_dns_ip6_1:
                type: int
                description: no description
            secondary_dns_ip6_2:
                type: int
                description: no description
            secondary_dns_ip6_3:
                type: int
                description: no description
            secondary_dns_ip6_4:
                type: int
                description: no description
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: ADOM table, most attributes are read-only and can only be changed internally.
      fortinet.fortianalyzer.faz_dvmdb_adom:
        dvmdb_adom:
          desc: adom created via ansible
          name: fooadom
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
        '/dvmdb/adom'
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
        'dvmdb_adom': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'desc': {'type': 'str'},
                'flags': {
                    'type': 'list',
                    'choices': [
                        'migration', 'db_export', 'no_vpn_console', 'backup', 'other_devices', 'central_sdwan', 'is_autosync', 'per_device_wtp',
                        'policy_check_on_install', 'install_on_policy_check_fail', 'auto_push_cfg', 'per_device_fsw', 'install_deselect_all'
                    ],
                    'elements': 'str'
                },
                'log_db_retention_hours': {'type': 'int'},
                'log_disk_quota': {'type': 'int'},
                'log_disk_quota_alert_thres': {'type': 'int'},
                'log_disk_quota_split_ratio': {'type': 'int'},
                'log_file_retention_hours': {'type': 'int'},
                'meta fields': {'type': 'dict'},
                'mig_mr': {'type': 'int'},
                'mig_os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                'mode': {'choices': ['ems', 'gms', 'provider'], 'type': 'str'},
                'mr': {'type': 'int'},
                'name': {'type': 'str'},
                'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                'restricted_prds': {
                    'type': 'list',
                    'choices': [
                        'fos', 'foc', 'fml', 'fch', 'fwb', 'log', 'fct', 'faz', 'fsa', 'fsw', 'fmg', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw', 'fsr',
                        'fad', 'fts', 'fap', 'fxt', 'fai', 'fwc'
                    ],
                    'elements': 'str'
                },
                'state': {'type': 'int'},
                'uuid': {'type': 'str'},
                'create_time': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'workspace_mode': {'v_range': [['6.4.3', '']], 'type': 'int'},
                'tz': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'lock_override': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'primary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'primary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'secondary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'dvmdb_adom'),
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
