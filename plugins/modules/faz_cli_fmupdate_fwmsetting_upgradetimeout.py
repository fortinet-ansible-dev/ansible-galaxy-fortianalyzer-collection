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
module: faz_cli_fmupdate_fwmsetting_upgradetimeout
short_description: Configure the timeout value of image upgrade process.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.1.0"
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
    cli_fmupdate_fwmsetting_upgradetimeout:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            check-status-timeout:
                type: int
                description: 'timeout for checking status after tunnnel is up.(1-6000s, default=600)'
            ctrl-check-status-timeout:
                type: int
                description: 'timeout for checking fap/fsw/fext status after request upgrade.(1-12000s, default=1200)'
            ctrl-put-image-by-fds-timeout:
                type: int
                description: 'timeout for waiting device get fap/fsw/fext image from fortiguard.(1-9000ss, default=900)'
            ha-sync-timeout:
                type: int
                description: 'timeout for waiting HA sync.(1-18000s, default=1800)'
            license-check-timeout:
                type: int
                description: 'timeout for waiting fortigate check license.(1-6000s, default=600)'
            prepare-image-timeout:
                type: int
                description: 'timeout for preparing image.(1-6000s, default=600)'
            put-image-by-fds-timeout:
                type: int
                description: 'timeout for waiting device get image from fortiguard.(1-18000s, default=1800)'
            put-image-timeout:
                type: int
                description: 'timeout for waiting send image over tunnel.(1-18000s, default=1800)'
            reboot-of-fsck-timeout:
                type: int
                description: 'timeout for waiting fortigate reboot.(1-18000s, default=1800)'
            reboot-of-upgrade-timeout:
                type: int
                description: 'timeout for waiting fortigate reboot after image upgrade.(1-12000s, default=1200)'
            retrieve-timeout:
                type: int
                description: 'timeout for waiting retrieve.(1-18000s, default=1800)'
            rpc-timeout:
                type: int
                description: 'timeout for waiting fortigate rpc response.(1-1800s, default=180)'
            total-timeout:
                type: int
                description: 'timeout for the whole fortigate upgrade(1-86400s, default=3600)'
            health-check-timeout:
                type: int
                description: 'timeout for waiting retrieve.(1-6000s, default=600)'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure the timeout value of image upgrade process.
      fortinet.fortianalyzer.faz_cli_fmupdate_fwmsetting_upgradetimeout:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        cli_fmupdate_fwmsetting_upgradetimeout:
          check_status_timeout: <value of integer>
          ctrl_check_status_timeout: <value of integer>
          ctrl_put_image_by_fds_timeout: <value of integer>
          ha_sync_timeout: <value of integer>
          license_check_timeout: <value of integer>
          prepare_image_timeout: <value of integer>
          put_image_by_fds_timeout: <value of integer>
          put_image_timeout: <value of integer>
          reboot_of_fsck_timeout: <value of integer>
          reboot_of_upgrade_timeout: <value of integer>
          retrieve_timeout: <value of integer>
          rpc_timeout: <value of integer>
          total_timeout: <value of integer>
          health_check_timeout: <value of integer>
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
        '/cli/global/fmupdate/fwm-setting/upgrade-timeout'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/fwm-setting/upgrade-timeout/{upgrade-timeout}'
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
        'cli_fmupdate_fwmsetting_upgradetimeout': {
            'type': 'dict',
            'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']],
            'options': {
                'check-status-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-check-status-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'ha-sync-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'license-check-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'prepare-image-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'put-image-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-fsck-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-upgrade-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'retrieve-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'rpc-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'total-timeout': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'health-check-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_fwmsetting_upgradetimeout'),
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
