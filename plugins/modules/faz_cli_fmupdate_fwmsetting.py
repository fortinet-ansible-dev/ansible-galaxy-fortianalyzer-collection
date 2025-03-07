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
module: faz_cli_fmupdate_fwmsetting
short_description: Configure firmware management settings.
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
    cli_fmupdate_fwmsetting:
        description: The top level parameters set.
        type: dict
        suboptions:
            auto_scan_fgt_disk:
                aliases: ['auto-scan-fgt-disk']
                type: str
                description:
                 - auto scan fgt disk if needed.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            check_fgt_disk:
                aliases: ['check-fgt-disk']
                type: str
                description:
                 - check fgt disk before upgrade image.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            fds_failover_fmg:
                aliases: ['fds-failover-fmg']
                type: str
                description:
                 - using fmg local image file is download from fds fails.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            fds_image_timeout:
                aliases: ['fds-image-timeout']
                type: int
                description: timer for fgt download image from fortiguard
            multiple_steps_interval:
                aliases: ['multiple-steps-interval']
                type: int
                description: waiting time between multiple steps upgrade
            max_fds_retry:
                aliases: ['max-fds-retry']
                type: int
                description: The retries when fgt download from fds fail
            skip_disk_check:
                aliases: ['skip-disk-check']
                type: str
                description:
                 - skip disk check when upgrade image.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            immx_source:
                aliases: ['immx-source']
                type: str
                description:
                 - Configure which of IMMX file to be used for choosing upgrade pach.
                 - fmg - Use IMMX file for FortiManager
                 - fgt - Use IMMX file for FortiGate
                 - cloud - Use IMMX file for FortiCloud
                choices: ['fmg', 'fgt', 'cloud']
            log:
                type: str
                description:
                 - Configure log setting for fwm daemon
                 - fwm - FWM daemon log
                 - fwm_dm - FWM and Deployment service log
                 - fwm_dm_json - FWM and Deployment service log with JSON data between FMG-FGT
                choices: ['fwm', 'fwm_dm', 'fwm_dm_json']
            upgrade_timeout:
                aliases: ['upgrade-timeout']
                description: no description
                type: dict
                suboptions:
                    check_status_timeout:
                        aliases: ['check-status-timeout']
                        type: int
                        description: timeout for checking status after tunnnel is up.
                    ctrl_check_status_timeout:
                        aliases: ['ctrl-check-status-timeout']
                        type: int
                        description: timeout for checking fap/fsw/fext status after request upgrade.
                    ctrl_put_image_by_fds_timeout:
                        aliases: ['ctrl-put-image-by-fds-timeout']
                        type: int
                        description: timeout for waiting device get fap/fsw/fext image from fortiguard.
                    ha_sync_timeout:
                        aliases: ['ha-sync-timeout']
                        type: int
                        description: timeout for waiting HA sync.
                    license_check_timeout:
                        aliases: ['license-check-timeout']
                        type: int
                        description: timeout for waiting fortigate check license.
                    prepare_image_timeout:
                        aliases: ['prepare-image-timeout']
                        type: int
                        description: timeout for preparing image.
                    put_image_by_fds_timeout:
                        aliases: ['put-image-by-fds-timeout']
                        type: int
                        description: timeout for waiting device get image from fortiguard.
                    put_image_timeout:
                        aliases: ['put-image-timeout']
                        type: int
                        description: timeout for waiting send image over tunnel.
                    reboot_of_fsck_timeout:
                        aliases: ['reboot-of-fsck-timeout']
                        type: int
                        description: timeout for waiting fortigate reboot.
                    reboot_of_upgrade_timeout:
                        aliases: ['reboot-of-upgrade-timeout']
                        type: int
                        description: timeout for waiting fortigate reboot after image upgrade.
                    retrieve_timeout:
                        aliases: ['retrieve-timeout']
                        type: int
                        description: timeout for waiting retrieve.
                    rpc_timeout:
                        aliases: ['rpc-timeout']
                        type: int
                        description: timeout for waiting fortigate rpc response.
                    total_timeout:
                        aliases: ['total-timeout']
                        type: int
                        description: timeout for the whole fortigate upgrade
                    health_check_timeout:
                        aliases: ['health-check-timeout']
                        type: int
                        description: timeout for waiting retrieve.
            retry_interval:
                aliases: ['retry-interval']
                type: int
                description: waiting time for resending request to device
            retry_max:
                aliases: ['retry-max']
                type: int
                description: max retry times
            send_image_retry:
                aliases: ['send-image-retry']
                type: int
                description: retry send image when failed
            health_check:
                aliases: ['health-check']
                type: str
                description:
                 - do health check after upgrade
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            max_device_history:
                aliases: ['max-device-history']
                type: int
                description: max number of device upgrade report
            max_profile_history:
                aliases: ['max-profile-history']
                type: int
                description: max number of profile upgrade report
            retrieve:
                type: str
                description:
                 - do retrieve after upgrade
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            revision_diff:
                aliases: ['revision-diff']
                type: str
                description:
                 - calculate diff script after upgrade
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Configure firmware management settings.
      fortinet.fortianalyzer.faz_cli_fmupdate_fwmsetting:
        cli_fmupdate_fwmsetting:
          auto_scan_fgt_disk: disable
          check_fgt_disk: disable
          fds_failover_fmg: disable
          # fds_image_timeout: <value of integer>
          # immx_source: <value in [fmg, fgt, cloud]>
          # max_fds_retry: <value of integer>
          # multiple_steps_interval: <value of integer>
          # skip_disk_check: disable
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
        '/cli/global/fmupdate/fwm-setting'
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
        'cli_fmupdate_fwmsetting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'auto-scan-fgt-disk': {'v_range': [['6.2.1', '6.2.1'], ['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'check-fgt-disk': {'v_range': [['6.2.1', '6.2.1'], ['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fds-failover-fmg': {'v_range': [['6.2.1', '6.2.1'], ['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fds-image-timeout': {'type': 'int'},
                'multiple-steps-interval': {'type': 'int'},
                'max-fds-retry': {'v_range': [['6.2.2', '6.2.3']], 'type': 'int'},
                'skip-disk-check': {'v_range': [['6.2.2', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'immx-source': {'v_range': [['6.4.2', '']], 'choices': ['fmg', 'fgt', 'cloud'], 'type': 'str'},
                'log': {'v_range': [['6.4.8', '6.4.15'], ['7.0.1', '']], 'choices': ['fwm', 'fwm_dm', 'fwm_dm_json'], 'type': 'str'},
                'upgrade-timeout': {
                    'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']],
                    'type': 'dict',
                    'options': {
                        'check-status-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'ctrl-check-status-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'ctrl-put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'ha-sync-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'license-check-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'prepare-image-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'put-image-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'reboot-of-fsck-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'reboot-of-upgrade-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'retrieve-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'rpc-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'total-timeout': {'v_range': [['7.0.5', '7.0.13'], ['7.2.2', '']], 'type': 'int'},
                        'health-check-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'}
                    }
                },
                'retry-interval': {'v_range': [['7.0.10', '7.0.13'], ['7.2.5', '7.2.10'], ['7.4.2', '']], 'type': 'int'},
                'retry-max': {'v_range': [['7.0.10', '7.0.13'], ['7.2.5', '7.2.10'], ['7.4.2', '']], 'type': 'int'},
                'send-image-retry': {'v_range': [['7.2.6', '7.2.10'], ['7.4.4', '7.4.6'], ['7.6.2', '']], 'type': 'int'},
                'health-check': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-device-history': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'max-profile-history': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'retrieve': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'revision-diff': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_fmupdate_fwmsetting'),
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
