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
module: faz_cli_system_admin_profile
short_description: Admin profile.
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
    cli_system_admin_profile:
        description: The top level parameters set.
        type: dict
        suboptions:
            adom_lock:
                aliases: ['adom-lock']
                type: str
                description:
                 - ADOM locking
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            adom_switch:
                aliases: ['adom-switch']
                type: str
                description:
                 - Administrator domain.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            allow_to_install:
                aliases: ['allow-to-install']
                type: str
                description:
                 - Enable/disable the restricted user to install objects to the devices.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            change_password:
                aliases: ['change-password']
                type: str
                description:
                 - Enable/disable the user to change self password.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            datamask:
                type: str
                description:
                 - Enable/disable data masking.
                 - disable - Disable data masking.
                 - enable - Enable data masking.
                choices: ['disable', 'enable']
            datamask_custom_fields:
                aliases: ['datamask-custom-fields']
                description: no description
                type: list
                elements: dict
                suboptions:
                    field_category:
                        aliases: ['field-category']
                        description:
                         - Field categories.
                         - log - Log.
                         - fortiview - FortiView.
                         - alert - Event management.
                         - ueba - UEBA.
                         - all - All.
                        type: list
                        elements: str
                        choices: ['log', 'fortiview', 'alert', 'ueba', 'all']
                    field_name:
                        aliases: ['field-name']
                        type: str
                        description: Field name.
                    field_status:
                        aliases: ['field-status']
                        type: str
                        description:
                         - Field status.
                         - disable - Disable field.
                         - enable - Enable field.
                        choices: ['disable', 'enable']
                    field_type:
                        aliases: ['field-type']
                        type: str
                        description:
                         - Field type.
                         - string - String.
                         - ip - IP.
                         - mac - MAC address.
                         - email - Email address.
                         - unknown - Unknown.
                        choices: ['string', 'ip', 'mac', 'email', 'unknown']
            datamask_custom_priority:
                aliases: ['datamask-custom-priority']
                type: str
                description:
                 - Prioritize custom fields.
                 - disable - Disable custom field search priority.
                 - enable - Enable custom field search priority.
                choices: ['disable', 'enable']
            datamask_fields:
                aliases: ['datamask-fields']
                description:
                 - Data masking fields.
                 - user - User name.
                 - srcip - Source IP.
                 - srcname - Source name.
                 - srcmac - Source MAC.
                 - dstip - Destination IP.
                 - dstname - Dst name.
                 - email - Email.
                 - message - Message.
                 - domain - Domain.
                type: list
                elements: str
                choices: ['user', 'srcip', 'srcname', 'srcmac', 'dstip', 'dstname', 'email', 'message', 'domain']
            datamask_key:
                aliases: ['datamask-key']
                description: Data masking encryption key.
                type: str
            datamask_unmasked_time:
                aliases: ['datamask-unmasked-time']
                type: int
                description: Time in days without data masking.
            description:
                type: str
                description: Description.
            device_ap:
                aliases: ['device-ap']
                type: str
                description:
                 - Manage AP.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_forticlient:
                aliases: ['device-forticlient']
                type: str
                description:
                 - Manage FortiClient.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_fortiswitch:
                aliases: ['device-fortiswitch']
                type: str
                description:
                 - Manage FortiSwitch.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_manager:
                aliases: ['device-manager']
                type: str
                description:
                 - Device manager.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_op:
                aliases: ['device-op']
                type: str
                description:
                 - Device add/delete/edit.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_policy_package_lock:
                aliases: ['device-policy-package-lock']
                type: str
                description:
                 - Device/Policy Package locking
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            device_wan_link_load_balance:
                aliases: ['device-wan-link-load-balance']
                type: str
                description:
                 - Manage WAN link load balance.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            event_management:
                aliases: ['event-management']
                type: str
                description:
                 - Event management.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            fortirecorder_setting:
                aliases: ['fortirecorder-setting']
                type: str
                description:
                 - FortiRecorder settings.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            log_viewer:
                aliases: ['log-viewer']
                type: str
                description:
                 - Log viewer.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            profileid:
                type: str
                description: Profile ID.
            realtime_monitor:
                aliases: ['realtime-monitor']
                type: str
                description:
                 - Realtime monitor.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            report_viewer:
                aliases: ['report-viewer']
                type: str
                description:
                 - Report viewer.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            scope:
                type: str
                description:
                 - Scope.
                 - global - Global scope.
                 - adom - ADOM scope.
                choices: ['global', 'adom']
            super_user_profile:
                aliases: ['super-user-profile']
                type: str
                description:
                 - Enable/disable super user profile
                 - disable - Disable super user profile
                 - enable - Enable super user profile
                choices: ['disable', 'enable']
            system_setting:
                aliases: ['system-setting']
                type: str
                description:
                 - System setting.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            fabric_viewer:
                aliases: ['fabric-viewer']
                type: str
                description:
                 - Fabric viewer.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            execute_playbook:
                aliases: ['execute-playbook']
                type: str
                description:
                 - Execute playbook.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            extension_access:
                aliases: ['extension-access']
                type: str
                description:
                 - Manage extension access.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            run_report:
                aliases: ['run-report']
                type: str
                description:
                 - Run reports.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            script_access:
                aliases: ['script-access']
                type: str
                description:
                 - Script access.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            triage_events:
                aliases: ['triage-events']
                type: str
                description:
                 - Triage events.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            update_incidents:
                aliases: ['update-incidents']
                type: str
                description:
                 - Create/update incidents.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            ips_baseline_ovrd:
                aliases: ['ips-baseline-ovrd']
                type: str
                description:
                 - Enable/disable override baseline ips sensor.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            ipv6_trusthost1:
                type: str
                description: 'Admin user trusted host IPv6, default ::/0 for all.'
            ipv6_trusthost10:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost2:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost3:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost4:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost5:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost6:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost7:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost8:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost9:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            rpc_permit:
                aliases: ['rpc-permit']
                type: str
                description:
                 - Set none/read/read-write rpc-permission
                 - read-write - Read-write permission.
                 - none - No permission.
                 - read - Read-only permission.
                choices: ['read-write', 'none', 'read']
            trusthost1:
                type: str
                description: Admin user trusted host IP, default 0.0.0.0 0.0.0.0 for all.
            trusthost10:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost2:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost3:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost4:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost5:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost6:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost7:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost8:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost9:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            device_fortiextender:
                aliases: ['device-fortiextender']
                type: str
                description:
                 - Manage FortiExtender.
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            ips_lock:
                aliases: ['ips-lock']
                type: str
                description:
                 - IPS locking
                 - none - No permission.
                 - read - Read permission.
                 - read-write - Read-write permission.
                choices: ['none', 'read', 'read-write']
            fgt_gui_proxy:
                aliases: ['fgt-gui-proxy']
                type: str
                description:
                 - FortiGate GUI proxy.
                 - disable - No permission.
                 - enable - With permission.
                choices: ['disable', 'enable']
            write_passwd_access:
                aliases: ['write-passwd-access']
                type: str
                description:
                 - set all/specify-by-user/specify-by-profile write password access mode.
                 - all - All except super users.
                 - specify-by-user - Specify by user.
                 - specify-by-profile - Specify by profile.
                choices: ['all', 'specify-by-user', 'specify-by-profile']
            write_passwd_profiles:
                aliases: ['write-passwd-profiles']
                description: no description
                type: list
                elements: dict
                suboptions:
                    profileid:
                        type: str
                        description: Profile ID.
            write_passwd_user_list:
                aliases: ['write-passwd-user-list']
                description: no description
                type: list
                elements: dict
                suboptions:
                    userid:
                        type: str
                        description: User ID.
            adom_admin:
                aliases: ['adom-admin']
                type: str
                description:
                 - Enable Adom Admin.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Admin profile.
      fortinet.fortianalyzer.faz_cli_system_admin_profile:
        cli_system_admin_profile:
          allow_to_install: disable
          change_password: disable
          datamask: disable
          profileid: 1
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
        '/cli/global/system/admin/profile'
    ]

    url_params = []
    module_primary_key = 'profileid'
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
        'cli_system_admin_profile': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'adom-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'adom-switch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'allow-to-install': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'change-password': {'choices': ['disable', 'enable'], 'no_log': False, 'type': 'str'},
                'datamask': {'choices': ['disable', 'enable'], 'type': 'str'},
                'datamask-custom-fields': {
                    'type': 'list',
                    'options': {
                        'field-category': {'type': 'list', 'choices': ['log', 'fortiview', 'alert', 'ueba', 'all'], 'elements': 'str'},
                        'field-name': {'type': 'str'},
                        'field-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'field-type': {'choices': ['string', 'ip', 'mac', 'email', 'unknown'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'datamask-custom-priority': {'choices': ['disable', 'enable'], 'type': 'str'},
                'datamask-fields': {
                    'type': 'list',
                    'choices': ['user', 'srcip', 'srcname', 'srcmac', 'dstip', 'dstname', 'email', 'message', 'domain'],
                    'elements': 'str'
                },
                'datamask-key': {'no_log': True, 'type': 'str'},
                'datamask-unmasked-time': {'type': 'int'},
                'description': {'type': 'str'},
                'device-ap': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-forticlient': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-fortiswitch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-manager': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-op': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-policy-package-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-wan-link-load-balance': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'event-management': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fortirecorder-setting': {'v_range': [['6.2.1', '7.2.10']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'log-viewer': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'profileid': {'type': 'str'},
                'realtime-monitor': {'v_range': [['6.2.1', '7.4.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'report-viewer': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'scope': {'choices': ['global', 'adom'], 'type': 'str'},
                'super-user-profile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'system-setting': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fabric-viewer': {'v_range': [['6.4.6', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'execute-playbook': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'extension-access': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'run-report': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'script-access': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'triage-events': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'update-incidents': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-baseline-ovrd': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6_trusthost1': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost10': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost2': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost3': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost4': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost5': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost6': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost7': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost8': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost9': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'rpc-permit': {'v_range': [['7.0.3', '']], 'choices': ['read-write', 'none', 'read'], 'type': 'str'},
                'trusthost1': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost10': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost2': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost3': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost4': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost5': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost6': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost7': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost8': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost9': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'device-fortiextender': {'v_range': [['7.0.4', '7.0.13'], ['7.2.1', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-lock': {'v_range': [['7.2.2', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgt-gui-proxy': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'write-passwd-access': {
                    'v_range': [['7.4.2', '']],
                    'choices': ['all', 'specify-by-user', 'specify-by-profile'],
                    'no_log': False,
                    'type': 'str'
                },
                'write-passwd-profiles': {
                    'v_range': [['7.4.2', '']],
                    'no_log': False,
                    'type': 'list',
                    'options': {'profileid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'write-passwd-user-list': {
                    'v_range': [['7.4.2', '']],
                    'no_log': False,
                    'type': 'list',
                    'options': {'userid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'adom-admin': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_profile'),
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
