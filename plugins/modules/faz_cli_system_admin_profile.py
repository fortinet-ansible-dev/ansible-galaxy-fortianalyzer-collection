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
    cli_system_admin_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom-lock:
                type: str
                description:
                 - 'ADOM locking'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            adom-switch:
                type: str
                description:
                 - 'Administrator domain.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            allow-to-install:
                type: str
                description:
                 - 'Enable/disable the restricted user to install objects to the devices.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            change-password:
                type: str
                description:
                 - 'Enable/disable the user to change self password.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask:
                type: str
                description:
                 - 'Enable/disable data masking.'
                 - 'disable - Disable data masking.'
                 - 'enable - Enable data masking.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-custom-fields:
                description: no description
                type: list
                elements: dict
                suboptions:
                    field-category:
                        description: no description
                        type: list
                        elements: str
                        choices:
                            - 'log'
                            - 'fortiview'
                            - 'alert'
                            - 'ueba'
                            - 'all'
                    field-name:
                        type: str
                        description: 'Field name.'
                    field-status:
                        type: str
                        description:
                         - 'Field status.'
                         - 'disable - Disable field.'
                         - 'enable - Enable field.'
                        choices:
                            - 'disable'
                            - 'enable'
                    field-type:
                        type: str
                        description:
                         - 'Field type.'
                         - 'string - String.'
                         - 'ip - IP.'
                         - 'mac - MAC address.'
                         - 'email - Email address.'
                         - 'unknown - Unknown.'
                        choices:
                            - 'string'
                            - 'ip'
                            - 'mac'
                            - 'email'
                            - 'unknown'
            datamask-custom-priority:
                type: str
                description:
                 - 'Prioritize custom fields.'
                 - 'disable - Disable custom field search priority.'
                 - 'enable - Enable custom field search priority.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-fields:
                description: no description
                type: list
                elements: str
                choices:
                    - 'user'
                    - 'srcip'
                    - 'srcname'
                    - 'srcmac'
                    - 'dstip'
                    - 'dstname'
                    - 'email'
                    - 'message'
                    - 'domain'
            datamask-key:
                description: no description
                type: str
            datamask-unmasked-time:
                type: int
                description: 'Time in days without data masking.'
            description:
                type: str
                description: 'Description.'
            device-ap:
                type: str
                description:
                 - 'Manage AP.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-forticlient:
                type: str
                description:
                 - 'Manage FortiClient.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-fortiswitch:
                type: str
                description:
                 - 'Manage FortiSwitch.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-manager:
                type: str
                description:
                 - 'Device manager.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-op:
                type: str
                description:
                 - 'Device add/delete/edit.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-policy-package-lock:
                type: str
                description:
                 - 'Device/Policy Package locking'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-wan-link-load-balance:
                type: str
                description:
                 - 'Manage WAN link load balance.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            event-management:
                type: str
                description:
                 - 'Event management.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fortirecorder-setting:
                type: str
                description:
                 - 'FortiRecorder settings.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            log-viewer:
                type: str
                description:
                 - 'Log viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            profileid:
                type: str
                description: 'Profile ID.'
            realtime-monitor:
                type: str
                description:
                 - 'Realtime monitor.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            report-viewer:
                type: str
                description:
                 - 'Report viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            scope:
                type: str
                description:
                 - 'Scope.'
                 - 'global - Global scope.'
                 - 'adom - ADOM scope.'
                choices:
                    - 'global'
                    - 'adom'
            super-user-profile:
                type: str
                description:
                 - 'Enable/disable super user profile'
                 - 'disable - Disable super user profile'
                 - 'enable - Enable super user profile'
                choices:
                    - 'disable'
                    - 'enable'
            system-setting:
                type: str
                description:
                 - 'System setting.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fabric-viewer:
                type: str
                description:
                 - 'Fabric viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            execute-playbook:
                type: str
                description:
                 - 'Execute playbook.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            extension-access:
                type: str
                description:
                 - 'Manage extension access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            run-report:
                type: str
                description:
                 - 'Run reports.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            script-access:
                type: str
                description:
                 - 'Script access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            triage-events:
                type: str
                description:
                 - 'Triage events.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            update-incidents:
                type: str
                description:
                 - 'Create/update incidents.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips-baseline-ovrd:
                type: str
                description:
                 - 'Enable/disable override baseline ips sensor.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
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
            rpc-permit:
                type: str
                description:
                 - 'Set none/read/read-write rpc-permission'
                 - 'read-write - Read-write permission.'
                 - 'none - No permission.'
                 - 'read - Read-only permission.'
                choices:
                    - 'read-write'
                    - 'none'
                    - 'read'
            trusthost1:
                type: str
                description: 'Admin user trusted host IP, default 0.0.0.0 0.0.0.0 for all.'
            trusthost10:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost2:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost3:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost4:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost5:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost6:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost7:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost8:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost9:
                type: str
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            device-fortiextender:
                type: str
                description:
                 - 'Manage FortiExtender.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips-lock:
                type: str
                description:
                 - 'IPS locking'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgt-gui-proxy:
                type: str
                description:
                 - 'FortiGate GUI proxy.'
                 - 'disable - No permission.'
                 - 'enable - With permission.'
                choices:
                    - 'disable'
                    - 'enable'
            write-passwd-access:
                type: str
                description:
                 - 'set all/specify-by-user/specify-by-profile write password access mode.'
                 - 'all - All except super users.'
                 - 'specify-by-user - Specify by user.'
                 - 'specify-by-profile - Specify by profile.'
                choices:
                    - 'all'
                    - 'specify-by-user'
                    - 'specify-by-profile'
            write-passwd-profiles:
                description: no description
                type: list
                elements: dict
                suboptions:
                    profileid:
                        type: str
                        description: 'Profile ID.'
            write-passwd-user-list:
                description: no description
                type: list
                elements: dict
                suboptions:
                    userid:
                        type: str
                        description: 'User ID.'
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
        '/cli/global/system/admin/profile'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/profile/{profile}'
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
        'state': {'type': 'str', 'required': True, 'choices': ['present', 'absent']},
        'cli_system_admin_profile': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'adom-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'adom-switch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'allow-to-install': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'change-password': {'choices': ['disable', 'enable'], 'no_log': True, 'type': 'str'},
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
                'device-forticlient': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-fortiswitch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-manager': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-op': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-policy-package-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-wan-link-load-balance': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'event-management': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fortirecorder-setting': {'v_range': [['6.2.1', '7.2.4']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'log-viewer': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'profileid': {'type': 'str'},
                'realtime-monitor': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
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
                'device-fortiextender': {'v_range': [['7.0.4', '7.0.11'], ['7.2.1', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-lock': {'v_range': [['7.2.2', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgt-gui-proxy': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'write-passwd-access': {
                    'v_range': [['7.4.2', '']],
                    'choices': ['all', 'specify-by-user', 'specify-by-profile'],
                    'no_log': True,
                    'type': 'str'
                },
                'write-passwd-profiles': {
                    'v_range': [['7.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {'profileid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'write-passwd-user-list': {
                    'v_range': [['7.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {'userid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_profile'),
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
