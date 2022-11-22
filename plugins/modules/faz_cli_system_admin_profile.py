#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021 Fortinet, Inc.
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

version_added: "2.11"
author:
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    cli_system_admin_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom-lock:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'enable'
                description:
                 - 'Enable/disable the restricted user to install objects to the devices.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            change-password:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable the user to change self password.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask:
                type: str
                default: 'disable'
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
                suboptions:
                    field-category:
                        description: no description
                        type: list
                        choices:
                         - log
                         - fortiview
                         - alert
                         - ueba
                         - all
                    field-name:
                        type: str
                        description: 'Field name.'
                    field-status:
                        type: str
                        default: 'enable'
                        description:
                         - 'Field status.'
                         - 'disable - Disable field.'
                         - 'enable - Enable field.'
                        choices:
                            - 'disable'
                            - 'enable'
                    field-type:
                        type: str
                        default: 'string'
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
                default: 'disable'
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
                choices:
                 - user
                 - srcip
                 - srcname
                 - srcmac
                 - dstip
                 - dstname
                 - email
                 - message
                 - domain
            datamask-key:
                description: no description
                type: str
            datamask-unmasked-time:
                type: int
                default: 0
                description: 'Time in days without data masking.'
            description:
                type: str
                description: 'Description.'
            device-ap:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'global'
                description:
                 - 'Scope.'
                 - 'global - Global scope.'
                 - 'adom - ADOM scope.'
                choices:
                    - 'global'
                    - 'adom'
            super-user-profile:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable super user profile'
                 - 'disable - Disable super user profile'
                 - 'enable - Enable super user profile'
                choices:
                    - 'disable'
                    - 'enable'
            system-setting:
                type: str
                default: 'none'
                description:
                 - 'System setting.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            execute-playbook:
                type: str
                default: 'none'
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
                default: 'none'
                description:
                 - 'Manage extension access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fabric-viewer:
                type: str
                default: 'none'
                description:
                 - 'Fabric viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            run-report:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
                description:
                 - 'Create/update incidents.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ipv6_trusthost1:
                type: str
                default: '::/0'
                description: 'Admin user trusted host IPv6, default ::/0 for all.'
            ipv6_trusthost10:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost2:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost3:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost4:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost5:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost6:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost7:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost8:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost9:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            rpc-permit:
                type: str
                default: 'none'
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
                default: '0.0.0.0 0.0.0.0'
                description: 'Admin user trusted host IP, default 0.0.0.0 0.0.0.0 for all.'
            trusthost10:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost2:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost3:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost4:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost5:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost6:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost7:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost8:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost9:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_admin_profile:
       cli_system_admin_profile:
         allow-to-install: disable
         change-password: disable
         datamask: disable
         profileid: 1
       state: present
     name: Admin profile.
   vars:
     ansible_httpapi_port: 443
     ansible_httpapi_use_ssl: true
     ansible_httpapi_validate_certs: false

'''

RETURN = '''
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
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass


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
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'cli_system_admin_profile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'adom-lock': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'adom-switch': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'allow-to-install': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.2.6': False,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'change-password': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-custom-fields': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'field-category': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'log',
                                'fortiview',
                                'alert',
                                'ueba',
                                'all'
                            ]
                        },
                        'field-name': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'field-status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'field-type': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'string',
                                'ip',
                                'mac',
                                'email',
                                'unknown'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'datamask-custom-priority': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-fields': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'user',
                        'srcip',
                        'srcname',
                        'srcmac',
                        'dstip',
                        'dstname',
                        'email',
                        'message',
                        'domain'
                    ]
                },
                'datamask-key': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'datamask-unmasked-time': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'description': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'device-ap': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-forticlient': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-fortiswitch': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-manager': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-op': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-policy-package-lock': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-wan-link-load-balance': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'event-management': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fortirecorder-setting': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'log-viewer': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'profileid': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'realtime-monitor': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'report-viewer': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'scope': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'global',
                        'adom'
                    ],
                    'type': 'str'
                },
                'super-user-profile': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'system-setting': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'execute-playbook': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'extension-access': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fabric-viewer': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'run-report': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'script-access': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'triage-events': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'update-incidents': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'ipv6_trusthost1': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost10': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost2': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost3': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost4': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost5': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost7': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost8': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost9': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'rpc-permit': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'read-write',
                        'none',
                        'read'
                    ],
                    'type': 'str'
                },
                'trusthost1': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost10': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost2': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost3': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost4': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost5': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost7': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost8': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'trusthost9': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_admin_profile'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
