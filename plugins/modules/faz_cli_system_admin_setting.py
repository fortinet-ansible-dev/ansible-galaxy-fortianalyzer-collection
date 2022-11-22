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
module: faz_cli_system_admin_setting
short_description: Admin setting.
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
    cli_system_admin_setting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            access-banner:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable access banner.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            admin-https-redirect:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable redirection of HTTP admin traffic to HTTPS.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            admin-login-max:
                type: int
                default: 256
                description: 'Maximum number admin users logged in at one time (1 - 256).'
            admin_server_cert:
                type: str
                default: 'server.crt'
                description: 'HTTPS & Web Service server certificate.'
            banner-message:
                type: str
                description: 'Banner message.'
            gui-theme:
                type: str
                default: 'blue'
                description:
                 - 'Color scheme to use for the administration GUI.'
                 - 'blue - Blueberry'
                 - 'green - Kiwi'
                 - 'red - Cherry'
                 - 'melongene - Plum'
                 - 'spring - Spring'
                 - 'summer - Summer'
                 - 'autumn - Autumn'
                 - 'winter - Winter'
                 - 'space - Space'
                 - 'calla-lily - Calla Lily'
                 - 'binary-tunnel - Binary Tunnel'
                 - 'diving - Diving'
                 - 'dreamy - Dreamy'
                 - 'technology - Technology'
                 - 'landscape - Landscape'
                 - 'twilight - Twilight'
                 - 'canyon - Canyon'
                 - 'northern-light - Northern Light'
                 - 'astronomy - Astronomy'
                 - 'fish - Fish'
                 - 'penguin - Penguin'
                 - 'panda - Panda'
                 - 'polar-bear - Polar Bear'
                 - 'parrot - Parrot'
                 - 'cave - Cave'
                choices:
                    - 'blue'
                    - 'green'
                    - 'red'
                    - 'melongene'
                    - 'spring'
                    - 'summer'
                    - 'autumn'
                    - 'winter'
                    - 'space'
                    - 'calla-lily'
                    - 'binary-tunnel'
                    - 'diving'
                    - 'dreamy'
                    - 'technology'
                    - 'landscape'
                    - 'twilight'
                    - 'canyon'
                    - 'northern-light'
                    - 'astronomy'
                    - 'fish'
                    - 'penguin'
                    - 'panda'
                    - 'polar-bear'
                    - 'parrot'
                    - 'cave'
                    - 'mountain'
                    - 'zebra'
                    - 'contrast-dark'
                    - 'circuit-board'
                    - 'mars'
                    - 'blue-sea'
            http_port:
                type: int
                default: 80
                description: 'HTTP port.'
            https_port:
                type: int
                default: 443
                description: 'HTTPS port.'
            idle_timeout:
                type: int
                default: 15
                description: 'Idle timeout (1 - 480 min).'
            objects-force-deletion:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable used objects force deletion.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            shell-access:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable shell access.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            shell-password:
                description: no description
                type: str
            show-add-multiple:
                type: str
                default: 'disable'
                description:
                 - 'Show add multiple button.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-checkbox-in-table:
                type: str
                default: 'disable'
                description:
                 - 'Show checkboxs in tables on GUI.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-device-import-export:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable import/export of ADOM, device, and group lists.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-fct-manager:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable FCT manager.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-hostname:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable hostname display in the GUI login page.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-log-forwarding:
                type: str
                default: 'enable'
                description:
                 - 'Show log forwarding tab in regular mode.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            unreg_dev_opt:
                type: str
                default: 'add_allow_service'
                description:
                 - 'Action to take when unregistered device connects to FortiAnalyzer.'
                 - 'add_no_service - Add unregistered devices but deny service requests.'
                 - 'ignore - Ignore unregistered devices.'
                 - 'add_allow_service - Add unregistered devices and allow service requests.'
                choices:
                    - 'add_no_service'
                    - 'ignore'
                    - 'add_allow_service'
            webadmin_language:
                type: str
                default: 'auto_detect'
                description:
                 - 'Web admin language.'
                 - 'auto_detect - Automatically detect language.'
                 - 'english - English.'
                 - 'simplified_chinese - Simplified Chinese.'
                 - 'traditional_chinese - Traditional Chinese.'
                 - 'japanese - Japanese.'
                 - 'korean - Korean.'
                 - 'spanish - Spanish.'
                choices:
                    - 'auto_detect'
                    - 'english'
                    - 'simplified_chinese'
                    - 'traditional_chinese'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'french'
            idle_timeout_api:
                type: int
                default: 900
                description: 'Idle timeout for API sessions (1 - 28800 sec).'
            idle_timeout_gui:
                type: int
                default: 900
                description: 'Idle timeout for GUI sessions (60 - 28800 sec).'
            auth-addr:
                type: str
                description: 'IP which is used by FGT to authorize FAZ.'
            auth-port:
                type: int
                default: 443
                description: 'Port which is used by FGT to authorize FAZ.'
            idle_timeout_sso:
                type: int
                default: 900
                description: 'Idle timeout for SSO sessions (60 - 28800 sec).'
            preferred-fgfm-intf:
                type: str
                description: 'Preferred interface for FGFM connection.'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_admin_setting:
       cli_system_admin_setting:
         access-banner: disable
         admin-https-redirect: disable
         objects-force-deletion: disable
         shell-access: disable
         show-add-multiple: disable
         show-checkbox-in-table: disable
         show-device-import-export: disable
         show-fct-manager: disable
         show-hostname: disable
         show-log-forwarding: disable
     name: Admin setting.
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
        '/cli/global/system/admin/setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/setting/{setting}'
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
        'cli_system_admin_setting': {
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
                'access-banner': {
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
                'admin-https-redirect': {
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
                'admin-login-max': {
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
                'admin_server_cert': {
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
                'banner-message': {
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
                'gui-theme': {
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
                        'blue',
                        'green',
                        'red',
                        'melongene',
                        'spring',
                        'summer',
                        'autumn',
                        'winter',
                        'space',
                        'calla-lily',
                        'binary-tunnel',
                        'diving',
                        'dreamy',
                        'technology',
                        'landscape',
                        'twilight',
                        'canyon',
                        'northern-light',
                        'astronomy',
                        'fish',
                        'penguin',
                        'panda',
                        'polar-bear',
                        'parrot',
                        'cave',
                        'mountain',
                        'zebra',
                        'contrast-dark',
                        'circuit-board',
                        'mars',
                        'blue-sea'
                    ],
                    'type': 'str'
                },
                'http_port': {
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
                'https_port': {
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
                'idle_timeout': {
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
                'objects-force-deletion': {
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
                'shell-access': {
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
                'shell-password': {
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
                'show-add-multiple': {
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
                'show-checkbox-in-table': {
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
                'show-device-import-export': {
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
                'show-fct-manager': {
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
                'show-hostname': {
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
                'show-log-forwarding': {
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
                'unreg_dev_opt': {
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
                        'add_no_service',
                        'ignore',
                        'add_allow_service'
                    ],
                    'type': 'str'
                },
                'webadmin_language': {
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
                        'auto_detect',
                        'english',
                        'simplified_chinese',
                        'traditional_chinese',
                        'japanese',
                        'korean',
                        'spanish',
                        'french'
                    ],
                    'type': 'str'
                },
                'idle_timeout_api': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'idle_timeout_gui': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'auth-addr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'auth-port': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'idle_timeout_sso': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'preferred-fgfm-intf': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_admin_setting'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
