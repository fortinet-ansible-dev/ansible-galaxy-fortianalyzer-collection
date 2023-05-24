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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        required: false
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
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
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        type: str
        required: false
        choices:
            - set
            - update
            - add
    cli_fmupdate_fwmsetting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auto-scan-fgt-disk:
                type: str
                description:
                 - 'auto scan fgt disk if needed.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            check-fgt-disk:
                type: str
                description:
                 - 'check fgt disk before upgrade image.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            fds-failover-fmg:
                type: str
                description:
                 - 'using fmg local image file is download from fds fails.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            fds-image-timeout:
                type: int
                description: 'timer for fgt download image from fortiguard (300-3600s default=1800)'
            multiple-steps-interval:
                type: int
                description: 'waiting time between multiple steps upgrade (30-180s, default=60)'
            max-fds-retry:
                type: int
                description: 'The retries when fgt download from fds fail (5-20, default=10)'
            skip-disk-check:
                type: str
                description:
                 - 'skip disk check when upgrade image.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            immx-source:
                type: str
                description:
                 - 'Configure which of IMMX file to be used for choosing upgrade pach. Default is file for FortiManager'
                 - 'fmg - Use IMMX file for FortiManager'
                 - 'fgt - Use IMMX file for FortiGate'
                 - 'cloud - Use IMMX file for FortiCloud'
                choices:
                    - 'fmg'
                    - 'fgt'
                    - 'cloud'
            log:
                type: str
                description:
                 - 'Configure log setting for fwm daemon'
                 - 'fwm - FWM daemon log'
                 - 'fwm_dm - FWM and Deployment service log'
                 - 'fwm_dm_json - FWM and Deployment service log with JSON data between FMG-FGT'
                choices:
                    - 'fwm'
                    - 'fwm_dm'
                    - 'fwm_dm_json'
            upgrade-timeout:
                description: no description
                type: dict
                required: false
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

'''

EXAMPLES = '''
- collections:
    - fortinet.fortianalyzer
  connection: httpapi
  hosts: fortianalyzer_inventory
  tasks:
    - faz_cli_fmupdate_fwmsetting:
        cli_fmupdate_fwmsetting:
          auto-scan-fgt-disk: disable
          check-fgt-disk: disable
          fds-failover-fmg: disable
          #fds-image-timeout: <value of integer>
          #immx-source: <value in [fmg, fgt, cloud]>
          #max-fds-retry: <value of integer>
          #multiple-steps-interval: <value of integer>
          #skip-disk-check: disable
      name: Configure firmware management settings.
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
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass, remove_revision


def main():
    jrpc_urls = [
        '/cli/global/fmupdate/fwm-setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/fwm-setting/{fwm-setting}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'log_path': {
            'type': 'str',
            'required': False,
            'default': '/tmp/fortianalyzer.ansible.log'
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
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
        'cli_fmupdate_fwmsetting': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True
            },
            'options': {
                'auto-scan-fgt-disk': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'check-fgt-disk': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fds-failover-fmg': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fds-image-timeout': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'int'
                },
                'multiple-steps-interval': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'type': 'int'
                },
                'max-fds-retry': {
                    'required': False,
                    'revision': {
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.2': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.5': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.0': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.0': False,
                        '7.2.1': False,
                        '7.2.2': False
                    },
                    'type': 'int'
                },
                'skip-disk-check': {
                    'required': False,
                    'revision': {
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.2': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.5': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.0': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.0': False,
                        '7.2.1': False,
                        '7.2.2': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'immx-source': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'fmg',
                        'fgt',
                        'cloud'
                    ],
                    'type': 'str'
                },
                'log': {
                    'required': False,
                    'revision': {
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.0': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True
                    },
                    'choices': [
                        'fwm',
                        'fwm_dm',
                        'fwm_dm_json'
                    ],
                    'type': 'str'
                },
                'upgrade-timeout': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'check-status-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'ctrl-check-status-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'ctrl-put-image-by-fds-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'ha-sync-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'license-check-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'prepare-image-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'put-image-by-fds-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'put-image-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'reboot-of-fsck-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'reboot-of-upgrade-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'retrieve-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'rpc-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        },
                        'total-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.0': False,
                                '7.2.1': False,
                                '7.2.2': True
                            },
                            'type': 'int'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=remove_revision(check_parameter_bypass(module_arg_spec, 'cli_fmupdate_fwmsetting')),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='partial crud')
    faz.validate_parameters(params_validation_blob)
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
