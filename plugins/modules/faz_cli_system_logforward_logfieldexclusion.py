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
module: faz_cli_system_logforward_logfieldexclusion
short_description: Log field exclusion configuration.
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
    log-forward:
        description: the parameter (log-forward) in requested url
        type: str
        required: true
    cli_system_logforward_logfieldexclusion:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            dev-type:
                type: str
                description:
                 - 'Device type.'
                 - 'FortiGate - FortiGate Device'
                 - 'FortiManager - FortiManager Device'
                 - 'Syslog - Syslog Device'
                 - 'FortiMail - FortiMail Device'
                 - 'FortiWeb - FortiWeb Device'
                 - 'FortiCache - FortiCache Device'
                 - 'FortiAnalyzer - FortiAnalyzer Device'
                 - 'FortiSandbox - FortiSandbox Device'
                 - 'FortiDDoS - FortiDDoS Device'
                 - 'FortiNAC - FortiNAC Device'
                 - 'FortiDeceptor - FortiDeceptor Device'
                choices:
                    - 'FortiGate'
                    - 'FortiManager'
                    - 'Syslog'
                    - 'FortiMail'
                    - 'FortiWeb'
                    - 'FortiCache'
                    - 'FortiAnalyzer'
                    - 'FortiSandbox'
                    - 'FortiDDoS'
                    - 'FortiNAC'
                    - 'FortiDeceptor'
                    - 'FortiFirewall'
                    - 'FortiADC'
                    - 'FortiClient'
                    - 'FortiAuthenticator'
                    - 'FortiProxy'
                    - 'FortiIsolator'
                    - 'FortiEDR'
                    - 'FortiPAM'
                    - 'FortiCASB'
                    - 'FortiToken'
            field-list:
                type: str
                description: 'List of fields to be excluded.'
            id:
                type: int
                description: 'Log field exclusion ID.'
            log-type:
                type: str
                description:
                 - 'Log type.'
                 - 'app-ctrl - Application Control'
                 - 'appevent - APPEVENT'
                 - 'attack - Attack'
                 - 'content - DLP Archive'
                 - 'dlp - Data Leak Prevention'
                 - 'emailfilter - Email Filter'
                 - 'event - Event'
                 - 'generic - Generic'
                 - 'history - Mail Statistics'
                 - 'traffic - Traffic'
                 - 'virus - Virus'
                 - 'voip - VoIP'
                 - 'webfilter - Web Filter'
                 - 'netscan - Network Scan'
                 - 'waf - WAF'
                 - 'gtp - GTP'
                 - 'dns - Domain Name System'
                 - 'ssh - SSH'
                 - 'ssl - SSL'
                 - 'file-filter - FFLT'
                 - 'Asset - Asset'
                 - 'protocol - PROTOCOL'
                 - 'ANY-TYPE - Any log type'
                choices:
                    - 'app-ctrl'
                    - 'appevent'
                    - 'attack'
                    - 'content'
                    - 'dlp'
                    - 'emailfilter'
                    - 'event'
                    - 'generic'
                    - 'history'
                    - 'traffic'
                    - 'virus'
                    - 'voip'
                    - 'webfilter'
                    - 'netscan'
                    - 'waf'
                    - 'gtp'
                    - 'dns'
                    - 'ssh'
                    - 'ssl'
                    - 'file-filter'
                    - 'Asset'
                    - 'protocol'
                    - 'ANY-TYPE'
                    - 'fct-event'
                    - 'fct-traffic'
                    - 'fct-netscan'
                    - 'ztna'
                    - 'security'

'''

EXAMPLES = '''
- collections:
    - fortinet.fortianalyzer
  connection: httpapi
  hosts: fortianalyzer_inventory
  tasks:
    - faz_cli_system_logforward_logfieldexclusion:
        cli_system_logforward_logfieldexclusion:
          dev-type: FortiGate
          field-list: dstepid
          id: 1
          log-type: app-ctrl
        log-forward: 1
        state: present
      name: Log field exclusion configuration.
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
        '/cli/global/system/log-forward/{log-forward}/log-field-exclusion'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log-forward/{log-forward}/log-field-exclusion/{log-field-exclusion}'
    ]

    url_params = ['log-forward']
    module_primary_key = 'id'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'log_path': {
            'type': 'str',
            'required': False,
            'default': '/tmp/fortianalyzer.ansible.log'
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
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'log-forward': {
            'required': True,
            'type': 'str'
        },
        'cli_system_logforward_logfieldexclusion': {
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
                '6.2.11': True,
                '6.2.12': True,
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
                '6.4.12': True,
                '6.4.13': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.0.8': True,
                '7.0.9': True,
                '7.0.10': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.2.3': True,
                '7.2.4': True,
                '7.4.0': True,
                '7.4.1': True
            },
            'options': {
                'dev-type': {
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
                        '6.2.11': True,
                        '6.2.12': True,
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
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.0.10': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'FortiGate',
                        'FortiManager',
                        'Syslog',
                        'FortiMail',
                        'FortiWeb',
                        'FortiCache',
                        'FortiAnalyzer',
                        'FortiSandbox',
                        'FortiDDoS',
                        'FortiNAC',
                        'FortiDeceptor',
                        'FortiFirewall',
                        'FortiADC',
                        'FortiClient',
                        'FortiAuthenticator',
                        'FortiProxy',
                        'FortiIsolator',
                        'FortiEDR',
                        'FortiPAM',
                        'FortiCASB',
                        'FortiToken'
                    ],
                    'type': 'str'
                },
                'field-list': {
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
                        '6.2.11': True,
                        '6.2.12': True,
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
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.0.10': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'id': {
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
                        '6.2.11': True,
                        '6.2.12': True,
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
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.0.10': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'log-type': {
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
                        '6.2.11': True,
                        '6.2.12': True,
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
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.0.10': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'app-ctrl',
                        'appevent',
                        'attack',
                        'content',
                        'dlp',
                        'emailfilter',
                        'event',
                        'generic',
                        'history',
                        'traffic',
                        'virus',
                        'voip',
                        'webfilter',
                        'netscan',
                        'waf',
                        'gtp',
                        'dns',
                        'ssh',
                        'ssl',
                        'file-filter',
                        'Asset',
                        'protocol',
                        'ANY-TYPE',
                        'fct-event',
                        'fct-traffic',
                        'fct-netscan',
                        'ztna',
                        'security'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    module = AnsibleModule(argument_spec=remove_revision(check_parameter_bypass(module_arg_spec, 'cli_system_logforward_logfieldexclusion')),
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
