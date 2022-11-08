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
module: faz_cli_system_mail
short_description: Alert emails.
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
    cli_system_mail:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auth:
                type: str
                default: 'disable'
                description:
                 - 'Enable authentication.'
                 - 'disable - Disable authentication.'
                 - 'enable - Enable authentication.'
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: str
                description: 'Mail Service ID.'
            passwd:
                description: no description
                type: str
            port:
                type: int
                default: 25
                description: 'SMTP server port.'
            secure-option:
                type: str
                default: 'default'
                description:
                 - 'Communication secure option.'
                 - 'default - Try STARTTLS, proceed as plain text communication otherwise.'
                 - 'none - Communication will be in plain text format.'
                 - 'smtps - Communication will be protected by SMTPS.'
                 - 'starttls - Communication will be protected by STARTTLS.'
                choices:
                    - 'default'
                    - 'none'
                    - 'smtps'
                    - 'starttls'
            server:
                type: str
                description: 'SMTP server.'
            user:
                type: str
                description: 'SMTP account username.'
            auth-type:
                type: str
                default: 'psk'
                description:
                 - 'SMTP authentication type.'
                 - 'psk - Use username and password to authenticate.'
                 - 'certificate - Use local certificate to authenticate.'
                choices:
                    - 'psk'
                    - 'certificate'
            local-cert:
                type: str
                description: 'SMTP local certificate.'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_mail:
       cli_system_mail:
         auth: disable
         id: 1
         passwd: foopasswd
         port: 443
         secure-option: default
         server: foo.bar.baz
         user: fooadmin
       state: present
     name: Alert emails.
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
        '/cli/global/system/mail'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/mail/{mail}'
    ]

    url_params = []
    module_primary_key = 'id'
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
        'cli_system_mail': {
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
                'auth': {
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
                'id': {
                    'required': True,
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
                'passwd': {
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
                'port': {
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
                'secure-option': {
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
                        'default',
                        'none',
                        'smtps',
                        'starttls'
                    ],
                    'type': 'str'
                },
                'server': {
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
                'user': {
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
                'auth-type': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'psk',
                        'certificate'
                    ],
                    'type': 'str'
                },
                'local-cert': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_mail'),
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
