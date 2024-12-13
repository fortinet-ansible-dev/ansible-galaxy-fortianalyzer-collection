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
module: faz_eventmgmt_config_trigger
short_description: trigger
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode and diff mode.
version_added: "1.8.0"
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    eventmgmt_config_trigger:
        description: The top level parameters set.
        type: dict
        suboptions:
            address_filter:
                aliases: ['address-filter']
                description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/address-filter'
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: no description
                    include_option:
                        aliases: ['include-option']
                        type: raw
                        description: no description
                    address_type:
                        aliases: ['address-type']
                        type: str
                        description: no description
                        choices: ['address-group', 'address-obj']
                    grp_name:
                        aliases: ['grp-name']
                        type: str
                        description: no description
                    obj_name:
                        aliases: ['obj-name']
                        type: str
                        description: no description
            device:
                description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/device'
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: no description
                    name:
                        type: str
                        description: no description
                    type:
                        type: raw
                        description: no description
                    vdom:
                        type: str
                        description: no description
            fabric_connector:
                aliases: ['fabric-connector']
                description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/fabric-connector'
                type: list
                elements: dict
                suboptions:
                    refid:
                        type: str
                        description: no description
            filter:
                description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/filter'
                type: list
                elements: dict
                suboptions:
                    dev_type:
                        aliases: ['dev-type']
                        type: raw
                        description: no description
                    id:
                        type: int
                        description: no description
                    rule:
                        description: 'reference: /eventmgmt/adom/<adom-name>/config/trigger/<trigger_id>/filter/<filter_id>/rule'
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: no description
                            key:
                                type: str
                                description: no description
                            value:
                                type: str
                                description: no description
                            value_type:
                                aliases: ['value-type']
                                type: int
                                description: no description
                            oper:
                                type: str
                                description: no description
                                choices:
                                    - 'less-than'
                                    - 'not-contain'
                                    - 'less-or-equal'
                                    - 'equal'
                                    - 'great-or-equal'
                                    - 'not-equal'
                                    - 'contain'
                                    - 'great-than'
                    subject:
                        type: str
                        description: no description
                    tag:
                        type: str
                        description: no description
                    enable:
                        type: str
                        description: no description
                        choices: ['enable', 'disable']
                    eventstatus:
                        type: str
                        description: no description
                    eventtype:
                        type: str
                        description: no description
                    extrainfo:
                        type: str
                        description: no description
                    extrainfo_type:
                        aliases: ['extrainfo-type']
                        type: str
                        description: no description
                        choices: ['default', 'custom']
                    filter_expr:
                        aliases: ['filter-expr']
                        type: str
                        description: no description
                    groupby1:
                        type: str
                        description: no description
                    groupby2:
                        type: str
                        description: no description
                    logtype:
                        type: str
                        description: no description
                    rule_relation:
                        aliases: ['rule-relation']
                        type: int
                        description: no description
                    severity:
                        type: str
                        description: no description
                        choices: ['high', 'medium', 'critical', 'low']
                    thres_count:
                        aliases: ['thres-count']
                        type: int
                        description: no description
                    thres_duration:
                        aliases: ['thres-duration']
                        type: int
                        description: no description
                    utmevent:
                        type: str
                        description: no description
                    indicator:
                        description: 'reference: /log-alert/trigger/filter/indicator'
                        type: list
                        elements: dict
                        suboptions:
                            count:
                                type: int
                                description: no description
                            name:
                                type: str
                                description: no description
                            type:
                                type: str
                                description: no description
            id:
                type: int
                description: no description
            name:
                type: str
                description: no description
            uuid:
                type: str
                description: no description
            version:
                type: int
                description: no description
            creation_time:
                aliases: ['creation-time']
                type: int
                description: no description
            description:
                type: str
                description: no description
            device_specify:
                aliases: ['device-specify']
                type: str
                description: no description
                choices: ['all-devices', 'specify', 'local-host']
            email_from:
                aliases: ['email-from']
                type: str
                description: no description
            email_html_format:
                aliases: ['email-html-format']
                type: int
                description: no description
            email_subject:
                aliases: ['email-subject']
                type: str
                description: no description
            email_svr:
                aliases: ['email-svr']
                type: str
                description: no description
            email_to:
                aliases: ['email-to']
                type: str
                description: no description
            enable:
                type: str
                description: no description
                choices: ['enable', 'disable']
            enable_time:
                aliases: ['enable-time']
                type: int
                description: no description
            filter_relation:
                aliases: ['filter-relation']
                type: int
                description: no description
            handlertype:
                type: str
                description: no description
                choices: ['handler-type-local', 'handler-type-remote']
            protected:
                type: str
                description: no description
                choices: ['enable', 'disable']
            snmp_community:
                aliases: ['snmp-community']
                type: str
                description: no description
            snmpv3_user:
                aliases: ['snmpv3-user']
                type: str
                description: no description
            syslog_svr:
                aliases: ['syslog-svr']
                type: str
                description: no description
            target_enable:
                aliases: ['target-enable']
                type: int
                description: no description
            template_url:
                aliases: ['template-url']
                type: str
                description: no description
            update_time:
                aliases: ['update-time']
                type: int
                description: no description
            content_pack_id:
                aliases: ['content-pack-id']
                type: str
                description: no description
            content_pack_uuid:
                aliases: ['content-pack-uuid']
                type: str
                description: no description
            pre_filter:
                aliases: ['pre-filter']
                description: 'reference: /log-alert/trigger/pre-filter'
                type: list
                elements: dict
                suboptions:
                    dev_type:
                        aliases: ['dev-type']
                        type: raw
                        description: no description
                    id:
                        type: int
                        description: no description
                    rule:
                        description: 'reference: /log-alert/trigger/pre-filter/rule'
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: no description
                            key:
                                type: str
                                description: no description
                            value:
                                type: str
                                description: no description
                            value_type:
                                aliases: ['value-type']
                                type: int
                                description: no description
                    subject:
                        type: str
                        description: no description
                    tag:
                        type: str
                        description: no description
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    ansible_network_os: fortinet.fortianalyzer.fortianalyzer
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
  tasks:
    - name: trigger
      fortinet.fortianalyzer.faz_eventmgmt_config_trigger:
        # bypass_validation: false
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        eventmgmt_config_trigger:
          address_filter:
            - id: <value of integer>
              include_option: <any type of data>
              address_type: <value in [address-group, address-obj]>
              grp_name: <value of string>
              obj_name: <value of string>
          device:
            - id: <value of integer>
              name: <value of string>
              type: <any type of data>
              vdom: <value of string>
          fabric_connector:
            - refid: <value of string>
          filter:
            - dev_type: <any type of data>
              id: <value of integer>
              rule:
                - id: <value of integer>
                  key: <value of string>
                  value: <value of string>
                  value_type: <value of integer>
                  oper: <value in [less-than, not-contain, less-or-equal, ...]>
              subject: <value of string>
              tag: <value of string>
              enable: <value in [enable, disable]>
              eventstatus: <value of string>
              eventtype: <value of string>
              extrainfo: <value of string>
              extrainfo_type: <value in [default, custom]>
              filter_expr: <value of string>
              groupby1: <value of string>
              groupby2: <value of string>
              logtype: <value of string>
              rule_relation: <value of integer>
              severity: <value in [high, medium, critical, ...]>
              thres_count: <value of integer>
              thres_duration: <value of integer>
              utmevent: <value of string>
              indicator:
                - count: <value of integer>
                  name: <value of string>
                  type: <value of string>
          id: <value of integer>
          name: <value of string>
          uuid: <value of string>
          version: <value of integer>
          creation_time: <value of integer>
          description: <value of string>
          device_specify: <value in [all-devices, specify, local-host]>
          email_from: <value of string>
          email_html_format: <value of integer>
          email_subject: <value of string>
          email_svr: <value of string>
          email_to: <value of string>
          enable: <value in [enable, disable]>
          enable_time: <value of integer>
          filter_relation: <value of integer>
          handlertype: <value in [handler-type-local, handler-type-remote]>
          protected: <value in [enable, disable]>
          snmp_community: <value of string>
          snmpv3_user: <value of string>
          syslog_svr: <value of string>
          target_enable: <value of integer>
          template_url: <value of string>
          update_time: <value of integer>
          content_pack_id: <value of string>
          content_pack_uuid: <value of string>
          pre_filter:
            - dev_type: <any type of data>
              id: <value of integer>
              rule:
                - id: <value of integer>
                  key: <value of string>
                  value: <value of string>
                  value_type: <value of integer>
              subject: <value of string>
              tag: <value of string>
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
        '/eventmgmt/adom/{adom}/config/trigger'
    ]

    url_params = ['adom']
    module_primary_key = 'id'
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
        'adom': {'required': True, 'type': 'str'},
        'eventmgmt_config_trigger': {
            'type': 'dict',
            'v_range': [['6.2.1', '7.2.1']],
            'options': {
                'address-filter': {
                    'v_range': [['6.2.1', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                        'include-option': {'v_range': [['6.2.1', '7.2.1']], 'type': 'raw'},
                        'address-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['address-group', 'address-obj'], 'type': 'str'},
                        'grp-name': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'obj-name': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'device': {
                    'v_range': [['6.2.1', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                        'name': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                        'type': {'v_range': [['6.2.1', '7.2.1']], 'type': 'raw'},
                        'vdom': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-connector': {
                    'v_range': [['6.2.1', '7.2.1']],
                    'type': 'list',
                    'options': {'refid': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'filter': {
                    'v_range': [['6.2.1', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'dev-type': {'v_range': [['6.2.1', '7.2.1']], 'type': 'raw'},
                        'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                        'rule': {
                            'v_range': [['6.2.1', '7.2.1']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                                'key': {'v_range': [['6.2.1', '7.2.1']], 'no_log': False, 'type': 'str'},
                                'value': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                                'value-type': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                                'oper': {
                                    'v_range': [['6.2.2', '6.2.13']],
                                    'choices': [
                                        'less-than', 'not-contain', 'less-or-equal', 'equal', 'great-or-equal', 'not-equal', 'contain', 'great-than'
                                    ],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'subject': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                        'tag': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                        'enable': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                        'eventstatus': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'eventtype': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'extrainfo': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'extrainfo-type': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['default', 'custom'], 'type': 'str'},
                        'filter-expr': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'groupby1': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'groupby2': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'logtype': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'rule-relation': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                        'severity': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['high', 'medium', 'critical', 'low'], 'type': 'str'},
                        'thres-count': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                        'thres-duration': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                        'utmevent': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                        'indicator': {
                            'v_range': [['7.0.3', '7.2.1']],
                            'type': 'list',
                            'options': {
                                'count': {'v_range': [['7.0.3', '7.2.1']], 'type': 'int'},
                                'name': {'v_range': [['7.0.3', '7.2.1']], 'type': 'str'},
                                'type': {'v_range': [['7.0.3', '7.2.1']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                'name': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '7.2.1']], 'type': 'str'},
                'version': {'v_range': [['6.2.1', '7.2.1']], 'type': 'int'},
                'creation-time': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'description': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'device-specify': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['all-devices', 'specify', 'local-host'], 'type': 'str'},
                'email-from': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'email-html-format': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'email-subject': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'email-svr': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'email-to': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'enable': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'enable-time': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'filter-relation': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'handlertype': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['handler-type-local', 'handler-type-remote'], 'type': 'str'},
                'protected': {'v_range': [['6.2.2', '6.2.13']], 'choices': ['enable', 'disable'], 'type': 'str'},
                'snmp-community': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'snmpv3-user': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'syslog-svr': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'target-enable': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'template-url': {'v_range': [['6.2.2', '6.2.13']], 'type': 'str'},
                'update-time': {'v_range': [['6.2.2', '6.2.13']], 'type': 'int'},
                'content-pack-id': {'v_range': [['6.4.6', '7.2.1']], 'type': 'str'},
                'content-pack-uuid': {'v_range': [['6.4.6', '7.2.1']], 'type': 'str'},
                'pre-filter': {
                    'v_range': [['7.0.1', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'dev-type': {'v_range': [['7.0.1', '7.2.1']], 'type': 'raw'},
                        'id': {'v_range': [['7.0.1', '7.2.1']], 'type': 'int'},
                        'rule': {
                            'v_range': [['7.0.1', '7.2.1']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.0.1', '7.2.1']], 'type': 'int'},
                                'key': {'v_range': [['7.0.1', '7.2.1']], 'no_log': False, 'type': 'str'},
                                'value': {'v_range': [['7.0.1', '7.2.1']], 'type': 'str'},
                                'value-type': {'v_range': [['7.0.1', '7.2.1']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'subject': {'v_range': [['7.0.1', '7.2.1']], 'type': 'str'},
                        'tag': {'v_range': [['7.0.1', '7.2.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'eventmgmt_config_trigger'),
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
