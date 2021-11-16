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
module: faz_cli_system_logforward
short_description: Log forwarding.
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
    cli_system_logforward:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            agg-archive-types:
                description: no description
                type: list
                choices:
                 - Web_Archive
                 - Secure_Web_Archive
                 - Email_Archive
                 - File_Transfer_Archive
                 - IM_Archive
                 - MMS_Archive
                 - AV_Quarantine
                 - IPS_Packets
            agg-logtypes:
                description: no description
                type: list
                choices:
                 - none
                 - app-ctrl
                 - attack
                 - content
                 - dlp
                 - emailfilter
                 - event
                 - generic
                 - history
                 - traffic
                 - virus
                 - webfilter
                 - netscan
                 - fct-event
                 - fct-traffic
                 - fct-netscan
                 - waf
                 - gtp
                 - dns
                 - ssh
                 - ssl
                 - file-filter
                 - asset
                 - protocol
                 - siem
            agg-password:
                description: no description
                type: str
            agg-time:
                type: int
                default: 0
                description: 'Daily at.'
            agg-user:
                type: str
                description: 'Log aggregation access user name for server.'
            device-filter:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        default: 'include'
                        description:
                         - 'Include or exclude the specified device.'
                         - 'include - Include specified device.'
                         - 'exclude - Exclude specified device.'
                         - 'include-like - Include specified device matching the given wildcard expression.'
                         - 'exclude-like - Exclude specified device matching the given wildcard expression.'
                        choices:
                            - 'include'
                            - 'exclude'
                            - 'include-like'
                            - 'exclude-like'
                    device:
                        type: str
                        description: 'Device ID of log client device, or a wildcard expression matching log client device(s) if action is a like action.'
                    id:
                        type: int
                        default: 0
                        description: 'Device filter ID.'
            fwd-archive-types:
                description: no description
                type: list
                choices:
                 - Web_Archive
                 - Email_Archive
                 - IM_Archive
                 - File_Transfer_Archive
                 - MMS_Archive
                 - AV_Quarantine
                 - IPS_Packets
                 - EDISC_Archive
            fwd-archives:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable forwarding archives.'
                 - 'disable - Disable forwarding archives.'
                 - 'enable - Enable forwarding archives.'
                choices:
                    - 'disable'
                    - 'enable'
            fwd-facility:
                type: str
                default: 'local7'
                description:
                 - 'Facility for remote syslog.'
                 - 'kernel - kernel messages'
                 - 'user - random user level messages'
                 - 'mail - Mail system.'
                 - 'daemon - System daemons.'
                 - 'auth - Security/authorization messages.'
                 - 'syslog - Messages generated internally by syslog daemon.'
                 - 'lpr - Line printer subsystem.'
                 - 'news - Network news subsystem.'
                 - 'uucp - Network news subsystem.'
                 - 'clock - Clock daemon.'
                 - 'authpriv - Security/authorization messages (private).'
                 - 'ftp - FTP daemon.'
                 - 'ntp - NTP daemon.'
                 - 'audit - Log audit.'
                 - 'alert - Log alert.'
                 - 'cron - Clock daemon.'
                 - 'local0 - Reserved for local use.'
                 - 'local1 - Reserved for local use.'
                 - 'local2 - Reserved for local use.'
                 - 'local3 - Reserved for local use.'
                 - 'local4 - Reserved for local use.'
                 - 'local5 - Reserved for local use.'
                 - 'local6 - Reserved for local use.'
                 - 'local7 - Reserved for local use.'
                choices:
                    - 'kernel'
                    - 'user'
                    - 'mail'
                    - 'daemon'
                    - 'auth'
                    - 'syslog'
                    - 'lpr'
                    - 'news'
                    - 'uucp'
                    - 'clock'
                    - 'authpriv'
                    - 'ftp'
                    - 'ntp'
                    - 'audit'
                    - 'alert'
                    - 'cron'
                    - 'local0'
                    - 'local1'
                    - 'local2'
                    - 'local3'
                    - 'local4'
                    - 'local5'
                    - 'local6'
                    - 'local7'
            fwd-log-source-ip:
                type: str
                default: 'local_ip'
                description:
                 - 'Logs source IP address (no effect for reliable forwarding).'
                 - 'local_ip - Use FAZVM64 local ip.'
                 - 'original_ip - Use original source ip.'
                choices:
                    - 'local_ip'
                    - 'original_ip'
            fwd-max-delay:
                type: str
                default: '5min'
                description:
                 - 'Max delay for near realtime log forwarding.'
                 - 'realtime - Realtime forwarding, no delay.'
                 - '1min - Near realtime forwarding with up to one miniute delay.'
                 - '5min - Near realtime forwarding with up to five miniutes delay.'
                choices:
                    - 'realtime'
                    - '1min'
                    - '5min'
            fwd-reliable:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable reliable logging.'
                 - 'disable - Disable reliable logging.'
                 - 'enable - Enable reliable logging.'
                choices:
                    - 'disable'
                    - 'enable'
            fwd-secure:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable TLS/SSL secured reliable logging.'
                 - 'disable - Disable TLS/SSL secured reliable logging.'
                 - 'enable - Enable TLS/SSL secured reliable logging.'
                choices:
                    - 'disable'
                    - 'enable'
            fwd-server-type:
                type: str
                default: 'fortianalyzer'
                description:
                 - 'Forwarding all logs to syslog server or FortiAnalyzer.'
                 - 'syslog - Forward logs to generic syslog server.'
                 - 'fortianalyzer - Forward logs to FortiAnalyzer.'
                 - 'cef - Forward logs to a CEF (Common Event Format) server.'
                choices:
                    - 'syslog'
                    - 'fortianalyzer'
                    - 'cef'
                    - 'syslog-pack'
            id:
                type: int
                default: 0
                description: 'Log forwarding ID.'
            log-field-exclusion:
                description: no description
                type: list
                suboptions:
                    dev-type:
                        type: str
                        default: 'FortiGate'
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
                            - 'FortiADC'
                            - 'FortiFirewall'
                    field-list:
                        type: str
                        description: 'List of fields to be excluded.'
                    id:
                        type: int
                        default: 0
                        description: 'Log field exclusion ID.'
                    log-type:
                        type: str
                        default: 'traffic'
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
            log-field-exclusion-status:
                type: str
                default: 'disable'
                description:
                 - 'Enable or disable log field exclusion.'
                 - 'disable - Disable log field exclusion.'
                 - 'enable - Enable log field exclusion.'
                choices:
                    - 'disable'
                    - 'enable'
            log-filter:
                description: no description
                type: list
                suboptions:
                    field:
                        type: str
                        default: 'type'
                        description:
                         - 'Field name.'
                         - 'type - Log type'
                         - 'logid - Log ID'
                         - 'level - Level'
                         - 'devid - Device ID'
                         - 'vd - Vdom ID'
                         - 'srcip - Source IP'
                         - 'srcintf - Source Interface'
                         - 'dstip - Destination IP'
                         - 'dstintf - Destination Interface'
                         - 'dstport - Destination Port'
                         - 'user - User'
                         - 'group - Group'
                         - 'free-text - General free-text filter'
                        choices:
                            - 'type'
                            - 'logid'
                            - 'level'
                            - 'devid'
                            - 'vd'
                            - 'srcip'
                            - 'srcintf'
                            - 'dstip'
                            - 'dstintf'
                            - 'dstport'
                            - 'user'
                            - 'group'
                            - 'free-text'
                    id:
                        type: int
                        default: 0
                        description: 'Log filter ID.'
                    oper:
                        type: str
                        default: '='
                        description:
                         - 'Field filter operator.'
                         - '&lt; - =Less than or equal to'
                         - '&gt; - =Greater than or equal to'
                         - 'contain - Contain'
                         - 'not-contain - Not contain'
                         - 'match - Match (expression)'
                        choices:
                            - '='
                            - '!='
                            - '<'
                            - '>'
                            - '<='
                            - '>='
                            - 'contain'
                            - 'not-contain'
                            - 'match'
                    value:
                        type: str
                        description: 'Field filter operand or free-text matching expression.'
            log-filter-logic:
                type: str
                default: 'or'
                description:
                 - 'Logic operator used to connect filters.'
                 - 'and - Conjunctive filters.'
                 - 'or - Disjunctive filters.'
                choices:
                    - 'and'
                    - 'or'
            log-filter-status:
                type: str
                default: 'disable'
                description:
                 - 'Enable or disable log filtering.'
                 - 'disable - Disable log filtering.'
                 - 'enable - Enable log filtering.'
                choices:
                    - 'disable'
                    - 'enable'
            mode:
                type: str
                default: 'disable'
                description:
                 - 'Log forwarding mode.'
                 - 'forwarding - Realtime or near realtime forwarding logs to servers.'
                 - 'aggregation - Aggregate logs and archives to Analyzer.'
                 - 'disable - Do not forward or aggregate logs.'
                choices:
                    - 'forwarding'
                    - 'aggregation'
                    - 'disable'
            proxy-service:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable proxy service under collector mode.'
                 - 'disable - Disable proxy service.'
                 - 'enable - Enable proxy service.'
                choices:
                    - 'disable'
                    - 'enable'
            proxy-service-priority:
                type: int
                default: 10
                description: 'Proxy service priority from 1 (lowest) to 20 (highest).'
            server-device:
                type: str
                description: 'Log forwarding server device ID.'
            server-ip:
                type: str
                description: 'Remote server IP address.'
            server-name:
                type: str
                description: 'Log forwarding server name.'
            server-port:
                type: int
                default: 514
                description: 'Server listen port (1 - 65535).'
            signature:
                type: int
                default: 0
                description: 'Aggregation cfg hash token.'
            sync-metadata:
                description: no description
                type: list
                choices:
                 - sf-topology
                 - interface-role
                 - device
                 - endusr-avatar
            fwd-syslog-format:
                type: str
                default: 'fgt'
                description:
                 - 'Forwarding format for syslog.'
                 - 'fgt - fgt syslog format'
                 - 'rfc-5424 - rfc-5424 syslog format'
                choices:
                    - 'fgt'
                    - 'rfc-5424'
            fwd-compression:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable compression for better bandwidth efficiency.'
                 - 'disable - Disable compression of messages.'
                 - 'enable - Enable compression of messages.'
                choices:
                    - 'disable'
                    - 'enable'
            log-masking-custom:
                description: no description
                type: list
                suboptions:
                    field-name:
                        type: str
                        description: 'Field name.'
                    field-type:
                        type: str
                        default: 'unknown'
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
                    id:
                        type: int
                        default: 0
                        description: 'Field masking id.'
            log-masking-custom-priority:
                type: str
                default: 'disable'
                description:
                 - 'Prioritize custom fields.'
                 - 'disable - Disable custom field search priority.'
                 - ' - Prioritize custom fields.'
                choices:
                    - 'disable'
                    - ''
            log-masking-fields:
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
            log-masking-key:
                description: no description
                type: str
            log-masking-status:
                type: str
                default: 'disable'
                description:
                 - 'Enable or disable log field masking.'
                 - 'disable - Disable log field masking.'
                 - 'enable - Enable log field masking.'
                choices:
                    - 'disable'
                    - 'enable'
            server-addr:
                type: str
                description: 'Remote server address.'

'''

EXAMPLES = '''
 - collections:
   - fortinet.fortianalyzer
   connection: httpapi
   hosts: fortianalyzer-inventory
   tasks:
   - faz_cli_system_logforward:
       cli_system_logforward:
         id: 1
         server-name: 'fooname'
         server-addr: 12.3.4.5
         #server-device: ''
         #server-port: 514
         fwd-server-type: fortianalyzer
         mode: forwarding
         #server-ip: "23.231.1.1"
         log-filter-status: enable
         log-filter-logic: and
         log-field-exclusion-status: enable
         fwd-reliable: disable
         fwd-max-delay: 5min
         log-masking-status: enable
       state: present
     name: Log forwarding.
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
        '/cli/global/system/log-forward'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log-forward/{log-forward}'
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
        'cli_system_logforward': {
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
                '7.0.0': True
            },
            'options': {
                'agg-archive-types': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'Web_Archive',
                        'Secure_Web_Archive',
                        'Email_Archive',
                        'File_Transfer_Archive',
                        'IM_Archive',
                        'MMS_Archive',
                        'AV_Quarantine',
                        'IPS_Packets'
                    ]
                },
                'agg-logtypes': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'none',
                        'app-ctrl',
                        'attack',
                        'content',
                        'dlp',
                        'emailfilter',
                        'event',
                        'generic',
                        'history',
                        'traffic',
                        'virus',
                        'webfilter',
                        'netscan',
                        'fct-event',
                        'fct-traffic',
                        'fct-netscan',
                        'waf',
                        'gtp',
                        'dns',
                        'ssh',
                        'ssl',
                        'file-filter',
                        'asset',
                        'protocol',
                        'siem'
                    ]
                },
                'agg-password': {
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'agg-time': {
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'agg-user': {
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'device-filter': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
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
                                '7.0.0': True
                            },
                            'choices': [
                                'include',
                                'exclude',
                                'include-like',
                                'exclude-like'
                            ],
                            'type': 'str'
                        },
                        'device': {
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
                                '7.0.0': True
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
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'fwd-archive-types': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'Web_Archive',
                        'Email_Archive',
                        'IM_Archive',
                        'File_Transfer_Archive',
                        'MMS_Archive',
                        'AV_Quarantine',
                        'IPS_Packets',
                        'EDISC_Archive'
                    ]
                },
                'fwd-archives': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fwd-facility': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'kernel',
                        'user',
                        'mail',
                        'daemon',
                        'auth',
                        'syslog',
                        'lpr',
                        'news',
                        'uucp',
                        'clock',
                        'authpriv',
                        'ftp',
                        'ntp',
                        'audit',
                        'alert',
                        'cron',
                        'local0',
                        'local1',
                        'local2',
                        'local3',
                        'local4',
                        'local5',
                        'local6',
                        'local7'
                    ],
                    'type': 'str'
                },
                'fwd-log-source-ip': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'local_ip',
                        'original_ip'
                    ],
                    'type': 'str'
                },
                'fwd-max-delay': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'realtime',
                        '1min',
                        '5min'
                    ],
                    'type': 'str'
                },
                'fwd-reliable': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fwd-secure': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fwd-server-type': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'syslog',
                        'fortianalyzer',
                        'cef',
                        'syslog-pack'
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'log-field-exclusion': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'dev-type': {
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
                                '7.0.0': True
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
                                'FortiADC',
                                'FortiFirewall'
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
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                'ANY-TYPE'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'log-field-exclusion-status': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-filter': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'field': {
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
                                '7.0.0': True
                            },
                            'choices': [
                                'type',
                                'logid',
                                'level',
                                'devid',
                                'vd',
                                'srcip',
                                'srcintf',
                                'dstip',
                                'dstintf',
                                'dstport',
                                'user',
                                'group',
                                'free-text'
                            ],
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
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'oper': {
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
                                '7.0.0': True
                            },
                            'choices': [
                                '=',
                                '!=',
                                '<',
                                '>',
                                '<=',
                                '>=',
                                'contain',
                                'not-contain',
                                'match'
                            ],
                            'type': 'str'
                        },
                        'value': {
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
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'log-filter-logic': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'and',
                        'or'
                    ],
                    'type': 'str'
                },
                'log-filter-status': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mode': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'forwarding',
                        'aggregation',
                        'disable'
                    ],
                    'type': 'str'
                },
                'proxy-service': {
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'proxy-service-priority': {
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'server-device': {
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'server-ip': {
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
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'server-name': {
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'server-port': {
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'signature': {
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'sync-metadata': {
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'sf-topology',
                        'interface-role',
                        'device',
                        'endusr-avatar'
                    ]
                },
                'fwd-syslog-format': {
                    'required': False,
                    'revision': {
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'fgt',
                        'rfc-5424'
                    ],
                    'type': 'str'
                },
                'fwd-compression': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-masking-custom': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'field-name': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'field-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'string',
                                'ip',
                                'mac',
                                'email',
                                'unknown'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'log-masking-custom-priority': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        ''
                    ],
                    'type': 'str'
                },
                'log-masking-fields': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
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
                'log-masking-key': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'log-masking-status': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'server-addr': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_logforward'),
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
