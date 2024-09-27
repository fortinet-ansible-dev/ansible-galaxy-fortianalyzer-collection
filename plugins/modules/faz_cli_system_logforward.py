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
module: faz_cli_system_logforward
short_description: Log forwarding.
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
    cli_system_logforward:
        description: The top level parameters set.
        type: dict
        suboptions:
            agg_archive_types:
                description:
                 - Archive types.
                 - Web_Archive
                 - Secure_Web_Archive
                 - Email_Archive
                 - File_Transfer_Archive
                 - IM_Archive
                 - MMS_Archive
                 - AV_Quarantine
                 - IPS_Packets
                type: list
                elements: str
                choices:
                    - 'Web_Archive'
                    - 'Secure_Web_Archive'
                    - 'Email_Archive'
                    - 'File_Transfer_Archive'
                    - 'IM_Archive'
                    - 'MMS_Archive'
                    - 'AV_Quarantine'
                    - 'IPS_Packets'
                    - 'CDR_Archive'
            agg_logtypes:
                description:
                 - Log types.
                 - none - none
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
                type: list
                elements: str
                choices:
                    - 'none'
                    - 'app-ctrl'
                    - 'attack'
                    - 'content'
                    - 'dlp'
                    - 'emailfilter'
                    - 'event'
                    - 'generic'
                    - 'history'
                    - 'traffic'
                    - 'virus'
                    - 'webfilter'
                    - 'netscan'
                    - 'fct-event'
                    - 'fct-traffic'
                    - 'fct-netscan'
                    - 'waf'
                    - 'gtp'
                    - 'dns'
                    - 'ssh'
                    - 'ssl'
                    - 'file-filter'
                    - 'asset'
                    - 'protocol'
                    - 'siem'
                    - 'ztna'
                    - 'security'
            agg_password:
                description: Log aggregation access password for server.
                type: str
            agg_time:
                type: int
                description: Daily at.
            agg_user:
                type: str
                description: Log aggregation access user name for server.
            device_filter:
                description: no description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description:
                         - Include or exclude the specified device.
                         - include - Include specified device.
                         - exclude - Exclude specified device.
                         - include-like - Include specified device matching the given wildcard expression.
                         - exclude-like - Exclude specified device matching the given wildcard expression.
                        choices:
                            - 'include'
                            - 'exclude'
                            - 'include-like'
                            - 'exclude-like'
                    device:
                        type: str
                        description: Device ID of log client device, or a wildcard expression matching log client device
                    id:
                        type: int
                        description: Device filter ID.
                    adom:
                        type: str
                        description: Adom name or
            fwd_archive_types:
                description:
                 - forwarding archive types.
                 - Web_Archive
                 - Email_Archive
                 - IM_Archive
                 - File_Transfer_Archive
                 - MMS_Archive
                 - AV_Quarantine
                 - IPS_Packets
                 - EDISC_Archive
                type: list
                elements: str
                choices:
                    - 'Web_Archive'
                    - 'Email_Archive'
                    - 'IM_Archive'
                    - 'File_Transfer_Archive'
                    - 'MMS_Archive'
                    - 'AV_Quarantine'
                    - 'IPS_Packets'
                    - 'EDISC_Archive'
                    - 'CDR_Archive'
            fwd_archives:
                type: str
                description:
                 - Enable/disable forwarding archives.
                 - disable - Disable forwarding archives.
                 - enable - Enable forwarding archives.
                choices:
                    - 'disable'
                    - 'enable'
            fwd_facility:
                type: str
                description:
                 - Facility for remote syslog.
                 - kernel - kernel messages
                 - user - random user level messages
                 - mail - Mail system.
                 - daemon - System daemons.
                 - auth - Security/authorization messages.
                 - syslog - Messages generated internally by syslog daemon.
                 - lpr - Line printer subsystem.
                 - news - Network news subsystem.
                 - uucp - Network news subsystem.
                 - clock - Clock daemon.
                 - authpriv - Security/authorization messages
                 - ftp - FTP daemon.
                 - ntp - NTP daemon.
                 - audit - Log audit.
                 - alert - Log alert.
                 - cron - Clock daemon.
                 - local0 - Reserved for local use.
                 - local1 - Reserved for local use.
                 - local2 - Reserved for local use.
                 - local3 - Reserved for local use.
                 - local4 - Reserved for local use.
                 - local5 - Reserved for local use.
                 - local6 - Reserved for local use.
                 - local7 - Reserved for local use.
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
            fwd_log_source_ip:
                type: str
                description:
                 - Logs source IP address
                 - local_ip - Use FAZVM64 local ip.
                 - original_ip - Use original source ip.
                choices:
                    - 'local_ip'
                    - 'original_ip'
            fwd_max_delay:
                type: str
                description:
                 - Max delay for near realtime log forwarding.
                 - realtime - Realtime forwarding, no delay.
                 - 1min - Near realtime forwarding with up to one miniute delay.
                 - 5min - Near realtime forwarding with up to five miniutes delay.
                choices:
                    - 'realtime'
                    - '1min'
                    - '5min'
            fwd_reliable:
                type: str
                description:
                 - Enable/disable reliable logging.
                 - disable - Disable reliable logging.
                 - enable - Enable reliable logging.
                choices:
                    - 'disable'
                    - 'enable'
            fwd_secure:
                type: str
                description:
                 - Enable/disable TLS/SSL secured reliable logging.
                 - disable - Disable TLS/SSL secured reliable logging.
                 - enable - Enable TLS/SSL secured reliable logging.
                choices:
                    - 'disable'
                    - 'enable'
            fwd_server_type:
                type: str
                description:
                 - Forwarding all logs to syslog server or FortiAnalyzer.
                 - syslog - Forward logs to generic syslog server.
                 - fortianalyzer - Forward logs to FortiAnalyzer.
                 - cef - Forward logs to a CEF
                choices:
                    - 'syslog'
                    - 'fortianalyzer'
                    - 'cef'
                    - 'syslog-pack'
                    - 'fwd-via-output-plugin'
                    - 'elite-service'
            id:
                type: int
                description: Log forwarding ID.
            log_field_exclusion:
                description: no description
                type: list
                elements: dict
                suboptions:
                    dev_type:
                        type: str
                        description:
                         - Device type.
                         - FortiGate - FortiGate Device
                         - FortiManager - FortiManager Device
                         - Syslog - Syslog Device
                         - FortiMail - FortiMail Device
                         - FortiWeb - FortiWeb Device
                         - FortiCache - FortiCache Device
                         - FortiAnalyzer - FortiAnalyzer Device
                         - FortiSandbox - FortiSandbox Device
                         - FortiDDoS - FortiDDoS Device
                         - FortiNAC - FortiNAC Device
                         - FortiDeceptor - FortiDeceptor Device
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
                    field_list:
                        type: str
                        description: List of fields to be excluded.
                    id:
                        type: int
                        description: Log field exclusion ID.
                    log_type:
                        type: str
                        description:
                         - Log type.
                         - app-ctrl - Application Control
                         - appevent - APPEVENT
                         - attack - Attack
                         - content - DLP Archive
                         - dlp - Data Leak Prevention
                         - emailfilter - Email Filter
                         - event - Event
                         - generic - Generic
                         - history - Mail Statistics
                         - traffic - Traffic
                         - virus - Virus
                         - voip - VoIP
                         - webfilter - Web Filter
                         - netscan - Network Scan
                         - waf - WAF
                         - gtp - GTP
                         - dns - Domain Name System
                         - ssh - SSH
                         - ssl - SSL
                         - file-filter - FFLT
                         - Asset - Asset
                         - protocol - PROTOCOL
                         - ANY-TYPE - Any log type
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
            log_field_exclusion_status:
                type: str
                description:
                 - Enable or disable log field exclusion.
                 - disable - Disable log field exclusion.
                 - enable - Enable log field exclusion.
                choices:
                    - 'disable'
                    - 'enable'
            log_filter:
                description: no description
                type: list
                elements: dict
                suboptions:
                    field:
                        type: str
                        description:
                         - Field name.
                         - type - Log type
                         - logid - Log ID
                         - level - Level
                         - devid - Device ID
                         - vd - Vdom ID
                         - srcip - Source IP
                         - srcintf - Source Interface
                         - dstip - Destination IP
                         - dstintf - Destination Interface
                         - dstport - Destination Port
                         - user - User
                         - group - Group
                         - free-text - General free-text filter
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
                        description: Log filter ID.
                    oper:
                        type: str
                        description:
                         - Field filter operator.
                         - no description
                         - no description
                         - contain - Contain
                         - not-contain - Not contain
                         - match - Match
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
                        description: Field filter operand or free-text matching expression.
            log_filter_logic:
                type: str
                description:
                 - Logic operator used to connect filters.
                 - and - Conjunctive filters.
                 - or - Disjunctive filters.
                choices:
                    - 'and'
                    - 'or'
            log_filter_status:
                type: str
                description:
                 - Enable or disable log filtering.
                 - disable - Disable log filtering.
                 - enable - Enable log filtering.
                choices:
                    - 'disable'
                    - 'enable'
            mode:
                type: str
                description:
                 - Log forwarding mode.
                 - forwarding - Realtime or near realtime forwarding logs to servers.
                 - aggregation - Aggregate logs and archives to Analyzer.
                 - disable - Do not forward or aggregate logs.
                choices:
                    - 'forwarding'
                    - 'aggregation'
                    - 'disable'
            proxy_service:
                type: str
                description:
                 - Enable/disable proxy service under collector mode.
                 - disable - Disable proxy service.
                 - enable - Enable proxy service.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_service_priority:
                type: int
                description: Proxy service priority from 1
            server_device:
                type: str
                description: Log forwarding server device ID.
            server_ip:
                type: str
                description: Remote server IP address.
            server_name:
                type: str
                description: Log forwarding server name.
            server_port:
                type: int
                description: Server listen port
            signature:
                type: int
                description: Aggregation cfg hash token.
            sync_metadata:
                description:
                 - Synchronizing meta data types.
                 - sf-topology - Security Fabric topology
                 - interface-role - Interface Role
                 - device - Device information
                 - endusr-avatar - End-user avatar
                type: list
                elements: str
                choices:
                    - 'sf-topology'
                    - 'interface-role'
                    - 'device'
                    - 'endusr-avatar'
                    - 'fgt-policy'
                    - 'interface-info'
            fwd_syslog_format:
                type: str
                description:
                 - Forwarding format for syslog.
                 - fgt - fgt syslog format
                 - rfc-5424 - rfc-5424 syslog format
                choices:
                    - 'fgt'
                    - 'rfc-5424'
            fwd_ha_bind_vip:
                type: str
                description:
                 - When HA is enabled, always use vip as forwarding port
                 - disable - Disable bind forwarding to vip interface.
                 - enable - Enable bind forwarding to vip interface.
                choices:
                    - 'disable'
                    - 'enable'
            server_addr:
                type: str
                description: Remote server address.
            fwd_compression:
                type: str
                description:
                 - Enable/disable compression for better bandwidth efficiency.
                 - disable - Disable compression of messages.
                 - enable - Enable compression of messages.
                choices:
                    - 'disable'
                    - 'enable'
            log_masking_custom:
                description: no description
                type: list
                elements: dict
                suboptions:
                    field_name:
                        type: str
                        description: Field name.
                    field_type:
                        type: str
                        description:
                         - Field type.
                         - string - String.
                         - ip - IP.
                         - mac - MAC address.
                         - email - Email address.
                         - unknown - Unknown.
                        choices:
                            - 'string'
                            - 'ip'
                            - 'mac'
                            - 'email'
                            - 'unknown'
                    id:
                        type: int
                        description: Field masking id.
            log_masking_custom_priority:
                type: str
                description:
                 - Prioritize custom fields.
                 - disable - Disable custom field search priority.
                 - no description
                choices:
                    - 'disable'
                    - ''
                    - 'enable'
            log_masking_fields:
                description:
                 - Log field masking fields.
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
            log_masking_key:
                description: Log field masking key.
                type: str
            log_masking_status:
                type: str
                description:
                 - Enable or disable log field masking.
                 - disable - Disable log field masking.
                 - enable - Enable log field masking.
                choices:
                    - 'disable'
                    - 'enable'
            agg_data_end_time:
                description: 'End date and time of the data-range <hh:mm yyyy/mm/dd>.'
                type: str
            agg_data_start_time:
                description: 'Start date and time of the data-range <hh:mm yyyy/mm/dd>.'
                type: str
            agg_schedule:
                type: str
                description:
                 - Schedule log aggregation mode.
                 - daily - Run daily log aggregation
                 - on-demand - Run log aggregation on demand
                choices:
                    - 'daily'
                    - 'on-demand'
            pcapurl_domain_ip:
                type: str
                description: The domain name or ip for forming a pcapurl.
            pcapurl_enrich:
                type: str
                description:
                 - Enable/disable enriching pcapurl.
                 - disable - Disable enriching pcapurl.
                 - enable - Enable enriching pcapurl.
                choices:
                    - 'disable'
                    - 'enable'
            peer_cert_cn:
                type: str
                description: Certificate common name of log-forward server.
            fwd_output_plugin_id:
                type: str
                description: Name of the output plugin profile
            fwd_syslog_transparent:
                type: str
                description:
                 - Enable/disable transparently forwarding logs from syslog devices to syslog server.
                 - disable - Disable syslog transparent forward mode.
                 - enable - Enable syslog transparent forward mode.
                 - faz-enrich - Disable syslog transparent forward mode.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'faz-enrich'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Log forwarding.
      fortinet.fortianalyzer.faz_cli_system_logforward:
        cli_system_logforward:
          id: 1
          server_name: "fooname"
          server_addr: 12.3.4.5
          # server_device: ''
          # server_port: 514
          fwd_server_type: fortianalyzer
          mode: forwarding
          # server_ip: "23.231.1.1"
          log_filter_status: enable
          log_filter_logic: and
          log_field_exclusion_status: enable
          fwd_reliable: disable
          fwd_max_delay: 5min
          log_masking_status: enable
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
        '/cli/global/system/log-forward'
    ]

    url_params = []
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
        'cli_system_logforward': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'agg-archive-types': {
                    'type': 'list',
                    'choices': [
                        'Web_Archive', 'Secure_Web_Archive', 'Email_Archive', 'File_Transfer_Archive', 'IM_Archive', 'MMS_Archive', 'AV_Quarantine',
                        'IPS_Packets', 'CDR_Archive'
                    ],
                    'elements': 'str'
                },
                'agg-logtypes': {
                    'type': 'list',
                    'choices': [
                        'none', 'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'webfilter',
                        'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'asset', 'protocol',
                        'siem', 'ztna', 'security'
                    ],
                    'elements': 'str'
                },
                'agg-password': {'no_log': True, 'type': 'str'},
                'agg-time': {'type': 'int'},
                'agg-user': {'type': 'str'},
                'device-filter': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['include', 'exclude', 'include-like', 'exclude-like'], 'type': 'str'},
                        'device': {'type': 'str'},
                        'id': {'type': 'int'},
                        'adom': {'v_range': [['7.0.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fwd-archive-types': {
                    'type': 'list',
                    'choices': [
                        'Web_Archive', 'Email_Archive', 'IM_Archive', 'File_Transfer_Archive', 'MMS_Archive', 'AV_Quarantine', 'IPS_Packets',
                        'EDISC_Archive', 'CDR_Archive'
                    ],
                    'elements': 'str'
                },
                'fwd-archives': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd-facility': {
                    'choices': [
                        'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'clock', 'authpriv', 'ftp', 'ntp', 'audit', 'alert',
                        'cron', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                    ],
                    'type': 'str'
                },
                'fwd-log-source-ip': {'choices': ['local_ip', 'original_ip'], 'type': 'str'},
                'fwd-max-delay': {'choices': ['realtime', '1min', '5min'], 'type': 'str'},
                'fwd-reliable': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd-secure': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd-server-type': {'choices': ['syslog', 'fortianalyzer', 'cef', 'syslog-pack', 'fwd-via-output-plugin', 'elite-service'], 'type': 'str'},
                'id': {'type': 'int'},
                'log-field-exclusion': {
                    'type': 'list',
                    'options': {
                        'dev-type': {
                            'choices': [
                                'FortiGate', 'FortiManager', 'Syslog', 'FortiMail', 'FortiWeb', 'FortiCache', 'FortiAnalyzer', 'FortiSandbox',
                                'FortiDDoS', 'FortiNAC', 'FortiDeceptor', 'FortiFirewall', 'FortiADC', 'FortiClient', 'FortiAuthenticator', 'FortiProxy',
                                'FortiIsolator', 'FortiEDR', 'FortiPAM', 'FortiCASB', 'FortiToken'
                            ],
                            'type': 'str'
                        },
                        'field-list': {'type': 'str'},
                        'id': {'type': 'int'},
                        'log-type': {
                            'choices': [
                                'app-ctrl', 'appevent', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus',
                                'voip', 'webfilter', 'netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'Asset', 'protocol', 'ANY-TYPE',
                                'fct-event', 'fct-traffic', 'fct-netscan', 'ztna', 'security'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'log-field-exclusion-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-filter': {
                    'type': 'list',
                    'options': {
                        'field': {
                            'choices': [
                                'type', 'logid', 'level', 'devid', 'vd', 'srcip', 'srcintf', 'dstip', 'dstintf', 'dstport', 'user', 'group', 'free-text'
                            ],
                            'type': 'str'
                        },
                        'id': {'type': 'int'},
                        'oper': {'choices': ['=', '!=', '<', '>', '<=', '>=', 'contain', 'not-contain', 'match'], 'type': 'str'},
                        'value': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'log-filter-logic': {'choices': ['and', 'or'], 'type': 'str'},
                'log-filter-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mode': {'choices': ['forwarding', 'aggregation', 'disable'], 'type': 'str'},
                'proxy-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-service-priority': {'type': 'int'},
                'server-device': {'type': 'str'},
                'server-ip': {'v_range': [['6.2.1', '6.4.7']], 'type': 'str'},
                'server-name': {'type': 'str'},
                'server-port': {'type': 'int'},
                'signature': {'type': 'int'},
                'sync-metadata': {
                    'type': 'list',
                    'choices': ['sf-topology', 'interface-role', 'device', 'endusr-avatar', 'fgt-policy', 'interface-info'],
                    'elements': 'str'
                },
                'fwd-syslog-format': {'v_range': [['6.4.3', '']], 'choices': ['fgt', 'rfc-5424'], 'type': 'str'},
                'fwd-ha-bind-vip': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-addr': {'v_range': [['6.4.8', '']], 'type': 'str'},
                'fwd-compression': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-masking-custom': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'field-name': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'field-type': {'v_range': [['7.0.0', '']], 'choices': ['string', 'ip', 'mac', 'email', 'unknown'], 'type': 'str'},
                        'id': {'v_range': [['7.0.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'log-masking-custom-priority': {'v_range': [['7.0.0', '']], 'choices': ['disable', '', 'enable'], 'type': 'str'},
                'log-masking-fields': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'choices': ['user', 'srcip', 'srcname', 'srcmac', 'dstip', 'dstname', 'email', 'message', 'domain'],
                    'elements': 'str'
                },
                'log-masking-key': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'str'},
                'log-masking-status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'agg-data-end-time': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'agg-data-start-time': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'agg-schedule': {'v_range': [['7.0.3', '']], 'choices': ['daily', 'on-demand'], 'type': 'str'},
                'pcapurl-domain-ip': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'pcapurl-enrich': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'peer-cert-cn': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'fwd-output-plugin-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'fwd-syslog-transparent': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'faz-enrich'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_logforward'),
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
