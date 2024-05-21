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
module: faz_cli_system_log_settings
short_description: Log settings.
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
    cli_system_log_settings:
        description: The top level parameters set.
        type: dict
        suboptions:
            FAC-custom-field1:
                type: str
                description: Name of custom log field to index.
            FAZ-custom-field1:
                type: str
                description: Name of custom log field to index.
            FCH-custom-field1:
                type: str
                description: Name of custom log field to index.
            FCT-custom-field1:
                type: str
                description: Name of custom log field to index.
            FDD-custom-field1:
                type: str
                description: Name of custom log field to index.
            FGT-custom-field1:
                type: str
                description: Name of custom log field to index.
            FMG-custom-field1:
                type: str
                description: Name of custom log field to index.
            FML-custom-field1:
                type: str
                description: Name of custom log field to index.
            FPX-custom-field1:
                type: str
                description: Name of custom log field to index.
            FSA-custom-field1:
                type: str
                description: Name of custom log field to index.
            FWB-custom-field1:
                type: str
                description: Name of custom log field to index.
            browse-max-logfiles:
                type: int
                description: Maximum number of log files for each log browse attempt for each Adom.
            dns-resolve-dstip:
                type: str
                description:
                 - Enable/Disable resolving destination IP by DNS.
                 - disable - Disable resolving destination IP by DNS.
                 - enable - Enable resolving destination IP by DNS.
                choices:
                    - 'disable'
                    - 'enable'
            download-max-logs:
                type: int
                description: Maximum number of logs for each log download attempt.
            ha-auto-migrate:
                type: str
                description:
                 - Enabled/Disable automatically merging HA members logs to HA cluster.
                 - disable - Disable automatically merging HA members logs to HA cluster.
                 - enable - Enable automatically merging HA members logs to HA cluster.
                choices:
                    - 'disable'
                    - 'enable'
            import-max-logfiles:
                type: int
                description: Maximum number of log files for each log import attempt.
            log-file-archive-name:
                type: str
                description:
                 - Log file name format for archiving, such as backup, upload or download.
                 - basic - Basic format for log archive file name, e.g.
                 - extended - Extended format for log archive file name, e.g.
                choices:
                    - 'basic'
                    - 'extended'
            rolling-analyzer:
                description: no description
                type: dict
                suboptions:
                    days:
                        description:
                         - Log files rolling schedule
                         - sun - Sunday.
                         - mon - Monday.
                         - tue - Tuesday.
                         - wed - Wednesday.
                         - thu - Thursday.
                         - fri - Friday.
                         - sat - Saturday.
                        type: list
                        elements: str
                        choices:
                            - 'sun'
                            - 'mon'
                            - 'tue'
                            - 'wed'
                            - 'thu'
                            - 'fri'
                            - 'sat'
                    del-files:
                        type: str
                        description:
                         - Enable/disable log file deletion after uploading.
                         - disable - Disable log file deletion.
                         - enable - Enable log file deletion.
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: Upload server directory, for Unix server, use absolute
                    file-size:
                        type: int
                        description: Roll log files when they reach this size
                    gzip-format:
                        type: str
                        description:
                         - Enable/disable compression of uploaded log files.
                         - disable - Disable compression.
                         - enable - Enable compression.
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        description: Log files rolling schedule
                    ip:
                        type: str
                        description: Upload server IP address.
                    ip2:
                        type: str
                        description: Upload server IP2 address.
                    ip3:
                        type: str
                        description: Upload server IP3 address.
                    log-format:
                        type: str
                        description:
                         - Format of uploaded log files.
                         - native - Native format
                         - text - Text format
                         - csv - CSV
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        description: Log files rolling schedule
                    password:
                        description: Upload server login password.
                        type: str
                    password2:
                        description: Upload server login password2.
                        type: str
                    password3:
                        description: Upload server login password3.
                        type: str
                    port:
                        type: int
                        description: Upload server IP1 port number.
                    port2:
                        type: int
                        description: Upload server IP2 port number.
                    port3:
                        type: int
                        description: Upload server IP3 port number.
                    server-type:
                        type: str
                        description:
                         - Upload server type.
                         - ftp - Upload via FTP.
                         - sftp - Upload via SFTP.
                         - scp - Upload via SCP.
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        description:
                         - Enable/disable log file uploads.
                         - disable - Disable log files uploading.
                         - enable - Enable log files uploading.
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        description: Log files upload schedule
                    upload-mode:
                        type: str
                        description:
                         - Upload mode with multiple servers.
                         - backup - Servers are attempted and used one after the other upon failure to connect.
                         - mirror - All configured servers are attempted and used.
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        description:
                         - Event triggering log files upload.
                         - on-roll - Upload log files after they are rolled.
                         - on-schedule - Upload log files daily.
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: Upload server login username.
                    username2:
                        type: str
                        description: Upload server login username2.
                    username3:
                        type: str
                        description: Upload server login username3.
                    when:
                        type: str
                        description:
                         - Roll log files periodically.
                         - none - Do not roll log files periodically.
                         - daily - Roll log files daily.
                         - weekly - Roll log files on certain days of week.
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
                    rolling-upgrade-status:
                        type: int
                        description: rolling upgrade status
                    server:
                        type: str
                        description: Upload server FQDN/IP.
                    server2:
                        type: str
                        description: Upload server2 FQDN/IP.
                    server3:
                        type: str
                        description: Upload server3 FQDN/IP.
            rolling-local:
                description: no description
                type: dict
                suboptions:
                    days:
                        description:
                         - Log files rolling schedule
                         - sun - Sunday.
                         - mon - Monday.
                         - tue - Tuesday.
                         - wed - Wednesday.
                         - thu - Thursday.
                         - fri - Friday.
                         - sat - Saturday.
                        type: list
                        elements: str
                        choices:
                            - 'sun'
                            - 'mon'
                            - 'tue'
                            - 'wed'
                            - 'thu'
                            - 'fri'
                            - 'sat'
                    del-files:
                        type: str
                        description:
                         - Enable/disable log file deletion after uploading.
                         - disable - Disable log file deletion.
                         - enable - Enable log file deletion.
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: Upload server directory, for Unix server, use absolute
                    file-size:
                        type: int
                        description: Roll log files when they reach this size
                    gzip-format:
                        type: str
                        description:
                         - Enable/disable compression of uploaded log files.
                         - disable - Disable compression.
                         - enable - Enable compression.
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        description: Log files rolling schedule
                    ip:
                        type: str
                        description: Upload server IP address.
                    ip2:
                        type: str
                        description: Upload server IP2 address.
                    ip3:
                        type: str
                        description: Upload server IP3 address.
                    log-format:
                        type: str
                        description:
                         - Format of uploaded log files.
                         - native - Native format
                         - text - Text format
                         - csv - CSV
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        description: Log files rolling schedule
                    password:
                        description: Upload server login password.
                        type: str
                    password2:
                        description: Upload server login password2.
                        type: str
                    password3:
                        description: Upload server login password3.
                        type: str
                    port:
                        type: int
                        description: Upload server IP1 port number.
                    port2:
                        type: int
                        description: Upload server IP2 port number.
                    port3:
                        type: int
                        description: Upload server IP3 port number.
                    server-type:
                        type: str
                        description:
                         - Upload server type.
                         - ftp - Upload via FTP.
                         - sftp - Upload via SFTP.
                         - scp - Upload via SCP.
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        description:
                         - Enable/disable log file uploads.
                         - disable - Disable log files uploading.
                         - enable - Enable log files uploading.
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        description: Log files upload schedule
                    upload-mode:
                        type: str
                        description:
                         - Upload mode with multiple servers.
                         - backup - Servers are attempted and used one after the other upon failure to connect.
                         - mirror - All configured servers are attempted and used.
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        description:
                         - Event triggering log files upload.
                         - on-roll - Upload log files after they are rolled.
                         - on-schedule - Upload log files daily.
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: Upload server login username.
                    username2:
                        type: str
                        description: Upload server login username2.
                    username3:
                        type: str
                        description: Upload server login username3.
                    when:
                        type: str
                        description:
                         - Roll log files periodically.
                         - none - Do not roll log files periodically.
                         - daily - Roll log files daily.
                         - weekly - Roll log files on certain days of week.
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
                    rolling-upgrade-status:
                        type: int
                        description: rolling upgrade status
                    server:
                        type: str
                        description: Upload server FQDN/IP.
                    server2:
                        type: str
                        description: Upload server2 FQDN/IP.
                    server3:
                        type: str
                        description: Upload server3 FQDN/IP.
            rolling-regular:
                description: no description
                type: dict
                suboptions:
                    days:
                        description:
                         - Log files rolling schedule
                         - sun - Sunday.
                         - mon - Monday.
                         - tue - Tuesday.
                         - wed - Wednesday.
                         - thu - Thursday.
                         - fri - Friday.
                         - sat - Saturday.
                        type: list
                        elements: str
                        choices:
                            - 'sun'
                            - 'mon'
                            - 'tue'
                            - 'wed'
                            - 'thu'
                            - 'fri'
                            - 'sat'
                    del-files:
                        type: str
                        description:
                         - Enable/disable log file deletion after uploading.
                         - disable - Disable log file deletion.
                         - enable - Enable log file deletion.
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: Upload server directory, for Unix server, use absolute
                    file-size:
                        type: int
                        description: Roll log files when they reach this size
                    gzip-format:
                        type: str
                        description:
                         - Enable/disable compression of uploaded log files.
                         - disable - Disable compression.
                         - enable - Enable compression.
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        description: Log files rolling schedule
                    ip:
                        type: str
                        description: Upload server IP address.
                    ip2:
                        type: str
                        description: Upload server IP2 address.
                    ip3:
                        type: str
                        description: Upload server IP3 address.
                    log-format:
                        type: str
                        description:
                         - Format of uploaded log files.
                         - native - Native format
                         - text - Text format
                         - csv - CSV
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        description: Log files rolling schedule
                    password:
                        description: Upload server login password.
                        type: str
                    password2:
                        description: Upload server login password2.
                        type: str
                    password3:
                        description: Upload server login password3.
                        type: str
                    port:
                        type: int
                        description: Upload server IP1 port number.
                    port2:
                        type: int
                        description: Upload server IP2 port number.
                    port3:
                        type: int
                        description: Upload server IP3 port number.
                    server-type:
                        type: str
                        description:
                         - Upload server type.
                         - ftp - Upload via FTP.
                         - sftp - Upload via SFTP.
                         - scp - Upload via SCP.
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        description:
                         - Enable/disable log file uploads.
                         - disable - Disable log files uploading.
                         - enable - Enable log files uploading.
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        description: Log files upload schedule
                    upload-mode:
                        type: str
                        description:
                         - Upload mode with multiple servers.
                         - backup - Servers are attempted and used one after the other upon failure to connect.
                         - mirror - All configured servers are attempted and used.
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        description:
                         - Event triggering log files upload.
                         - on-roll - Upload log files after they are rolled.
                         - on-schedule - Upload log files daily.
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: Upload server login username.
                    username2:
                        type: str
                        description: Upload server login username2.
                    username3:
                        type: str
                        description: Upload server login username3.
                    when:
                        type: str
                        description:
                         - Roll log files periodically.
                         - none - Do not roll log files periodically.
                         - daily - Roll log files daily.
                         - weekly - Roll log files on certain days of week.
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
                    rolling-upgrade-status:
                        type: int
                        description: rolling upgrade status
                    server:
                        type: str
                        description: Upload server FQDN/IP.
                    server2:
                        type: str
                        description: Upload server2 FQDN/IP.
                    server3:
                        type: str
                        description: Upload server3 FQDN/IP.
            sync-search-timeout:
                type: int
                description: Maximum number of seconds for running a log search session in synchronous mode.
            keep-dev-logs:
                type: str
                description:
                 - Enable/Disable keeping the dev logs after the device has been deleted.
                 - disable - Disable keeping the dev logs after the device has been deleted.
                 - enable - Enable keeping the dev logs after the device has been deleted.
                choices:
                    - 'disable'
                    - 'enable'
            device-auto-detect:
                type: str
                description:
                 - Enable/Disable looking up device ID in syslog received with no encryption.
                 - disable - Disable looking up device ID in syslog received with no encryption.
                 - enable - Enable looking up device ID in syslog received with no encryption.
                choices:
                    - 'disable'
                    - 'enable'
            unencrypted-logging:
                type: str
                description:
                 - Enable/Disable receiving syslog through UDP
                 - disable - Disable receiving syslog through UDP
                 - enable - Enable receiving syslog through UDP
                choices:
                    - 'disable'
                    - 'enable'
            log-interval-dev-no-logging:
                type: int
                description: Interval in minute of no log received from a device when considering the device down.
            log-upload-interval-dev-no-logging:
                type: int
                description: Interval in minute of no log uploaded from a device when considering the device down.
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Log settings.
      fortinet.fortianalyzer.faz_cli_system_log_settings:
        cli_system_log_settings:
          dns_resolve_dstip: disable
          download_max_logs: 100000
          ha_auto_migrate: disable
          import_max_logfiles: 10000
          sync_search_timeout: 60
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
        '/cli/global/system/log/settings'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log/settings/{settings}'
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
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_system_log_settings': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'FAC-custom-field1': {'type': 'str'},
                'FAZ-custom-field1': {'v_range': [['6.2.1', '7.2.0']], 'type': 'str'},
                'FCH-custom-field1': {'type': 'str'},
                'FCT-custom-field1': {'type': 'str'},
                'FDD-custom-field1': {'type': 'str'},
                'FGT-custom-field1': {'type': 'str'},
                'FMG-custom-field1': {'v_range': [['6.2.1', '7.2.0']], 'type': 'str'},
                'FML-custom-field1': {'type': 'str'},
                'FPX-custom-field1': {'type': 'str'},
                'FSA-custom-field1': {'type': 'str'},
                'FWB-custom-field1': {'type': 'str'},
                'browse-max-logfiles': {'type': 'int'},
                'dns-resolve-dstip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'download-max-logs': {'type': 'int'},
                'ha-auto-migrate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'import-max-logfiles': {'type': 'int'},
                'log-file-archive-name': {'choices': ['basic', 'extended'], 'type': 'str'},
                'rolling-analyzer': {
                    'type': 'dict',
                    'options': {
                        'days': {'type': 'list', 'choices': ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'elements': 'str'},
                        'del-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'directory': {'type': 'str'},
                        'file-size': {'type': 'int'},
                        'gzip-format': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'hour': {'type': 'int'},
                        'ip': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip2': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip3': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'log-format': {'choices': ['native', 'text', 'csv'], 'type': 'str'},
                        'min': {'type': 'int'},
                        'password': {'no_log': True, 'type': 'str'},
                        'password2': {'no_log': True, 'type': 'str'},
                        'password3': {'no_log': True, 'type': 'str'},
                        'port': {'type': 'int'},
                        'port2': {'type': 'int'},
                        'port3': {'type': 'int'},
                        'server-type': {'choices': ['ftp', 'sftp', 'scp'], 'type': 'str'},
                        'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'upload-hour': {'type': 'int'},
                        'upload-mode': {'choices': ['backup', 'mirror'], 'type': 'str'},
                        'upload-trigger': {'choices': ['on-roll', 'on-schedule'], 'type': 'str'},
                        'username': {'type': 'str'},
                        'username2': {'type': 'str'},
                        'username3': {'type': 'str'},
                        'when': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                        'rolling-upgrade-status': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server2': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server3': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    }
                },
                'rolling-local': {
                    'type': 'dict',
                    'options': {
                        'days': {'type': 'list', 'choices': ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'elements': 'str'},
                        'del-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'directory': {'type': 'str'},
                        'file-size': {'type': 'int'},
                        'gzip-format': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'hour': {'type': 'int'},
                        'ip': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip2': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip3': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'log-format': {'choices': ['native', 'text', 'csv'], 'type': 'str'},
                        'min': {'type': 'int'},
                        'password': {'no_log': True, 'type': 'str'},
                        'password2': {'no_log': True, 'type': 'str'},
                        'password3': {'no_log': True, 'type': 'str'},
                        'port': {'type': 'int'},
                        'port2': {'type': 'int'},
                        'port3': {'type': 'int'},
                        'server-type': {'choices': ['ftp', 'sftp', 'scp'], 'type': 'str'},
                        'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'upload-hour': {'type': 'int'},
                        'upload-mode': {'choices': ['backup', 'mirror'], 'type': 'str'},
                        'upload-trigger': {'choices': ['on-roll', 'on-schedule'], 'type': 'str'},
                        'username': {'type': 'str'},
                        'username2': {'type': 'str'},
                        'username3': {'type': 'str'},
                        'when': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                        'rolling-upgrade-status': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server2': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server3': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    }
                },
                'rolling-regular': {
                    'type': 'dict',
                    'options': {
                        'days': {'type': 'list', 'choices': ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'elements': 'str'},
                        'del-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'directory': {'type': 'str'},
                        'file-size': {'type': 'int'},
                        'gzip-format': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'hour': {'type': 'int'},
                        'ip': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip2': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'ip3': {'v_range': [['6.2.1', '7.0.12']], 'type': 'str'},
                        'log-format': {'choices': ['native', 'text', 'csv'], 'type': 'str'},
                        'min': {'type': 'int'},
                        'password': {'no_log': True, 'type': 'str'},
                        'password2': {'no_log': True, 'type': 'str'},
                        'password3': {'no_log': True, 'type': 'str'},
                        'port': {'type': 'int'},
                        'port2': {'type': 'int'},
                        'port3': {'type': 'int'},
                        'server-type': {'choices': ['ftp', 'sftp', 'scp'], 'type': 'str'},
                        'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'upload-hour': {'type': 'int'},
                        'upload-mode': {'choices': ['backup', 'mirror'], 'type': 'str'},
                        'upload-trigger': {'choices': ['on-roll', 'on-schedule'], 'type': 'str'},
                        'username': {'type': 'str'},
                        'username2': {'type': 'str'},
                        'username3': {'type': 'str'},
                        'when': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                        'rolling-upgrade-status': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server2': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'server3': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    }
                },
                'sync-search-timeout': {'type': 'int'},
                'keep-dev-logs': {'v_range': [['6.4.7', '6.4.14'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-auto-detect': {
                    'v_range': [['7.0.10', '7.0.12'], ['7.2.4', '7.2.5'], ['7.4.1', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'unencrypted-logging': {
                    'v_range': [['7.0.10', '7.0.12'], ['7.2.4', '7.2.5'], ['7.4.1', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'log-interval-dev-no-logging': {'v_range': [['7.2.5', '7.2.5'], ['7.4.2', '']], 'type': 'int'},
                'log-upload-interval-dev-no-logging': {'v_range': [['7.2.5', '7.2.5'], ['7.4.2', '']], 'type': 'int'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_log_settings'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params['access_token'])
    connection.set_option('enable_log', module.params['enable_log'])
    connection.set_option('forticloud_access_token', module.params['forticloud_access_token'])
    connection.set_option('log_path', module.params['log_path'])
    faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection,
                      metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
