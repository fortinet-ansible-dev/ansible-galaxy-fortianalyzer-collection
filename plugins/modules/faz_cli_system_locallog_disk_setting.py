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
module: faz_cli_system_locallog_disk_setting
short_description: Settings for local disk logging.
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
    cli_system_locallog_disk_setting:
        description: The top level parameters set.
        type: dict
        suboptions:
            diskfull:
                type: str
                description:
                 - Policy to apply when disk is full.
                 - overwrite - Overwrite oldest log when disk is full.
                 - nolog - Stop logging when disk is full.
                choices: ['overwrite', 'nolog']
            log_disk_full_percentage:
                aliases: ['log-disk-full-percentage']
                type: int
                description: Consider log disk as full at this usage percentage.
            max_log_file_size:
                aliases: ['max-log-file-size']
                type: int
                description: Maximum log file size before rolling.
            roll_day:
                aliases: ['roll-day']
                description:
                 - Days of week to roll logs.
                 - sunday - Sunday.
                 - monday - Monday.
                 - tuesday - Tuesday.
                 - wednesday - Wednesday.
                 - thursday - Thursday.
                 - friday - Friday.
                 - saturday - Saturday.
                type: list
                elements: str
                choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
            roll_schedule:
                aliases: ['roll-schedule']
                type: str
                description:
                 - Frequency to check log file for rolling.
                 - none - Not scheduled.
                 - daily - Every day.
                 - weekly - Every week.
                choices: ['none', 'daily', 'weekly']
            roll_time:
                aliases: ['roll-time']
                type: str
                description: Time to roll logs
            server_type:
                aliases: ['server-type']
                type: str
                description:
                 - Server type.
                 - FTP - Upload via FTP.
                 - SFTP - Upload via SFTP.
                 - SCP - Upload via SCP.
                choices: ['FTP', 'SFTP', 'SCP']
            severity:
                type: str
                description:
                 - Least severity level to log.
                 - emergency - Emergency level.
                 - alert - Alert level.
                 - critical - Critical level.
                 - error - Error level.
                 - warning - Warning level.
                 - notification - Notification level.
                 - information - Information level.
                 - debug - Debug level.
                choices: ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug']
            status:
                type: str
                description:
                 - Enable/disable local disk log.
                 - disable - Do not log to local disk.
                 - enable - Log to local disk.
                choices: ['disable', 'enable']
            upload:
                type: str
                description:
                 - Upload log file when rolling.
                 - disable - Disable uploading when rolling log file.
                 - enable - Enable uploading when rolling log file.
                choices: ['disable', 'enable']
            upload_delete_files:
                aliases: ['upload-delete-files']
                type: str
                description:
                 - Delete log files after uploading
                 - disable - Do not delete log files after uploading.
                 - enable - Delete log files after uploading.
                choices: ['disable', 'enable']
            upload_time:
                aliases: ['upload-time']
                type: str
                description: Time to upload logs
            uploaddir:
                type: str
                description: Log file upload remote directory.
            uploadip:
                type: str
                description: IP address of log uploading server.
            uploadpass:
                description: Password of user account in upload server.
                type: str
            uploadport:
                type: int
                description: Server port
            uploadsched:
                type: str
                description:
                 - Scheduled upload
                 - disable - Upload when rolling.
                 - enable - Scheduled upload.
                choices: ['disable', 'enable']
            uploadtype:
                description:
                 - Types of log files that need to be uploaded.
                 - event - Upload event log.
                type: list
                elements: str
                choices: ['event']
            uploaduser:
                type: str
                description: User account in upload server.
            uploadzip:
                type: str
                description:
                 - Compress upload logs.
                 - disable - Upload log files as plain text.
                 - enable - Upload log files compressed.
                choices: ['disable', 'enable']
            max_log_file_num:
                aliases: ['max-log-file-num']
                type: int
                description: Maximum number of log files before rolling.
            log_disk_quota:
                aliases: ['log-disk-quota']
                type: int
                description: Quota for controlling local log size.
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Settings for local disk logging.
      fortinet.fortianalyzer.faz_cli_system_locallog_disk_setting:
        cli_system_locallog_disk_setting:
          # diskfull: <value in [overwrite, nolog]>
          # log_disk_full_percentage: <value of integer>
          # max_log_file_size: <value of integer>
          roll_day:
            - sunday
            - monday
            - tuesday
            - wednesday
            - thursday
            - friday
            - saturday
          # roll_schedule: <value in [none, daily, weekly]>
          # roll_time: <value of string>
          # server_type: <value in [FTP, SFTP, SCP]>
          # severity: <value in [emergency, alert, critical, ...]>
          status: disable
          upload: disable
          upload_delete_files: disable
          # upload_time: <value of string>
          # uploaddir: <value of string>
          # uploadip: <value of string>
          # uploadpass: <value of string>
          # uploadport: <value of integer>
          uploadsched: disable
          uploadtype:
            - event
          # uploaduser: <value of string>
          uploadzip: disable
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
        '/cli/global/system/locallog/disk/setting'
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
        'cli_system_locallog_disk_setting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'diskfull': {'choices': ['overwrite', 'nolog'], 'type': 'str'},
                'log-disk-full-percentage': {'type': 'int'},
                'max-log-file-size': {'type': 'int'},
                'roll-day': {'type': 'list', 'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'], 'elements': 'str'},
                'roll-schedule': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                'roll-time': {'type': 'str'},
                'server-type': {'choices': ['FTP', 'SFTP', 'SCP'], 'type': 'str'},
                'severity': {'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-delete-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-time': {'type': 'str'},
                'uploaddir': {'type': 'str'},
                'uploadip': {'type': 'str'},
                'uploadpass': {'no_log': True, 'type': 'str'},
                'uploadport': {'type': 'int'},
                'uploadsched': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uploadtype': {'type': 'list', 'choices': ['event'], 'elements': 'str'},
                'uploaduser': {'type': 'str'},
                'uploadzip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'max-log-file-num': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                'log-disk-quota': {'v_range': [['7.0.3', '']], 'type': 'int'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_locallog_disk_setting'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='partial crud')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
