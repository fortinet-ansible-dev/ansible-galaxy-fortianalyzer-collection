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
module: faz_cli_system_locallog_fortianalyzer2_filter
short_description: Filter for FortiAnalyzer2 logging.
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
    cli_system_locallog_fortianalyzer2_filter:
        description: The top level parameters set.
        type: dict
        suboptions:
            devcfg:
                type: str
                description:
                 - Log device configuration message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            devops:
                type: str
                description:
                 - Managered devices operations messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            diskquota:
                type: str
                description:
                 - Log Fortianalyzer disk quota messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dm:
                type: str
                description:
                 - Log deployment manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dvm:
                type: str
                description:
                 - Log device manager messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            ediscovery:
                type: str
                description:
                 - Log Fortianalyzer ediscovery messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            epmgr:
                type: str
                description:
                 - Log endpoint manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            event:
                type: str
                description:
                 - Log event messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            eventmgmt:
                type: str
                description:
                 - Log Fortianalyzer event handler messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            faz:
                type: str
                description:
                 - Log Fortianalyzer messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fazha:
                type: str
                description:
                 - Log Fortianalyzer HA messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fazsys:
                type: str
                description:
                 - Log Fortianalyzer system messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fgd:
                type: str
                description:
                 - Log FortiGuard service message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm:
                type: str
                description:
                 - Log FGFM protocol message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fips:
                type: str
                description:
                 - Whether to log fips messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmgws:
                type: str
                description:
                 - Log web service messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmlmgr:
                type: str
                description:
                 - Log FortiMail manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmwmgr:
                type: str
                description:
                 - Log firmware manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortiview:
                type: str
                description:
                 - Log Fortianalyzer FortiView messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            glbcfg:
                type: str
                description:
                 - Log global database message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            ha:
                type: str
                description:
                 - Log HA message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            hcache:
                type: str
                description:
                 - Log Fortianalyzer hcache messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            incident:
                type: str
                description:
                 - Log Fortianalyzer incident messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            iolog:
                type: str
                description:
                 - Log debug IO log message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logd:
                type: str
                description:
                 - Log the status of log daemon.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logdb:
                type: str
                description:
                 - Log Fortianalyzer log DB messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logdev:
                type: str
                description:
                 - Log Fortianalyzer log device messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logfile:
                type: str
                description:
                 - Log Fortianalyzer log file messages.
                 - enable - Enable setting.
                 - disable - Disable setting.
                choices:
                    - 'enable'
                    - 'disable'
            logging:
                type: str
                description:
                 - Log Fortianalyzer logging messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            lrmgr:
                type: str
                description:
                 - Log log and report manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            objcfg:
                type: str
                description:
                 - Log object configuration change message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            report:
                type: str
                description:
                 - Log Fortianalyzer report messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            rev:
                type: str
                description:
                 - Log revision history message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            rtmon:
                type: str
                description:
                 - Log real-time monitor message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scfw:
                type: str
                description:
                 - Log firewall objects message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scply:
                type: str
                description:
                 - Log policy console message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scrmgr:
                type: str
                description:
                 - Log script manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scvpn:
                type: str
                description:
                 - Log VPN console message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            system:
                type: str
                description:
                 - Log system manager message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            webport:
                type: str
                description:
                 - Log web portal message.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            aid:
                type: str
                description:
                 - Log aid messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            docker:
                type: str
                description:
                 - Docker application generic messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            controller:
                type: str
                description:
                 - Controller application generic messages.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Filter for FortiAnalyzer2 logging.
      fortinet.fortianalyzer.faz_cli_system_locallog_fortianalyzer2_filter:
        cli_system_locallog_fortianalyzer2_filter:
          # aid: disable
          devcfg: disable
          devops: disable
          diskquota: disable
          dm: disable
          # docker: disable
          dvm: disable
          ediscovery: disable
          epmgr: disable
          event: disable
          eventmgmt: disable
          faz: disable
          fazha: disable
          fazsys: disable
          fgd: disable
          fgfm: disable
          fips: disable
          fmgws: disable
          fmlmgr: disable
          fmwmgr: disable
          fortiview: disable
          glbcfg: disable
          ha: disable
          hcache: disable
          # incident: disable
          iolog: disable
          logd: disable
          logdb: disable
          logdev: disable
          # logfile: <value in [enable, disable]>
          logging: disable
          lrmgr: disable
          objcfg: disable
          report: disable
          rev: disable
          rtmon: disable
          scfw: disable
          scply: disable
          scrmgr: disable
          scvpn: disable
          system: disable
          webport: disable
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
        '/cli/global/system/locallog/fortianalyzer2/filter'
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
        'cli_system_locallog_fortianalyzer2_filter': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'devcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'devops': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diskquota': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dvm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ediscovery': {'choices': ['disable', 'enable'], 'type': 'str'},
                'epmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'event': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eventmgmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'faz': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fazha': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fazsys': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgfm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fips': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmgws': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmlmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmwmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiview': {'choices': ['disable', 'enable'], 'type': 'str'},
                'glbcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ha': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hcache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'incident': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iolog': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logdb': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logdev': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logfile': {'choices': ['enable', 'disable'], 'type': 'str'},
                'logging': {'choices': ['disable', 'enable'], 'type': 'str'},
                'lrmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'objcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'report': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rev': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rtmon': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scfw': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scrmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scvpn': {'choices': ['disable', 'enable'], 'type': 'str'},
                'system': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'aid': {'v_range': [['6.4.1', '7.2.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'docker': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'controller': {'v_range': [['7.0.9', '7.0.12'], ['7.2.4', '7.2.7'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_locallog_fortianalyzer2_filter'),
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
