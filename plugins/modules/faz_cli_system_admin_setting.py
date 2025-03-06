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
module: faz_cli_system_admin_setting
short_description: Admin setting.
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
    cli_system_admin_setting:
        description: The top level parameters set.
        type: dict
        suboptions:
            access_banner:
                aliases: ['access-banner']
                type: str
                description:
                 - Enable/disable access banner.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            admin_https_redirect:
                aliases: ['admin-https-redirect']
                type: str
                description:
                 - Enable/disable redirection of HTTP admin traffic to HTTPS.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            admin_login_max:
                aliases: ['admin-login-max']
                type: int
                description: Maximum number admin users logged in at one time
            admin_server_cert:
                type: str
                description: HTTPS & Web Service server certificate.
            banner_message:
                aliases: ['banner-message']
                type: str
                description: Banner message.
            gui_theme:
                aliases: ['gui-theme']
                type: str
                description:
                 - Color scheme to use for the administration GUI.
                 - blue - Blueberry
                 - green - Kiwi
                 - red - Cherry
                 - melongene - Plum
                 - spring - Spring
                 - summer - Summer
                 - autumn - Autumn
                 - winter - Winter
                 - space - Space
                 - calla-lily - Calla Lily
                 - binary-tunnel - Binary Tunnel
                 - diving - Diving
                 - dreamy - Dreamy
                 - technology - Technology
                 - landscape - Landscape
                 - twilight - Twilight
                 - canyon - Canyon
                 - northern-light - Northern Light
                 - astronomy - Astronomy
                 - fish - Fish
                 - penguin - Penguin
                 - panda - Panda
                 - polar-bear - Polar Bear
                 - parrot - Parrot
                 - cave - Cave
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
                    - 'mariner'
                    - 'jade'
                    - 'neutrino'
                    - 'dark-matter'
                    - 'forest'
                    - 'cat'
                    - 'graphite'
            http_port:
                type: int
                description: HTTP port.
            https_port:
                type: int
                description: HTTPS port.
            idle_timeout:
                type: int
                description: Idle timeout
            objects_force_deletion:
                aliases: ['objects-force-deletion']
                type: str
                description:
                 - Enable/disable used objects force deletion.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            shell_access:
                aliases: ['shell-access']
                type: str
                description:
                 - Enable/disable shell access.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            shell_password:
                aliases: ['shell-password']
                description: Password for shell access.
                type: str
            show_add_multiple:
                aliases: ['show-add-multiple']
                type: str
                description:
                 - Show add multiple button.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            show_checkbox_in_table:
                aliases: ['show-checkbox-in-table']
                type: str
                description:
                 - Show checkboxs in tables on GUI.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            show_device_import_export:
                aliases: ['show-device-import-export']
                type: str
                description:
                 - Enable/disable import/export of ADOM, device, and group lists.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            show_fct_manager:
                aliases: ['show-fct-manager']
                type: str
                description:
                 - Enable/disable FCT manager.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            show_hostname:
                aliases: ['show-hostname']
                type: str
                description:
                 - Enable/disable hostname display in the GUI login page.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            show_log_forwarding:
                aliases: ['show-log-forwarding']
                type: str
                description:
                 - Show log forwarding tab in regular mode.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            unreg_dev_opt:
                type: str
                description:
                 - Action to take when unregistered device connects to FortiAnalyzer.
                 - add_no_service - Add unregistered devices but deny service requests.
                 - ignore - Ignore unregistered devices.
                 - add_allow_service - Add unregistered devices and allow service requests.
                choices: ['add_no_service', 'ignore', 'add_allow_service']
            webadmin_language:
                type: str
                description:
                 - Web admin language.
                 - auto_detect - Automatically detect language.
                 - english - English.
                 - simplified_chinese - Simplified Chinese.
                 - traditional_chinese - Traditional Chinese.
                 - japanese - Japanese.
                 - korean - Korean.
                 - spanish - Spanish.
                choices: ['auto_detect', 'english', 'simplified_chinese', 'traditional_chinese', 'japanese', 'korean', 'spanish', 'french']
            idle_timeout_api:
                type: int
                description: Idle timeout for API sessions
            idle_timeout_gui:
                type: int
                description: Idle timeout for GUI sessions
            auth_addr:
                aliases: ['auth-addr']
                type: str
                description: IP which is used by FGT to authorize FAZ.
            auth_port:
                aliases: ['auth-port']
                type: int
                description: Port which is used by FGT to authorize FAZ.
            preferred_fgfm_intf:
                aliases: ['preferred-fgfm-intf']
                type: str
                description: Preferred interface for FGFM connection.
            idle_timeout_sso:
                type: int
                description: Idle timeout for SSO sessions
            fsw_ignore_platform_check:
                aliases: ['fsw-ignore-platform-check']
                type: str
                description:
                 - Enable/disable FortiSwitch Manager switch platform support check.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            firmware_upgrade_check:
                aliases: ['firmware-upgrade-check']
                type: str
                description:
                 - Enable/disable firmware upgrade check.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            fgt_gui_proxy:
                aliases: ['fgt-gui-proxy']
                type: str
                description:
                 - Enable/disable FortiGate GUI proxy.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices: ['disable', 'enable']
            fgt_gui_proxy_port:
                aliases: ['fgt-gui-proxy-port']
                type: int
                description: FortiGate GUI proxy port.
            object_threshold_limit:
                aliases: ['object-threshold-limit']
                type: str
                description: no description
                choices: ['disable', 'enable']
            object_threshold_limit_value:
                aliases: ['object-threshold-limit-value']
                type: int
                description: no description
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Admin setting.
      fortinet.fortianalyzer.faz_cli_system_admin_setting:
        cli_system_admin_setting:
          access_banner: disable
          admin_https_redirect: disable
          objects_force_deletion: disable
          shell_access: disable
          show_add_multiple: disable
          show_checkbox_in_table: disable
          show_device_import_export: disable
          show_fct_manager: disable
          show_hostname: disable
          show_log_forwarding: disable
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
        '/cli/global/system/admin/setting'
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
        'cli_system_admin_setting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'access-banner': {'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-https-redirect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-login-max': {'type': 'int'},
                'admin_server_cert': {'type': 'str'},
                'banner-message': {'type': 'str'},
                'gui-theme': {
                    'choices': [
                        'blue', 'green', 'red', 'melongene', 'spring', 'summer', 'autumn', 'winter', 'space', 'calla-lily', 'binary-tunnel', 'diving',
                        'dreamy', 'technology', 'landscape', 'twilight', 'canyon', 'northern-light', 'astronomy', 'fish', 'penguin', 'panda',
                        'polar-bear', 'parrot', 'cave', 'mountain', 'zebra', 'contrast-dark', 'circuit-board', 'mars', 'blue-sea', 'mariner', 'jade',
                        'neutrino', 'dark-matter', 'forest', 'cat', 'graphite'
                    ],
                    'type': 'str'
                },
                'http_port': {'type': 'int'},
                'https_port': {'type': 'int'},
                'idle_timeout': {'type': 'int'},
                'objects-force-deletion': {'choices': ['disable', 'enable'], 'type': 'str'},
                'shell-access': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'shell-password': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.3']], 'no_log': True, 'type': 'str'},
                'show-add-multiple': {'choices': ['disable', 'enable'], 'type': 'str'},
                'show-checkbox-in-table': {'choices': ['disable', 'enable'], 'type': 'str'},
                'show-device-import-export': {'choices': ['disable', 'enable'], 'type': 'str'},
                'show-fct-manager': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'show-hostname': {'choices': ['disable', 'enable'], 'type': 'str'},
                'show-log-forwarding': {'choices': ['disable', 'enable'], 'type': 'str'},
                'unreg_dev_opt': {'choices': ['add_no_service', 'ignore', 'add_allow_service'], 'type': 'str'},
                'webadmin_language': {
                    'choices': ['auto_detect', 'english', 'simplified_chinese', 'traditional_chinese', 'japanese', 'korean', 'spanish', 'french'],
                    'type': 'str'
                },
                'idle_timeout_api': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'idle_timeout_gui': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'auth-addr': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'auth-port': {'v_range': [['7.0.1', '']], 'type': 'int'},
                'preferred-fgfm-intf': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'idle_timeout_sso': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'fsw-ignore-platform-check': {'v_range': [['7.0.7', '7.0.13'], ['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firmware-upgrade-check': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgt-gui-proxy': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgt-gui-proxy-port': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'object-threshold-limit': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'object-threshold-limit-value': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_setting'),
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
