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
module: faz_cli_system_admin_user
short_description: Admin user.
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
    cli_system_admin_user:
        description: The top level parameters set.
        type: dict
        suboptions:
            adom:
                description: no description
                type: list
                elements: dict
                suboptions:
                    adom_name:
                        type: str
                        description: Admin domain names.
            adom_exclude:
                description: no description
                type: list
                elements: dict
                suboptions:
                    adom_name:
                        type: str
                        description: Admin domain names.
            avatar:
                type: str
                description: Image file for avatar
            ca:
                type: str
                description: PKI user certificate CA
            change_password:
                type: str
                description:
                 - Enable/disable restricted user to change self password.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dashboard:
                description: no description
                type: list
                elements: dict
                suboptions:
                    column:
                        type: int
                        description: Widgets column ID.
                    diskio_content_type:
                        type: str
                        description:
                         - Disk I/O Monitor widgets chart type.
                         - util - bandwidth utilization.
                         - iops - the number of I/O requests.
                         - blks - the amount of data of I/O requests.
                        choices:
                            - 'util'
                            - 'iops'
                            - 'blks'
                    diskio_period:
                        type: str
                        description:
                         - Disk I/O Monitor widgets data period.
                         - 1hour - 1 hour.
                         - 8hour - 8 hour.
                         - 24hour - 24 hour.
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    log_rate_period:
                        type: str
                        description:
                         - Log receive monitor widgets data period.
                         - 2min  - 2 minutes.
                         - 1hour - 1 hour.
                         - 6hours - 6 hours.
                        choices:
                            - '2min '
                            - '1hour'
                            - '6hours'
                    log_rate_topn:
                        type: str
                        description:
                         - Log receive monitor widgets number of top items to display.
                         - 1 - Top 1.
                         - 2 - Top 2.
                         - 3 - Top 3.
                         - 4 - Top 4.
                         - 5 - Top 5.
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    log_rate_type:
                        type: str
                        description:
                         - Log receive monitor widgets statistics breakdown options.
                         - log - Show log rates for each log type.
                         - device - Show log rates for each device.
                        choices:
                            - 'log'
                            - 'device'
                    moduleid:
                        type: int
                        description: Widget ID.
                    name:
                        type: str
                        description: Widget name.
                    num_entries:
                        type: int
                        description: Number of entries.
                    refresh_interval:
                        type: int
                        description: Widgets refresh interval.
                    res_cpu_display:
                        type: str
                        description:
                         - Widgets CPU display type.
                         - average  - Average usage of CPU.
                         - each - Each usage of CPU.
                        choices:
                            - 'average '
                            - 'each'
                    res_period:
                        type: str
                        description:
                         - Widgets data period.
                         - 10min  - Last 10 minutes.
                         - hour - Last hour.
                         - day - Last day.
                        choices:
                            - '10min '
                            - 'hour'
                            - 'day'
                    res_view_type:
                        type: str
                        description:
                         - Widgets data view type.
                         - real-time  - Real-time view.
                         - history - History view.
                        choices:
                            - 'real-time '
                            - 'history'
                    status:
                        type: str
                        description:
                         - Widgets opened/closed state.
                         - close - Widget closed.
                         - open - Widget opened.
                        choices:
                            - 'close'
                            - 'open'
                    tabid:
                        type: int
                        description: ID of tab where widget is displayed.
                    time_period:
                        type: str
                        description:
                         - Log Database Monitor widgets data period.
                         - 1hour - 1 hour.
                         - 8hour - 8 hour.
                         - 24hour - 24 hour.
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    widget_type:
                        type: str
                        description:
                         - Widget type.
                         - top-lograte - Log Receive Monitor.
                         - sysres - System resources.
                         - sysinfo - System Information.
                         - licinfo - License Information.
                         - jsconsole - CLI Console.
                         - sysop - Unit Operation.
                         - alert - Alert Message Console.
                         - statistics - Statistics.
                         - rpteng - Report Engine.
                         - raid - Disk Monitor.
                         - logrecv - Logs/Data Received.
                         - devsummary - Device Summary.
                         - logdb-perf - Log Database Performance Monitor.
                         - logdb-lag - Log Database Lag Time.
                         - disk-io - Disk I/O.
                         - log-rcvd-fwd - Log receive and forwarding Monitor.
                        choices:
                            - 'top-lograte'
                            - 'sysres'
                            - 'sysinfo'
                            - 'licinfo'
                            - 'jsconsole'
                            - 'sysop'
                            - 'alert'
                            - 'statistics'
                            - 'rpteng'
                            - 'raid'
                            - 'logrecv'
                            - 'devsummary'
                            - 'logdb-perf'
                            - 'logdb-lag'
                            - 'disk-io'
                            - 'log-rcvd-fwd'
            dashboard_tabs:
                description: no description
                type: list
                elements: dict
                suboptions:
                    name:
                        type: str
                        description: Tab name.
                    tabid:
                        type: int
                        description: Tab ID.
            description:
                type: str
                description: Description.
            dev_group:
                type: str
                description: device group.
            email_address:
                type: str
                description: Email address.
            ext_auth_accprofile_override:
                type: str
                description:
                 - Allow to use the access profile provided by the remote authentication server.
                 - disable - Disable access profile override.
                 - enable - Enable access profile override.
                choices:
                    - 'disable'
                    - 'enable'
            ext_auth_adom_override:
                type: str
                description:
                 - Allow to use the ADOM provided by the remote authentication server.
                 - disable - Disable ADOM override.
                 - enable - Enable ADOM override.
                choices:
                    - 'disable'
                    - 'enable'
            ext_auth_group_match:
                type: str
                description: Only administrators belonging to this group can login.
            first_name:
                type: str
                description: First name.
            force_password_change:
                type: str
                description:
                 - Enable/disable force password change on next login.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            group:
                type: str
                description: Group name.
            hidden:
                type: int
                description: Hidden administrator.
            ipv6_trusthost1:
                type: str
                description: 'Admin user trusted host IPv6, default ::/0 for all.'
            ipv6_trusthost10:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost2:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost3:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost4:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost5:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost6:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost7:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost8:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost9:
                type: str
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            last_name:
                type: str
                description: Last name.
            ldap_server:
                type: str
                description: LDAP server name.
            meta_data:
                description: no description
                type: list
                elements: dict
                suboptions:
                    fieldlength:
                        type: int
                        description: Field length.
                    fieldname:
                        type: str
                        description: Field name.
                    fieldvalue:
                        type: str
                        description: Field value.
                    importance:
                        type: str
                        description:
                         - Importance.
                         - optional - This field is optional.
                         - required - This field is required.
                        choices:
                            - 'optional'
                            - 'required'
                    status:
                        type: str
                        description:
                         - Status.
                         - disabled - This field is disabled.
                         - enabled - This field is enabled.
                        choices:
                            - 'disabled'
                            - 'enabled'
            mobile_number:
                type: str
                description: Mobile number.
            pager_number:
                type: str
                description: Pager number.
            password:
                description: Password.
                type: str
            password_expire:
                type: str
                description: Password expire time in GMT.
            phone_number:
                type: str
                description: Phone number.
            policy_package:
                description: no description
                type: list
                elements: dict
                suboptions:
                    policy_package_name:
                        type: str
                        description: Policy package names.
            profileid:
                type: str
                description: Profile ID.
            radius_server:
                type: str
                description: RADIUS server name.
            restrict_access:
                type: str
                description:
                 - Enable/disable restricted access to development VDOM.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            restrict_dev_vdom:
                description: no description
                type: list
                elements: dict
                suboptions:
                    dev_vdom:
                        type: str
                        description: Device or device VDOM.
            rpc_permit:
                type: str
                description:
                 - set none/read/read-write rpc-permission.
                 - read-write - Read-write permission.
                 - none - No permission.
                 - read - Read-only permission.
                choices:
                    - 'read-write'
                    - 'none'
                    - 'read'
                    - 'from-profile'
            ssh_public_key1:
                description: SSH public key 1.
                type: str
            ssh_public_key2:
                description: SSH public key 2.
                type: str
            ssh_public_key3:
                description: SSH public key 3.
                type: str
            subject:
                type: str
                description: PKI user certificate name constraints.
            tacacs_plus_server:
                type: str
                description: TACACS+ server name.
            trusthost1:
                type: str
                description: Admin user trusted host IP, default 0.0.0.0 0.0.0.0 for all.
            trusthost10:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost2:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost3:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost4:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost5:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost6:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost7:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost8:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            trusthost9:
                type: str
                description: Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.
            two_factor_auth:
                type: str
                description:
                 - Enable 2-factor authentication
                 - disable - Disable 2-factor authentication.
                 - enable - Enable 2-factor authentication.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'password'
                    - 'ftc-ftm'
                    - 'ftc-email'
                    - 'ftc-sms'
            user_type:
                type: str
                description:
                 - User type.
                 - local - Local user.
                 - radius - RADIUS user.
                 - ldap - LDAP user.
                 - tacacs-plus - TACACS+ user.
                 - pki-auth - PKI user.
                 - group - Group user.
                 - sso - SSO user.
                choices:
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs-plus'
                    - 'pki-auth'
                    - 'group'
                    - 'sso'
                    - 'api'
            userid:
                type: str
                description: User name.
            wildcard:
                type: str
                description:
                 - Enable/disable wildcard remote authentication.
                 - disable - Disable username wildcard.
                 - enable - Enable username wildcard.
                choices:
                    - 'disable'
                    - 'enable'
            login_max:
                type: int
                description: Max login session for this user.
            fingerprint:
                type: str
                description: PKI user certificate fingerprint
            use_global_theme:
                type: str
                description:
                 - Enable/disble global theme for administration GUI.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            user_theme:
                type: str
                description:
                 - Color scheme to use for the admin user GUI.
                 - blue - Blueberry
                 - green - Kiwi
                 - red - Cherry
                 - melongene - Plum
                 - spring - Spring
                 - summer - Summer
                 - autumn - Autumn
                 - winter - Winter
                 - circuit-board - Circuit Board
                 - calla-lily - Calla Lily
                 - binary-tunnel - Binary Tunnel
                 - mars - Mars
                 - blue-sea - Blue Sea
                 - technology - Technology
                 - landscape - Landscape
                 - twilight - Twilight
                 - canyon - Canyon
                 - northern-light - Northern Light
                 - astronomy - Astronomy
                 - fish - Fish
                 - penguin - Penguin
                 - mountain - Mountain
                 - panda - Panda
                 - parrot - Parrot
                 - cave - Cave
                 - zebra - Zebra
                 - contrast-dark - High Contrast Dark
                choices:
                    - 'blue'
                    - 'green'
                    - 'red'
                    - 'melongene'
                    - 'spring'
                    - 'summer'
                    - 'autumn'
                    - 'winter'
                    - 'circuit-board'
                    - 'calla-lily'
                    - 'binary-tunnel'
                    - 'mars'
                    - 'blue-sea'
                    - 'technology'
                    - 'landscape'
                    - 'twilight'
                    - 'canyon'
                    - 'northern-light'
                    - 'astronomy'
                    - 'fish'
                    - 'penguin'
                    - 'mountain'
                    - 'panda'
                    - 'parrot'
                    - 'cave'
                    - 'zebra'
                    - 'contrast-dark'
                    - 'mariner'
                    - 'jade'
                    - 'neutrino'
                    - 'dark-matter'
                    - 'forest'
                    - 'cat'
                    - 'graphite'
            adom_access:
                type: str
                description:
                 - set all/specify/exclude adom access mode.
                 - all - All ADOMs access.
                 - specify - Specify ADOMs access.
                 - exclude - Exclude ADOMs access.
                choices:
                    - 'all'
                    - 'specify'
                    - 'exclude'
                    - 'per-adom-profile'
            th_from_profile:
                type: int
                description: 'Internal use only: trusthostX from-profile flag'
            th6_from_profile:
                type: int
                description: 'Internal use only: ipv6_trusthostX from-profile flag'
            cors_allow_origin:
                type: str
                description: Access-Control-Allow-Origin.
            fortiai:
                type: str
                description:
                 - Enable/disble FortiAI.
                 - disable - Disable setting.
                 - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            policy_block:
                description: no description
                type: list
                elements: dict
                suboptions:
                    policy_block_name:
                        type: str
                        description: Policy block names.
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Admin user.
      fortinet.fortianalyzer.faz_cli_system_admin_user:
        cli_system_admin_user:
          change_password: disable
          description: "admin user created via Ansible"
          email_address: "foo@ansible.com"
          ext_auth_accprofile_override: disable
          ext_auth_adom_override: disable
          profileid: 1
          two_factor_auth: disable
          userid: fooadminuser
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
        '/cli/global/system/admin/user'
    ]

    url_params = []
    module_primary_key = 'userid'
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
        'cli_system_admin_user': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'adom': {'type': 'list', 'options': {'adom-name': {'type': 'str'}}, 'elements': 'dict'},
                'adom-exclude': {
                    'v_range': [['6.2.1', '7.0.2']],
                    'type': 'list',
                    'options': {'adom-name': {'v_range': [['6.2.1', '7.0.2']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'avatar': {'type': 'str'},
                'ca': {'type': 'str'},
                'change-password': {'choices': ['disable', 'enable'], 'no_log': False, 'type': 'str'},
                'dashboard': {
                    'type': 'list',
                    'options': {
                        'column': {'type': 'int'},
                        'diskio-content-type': {'choices': ['util', 'iops', 'blks'], 'type': 'str'},
                        'diskio-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                        'log-rate-period': {'choices': ['2min ', '1hour', '6hours'], 'type': 'str'},
                        'log-rate-topn': {'choices': ['1', '2', '3', '4', '5'], 'type': 'str'},
                        'log-rate-type': {'choices': ['log', 'device'], 'type': 'str'},
                        'moduleid': {'type': 'int'},
                        'name': {'type': 'str'},
                        'num-entries': {'type': 'int'},
                        'refresh-interval': {'type': 'int'},
                        'res-cpu-display': {'choices': ['average ', 'each'], 'type': 'str'},
                        'res-period': {'choices': ['10min ', 'hour', 'day'], 'type': 'str'},
                        'res-view-type': {'choices': ['real-time ', 'history'], 'type': 'str'},
                        'status': {'choices': ['close', 'open'], 'type': 'str'},
                        'tabid': {'type': 'int'},
                        'time-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                        'widget-type': {
                            'choices': [
                                'top-lograte', 'sysres', 'sysinfo', 'licinfo', 'jsconsole', 'sysop', 'alert', 'statistics', 'rpteng', 'raid', 'logrecv',
                                'devsummary', 'logdb-perf', 'logdb-lag', 'disk-io', 'log-rcvd-fwd'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'dashboard-tabs': {'type': 'list', 'options': {'name': {'type': 'str'}, 'tabid': {'type': 'int'}}, 'elements': 'dict'},
                'description': {'type': 'str'},
                'dev-group': {'type': 'str'},
                'email-address': {'type': 'str'},
                'ext-auth-accprofile-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-auth-adom-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-auth-group-match': {'type': 'str'},
                'first-name': {'type': 'str'},
                'force-password-change': {'choices': ['disable', 'enable'], 'no_log': False, 'type': 'str'},
                'group': {'type': 'str'},
                'hidden': {'type': 'int'},
                'ipv6_trusthost1': {'type': 'str'},
                'ipv6_trusthost10': {'type': 'str'},
                'ipv6_trusthost2': {'type': 'str'},
                'ipv6_trusthost3': {'type': 'str'},
                'ipv6_trusthost4': {'type': 'str'},
                'ipv6_trusthost5': {'type': 'str'},
                'ipv6_trusthost6': {'type': 'str'},
                'ipv6_trusthost7': {'type': 'str'},
                'ipv6_trusthost8': {'type': 'str'},
                'ipv6_trusthost9': {'type': 'str'},
                'last-name': {'type': 'str'},
                'ldap-server': {'type': 'str'},
                'meta-data': {
                    'type': 'list',
                    'options': {
                        'fieldlength': {'type': 'int'},
                        'fieldname': {'type': 'str'},
                        'fieldvalue': {'type': 'str'},
                        'importance': {'choices': ['optional', 'required'], 'type': 'str'},
                        'status': {'choices': ['disabled', 'enabled'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mobile-number': {'type': 'str'},
                'pager-number': {'type': 'str'},
                'password': {'no_log': True, 'type': 'str'},
                'password-expire': {'no_log': False, 'type': 'str'},
                'phone-number': {'type': 'str'},
                'policy-package': {'type': 'list', 'options': {'policy-package-name': {'type': 'str'}}, 'elements': 'dict'},
                'profileid': {'type': 'str'},
                'radius_server': {'type': 'str'},
                'restrict-access': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restrict-dev-vdom': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'type': 'list',
                    'options': {'dev-vdom': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'rpc-permit': {'choices': ['read-write', 'none', 'read', 'from-profile'], 'type': 'str'},
                'ssh-public-key1': {'no_log': False, 'type': 'str'},
                'ssh-public-key2': {'no_log': False, 'type': 'str'},
                'ssh-public-key3': {'no_log': False, 'type': 'str'},
                'subject': {'type': 'str'},
                'tacacs-plus-server': {'type': 'str'},
                'trusthost1': {'type': 'str'},
                'trusthost10': {'type': 'str'},
                'trusthost2': {'type': 'str'},
                'trusthost3': {'type': 'str'},
                'trusthost4': {'type': 'str'},
                'trusthost5': {'type': 'str'},
                'trusthost6': {'type': 'str'},
                'trusthost7': {'type': 'str'},
                'trusthost8': {'type': 'str'},
                'trusthost9': {'type': 'str'},
                'two-factor-auth': {'choices': ['disable', 'enable', 'password', 'ftc-ftm', 'ftc-email', 'ftc-sms'], 'type': 'str'},
                'user_type': {'choices': ['local', 'radius', 'ldap', 'tacacs-plus', 'pki-auth', 'group', 'sso', 'api'], 'type': 'str'},
                'userid': {'type': 'str'},
                'wildcard': {'choices': ['disable', 'enable'], 'type': 'str'},
                'login-max': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'fingerprint': {'v_range': [['6.4.8', '6.4.14'], ['7.0.4', '']], 'type': 'str'},
                'use-global-theme': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-theme': {
                    'v_range': [['7.0.0', '']],
                    'choices': [
                        'blue', 'green', 'red', 'melongene', 'spring', 'summer', 'autumn', 'winter', 'circuit-board', 'calla-lily', 'binary-tunnel',
                        'mars', 'blue-sea', 'technology', 'landscape', 'twilight', 'canyon', 'northern-light', 'astronomy', 'fish', 'penguin',
                        'mountain', 'panda', 'parrot', 'cave', 'zebra', 'contrast-dark', 'mariner', 'jade', 'neutrino', 'dark-matter', 'forest', 'cat',
                        'graphite'
                    ],
                    'type': 'str'
                },
                'adom-access': {'v_range': [['7.0.3', '']], 'choices': ['all', 'specify', 'exclude', 'per-adom-profile'], 'type': 'str'},
                'th-from-profile': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'th6-from-profile': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'cors-allow-origin': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'fortiai': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-block': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {'policy-block-name': {'v_range': [['7.6.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_admin_user'),
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
