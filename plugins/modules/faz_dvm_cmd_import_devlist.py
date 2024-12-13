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
module: faz_dvm_cmd_import_devlist
short_description: Import a list of ADOMs and devices.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
    - This module supports check mode.
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
    dvm_cmd_import_devlist:
        description: The top level parameters set.
        type: dict
        suboptions:
            adom:
                type: str
                description: Name or ID of the ADOM where the command is to be executed on.
            flags:
                description:
                 - create_task - Create a new task in task manager database.
                 - nonblocking - The API will return immediately in for non-blocking call.
                type: list
                elements: str
                choices: ['none', 'create_task', 'nonblocking']
            import_adom_members:
                aliases: ['import-adom-members']
                description: Associations between devices and ADOMs.
                type: list
                elements: dict
                suboptions:
                    adom:
                        type: str
                        description: Target ADOM to associate device VDOM with.
                    dev:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            import_adoms:
                aliases: ['import-adoms']
                description: A list of ADOM and device group objects to be imported.
                type: list
                elements: dict
                suboptions:
                    desc:
                        type: str
                        description: no description
                    flags:
                        description: no description
                        type: list
                        elements: str
                        choices:
                            - 'migration'
                            - 'db_export'
                            - 'no_vpn_console'
                            - 'backup'
                            - 'other_devices'
                            - 'central_sdwan'
                            - 'is_autosync'
                            - 'per_device_wtp'
                            - 'policy_check_on_install'
                            - 'install_on_policy_check_fail'
                            - 'auto_push_cfg'
                            - 'per_device_fsw'
                            - 'install_deselect_all'
                    log_db_retention_hours:
                        type: int
                        description: no description
                    log_disk_quota:
                        type: int
                        description: no description
                    log_disk_quota_alert_thres:
                        type: int
                        description: no description
                    log_disk_quota_split_ratio:
                        type: int
                        description: no description
                    log_file_retention_hours:
                        type: int
                        description: no description
                    meta_fields:
                        aliases: ['meta fields']
                        description: no description
                        type: dict
                    mig_mr:
                        type: int
                        description: no description
                    mig_os_ver:
                        type: str
                        description: no description
                        choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0']
                    mode:
                        type: str
                        description:
                         - ems -
                         - provider - Global database.
                        choices: ['ems', 'gms', 'provider']
                    mr:
                        type: int
                        description: no description
                    name:
                        type: str
                        description: no description
                    os_ver:
                        type: str
                        description: no description
                        choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0']
                    restricted_prds:
                        description: no description
                        type: list
                        elements: str
                        choices:
                            - 'fos'
                            - 'foc'
                            - 'fml'
                            - 'fch'
                            - 'fwb'
                            - 'log'
                            - 'fct'
                            - 'faz'
                            - 'fsa'
                            - 'fsw'
                            - 'fmg'
                            - 'fdd'
                            - 'fac'
                            - 'fpx'
                            - 'fna'
                            - 'fdc'
                            - 'ffw'
                            - 'fsr'
                            - 'fad'
                            - 'fts'
                            - 'fap'
                            - 'fxt'
                            - 'fai'
                            - 'fwc'
                    state:
                        type: int
                        description: no description
                    uuid:
                        type: str
                        description: no description
                    create_time:
                        type: int
                        description: no description
                    workspace_mode:
                        type: int
                        description: no description
                    tz:
                        type: int
                        description: no description
                    lock_override:
                        type: int
                        description: no description
                    primary_dns_ip4:
                        type: str
                        description: no description
                    primary_dns_ip6_1:
                        type: int
                        description: no description
                    primary_dns_ip6_2:
                        type: int
                        description: no description
                    primary_dns_ip6_3:
                        type: int
                        description: no description
                    primary_dns_ip6_4:
                        type: int
                        description: no description
                    secondary_dns_ip4:
                        type: str
                        description: no description
                    secondary_dns_ip6_1:
                        type: int
                        description: no description
                    secondary_dns_ip6_2:
                        type: int
                        description: no description
                    secondary_dns_ip6_3:
                        type: int
                        description: no description
                    secondary_dns_ip6_4:
                        type: int
                        description: no description
            import_devices:
                aliases: ['import-devices']
                description: A list of device objects to be imported.
                type: list
                elements: dict
                suboptions:
                    adm_pass:
                        description: no description
                        type: str
                    adm_usr:
                        type: str
                        description: no description
                    app_ver:
                        type: str
                        description: no description
                    av_ver:
                        type: str
                        description: no description
                    beta:
                        type: int
                        description: no description
                    branch_pt:
                        type: int
                        description: no description
                    build:
                        type: int
                        description: no description
                    checksum:
                        type: str
                        description: no description
                    conf_status:
                        type: str
                        description: no description
                        choices: ['unknown', 'insync', 'outofsync']
                    conn_mode:
                        type: str
                        description: no description
                        choices: ['active', 'passive']
                    conn_status:
                        type: str
                        description: no description
                        choices: ['UNKNOWN', 'up', 'down']
                    db_status:
                        type: str
                        description: no description
                        choices: ['unknown', 'nomod', 'mod']
                    desc:
                        type: str
                        description: no description
                    dev_status:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'unknown'
                            - 'checkedin'
                            - 'inprogress'
                            - 'installed'
                            - 'aborted'
                            - 'sched'
                            - 'retry'
                            - 'canceled'
                            - 'pending'
                            - 'retrieved'
                            - 'changed_conf'
                            - 'sync_fail'
                            - 'timeout'
                            - 'rev_revert'
                            - 'auto_updated'
                    fap_cnt:
                        type: int
                        description: no description
                    faz_full_act:
                        aliases: ['faz.full_act']
                        type: int
                        description: no description
                    faz_perm:
                        aliases: ['faz.perm']
                        type: int
                        description: no description
                    faz_quota:
                        aliases: ['faz.quota']
                        type: int
                        description: no description
                    faz_used:
                        aliases: ['faz.used']
                        type: int
                        description: no description
                    fex_cnt:
                        type: int
                        description: no description
                    flags:
                        description: no description
                        type: list
                        elements: str
                        choices:
                            - 'has_hdd'
                            - 'vdom_enabled'
                            - 'discover'
                            - 'reload'
                            - 'interim_build'
                            - 'offline_mode'
                            - 'is_model'
                            - 'fips_mode'
                            - 'linked_to_model'
                            - 'ip-conflict'
                            - 'faz-autosync'
                            - 'need_reset'
                            - 'backup_mode'
                            - 'azure_vwan_nva'
                            - 'fgsp_configured'
                            - 'cnf_mode'
                            - 'sase_managed'
                            - 'override_management_intf'
                            - 'sdwan_management'
                            - 'deny_api_access'
                    foslic_cpu:
                        type: int
                        description: VM Meter vCPU count.
                    foslic_dr_site:
                        type: str
                        description: VM Meter DR Site status.
                        choices: ['disable', 'enable']
                    foslic_inst_time:
                        type: int
                        description: VM Meter first deployment time
                    foslic_last_sync:
                        type: int
                        description: VM Meter last synchronized time
                    foslic_ram:
                        type: int
                        description: VM Meter device RAM size
                    foslic_type:
                        type: str
                        description: VM Meter license type.
                        choices: ['temporary', 'trial', 'regular', 'trial_expired']
                    foslic_utm:
                        description:
                         - VM Meter services
                         - fw - Firewall
                         - av - Anti-virus
                         - ips - IPS
                         - app - App control
                         - url - Web filter
                         - utm - Full UTM
                         - fwb - FortiWeb
                        type: list
                        elements: str
                        choices: ['fw', 'av', 'ips', 'app', 'url', 'utm', 'fwb']
                    fsw_cnt:
                        type: int
                        description: no description
                    ha_group_id:
                        type: int
                        description: no description
                    ha_group_name:
                        type: str
                        description: no description
                    ha_mode:
                        type: str
                        description: enabled - Value reserved for non-FOS HA devices.
                        choices: ['standalone', 'AP', 'AA', 'ELBC', 'DUAL', 'enabled', 'unknown', 'fmg-enabled', 'autoscale']
                    ha_slave:
                        description: no description
                        type: list
                        elements: dict
                        suboptions:
                            idx:
                                type: int
                                description: no description
                            name:
                                type: str
                                description: no description
                            prio:
                                type: int
                                description: no description
                            role:
                                type: str
                                description: no description
                                choices: ['slave', 'master']
                            sn:
                                type: str
                                description: no description
                            status:
                                type: int
                                description: no description
                            conf_status:
                                type: int
                                description: no description
                    hdisk_size:
                        type: int
                        description: no description
                    hostname:
                        type: str
                        description: no description
                    hw_rev_major:
                        type: int
                        description: no description
                    hw_rev_minor:
                        type: int
                        description: no description
                    ip:
                        type: str
                        description: no description
                    ips_ext:
                        type: int
                        description: no description
                    ips_ver:
                        type: str
                        description: no description
                    last_checked:
                        type: int
                        description: no description
                    last_resync:
                        type: int
                        description: no description
                    latitude:
                        type: str
                        description: no description
                    lic_flags:
                        type: int
                        description: no description
                    lic_region:
                        type: str
                        description: no description
                    location_from:
                        type: str
                        description: no description
                    logdisk_size:
                        type: int
                        description: no description
                    longitude:
                        type: str
                        description: no description
                    maxvdom:
                        type: int
                        description: no description
                    meta_fields:
                        aliases: ['meta fields']
                        description: no description
                        type: dict
                    mgmt_id:
                        type: int
                        description: no description
                    mgmt_if:
                        type: str
                        description: no description
                    mgmt_mode:
                        type: str
                        description: no description
                        choices: ['unreg', 'fmg', 'faz', 'fmgfaz']
                    mgt_vdom:
                        type: str
                        description: no description
                    module_sn:
                        type: str
                        description: no description
                    mr:
                        type: int
                        description: no description
                    name:
                        type: str
                        description: Unique name for the device.
                    os_type:
                        type: str
                        description: no description
                        choices:
                            - 'unknown'
                            - 'fos'
                            - 'fsw'
                            - 'foc'
                            - 'fml'
                            - 'faz'
                            - 'fwb'
                            - 'fch'
                            - 'fct'
                            - 'log'
                            - 'fmg'
                            - 'fsa'
                            - 'fdd'
                            - 'fac'
                            - 'fpx'
                            - 'fna'
                            - 'fdc'
                            - 'ffw'
                            - 'fsr'
                            - 'fad'
                            - 'fts'
                            - 'fap'
                            - 'fxt'
                            - 'fai'
                            - 'fwc'
                            - 'fis'
                            - 'fed'
                            - 'fpa'
                            - 'fca'
                            - 'ftc'
                            - 'fss'
                    os_ver:
                        type: str
                        description: no description
                        choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0']
                    patch:
                        type: int
                        description: no description
                    platform_str:
                        type: str
                        description: no description
                    prefer_img_ver:
                        type: str
                        description: no description
                    psk:
                        type: str
                        description: no description
                    sn:
                        type: str
                        description: Unique value for each device.
                    vdom:
                        description: no description
                        type: list
                        elements: dict
                        suboptions:
                            comments:
                                type: str
                                description: no description
                            name:
                                type: str
                                description: no description
                            opmode:
                                type: str
                                description: no description
                                choices: ['nat', 'transparent']
                            rtm_prof_id:
                                type: int
                                description: no description
                            status:
                                type: str
                                description: no description
                            vpn_id:
                                type: int
                                description: no description
                            meta_fields:
                                aliases: ['meta fields']
                                description: no description
                                type: dict
                            vdom_type:
                                type: str
                                description: no description
                                choices: ['traffic', 'admin']
                    version:
                        type: int
                        description: no description
                    vm_cpu:
                        type: int
                        description: no description
                    vm_cpu_limit:
                        type: int
                        description: no description
                    vm_lic_expire:
                        type: int
                        description: no description
                    vm_mem:
                        type: int
                        description: no description
                    vm_mem_limit:
                        type: int
                        description: no description
                    vm_status:
                        type: int
                        description: no description
                    hyperscale:
                        type: int
                        description: no description
                    private_key:
                        type: str
                        description: no description
                    private_key_status:
                        type: int
                        description: no description
                    prio:
                        type: int
                        description: no description
                    role:
                        type: str
                        description: no description
                        choices: ['master', 'ha-slave', 'autoscale-slave']
                    nsxt_service_name:
                        type: str
                        description: no description
                    vm_lic_overdue_since:
                        type: int
                        description: no description
                    first_tunnel_up:
                        type: int
                        description: no description
                    eip:
                        type: str
                        description: no description
                    mgmt_uuid:
                        type: str
                        description: no description
                    hw_generation:
                        type: int
                        description: no description
                    ha_vsn:
                        aliases: ['ha.vsn']
                        type: str
                        description: no description
                    relver_info:
                        type: str
                        description: no description
                    ha_upgrade_mode:
                        type: int
                        description: no description
                    vm_payg_status:
                        type: int
                        description: no description
                    cluster_worker:
                        type: str
                        description: no description
            import_group_members:
                aliases: ['import-group-members']
                description: Associations between devices and device groups.
                type: list
                elements: dict
                suboptions:
                    adom:
                        type: str
                        description: ADOM where the device group is located.
                    dev:
                        type: str
                        description: no description
                    grp:
                        type: str
                        description: Target device group to associate device VDOM with.
                    vdom:
                        type: str
                        description: no description
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Import a list of ADOMs and devices.
      fortinet.fortianalyzer.faz_dvm_cmd_import_devlist:
        dvm_cmd_import_devlist:
          adom: root
          flags:
            - create_task
            - nonblocking
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
        '/dvm/cmd/import/dev-list'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'dvm_cmd_import_devlist': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'adom': {'type': 'str'},
                'flags': {'type': 'list', 'choices': ['none', 'create_task', 'nonblocking'], 'elements': 'str'},
                'import-adom-members': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'dev': {'type': 'str'}, 'vdom': {'type': 'str'}},
                    'elements': 'dict'
                },
                'import-adoms': {
                    'type': 'list',
                    'options': {
                        'desc': {'type': 'str'},
                        'flags': {
                            'type': 'list',
                            'choices': [
                                'migration', 'db_export', 'no_vpn_console', 'backup', 'other_devices', 'central_sdwan', 'is_autosync', 'per_device_wtp',
                                'policy_check_on_install', 'install_on_policy_check_fail', 'auto_push_cfg', 'per_device_fsw', 'install_deselect_all'
                            ],
                            'elements': 'str'
                        },
                        'log_db_retention_hours': {'type': 'int'},
                        'log_disk_quota': {'type': 'int'},
                        'log_disk_quota_alert_thres': {'type': 'int'},
                        'log_disk_quota_split_ratio': {'type': 'int'},
                        'log_file_retention_hours': {'type': 'int'},
                        'meta fields': {'type': 'dict'},
                        'mig_mr': {'type': 'int'},
                        'mig_os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                        'mode': {'choices': ['ems', 'gms', 'provider'], 'type': 'str'},
                        'mr': {'type': 'int'},
                        'name': {'type': 'str'},
                        'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                        'restricted_prds': {
                            'type': 'list',
                            'choices': [
                                'fos', 'foc', 'fml', 'fch', 'fwb', 'log', 'fct', 'faz', 'fsa', 'fsw', 'fmg', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw',
                                'fsr', 'fad', 'fts', 'fap', 'fxt', 'fai', 'fwc'
                            ],
                            'elements': 'str'
                        },
                        'state': {'type': 'int'},
                        'uuid': {'type': 'str'},
                        'create_time': {'v_range': [['6.4.1', '']], 'type': 'int'},
                        'workspace_mode': {'v_range': [['6.4.3', '']], 'type': 'int'},
                        'tz': {'v_range': [['7.4.0', '']], 'type': 'int'},
                        'lock_override': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'primary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'primary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'secondary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'import-devices': {
                    'type': 'list',
                    'options': {
                        'adm_pass': {'no_log': True, 'type': 'str'},
                        'adm_usr': {'type': 'str'},
                        'app_ver': {'type': 'str'},
                        'av_ver': {'type': 'str'},
                        'beta': {'type': 'int'},
                        'branch_pt': {'type': 'int'},
                        'build': {'type': 'int'},
                        'checksum': {'type': 'str'},
                        'conf_status': {'choices': ['unknown', 'insync', 'outofsync'], 'type': 'str'},
                        'conn_mode': {'choices': ['active', 'passive'], 'type': 'str'},
                        'conn_status': {'choices': ['UNKNOWN', 'up', 'down'], 'type': 'str'},
                        'db_status': {'choices': ['unknown', 'nomod', 'mod'], 'type': 'str'},
                        'desc': {'type': 'str'},
                        'dev_status': {
                            'choices': [
                                'none', 'unknown', 'checkedin', 'inprogress', 'installed', 'aborted', 'sched', 'retry', 'canceled', 'pending',
                                'retrieved', 'changed_conf', 'sync_fail', 'timeout', 'rev_revert', 'auto_updated'
                            ],
                            'type': 'str'
                        },
                        'fap_cnt': {'type': 'int'},
                        'faz.full_act': {'type': 'int'},
                        'faz.perm': {'type': 'int'},
                        'faz.quota': {'type': 'int'},
                        'faz.used': {'type': 'int'},
                        'fex_cnt': {'type': 'int'},
                        'flags': {
                            'type': 'list',
                            'choices': [
                                'has_hdd', 'vdom_enabled', 'discover', 'reload', 'interim_build', 'offline_mode', 'is_model', 'fips_mode',
                                'linked_to_model', 'ip-conflict', 'faz-autosync', 'need_reset', 'backup_mode', 'azure_vwan_nva', 'fgsp_configured',
                                'cnf_mode', 'sase_managed', 'override_management_intf', 'sdwan_management', 'deny_api_access'
                            ],
                            'elements': 'str'
                        },
                        'foslic_cpu': {'type': 'int'},
                        'foslic_dr_site': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'foslic_inst_time': {'type': 'int'},
                        'foslic_last_sync': {'type': 'int'},
                        'foslic_ram': {'type': 'int'},
                        'foslic_type': {'choices': ['temporary', 'trial', 'regular', 'trial_expired'], 'type': 'str'},
                        'foslic_utm': {'type': 'list', 'choices': ['fw', 'av', 'ips', 'app', 'url', 'utm', 'fwb'], 'elements': 'str'},
                        'fsw_cnt': {'type': 'int'},
                        'ha_group_id': {'type': 'int'},
                        'ha_group_name': {'type': 'str'},
                        'ha_mode': {
                            'choices': ['standalone', 'AP', 'AA', 'ELBC', 'DUAL', 'enabled', 'unknown', 'fmg-enabled', 'autoscale'],
                            'type': 'str'
                        },
                        'ha_slave': {
                            'type': 'list',
                            'options': {
                                'idx': {'type': 'int'},
                                'name': {'type': 'str'},
                                'prio': {'type': 'int'},
                                'role': {'choices': ['slave', 'master'], 'type': 'str'},
                                'sn': {'type': 'str'},
                                'status': {'type': 'int'},
                                'conf_status': {'v_range': [['7.0.10', '7.0.13'], ['7.2.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'hdisk_size': {'type': 'int'},
                        'hostname': {'type': 'str'},
                        'hw_rev_major': {'type': 'int'},
                        'hw_rev_minor': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'ips_ext': {'type': 'int'},
                        'ips_ver': {'type': 'str'},
                        'last_checked': {'type': 'int'},
                        'last_resync': {'type': 'int'},
                        'latitude': {'type': 'str'},
                        'lic_flags': {'type': 'int'},
                        'lic_region': {'type': 'str'},
                        'location_from': {'type': 'str'},
                        'logdisk_size': {'type': 'int'},
                        'longitude': {'type': 'str'},
                        'maxvdom': {'type': 'int'},
                        'meta fields': {'type': 'dict'},
                        'mgmt_id': {'v_range': [['6.2.1', '7.2.0']], 'type': 'int'},
                        'mgmt_if': {'type': 'str'},
                        'mgmt_mode': {'choices': ['unreg', 'fmg', 'faz', 'fmgfaz'], 'type': 'str'},
                        'mgt_vdom': {'type': 'str'},
                        'module_sn': {'type': 'str'},
                        'mr': {'type': 'int'},
                        'name': {'type': 'str'},
                        'os_type': {
                            'choices': [
                                'unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac', 'fpx', 'fna',
                                'fdc', 'ffw', 'fsr', 'fad', 'fts', 'fap', 'fxt', 'fai', 'fwc', 'fis', 'fed', 'fpa', 'fca', 'ftc', 'fss'
                            ],
                            'type': 'str'
                        },
                        'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                        'patch': {'type': 'int'},
                        'platform_str': {'type': 'str'},
                        'prefer_img_ver': {'type': 'str'},
                        'psk': {'type': 'str'},
                        'sn': {'type': 'str'},
                        'vdom': {
                            'type': 'list',
                            'options': {
                                'comments': {'type': 'str'},
                                'name': {'type': 'str'},
                                'opmode': {'choices': ['nat', 'transparent'], 'type': 'str'},
                                'rtm_prof_id': {'type': 'int'},
                                'status': {'type': 'str'},
                                'vpn_id': {'type': 'int'},
                                'meta fields': {'v_range': [['6.4.3', '']], 'type': 'dict'},
                                'vdom_type': {'v_range': [['7.2.0', '']], 'choices': ['traffic', 'admin'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'version': {'type': 'int'},
                        'vm_cpu': {'type': 'int'},
                        'vm_cpu_limit': {'type': 'int'},
                        'vm_lic_expire': {'type': 'int'},
                        'vm_mem': {'type': 'int'},
                        'vm_mem_limit': {'type': 'int'},
                        'vm_status': {'type': 'int'},
                        'hyperscale': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                        'private_key': {'v_range': [['6.2.7', '6.2.13'], ['6.4.4', '']], 'no_log': True, 'type': 'str'},
                        'private_key_status': {'v_range': [['6.2.7', '6.2.13'], ['6.4.4', '']], 'no_log': False, 'type': 'int'},
                        'prio': {'v_range': [['6.4.1', '']], 'type': 'int'},
                        'role': {'v_range': [['6.4.1', '']], 'choices': ['master', 'ha-slave', 'autoscale-slave'], 'type': 'str'},
                        'nsxt_service_name': {'v_range': [['6.4.4', '']], 'type': 'str'},
                        'vm_lic_overdue_since': {'v_range': [['6.4.12', '6.4.15'], ['7.0.8', '7.0.13'], ['7.2.3', '']], 'type': 'int'},
                        'first_tunnel_up': {'v_range': [['7.0.4', '7.0.13'], ['7.2.1', '']], 'type': 'int'},
                        'eip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'mgmt_uuid': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'hw_generation': {'v_range': [['7.2.4', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                        'ha.vsn': {'v_range': [['7.2.6', '7.2.8'], ['7.4.4', '']], 'type': 'str'},
                        'relver_info': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'ha_upgrade_mode': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'vm_payg_status': {'v_range': [['7.4.4', '7.4.5']], 'type': 'int'},
                        'cluster_worker': {'v_range': [['7.6.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'import-group-members': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'dev': {'type': 'str'}, 'grp': {'type': 'str'}, 'vdom': {'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'dvm_cmd_import_devlist'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(urls_list, module_primary_key, url_params, module, connection,
                               metadata=module_arg_spec, task_type='exec')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
