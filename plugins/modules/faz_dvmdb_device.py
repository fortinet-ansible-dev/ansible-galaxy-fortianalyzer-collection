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
module: faz_dvmdb_device
short_description: Device table, most attributes are read-only and can only be changed internally.
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
        required: false
        type: str
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    log_path:
        description:
            - The path to save log. Used if enable_log is true.
            - Please use absolute path instead of relative path.
            - If the log_path setting is incorrect, the log will be saved in /tmp/fortianalyzer.ansible.log
        required: false
        type: str
        default: '/tmp/fortianalyzer.ansible.log'
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        type: str
        required: false
        choices:
            - set
            - update
            - add
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
        elements: int
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
        required: false
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    dvmdb_device:
        description: The top level parameters set.
        required: false
        type: dict
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
                choices:
                    - 'unknown'
                    - 'insync'
                    - 'outofsync'
            conn_mode:
                type: str
                description: no description
                choices:
                    - 'active'
                    - 'passive'
            conn_status:
                type: str
                description: no description
                choices:
                    - 'UNKNOWN'
                    - 'up'
                    - 'down'
            db_status:
                type: str
                description: no description
                choices:
                    - 'unknown'
                    - 'nomod'
                    - 'mod'
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
            faz.full_act:
                type: int
                description: no description
            faz.perm:
                type: int
                description: no description
            faz.quota:
                type: int
                description: no description
            faz.used:
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
            foslic_cpu:
                type: int
                description: 'VM Meter vCPU count.'
            foslic_dr_site:
                type: str
                description: 'VM Meter DR Site status.'
                choices:
                    - 'disable'
                    - 'enable'
            foslic_inst_time:
                type: int
                description: 'VM Meter first deployment time (in UNIX timestamp).'
            foslic_last_sync:
                type: int
                description: 'VM Meter last synchronized time (in UNIX timestamp).'
            foslic_ram:
                type: int
                description: 'VM Meter device RAM size (in MB).'
            foslic_type:
                type: str
                description: 'VM Meter license type.'
                choices:
                    - 'temporary'
                    - 'trial'
                    - 'regular'
                    - 'trial_expired'
            foslic_utm:
                description: no description
                type: list
                elements: str
                choices:
                    - 'fw'
                    - 'av'
                    - 'ips'
                    - 'app'
                    - 'url'
                    - 'utm'
                    - 'fwb'
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
                description: 'enabled - Value reserved for non-FOS HA devices.'
                choices:
                    - 'standalone'
                    - 'AP'
                    - 'AA'
                    - 'ELBC'
                    - 'DUAL'
                    - 'enabled'
                    - 'unknown'
                    - 'fmg-enabled'
                    - 'autoscale'
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
                        choices:
                            - 'slave'
                            - 'master'
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
            meta fields:
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
                choices:
                    - 'unreg'
                    - 'fmg'
                    - 'faz'
                    - 'fmgfaz'
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
                description: 'Unique name for the device.'
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
            os_ver:
                type: str
                description: no description
                choices:
                    - 'unknown'
                    - '0.0'
                    - '1.0'
                    - '2.0'
                    - '3.0'
                    - '4.0'
                    - '5.0'
                    - '6.0'
                    - '7.0'
                    - '8.0'
                    - '9.0'
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
                description: 'Unique value for each device.'
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
                        choices:
                            - 'nat'
                            - 'transparent'
                    rtm_prof_id:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                    vpn_id:
                        type: int
                        description: no description
                    meta fields:
                        description: no description
                        type: dict
                    vdom_type:
                        type: str
                        description: no description
                        choices:
                            - 'traffic'
                            - 'admin'
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
                choices:
                    - 'master'
                    - 'ha-slave'
                    - 'autoscale-slave'
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
'''

EXAMPLES = '''
- name: Example playbook
  connection: httpapi
  hosts: fortianalyzers
  tasks:
    - name: Device table, most attributes are read-only and can only be changed internally.
      fortinet.fortianalyzer.faz_dvmdb_device:
        adom: root
        device: foodevice
        dvmdb_device:
          desc: device modified via module fortinet.fortianalyzer.faz_dvmdb_device
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
        '/dvmdb/adom/{adom}/device/{device}',
        '/dvmdb/device/{device}'
    ]

    perobject_jrpc_urls = [
        '/dvmdb/adom/{adom}/device/{device}',
        '/dvmdb/device/{device}'
    ]

    url_params = ['adom', 'device']
    module_primary_key = None
    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'bypass_validation': {'type': 'bool', 'default': False},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'proposed_method': {'type': 'str', 'choices': ['set', 'update', 'add']},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'adom': {'required': True, 'type': 'str'},
        'device': {'required': True, 'type': 'str'},
        'dvmdb_device': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
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
                        'none', 'unknown', 'checkedin', 'inprogress', 'installed', 'aborted', 'sched', 'retry', 'canceled', 'pending', 'retrieved',
                        'changed_conf', 'sync_fail', 'timeout', 'rev_revert', 'auto_updated'
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
                        'has_hdd', 'vdom_enabled', 'discover', 'reload', 'interim_build', 'offline_mode', 'is_model', 'fips_mode', 'linked_to_model',
                        'ip-conflict', 'faz-autosync', 'need_reset', 'backup_mode', 'azure_vwan_nva', 'fgsp_configured', 'cnf_mode', 'sase_managed',
                        'override_management_intf'
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
                'ha_mode': {'choices': ['standalone', 'AP', 'AA', 'ELBC', 'DUAL', 'enabled', 'unknown', 'fmg-enabled', 'autoscale'], 'type': 'str'},
                'ha_slave': {
                    'type': 'list',
                    'options': {
                        'idx': {'type': 'int'},
                        'name': {'type': 'str'},
                        'prio': {'type': 'int'},
                        'role': {'choices': ['slave', 'master'], 'type': 'str'},
                        'sn': {'type': 'str'},
                        'status': {'type': 'int'},
                        'conf_status': {'v_range': [['7.0.10', '7.0.11'], ['7.2.1', '']], 'type': 'int'}
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
                        'unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw',
                        'fsr', 'fad', 'fts', 'fap', 'fxt', 'fai', 'fwc', 'fis', 'fed', 'fpa', 'fca', 'ftc'
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
                'hyperscale': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'private_key': {'v_range': [['6.2.7', '6.2.12'], ['6.4.4', '']], 'no_log': True, 'type': 'str'},
                'private_key_status': {'v_range': [['6.2.7', '6.2.12'], ['6.4.4', '']], 'no_log': True, 'type': 'int'},
                'prio': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'role': {'v_range': [['6.4.1', '']], 'choices': ['master', 'ha-slave', 'autoscale-slave'], 'type': 'str'},
                'nsxt_service_name': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'vm_lic_overdue_since': {'v_range': [['6.4.12', '6.4.14'], ['7.0.8', '7.0.11'], ['7.2.3', '']], 'type': 'int'},
                'first_tunnel_up': {'v_range': [['7.0.4', '7.0.11'], ['7.2.1', '']], 'type': 'int'},
                'eip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'mgmt_uuid': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'hw_generation': {'v_range': [['7.2.4', '7.2.4'], ['7.4.1', '']], 'type': 'int'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'dvmdb_device'),
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
