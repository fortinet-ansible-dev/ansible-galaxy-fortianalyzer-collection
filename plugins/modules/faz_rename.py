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
module: faz_rename
short_description: Rename an object in FortiAnalyzer.
description:
    - This module is able to configure a FortiAnalyzer device by renaming an object.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.11"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiAnalyzer module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    rename:
        description: the top level parameters set
        type: dict
        required: false
'''

EXAMPLES = '''
- collections:
  - fortinet.fortianalyzer
  connection: httpapi
  hosts: fortianalyzer-inventory
  tasks:
  - faz_dvmdb_group:
      adom: root
      dvmdb_group:
        #desc: <value of string>
        #meta fields: <value of dict>
        name: foogroup
        os_type: unknown
        type: normal
      state: present
    name: Device group table.

  - faz_rename:
     rename:
       selector: dvmdb_group
       self:
        adom: root
        group: foogroup
       target:
        name: 'foogroup_renamed'

  - faz_fact:
      facts:
       selector: dvmdb_group
       params:
        adom: root
        group: foogroup
    register: info
    failed_when: info.rc == 0

  - faz_dvmdb_group:
     adom: root
     state: absent
     dvmdb_group:
        name: foogroup_renamed

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


def main():
    rename_metadata = {
        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip/{announce-ip}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_fmupdate_fdssetting_serveroverride_servlist': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override/servlist/{servlist}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_fmupdate_serveraccesspriorities_privateserver': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities/private-server/{private-server}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist/{servlist}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_admin_group': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/group/{group}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_group_member': {
            'params': [
                'group'
            ],
            'urls': [
                '/cli/global/system/admin/group/{group}/member/{member}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_ldap': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_radius': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/radius/{radius}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_tacacs': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/tacacs/{tacacs}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_user': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'userid'
        },
        'cli_system_admin_user_adom': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom/{adom}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'adom-name'
        },
        'cli_system_admin_user_adomexclude': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom-exclude/{adom-exclude}'
            ],
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
            'mkey': 'adom-name'
        },
        'cli_system_admin_user_dashboard': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'tabid'
        },
        'cli_system_admin_user_dashboardtabs': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard-tabs/{dashboard-tabs}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_admin_user_metadata': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/meta-data/{meta-data}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'fieldname'
        },
        'cli_system_admin_user_policypackage': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-package/{policy-package}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'policy-package-name'
        },
        'cli_system_admin_user_restrictdevvdom': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            },
            'mkey': 'dev-vdom'
        },
        'cli_system_alertevent': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/alert-event/{alert-event}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_certificate_ca': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/ca/{ca}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_certificate_crl': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/crl/{crl}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_certificate_local': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/local/{local}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_certificate_remote': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/remote/{remote}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_certificate_ssh': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/ssh/{ssh}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_ha_peer': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha/peer/{peer}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_ha_privatepeer': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha/private-peer/{private-peer}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_ha_vip': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha/vip/{vip}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_interface': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/interface/{interface}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_localinpolicy': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_localinpolicy6': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_log_devicedisable': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'revision': {
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_log_maildomain': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/mail-domain/{mail-domain}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_log_ratelimit_device': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'revision': {
                '7.0.0': True
            },
            'mkey': 'id'
        },
        'cli_system_log_ratelimit_ratelimits': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile_devicefilter': {
            'params': [
                'client-profile'
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter/{device-filter}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile_logfilter': {
            'params': [
                'client-profile'
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter/{log-filter}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logforward': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logforward_devicefilter': {
            'params': [
                'log-forward'
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/device-filter/{device-filter}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logforward_logfieldexclusion': {
            'params': [
                'log-forward'
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-field-exclusion/{log-field-exclusion}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logforward_logfilter': {
            'params': [
                'log-forward'
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-filter/{log-filter}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_logforward_logmaskingcustom': {
            'params': [
                'log-forward'
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-masking-custom/{log-masking-custom}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_mail': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/mail/{mail}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_metadata_admins': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/metadata/admins/{admins}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'fieldname'
        },
        'cli_system_ntp_ntpserver': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ntp/ntpserver/{ntpserver}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_report_group': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/group/{group}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'group-id'
        },
        'cli_system_route': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/route/{route}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'seq_num'
        },
        'cli_system_route6': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/route6/{route6}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'prio'
        },
        'cli_system_saml_fabricidp': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/saml/fabric-idp/{fabric-idp}'
            ],
            'revision': {
                '6.2.1': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'dev-id'
        },
        'cli_system_saml_serviceproviders': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/saml/service-providers/{service-providers}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_sniffer': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sniffer/{sniffer}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_snmp_community': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_snmp_community_hosts': {
            'params': [
                'community'
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_snmp_community_hosts6': {
            'params': [
                'community'
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_snmp_user': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/snmp/user/{user}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_sql_customindex': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sql/custom-index/{custom-index}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_sql_customskipidx': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sql/custom-skipidx/{custom-skipidx}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'id'
        },
        'cli_system_sql_tsindexfield': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sql/ts-index-field/{ts-index-field}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'category'
        },
        'cli_system_syslog': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/syslog/{syslog}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'cli_system_workflow_approvalmatrix': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}'
            ],
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
            'mkey': 'adom-name'
        },
        'dvmdb_adom': {
            'params': [
            ],
            'urls': [
                '/dvmdb/adom/{adom}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'dvmdb_device_vdom': {
            'params': [
                'adom',
                'device'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/vdom/{vdom}',
                '/dvmdb/device/{device}/vdom/{vdom}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'dvmdb_folder': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/folder/{folder}',
                '/dvmdb/folder/{folder}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'dvmdb_group': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/group/{group}',
                '/dvmdb/group/{group}'
            ],
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
                '7.0.0': True,
                '7.2.0': True
            },
            'mkey': 'name'
        }
    }

    module_arg_spec = {
        'enable_log': {
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
        'rename': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip',
                        'cli_fmupdate_fdssetting_serveroverride_servlist',
                        'cli_fmupdate_serveraccesspriorities_privateserver',
                        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist',
                        'cli_system_admin_group',
                        'cli_system_admin_group_member',
                        'cli_system_admin_ldap',
                        'cli_system_admin_radius',
                        'cli_system_admin_tacacs',
                        'cli_system_admin_user',
                        'cli_system_admin_user_adom',
                        'cli_system_admin_user_adomexclude',
                        'cli_system_admin_user_dashboard',
                        'cli_system_admin_user_dashboardtabs',
                        'cli_system_admin_user_metadata',
                        'cli_system_admin_user_policypackage',
                        'cli_system_admin_user_restrictdevvdom',
                        'cli_system_alertevent',
                        'cli_system_certificate_ca',
                        'cli_system_certificate_crl',
                        'cli_system_certificate_local',
                        'cli_system_certificate_remote',
                        'cli_system_certificate_ssh',
                        'cli_system_ha_peer',
                        'cli_system_ha_privatepeer',
                        'cli_system_ha_vip',
                        'cli_system_interface',
                        'cli_system_localinpolicy',
                        'cli_system_localinpolicy6',
                        'cli_system_log_devicedisable',
                        'cli_system_log_maildomain',
                        'cli_system_log_ratelimit_device',
                        'cli_system_log_ratelimit_ratelimits',
                        'cli_system_logfetch_clientprofile',
                        'cli_system_logfetch_clientprofile_devicefilter',
                        'cli_system_logfetch_clientprofile_logfilter',
                        'cli_system_logforward',
                        'cli_system_logforward_devicefilter',
                        'cli_system_logforward_logfieldexclusion',
                        'cli_system_logforward_logfilter',
                        'cli_system_logforward_logmaskingcustom',
                        'cli_system_mail',
                        'cli_system_metadata_admins',
                        'cli_system_ntp_ntpserver',
                        'cli_system_report_group',
                        'cli_system_route',
                        'cli_system_route6',
                        'cli_system_saml_fabricidp',
                        'cli_system_saml_serviceproviders',
                        'cli_system_sniffer',
                        'cli_system_snmp_community',
                        'cli_system_snmp_community_hosts',
                        'cli_system_snmp_community_hosts6',
                        'cli_system_snmp_user',
                        'cli_system_sql_customindex',
                        'cli_system_sql_customskipidx',
                        'cli_system_sql_tsindexfield',
                        'cli_system_syslog',
                        'cli_system_workflow_approvalmatrix',
                        'dvmdb_adom',
                        'dvmdb_device_vdom',
                        'dvmdb_folder',
                        'dvmdb_group'
                    ]
                },
                'self': {
                    'required': True,
                    'type': 'dict'
                },
                'target': {
                    'required': True,
                    'type': 'dict'
                }
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(None, None, None, None, module, connection)
        faz.process_rename(rename_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
