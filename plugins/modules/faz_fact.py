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
module: faz_fact
short_description: Gather FortiAnalyzer facts.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
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
    workspace_locking_adom:
        description: the adom to lock for FortiAnalyzer running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    facts:
        description: the top level parameters set
        type: dict
        required: false
'''

EXAMPLES = '''
- name: gathering fortianalyzer facts
  hosts: faz01
  gather_facts: no
  connection: httpapi
  collections:
    - fortinet.fortianalyzer
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
   - name: retrieve all the scripts
     faz_fact:
       facts:
           selector: 'dvmdb_script'
           params:
               adom: 'root'
               script: ''

   - name: retrive all the interfaces
     faz_fact:
       facts:
           selector: 'system_interface'
           params:
               interface: ''
   - name: retrieve the interface port1
     faz_fact:
       facts:
           selector: 'system_interface'
           params:
               interface: 'port1'
   - name: fetch urlfilter with name urlfilter4
     faz_fact:
       facts:
         selector: 'webfilter_urlfilter'
         params:
           adom: 'root'
           urlfilter: ''
         filter:
           -
             - 'name'
             - '=='
             - 'urlfilter4'
         fields:
           - 'id'
           - 'name'
           - 'comment'
         sortings:
           - 'id': 1
             'name': -1
   - name: Retrieve device
     faz_fact:
       facts:
         selector: 'dvmdb_device'
         params:
           adom: 'root'
           device: ''
         option:
           - 'get meta'
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
    facts_metadata = {
        'cli_metafields_system_admin_user': {
            'params': [
            ],
            'urls': [
                '/cli/global/_meta_fields/system/admin/user'
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
            }
        },
        'cli_fmupdate_analyzer_virusreport': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/analyzer/virusreport'
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
            }
        },
        'cli_fmupdate_avips_advancedlog': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/av-ips/advanced-log'
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
            }
        },
        'cli_fmupdate_avips_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/av-ips/web-proxy'
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
            }
        },
        'cli_fmupdate_customurllist': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/custom-url-list'
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
            }
        },
        'cli_fmupdate_diskquota': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/disk-quota'
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
            }
        },
        'cli_fmupdate_fctservices': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fct-services'
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
            }
        },
        'cli_fmupdate_fdssetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting'
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
            }
        },
        'cli_fmupdate_fdssetting_pushoverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override'
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
            }
        },
        'cli_fmupdate_fdssetting_pushoverridetoclient': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client'
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
            }
        },
        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'params': [
                'announce-ip'
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
            }
        },
        'cli_fmupdate_fdssetting_serveroverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override'
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
            }
        },
        'cli_fmupdate_fdssetting_serveroverride_servlist': {
            'params': [
                'servlist'
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
            }
        },
        'cli_fmupdate_fdssetting_updateschedule': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/update-schedule'
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
            }
        },
        'cli_fmupdate_fwmsetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fwm-setting'
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
            }
        },
        'cli_fmupdate_multilayer': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/multilayer'
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
            }
        },
        'cli_fmupdate_publicnetwork': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/publicnetwork'
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
            }
        },
        'cli_fmupdate_serveraccesspriorities': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities'
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
            }
        },
        'cli_fmupdate_serveraccesspriorities_privateserver': {
            'params': [
                'private-server'
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
            }
        },
        'cli_fmupdate_serveroverridestatus': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/server-override-status'
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
            }
        },
        'cli_fmupdate_service': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/service'
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
            }
        },
        'cli_fmupdate_webspam_fgdsetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting'
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
            }
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override'
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
            }
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'params': [
                'servlist'
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
            }
        },
        'cli_fmupdate_webspam_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/web-proxy'
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
            }
        },
        'cli_system_admin_group': {
            'params': [
                'group'
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
            }
        },
        'cli_system_admin_group_member': {
            'params': [
                'group',
                'member'
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
            }
        },
        'cli_system_admin_ldap': {
            'params': [
                'ldap'
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
            }
        },
        'cli_system_admin_ldap_adom': {
            'params': [
                'ldap',
                'adom'
            ],
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}/adom/{adom}'
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
            }
        },
        'cli_system_admin_profile': {
            'params': [
                'profile'
            ],
            'urls': [
                '/cli/global/system/admin/profile/{profile}'
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
            }
        },
        'cli_system_admin_profile_datamaskcustomfields': {
            'params': [
                'profile',
                'datamask-custom-fields'
            ],
            'urls': [
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields/{datamask-custom-fields}'
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
            }
        },
        'cli_system_admin_radius': {
            'params': [
                'radius'
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
            }
        },
        'cli_system_admin_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/setting'
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
            }
        },
        'cli_system_admin_tacacs': {
            'params': [
                'tacacs'
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
            }
        },
        'cli_system_admin_user': {
            'params': [
                'user'
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
            }
        },
        'cli_system_admin_user_adom': {
            'params': [
                'user',
                'adom'
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
            }
        },
        'cli_system_admin_user_adomexclude': {
            'params': [
                'user',
                'adom-exclude'
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
            }
        },
        'cli_system_admin_user_dashboard': {
            'params': [
                'user',
                'dashboard'
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
            }
        },
        'cli_system_admin_user_dashboardtabs': {
            'params': [
                'user',
                'dashboard-tabs'
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
            }
        },
        'cli_system_admin_user_metadata': {
            'params': [
                'user',
                'meta-data'
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
            }
        },
        'cli_system_admin_user_policypackage': {
            'params': [
                'user',
                'policy-package'
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
            }
        },
        'cli_system_admin_user_restrictdevvdom': {
            'params': [
                'user',
                'restrict-dev-vdom'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            }
        },
        'cli_system_alertconsole': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/alert-console'
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
            }
        },
        'cli_system_alertevent': {
            'params': [
                'alert-event'
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
            }
        },
        'cli_system_alertevent_alertdestination': {
            'params': [
                'alert-event',
                'alert-destination'
            ],
            'urls': [
                '/cli/global/system/alert-event/{alert-event}/alert-destination/{alert-destination}'
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
            }
        },
        'cli_system_alertemail': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/alertemail'
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
            }
        },
        'cli_system_autodelete': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete'
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
            }
        },
        'cli_system_autodelete_dlpfilesautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/dlp-files-auto-deletion'
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
            }
        },
        'cli_system_autodelete_logautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/log-auto-deletion'
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
            }
        },
        'cli_system_autodelete_quarantinefilesautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/quarantine-files-auto-deletion'
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
            }
        },
        'cli_system_autodelete_reportautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/report-auto-deletion'
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
            }
        },
        'cli_system_backup_allsettings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/backup/all-settings'
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
            }
        },
        'cli_system_centralmanagement': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/central-management'
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
            }
        },
        'cli_system_certificate_ca': {
            'params': [
                'ca'
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
            }
        },
        'cli_system_certificate_crl': {
            'params': [
                'crl'
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
            }
        },
        'cli_system_certificate_local': {
            'params': [
                'local'
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
            }
        },
        'cli_system_certificate_oftp': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/oftp'
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
            }
        },
        'cli_system_certificate_remote': {
            'params': [
                'remote'
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
            }
        },
        'cli_system_certificate_ssh': {
            'params': [
                'ssh'
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
            }
        },
        'cli_system_connector': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/connector'
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
            }
        },
        'cli_system_dns': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/dns'
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
            }
        },
        'cli_system_docker': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/docker'
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
            }
        },
        'cli_system_fips': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fips'
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
            }
        },
        'cli_system_fortiview_autocache': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fortiview/auto-cache'
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
            }
        },
        'cli_system_fortiview_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fortiview/setting'
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
            }
        },
        'cli_system_global': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/global'
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
            }
        },
        'cli_system_guiact': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/guiact'
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
            }
        },
        'cli_system_ha': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha'
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
            }
        },
        'cli_system_ha_peer': {
            'params': [
                'peer'
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
            }
        },
        'cli_system_ha_privatepeer': {
            'params': [
                'private-peer'
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
            }
        },
        'cli_system_interface': {
            'params': [
                'interface'
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
            }
        },
        'cli_system_interface_ipv6': {
            'params': [
                'interface'
            ],
            'urls': [
                '/cli/global/system/interface/{interface}/ipv6'
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
            }
        },
        'cli_system_locallog_disk_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/disk/filter'
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
            }
        },
        'cli_system_locallog_disk_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/disk/setting'
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
            }
        },
        'cli_system_locallog_fortianalyzer_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/filter'
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
            }
        },
        'cli_system_locallog_fortianalyzer_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/setting'
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
            }
        },
        'cli_system_locallog_fortianalyzer2_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/filter'
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
            }
        },
        'cli_system_locallog_fortianalyzer2_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/setting'
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
            }
        },
        'cli_system_locallog_fortianalyzer3_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/filter'
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
            }
        },
        'cli_system_locallog_fortianalyzer3_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/setting'
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
            }
        },
        'cli_system_locallog_memory_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/memory/filter'
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
            }
        },
        'cli_system_locallog_memory_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/memory/setting'
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
            }
        },
        'cli_system_locallog_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/setting'
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
            }
        },
        'cli_system_locallog_syslogd_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd/filter'
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
            }
        },
        'cli_system_locallog_syslogd_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd/setting'
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
            }
        },
        'cli_system_locallog_syslogd2_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd2/filter'
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
            }
        },
        'cli_system_locallog_syslogd2_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd2/setting'
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
            }
        },
        'cli_system_locallog_syslogd3_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd3/filter'
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
            }
        },
        'cli_system_locallog_syslogd3_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd3/setting'
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
            }
        },
        'cli_system_logfetch_clientprofile': {
            'params': [
                'client-profile'
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
            }
        },
        'cli_system_logfetch_clientprofile_devicefilter': {
            'params': [
                'client-profile',
                'device-filter'
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
            }
        },
        'cli_system_logfetch_clientprofile_logfilter': {
            'params': [
                'client-profile',
                'log-filter'
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
            }
        },
        'cli_system_logfetch_serversettings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log-fetch/server-settings'
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
            }
        },
        'cli_system_logforward': {
            'params': [
                'log-forward'
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
            }
        },
        'cli_system_logforwardservice': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log-forward-service'
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
            }
        },
        'cli_system_logforward_devicefilter': {
            'params': [
                'log-forward',
                'device-filter'
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
            }
        },
        'cli_system_logforward_logfieldexclusion': {
            'params': [
                'log-forward',
                'log-field-exclusion'
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
            }
        },
        'cli_system_logforward_logfilter': {
            'params': [
                'log-forward',
                'log-filter'
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
            }
        },
        'cli_system_log_alert': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/alert'
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
            }
        },
        'cli_system_log_interfacestats': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/interface-stats'
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
            }
        },
        'cli_system_log_ioc': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ioc'
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
            }
        },
        'cli_system_log_maildomain': {
            'params': [
                'mail-domain'
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
            }
        },
        'cli_system_log_settings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings'
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
            }
        },
        'cli_system_log_settings_rollinganalyzer': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-analyzer'
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
            }
        },
        'cli_system_log_settings_rollinglocal': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-local'
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
            }
        },
        'cli_system_log_settings_rollingregular': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-regular'
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
            }
        },
        'cli_system_mail': {
            'params': [
                'mail'
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
            }
        },
        'cli_system_metadata_admins': {
            'params': [
                'admins'
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
            }
        },
        'cli_system_ntp': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ntp'
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
            }
        },
        'cli_system_ntp_ntpserver': {
            'params': [
                'ntpserver'
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
            }
        },
        'cli_system_passwordpolicy': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/password-policy'
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
            }
        },
        'cli_system_performance': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/performance'
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
            }
        },
        'cli_system_report_autocache': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/auto-cache'
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
            }
        },
        'cli_system_report_estbrowsetime': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/est-browse-time'
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
            }
        },
        'cli_system_report_group': {
            'params': [
                'group'
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
            }
        },
        'cli_system_report_group_chartalternative': {
            'params': [
                'group',
                'chart-alternative'
            ],
            'urls': [
                '/cli/global/system/report/group/{group}/chart-alternative/{chart-alternative}'
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
            }
        },
        'cli_system_report_group_groupby': {
            'params': [
                'group',
                'group-by'
            ],
            'urls': [
                '/cli/global/system/report/group/{group}/group-by/{group-by}'
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
            }
        },
        'cli_system_report_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/setting'
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
            }
        },
        'cli_system_route': {
            'params': [
                'route'
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
            }
        },
        'cli_system_route6': {
            'params': [
                'route6'
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
            }
        },
        'cli_system_saml': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/saml'
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
            }
        },
        'cli_system_saml_fabricidp': {
            'params': [
                'fabric-idp'
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
            }
        },
        'cli_system_saml_serviceproviders': {
            'params': [
                'service-providers'
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
            }
        },
        'cli_system_sniffer': {
            'params': [
                'sniffer'
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
            }
        },
        'cli_system_snmp_community': {
            'params': [
                'community'
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
            }
        },
        'cli_system_snmp_community_hosts': {
            'params': [
                'community',
                'hosts'
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
            }
        },
        'cli_system_snmp_community_hosts6': {
            'params': [
                'community',
                'hosts6'
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
            }
        },
        'cli_system_snmp_sysinfo': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/snmp/sysinfo'
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
            }
        },
        'cli_system_snmp_user': {
            'params': [
                'user'
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
            }
        },
        'cli_system_sql': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sql'
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
            }
        },
        'cli_system_sql_customindex': {
            'params': [
                'custom-index'
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
            }
        },
        'cli_system_sql_customskipidx': {
            'params': [
                'custom-skipidx'
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
            }
        },
        'cli_system_sql_tsindexfield': {
            'params': [
                'ts-index-field'
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
            }
        },
        'cli_system_status': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/status'
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
            }
        },
        'cli_system_syslog': {
            'params': [
                'syslog'
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
            }
        },
        'cli_system_workflow_approvalmatrix': {
            'params': [
                'approval-matrix'
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
            }
        },
        'cli_system_workflow_approvalmatrix_approver': {
            'params': [
                'approval-matrix',
                'approver'
            ],
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver/{approver}'
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
            }
        },
        'eventmgmt_adom_<adomname>_alertfilter': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alertfilter'
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
            }
        },
        'eventmgmt_adom_<adomname>_alertlogs': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alertlogs'
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
            }
        },
        'eventmgmt_adom_<adomname>_alertlogs_count': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alertlogs/count'
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
            }
        },
        'eventmgmt_adom_<adomname>_alerts': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alerts'
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
            }
        },
        'eventmgmt_adom_<adomname>_alerts_count': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alerts/count'
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
            }
        },
        'eventmgmt_adom_<adomname>_alerts_extradetails': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alerts/extra-details'
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
            }
        },
        'fazsys_adom_<adomname>_enduseravatar': {
            'params': [
            ],
            'urls': [
                '/fazsys/adom/<adom-name>/enduser-avatar'
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
            }
        },
        'fazsys_language_fonts_export': {
            'params': [
            ],
            'urls': [
                '/fazsys/language/fonts/export'
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
            }
        },
        'fazsys_language_fonts_list': {
            'params': [
            ],
            'urls': [
                '/fazsys/language/fonts/list'
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
            }
        },
        'fazsys_language_translationfile_export': {
            'params': [
            ],
            'urls': [
                '/fazsys/language/translation-file/export'
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
            }
        },
        'fazsys_language_translationfile_list': {
            'params': [
            ],
            'urls': [
                '/fazsys/language/translation-file/list'
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
            }
        },
        'sys_ha_status': {
            'params': [
            ],
            'urls': [
                '/sys/ha/status'
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
            }
        },
        'sys_status': {
            'params': [
            ],
            'urls': [
                '/sys/status'
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
            }
        },
        'ueba_adom_<adomname>_endpoints': {
            'params': [
            ],
            'urls': [
                '/ueba/adom/<adom-name>/endpoints'
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
            }
        },
        'ueba_adom_<adomname>_endpoints_stats': {
            'params': [
            ],
            'urls': [
                '/ueba/adom/<adom-name>/endpoints/stats'
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
            }
        },
        'ueba_adom_<adomname>_endusers': {
            'params': [
            ],
            'urls': [
                '/ueba/adom/<adom-name>/endusers'
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
            }
        },
        'ueba_adom_<adomname>_endusers_stats': {
            'params': [
            ],
            'urls': [
                '/ueba/adom/<adom-name>/endusers/stats'
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
            }
        },
        'report_adom_<adomname>_reports_data_<tid>': {
            'params': [
            ],
            'urls': [
                '/report/adom/<adom-name>/reports/data/<tid>'
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
            }
        },
        'report_adom_<adomname>_reports_state': {
            'params': [
            ],
            'urls': [
                '/report/adom/<adom-name>/reports/state'
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
            }
        },
        'report_adom_<adomname>_run_<tid>': {
            'params': [
            ],
            'urls': [
                '/report/adom/<adom-name>/run/<tid>'
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
            }
        },
        'report_adom_<adomname>_template_export': {
            'params': [
            ],
            'urls': [
                '/report/adom/<adom-name>/template/export'
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
            }
        },
        'report_adom_root_template_language': {
            'params': [
            ],
            'urls': [
                '/report/adom/root/template/language'
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
            }
        },
        'report_adom_<adomname>_template_list': {
            'params': [
            ],
            'urls': [
                '/report/adom/<adom-name>/template/list'
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
            }
        },
        'task_task': {
            'params': [
                'task'
            ],
            'urls': [
                '/task/task/{task}'
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
            }
        },
        'task_task_line': {
            'params': [
                'task',
                'line'
            ],
            'urls': [
                '/task/task/{task}/line/{line}'
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
            }
        },
        'task_task_line_history': {
            'params': [
                'task',
                'line',
                'history'
            ],
            'urls': [
                '/task/task/{task}/line/{line}/history/{history}'
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
            }
        },
        'dvmdb_adom': {
            'params': [
                'adom'
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
            }
        },
        'dvmdb_device': {
            'params': [
                'device',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}',
                '/dvmdb/device/{device}'
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
            }
        },
        'dvmdb_device_haslave': {
            'params': [
                'device',
                'ha_slave',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/ha_slave/{ha_slave}',
                '/dvmdb/device/{device}/ha_slave/{ha_slave}'
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
            }
        },
        'dvmdb_device_vdom': {
            'params': [
                'device',
                'vdom',
                'adom'
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
            }
        },
        'dvmdb_group': {
            'params': [
                'group',
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
            }
        },
        'fortiview_adom_<adomname>_<viewname>_run_<tid>': {
            'params': [
            ],
            'urls': [
                '/fortiview/adom/<adom-name>/<view-name>/run/<tid>'
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
            }
        },
        'logview_adom_<adomname>_logfields': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logfields'
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
            }
        },
        'logview_adom_<adomname>_logfiles_data': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logfiles/data'
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
            }
        },
        'logview_adom_<adomname>_logfiles_search': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logfiles/search'
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
            }
        },
        'logview_adom_<adomname>_logfiles_state': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logfiles/state'
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
            }
        },
        'logview_adom_<adomname>_logsearch_<tid>': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logsearch/<tid>'
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
            }
        },
        'logview_adom_<adomname>_logstats': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logstats'
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
            }
        },
        'incidentmgmt_adom_<adomname>_attachments': {
            'params': [
            ],
            'urls': [
                '/incidentmgmt/adom/<adom-name>/attachments'
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
            }
        },
        'incidentmgmt_adom_<adomname>_attachments_count': {
            'params': [
            ],
            'urls': [
                '/incidentmgmt/adom/<adom-name>/attachments/count'
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
            }
        },
        'incidentmgmt_adom_<adomname>_incidents': {
            'params': [
            ],
            'urls': [
                '/incidentmgmt/adom/<adom-name>/incidents'
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
            }
        },
        'incidentmgmt_adom_<adomname>_incidents_count': {
            'params': [
            ],
            'urls': [
                '/incidentmgmt/adom/<adom-name>/incidents/count'
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
            }
        },
        'ioc_license_state': {
            'params': [
            ],
            'urls': [
                '/ioc/license/state'
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
            }
        },
        'ioc_adom_<adomname>_rescan_history': {
            'params': [
            ],
            'urls': [
                '/ioc/adom/<adom-name>/rescan/history'
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
            }
        },
        'ioc_adom_<adomname>_rescan_run': {
            'params': [
            ],
            'urls': [
                '/ioc/adom/<adom-name>/rescan/run'
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
            }
        },
        'task_task_history': {
            'params': [
                'task',
                'history'
            ],
            'urls': [
                '/task/task/{task}/history/{history}'
            ],
            'revision': {
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True
            }
        },
        'dvmdb_folder': {
            'params': [
                'folder',
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
            }
        },
        'soar_adom_<adomname>_config_connectors_<connectoruuid>': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/config/connectors/<connector-uuid>'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_config_playbooks_<playbookuuid>': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/config/playbooks/<playbook-uuid>'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_fosconnector_automationrules': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/fos-connector/automation-rules'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_playbook_monitor': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/playbook/monitor'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_task_monitor': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/task/monitor'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '7.2.0': True
            }
        },
        'incidentmgmt_adom_<adomname>_epeuhistory': {
            'params': [
            ],
            'urls': [
                '/incidentmgmt/adom/<adom-name>/epeu-history'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_log_devicedisable': {
            'params': [
                'device-disable'
            ],
            'urls': [
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'revision': {
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_interface_member': {
            'params': [
                'interface',
                'member'
            ],
            'urls': [
                '/cli/global/system/interface/{interface}/member/{member}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_log_ratelimit': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ratelimit'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_log_ratelimit_device': {
            'params': [
                'device'
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'revision': {
                '7.0.0': True
            }
        },
        'cli_system_logforward_logmaskingcustom': {
            'params': [
                'log-forward',
                'log-masking-custom'
            ],
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-masking-custom/{log-masking-custom}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_socfabric': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/soc-fabric'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'eventmgmt_adom_<adomname>_alerts_export': {
            'params': [
            ],
            'urls': [
                '/eventmgmt/adom/<adom-name>/alerts/export'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'cli_system_sslciphersuites': {
            'params': [
                'ssl-cipher-suites'
            ],
            'urls': [
                '/cli/global/system/global/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/web-proxy'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_localinpolicy': {
            'params': [
                'local-in-policy'
            ],
            'urls': [
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_localinpolicy6': {
            'params': [
                'local-in-policy6'
            ],
            'urls': [
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_log_fospolicystats': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/fos-policy-stats'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_log_ratelimit_ratelimits': {
            'params': [
                'ratelimits'
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_log_topology': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/topology'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'cli_system_ha_vip': {
            'params': [
                'vip'
            ],
            'urls': [
                '/cli/global/system/ha/vip/{vip}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'logview_adom_<adomname>_logsearch_count_<tid>': {
            'params': [
            ],
            'urls': [
                '/logview/adom/<adom-name>/logsearch/count/<tid>'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'logview_pcapfile': {
            'params': [
            ],
            'urls': [
                '/logview/pcapfile'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_playbook_export': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/playbook/export'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'soar_adom_<adomname>_subnet_export': {
            'params': [
            ],
            'urls': [
                '/soar/adom/<adom-name>/subnet/export'
            ],
            'revision': {
                '7.2.0': True
            }
        }
    }

    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'facts': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'cli_metafields_system_admin_user',
                        'cli_fmupdate_analyzer_virusreport',
                        'cli_fmupdate_avips_advancedlog',
                        'cli_fmupdate_avips_webproxy',
                        'cli_fmupdate_customurllist',
                        'cli_fmupdate_diskquota',
                        'cli_fmupdate_fctservices',
                        'cli_fmupdate_fdssetting',
                        'cli_fmupdate_fdssetting_pushoverride',
                        'cli_fmupdate_fdssetting_pushoverridetoclient',
                        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip',
                        'cli_fmupdate_fdssetting_serveroverride',
                        'cli_fmupdate_fdssetting_serveroverride_servlist',
                        'cli_fmupdate_fdssetting_updateschedule',
                        'cli_fmupdate_fwmsetting',
                        'cli_fmupdate_multilayer',
                        'cli_fmupdate_publicnetwork',
                        'cli_fmupdate_serveraccesspriorities',
                        'cli_fmupdate_serveraccesspriorities_privateserver',
                        'cli_fmupdate_serveroverridestatus',
                        'cli_fmupdate_service',
                        'cli_fmupdate_webspam_fgdsetting',
                        'cli_fmupdate_webspam_fgdsetting_serveroverride',
                        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist',
                        'cli_fmupdate_webspam_webproxy',
                        'cli_system_admin_group',
                        'cli_system_admin_group_member',
                        'cli_system_admin_ldap',
                        'cli_system_admin_ldap_adom',
                        'cli_system_admin_profile',
                        'cli_system_admin_profile_datamaskcustomfields',
                        'cli_system_admin_radius',
                        'cli_system_admin_setting',
                        'cli_system_admin_tacacs',
                        'cli_system_admin_user',
                        'cli_system_admin_user_adom',
                        'cli_system_admin_user_adomexclude',
                        'cli_system_admin_user_dashboard',
                        'cli_system_admin_user_dashboardtabs',
                        'cli_system_admin_user_metadata',
                        'cli_system_admin_user_policypackage',
                        'cli_system_admin_user_restrictdevvdom',
                        'cli_system_alertconsole',
                        'cli_system_alertevent',
                        'cli_system_alertevent_alertdestination',
                        'cli_system_alertemail',
                        'cli_system_autodelete',
                        'cli_system_autodelete_dlpfilesautodeletion',
                        'cli_system_autodelete_logautodeletion',
                        'cli_system_autodelete_quarantinefilesautodeletion',
                        'cli_system_autodelete_reportautodeletion',
                        'cli_system_backup_allsettings',
                        'cli_system_centralmanagement',
                        'cli_system_certificate_ca',
                        'cli_system_certificate_crl',
                        'cli_system_certificate_local',
                        'cli_system_certificate_oftp',
                        'cli_system_certificate_remote',
                        'cli_system_certificate_ssh',
                        'cli_system_connector',
                        'cli_system_dns',
                        'cli_system_docker',
                        'cli_system_fips',
                        'cli_system_fortiview_autocache',
                        'cli_system_fortiview_setting',
                        'cli_system_global',
                        'cli_system_guiact',
                        'cli_system_ha',
                        'cli_system_ha_peer',
                        'cli_system_ha_privatepeer',
                        'cli_system_interface',
                        'cli_system_interface_ipv6',
                        'cli_system_locallog_disk_filter',
                        'cli_system_locallog_disk_setting',
                        'cli_system_locallog_fortianalyzer_filter',
                        'cli_system_locallog_fortianalyzer_setting',
                        'cli_system_locallog_fortianalyzer2_filter',
                        'cli_system_locallog_fortianalyzer2_setting',
                        'cli_system_locallog_fortianalyzer3_filter',
                        'cli_system_locallog_fortianalyzer3_setting',
                        'cli_system_locallog_memory_filter',
                        'cli_system_locallog_memory_setting',
                        'cli_system_locallog_setting',
                        'cli_system_locallog_syslogd_filter',
                        'cli_system_locallog_syslogd_setting',
                        'cli_system_locallog_syslogd2_filter',
                        'cli_system_locallog_syslogd2_setting',
                        'cli_system_locallog_syslogd3_filter',
                        'cli_system_locallog_syslogd3_setting',
                        'cli_system_logfetch_clientprofile',
                        'cli_system_logfetch_clientprofile_devicefilter',
                        'cli_system_logfetch_clientprofile_logfilter',
                        'cli_system_logfetch_serversettings',
                        'cli_system_logforward',
                        'cli_system_logforwardservice',
                        'cli_system_logforward_devicefilter',
                        'cli_system_logforward_logfieldexclusion',
                        'cli_system_logforward_logfilter',
                        'cli_system_log_alert',
                        'cli_system_log_interfacestats',
                        'cli_system_log_ioc',
                        'cli_system_log_maildomain',
                        'cli_system_log_settings',
                        'cli_system_log_settings_rollinganalyzer',
                        'cli_system_log_settings_rollinglocal',
                        'cli_system_log_settings_rollingregular',
                        'cli_system_mail',
                        'cli_system_metadata_admins',
                        'cli_system_ntp',
                        'cli_system_ntp_ntpserver',
                        'cli_system_passwordpolicy',
                        'cli_system_performance',
                        'cli_system_report_autocache',
                        'cli_system_report_estbrowsetime',
                        'cli_system_report_group',
                        'cli_system_report_group_chartalternative',
                        'cli_system_report_group_groupby',
                        'cli_system_report_setting',
                        'cli_system_route',
                        'cli_system_route6',
                        'cli_system_saml',
                        'cli_system_saml_fabricidp',
                        'cli_system_saml_serviceproviders',
                        'cli_system_sniffer',
                        'cli_system_snmp_community',
                        'cli_system_snmp_community_hosts',
                        'cli_system_snmp_community_hosts6',
                        'cli_system_snmp_sysinfo',
                        'cli_system_snmp_user',
                        'cli_system_sql',
                        'cli_system_sql_customindex',
                        'cli_system_sql_customskipidx',
                        'cli_system_sql_tsindexfield',
                        'cli_system_status',
                        'cli_system_syslog',
                        'cli_system_workflow_approvalmatrix',
                        'cli_system_workflow_approvalmatrix_approver',
                        'eventmgmt_adom_<adomname>_alertfilter',
                        'eventmgmt_adom_<adomname>_alertlogs',
                        'eventmgmt_adom_<adomname>_alertlogs_count',
                        'eventmgmt_adom_<adomname>_alerts',
                        'eventmgmt_adom_<adomname>_alerts_count',
                        'eventmgmt_adom_<adomname>_alerts_extradetails',
                        'fazsys_adom_<adomname>_enduseravatar',
                        'fazsys_language_fonts_export',
                        'fazsys_language_fonts_list',
                        'fazsys_language_translationfile_export',
                        'fazsys_language_translationfile_list',
                        'sys_ha_status',
                        'sys_status',
                        'ueba_adom_<adomname>_endpoints',
                        'ueba_adom_<adomname>_endpoints_stats',
                        'ueba_adom_<adomname>_endusers',
                        'ueba_adom_<adomname>_endusers_stats',
                        'report_adom_<adomname>_reports_data_<tid>',
                        'report_adom_<adomname>_reports_state',
                        'report_adom_<adomname>_run_<tid>',
                        'report_adom_<adomname>_template_export',
                        'report_adom_root_template_language',
                        'report_adom_<adomname>_template_list',
                        'task_task',
                        'task_task_line',
                        'task_task_line_history',
                        'dvmdb_adom',
                        'dvmdb_device',
                        'dvmdb_device_haslave',
                        'dvmdb_device_vdom',
                        'dvmdb_group',
                        'fortiview_adom_<adomname>_<viewname>_run_<tid>',
                        'logview_adom_<adomname>_logfields',
                        'logview_adom_<adomname>_logfiles_data',
                        'logview_adom_<adomname>_logfiles_search',
                        'logview_adom_<adomname>_logfiles_state',
                        'logview_adom_<adomname>_logsearch_<tid>',
                        'logview_adom_<adomname>_logstats',
                        'incidentmgmt_adom_<adomname>_attachments',
                        'incidentmgmt_adom_<adomname>_attachments_count',
                        'incidentmgmt_adom_<adomname>_incidents',
                        'incidentmgmt_adom_<adomname>_incidents_count',
                        'ioc_license_state',
                        'ioc_adom_<adomname>_rescan_history',
                        'ioc_adom_<adomname>_rescan_run',
                        'task_task_history',
                        'dvmdb_folder',
                        'soar_adom_<adomname>_config_connectors_<connectoruuid>',
                        'soar_adom_<adomname>_config_playbooks_<playbookuuid>',
                        'soar_adom_<adomname>_fosconnector_automationrules',
                        'soar_adom_<adomname>_playbook_monitor',
                        'soar_adom_<adomname>_task_monitor',
                        'incidentmgmt_adom_<adomname>_epeuhistory',
                        'cli_system_log_devicedisable',
                        'cli_system_interface_member',
                        'cli_system_log_ratelimit',
                        'cli_system_log_ratelimit_device',
                        'cli_system_logforward_logmaskingcustom',
                        'cli_system_socfabric',
                        'eventmgmt_adom_<adomname>_alerts_export',
                        'cli_system_sslciphersuites',
                        'cli_system_webproxy',
                        'cli_system_localinpolicy',
                        'cli_system_localinpolicy6',
                        'cli_system_log_fospolicystats',
                        'cli_system_log_ratelimit_ratelimits',
                        'cli_system_log_topology',
                        'cli_system_ha_vip',
                        'logview_adom_<adomname>_logsearch_count_<tid>',
                        'logview_pcapfile',
                        'soar_adom_<adomname>_playbook_export',
                        'soar_adom_<adomname>_subnet_export'
                    ]
                },
                'params': {
                    'required': False,
                    'type': 'dict'
                },
                'filter': {
                    'required': False,
                    'type': 'list'
                },
                'sortings': {
                    'required': False,
                    'type': 'list'
                },
                'fields': {
                    'required': False,
                    'type': 'list'
                },
                'option': {
                    'required': False,
                    'type': 'list'
                }
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(None, None, None, None, module, connection)
        fmgr.process_fact(facts_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
