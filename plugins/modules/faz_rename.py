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
module: faz_rename
short_description: Rename an object in FortiAnalyzer.
description:
    - This module is able to configure a FortiAnalyzer device by renaming an object.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Normally, running one module can fail when a non-zero rc is returned.
      However, you can override the conditions to fail or succeed with parameters rc_failed and rc_succeeded.
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of forticloud managed API users, this option is available with FortiManager later than 6.4.0.
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
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    rename:
        description: The top level parameters set.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the renamed object.
                type: str
                choices:
                    - 'cli_fmupdate_fdssetting_pushoverridetoclient_announceip'
                    - 'cli_fmupdate_fdssetting_serveroverride_servlist'
                    - 'cli_fmupdate_serveraccesspriorities_privateserver'
                    - 'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist'
                    - 'cli_system_admin_group'
                    - 'cli_system_admin_group_member'
                    - 'cli_system_admin_ldap'
                    - 'cli_system_admin_ldap_adom'
                    - 'cli_system_admin_profile'
                    - 'cli_system_admin_profile_datamaskcustomfields'
                    - 'cli_system_admin_profile_writepasswdprofiles'
                    - 'cli_system_admin_profile_writepasswduserlist'
                    - 'cli_system_admin_radius'
                    - 'cli_system_admin_tacacs'
                    - 'cli_system_admin_user'
                    - 'cli_system_admin_user_adom'
                    - 'cli_system_admin_user_adomexclude'
                    - 'cli_system_admin_user_dashboard'
                    - 'cli_system_admin_user_dashboardtabs'
                    - 'cli_system_admin_user_metadata'
                    - 'cli_system_admin_user_policyblock'
                    - 'cli_system_admin_user_policypackage'
                    - 'cli_system_admin_user_restrictdevvdom'
                    - 'cli_system_alertevent'
                    - 'cli_system_certificate_ca'
                    - 'cli_system_certificate_crl'
                    - 'cli_system_certificate_local'
                    - 'cli_system_certificate_remote'
                    - 'cli_system_certificate_ssh'
                    - 'cli_system_csf_fabricconnector'
                    - 'cli_system_csf_trustedlist'
                    - 'cli_system_ha_peer'
                    - 'cli_system_ha_privatepeer'
                    - 'cli_system_ha_vip'
                    - 'cli_system_interface'
                    - 'cli_system_interface_member'
                    - 'cli_system_localinpolicy'
                    - 'cli_system_localinpolicy6'
                    - 'cli_system_log_devicedisable'
                    - 'cli_system_log_maildomain'
                    - 'cli_system_log_ratelimit_device'
                    - 'cli_system_log_ratelimit_ratelimits'
                    - 'cli_system_logfetch_clientprofile'
                    - 'cli_system_logfetch_clientprofile_devicefilter'
                    - 'cli_system_logfetch_clientprofile_logfilter'
                    - 'cli_system_logforward'
                    - 'cli_system_logforward_devicefilter'
                    - 'cli_system_logforward_logfieldexclusion'
                    - 'cli_system_logforward_logfilter'
                    - 'cli_system_logforward_logmaskingcustom'
                    - 'cli_system_mail'
                    - 'cli_system_metadata_admins'
                    - 'cli_system_ntp_ntpserver'
                    - 'cli_system_report_group'
                    - 'cli_system_report_group_chartalternative'
                    - 'cli_system_report_group_groupby'
                    - 'cli_system_route'
                    - 'cli_system_route6'
                    - 'cli_system_saml_fabricidp'
                    - 'cli_system_saml_serviceproviders'
                    - 'cli_system_sniffer'
                    - 'cli_system_snmp_community'
                    - 'cli_system_snmp_community_hosts'
                    - 'cli_system_snmp_community_hosts6'
                    - 'cli_system_snmp_user'
                    - 'cli_system_socfabric_trustedlist'
                    - 'cli_system_sql_customindex'
                    - 'cli_system_sql_customskipidx'
                    - 'cli_system_sql_tsindexfield'
                    - 'cli_system_sslciphersuites'
                    - 'cli_system_syslog'
                    - 'cli_system_workflow_approvalmatrix'
                    - 'cli_system_workflow_approvalmatrix_approver'
                    - 'dvmdb_adom'
                    - 'dvmdb_device_vdom'
                    - 'dvmdb_folder'
                    - 'dvmdb_group'
                    - 'report_config_chart'
                    - 'report_config_chart_drilldowntable'
                    - 'report_config_chart_tablecolumns'
                    - 'report_config_chart_variabletemplate'
                    - 'report_config_dataset'
                    - 'report_config_dataset_variable'
                    - 'report_config_layout'
                    - 'report_config_layout_component'
                    - 'report_config_layout_component_variable'
                    - 'report_config_layout_footer'
                    - 'report_config_layout_header'
                    - 'report_config_layoutfolder'
                    - 'report_config_macro'
                    - 'report_config_output'
                    - 'report_config_output_emailrecipients'
                    - 'report_config_schedule'
                    - 'report_config_schedule_addressfilter'
                    - 'report_config_schedule_devices'
                    - 'report_config_schedule_filter'
                    - 'report_config_schedule_reportlayout'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Attribute to override for target object.
                type: dict
'''

EXAMPLES = '''
- name: Rename a resource.
  connection: httpapi
  hosts: fortianalyzers
  vars:
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
  tasks:
    - name: Create device group table.
      fortinet.fortianalyzer.faz_dvmdb_group:
        adom: root
        dvmdb_group:
          name: foogroup
          os_type: unknown
          type: normal
        state: present
    - name: Rename device group table.
      fortinet.fortianalyzer.faz_rename:
        rename:
          selector: dvmdb_group
          self:
            adom: root
            group: foogroup
          target:
            name: "foogroup_renamed"
    - name: Get device group table information.
      fortinet.fortianalyzer.faz_fact:
        facts:
          selector: dvmdb_group
          params:
            adom: root
            group: foogroup
      register: info
      failed_when: info.rc == 0
    - name: Delete device group table.
      fortinet.fortianalyzer.faz_dvmdb_group:
        adom: root
        state: absent
        dvmdb_group:
          name: foogroup_renamed
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


def main():
    rename_metadata = {
        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip/{announce-ip}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_fmupdate_fdssetting_serveroverride_servlist': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override/servlist/{servlist}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_fmupdate_serveraccesspriorities_privateserver': {
            'urls': [
                '/cli/global/fmupdate/server-access-priorities/private-server/{private-server}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist/{servlist}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_admin_group': {
            'urls': [
                '/cli/global/system/admin/group/{group}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_group_member': {
            'urls': [
                '/cli/global/system/admin/group/{group}/member/{member}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_ldap': {
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_ldap_adom': {
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}/adom/{adom}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'adom-name'
        },
        'cli_system_admin_profile': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'profileid'
        },
        'cli_system_admin_profile_datamaskcustomfields': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields/{datamask-custom-fields}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'field-name'
        },
        'cli_system_admin_profile_writepasswdprofiles': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-profiles/{write-passwd-profiles}'
            ],
            'v_range': [['7.4.2', '']],
            'mkey': 'profileid'
        },
        'cli_system_admin_profile_writepasswduserlist': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-user-list/{write-passwd-user-list}'
            ],
            'v_range': [['7.4.2', '']],
            'mkey': 'userid'
        },
        'cli_system_admin_radius': {
            'urls': [
                '/cli/global/system/admin/radius/{radius}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_tacacs': {
            'urls': [
                '/cli/global/system/admin/tacacs/{tacacs}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_user': {
            'urls': [
                '/cli/global/system/admin/user/{user}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'userid'
        },
        'cli_system_admin_user_adom': {
            'urls': [
                '/cli/global/system/admin/user/{user}/adom/{adom}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'adom-name'
        },
        'cli_system_admin_user_adomexclude': {
            'urls': [
                '/cli/global/system/admin/user/{user}/adom-exclude/{adom-exclude}'
            ],
            'v_range': [['6.2.1', '7.0.2']],
            'mkey': 'adom-name'
        },
        'cli_system_admin_user_dashboard': {
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'tabid'
        },
        'cli_system_admin_user_dashboardtabs': {
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard-tabs/{dashboard-tabs}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_admin_user_metadata': {
            'urls': [
                '/cli/global/system/admin/user/{user}/meta-data/{meta-data}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'fieldname'
        },
        'cli_system_admin_user_policyblock': {
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-block/{policy-block}'
            ],
            'v_range': [['7.6.0', '']],
            'mkey': 'policy_block_name'
        },
        'cli_system_admin_user_policypackage': {
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-package/{policy-package}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'policy-package-name'
        },
        'cli_system_admin_user_restrictdevvdom': {
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'v_range': [['6.2.1', '6.2.3']],
            'mkey': 'dev-vdom'
        },
        'cli_system_alertevent': {
            'urls': [
                '/cli/global/system/alert-event/{alert-event}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_certificate_ca': {
            'urls': [
                '/cli/global/system/certificate/ca/{ca}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_certificate_crl': {
            'urls': [
                '/cli/global/system/certificate/crl/{crl}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_certificate_local': {
            'urls': [
                '/cli/global/system/certificate/local/{local}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_certificate_remote': {
            'urls': [
                '/cli/global/system/certificate/remote/{remote}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_certificate_ssh': {
            'urls': [
                '/cli/global/system/certificate/ssh/{ssh}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_csf_fabricconnector': {
            'urls': [
                '/cli/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'v_range': [['7.4.1', '']],
            'mkey': 'serial'
        },
        'cli_system_csf_trustedlist': {
            'urls': [
                '/cli/global/system/csf/trusted-list/{trusted-list}'
            ],
            'v_range': [['7.4.1', '']],
            'mkey': 'name'
        },
        'cli_system_ha_peer': {
            'urls': [
                '/cli/global/system/ha/peer/{peer}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_ha_privatepeer': {
            'urls': [
                '/cli/global/system/ha/private-peer/{private-peer}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_ha_vip': {
            'urls': [
                '/cli/global/system/ha/vip/{vip}'
            ],
            'v_range': [['7.0.5', '']],
            'mkey': 'id'
        },
        'cli_system_interface': {
            'urls': [
                '/cli/global/system/interface/{interface}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_interface_member': {
            'urls': [
                '/cli/global/system/interface/{interface}/member/{member}'
            ],
            'v_range': [['6.4.9', '']],
            'mkey': 'interface-name'
        },
        'cli_system_localinpolicy': {
            'urls': [
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'v_range': [['7.2.0', '']],
            'mkey': 'id'
        },
        'cli_system_localinpolicy6': {
            'urls': [
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'v_range': [['7.2.0', '']],
            'mkey': 'id'
        },
        'cli_system_log_devicedisable': {
            'urls': [
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'v_range': [['6.4.4', '']],
            'mkey': 'id'
        },
        'cli_system_log_maildomain': {
            'urls': [
                '/cli/global/system/log/mail-domain/{mail-domain}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_log_ratelimit_device': {
            'urls': [
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'v_range': [['6.4.8', '7.0.2']],
            'mkey': 'id'
        },
        'cli_system_log_ratelimit_ratelimits': {
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'v_range': [['7.0.3', '']],
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile_devicefilter': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter/{device-filter}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logfetch_clientprofile_logfilter': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter/{log-filter}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logforward': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logforward_devicefilter': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/device-filter/{device-filter}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logforward_logfieldexclusion': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-field-exclusion/{log-field-exclusion}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logforward_logfilter': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-filter/{log-filter}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_logforward_logmaskingcustom': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-masking-custom/{log-masking-custom}'
            ],
            'v_range': [['7.0.0', '']],
            'mkey': 'id'
        },
        'cli_system_mail': {
            'urls': [
                '/cli/global/system/mail/{mail}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_metadata_admins': {
            'urls': [
                '/cli/global/system/metadata/admins/{admins}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'fieldname'
        },
        'cli_system_ntp_ntpserver': {
            'urls': [
                '/cli/global/system/ntp/ntpserver/{ntpserver}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_report_group': {
            'urls': [
                '/cli/global/system/report/group/{group}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'group-id'
        },
        'cli_system_report_group_chartalternative': {
            'urls': [
                '/cli/global/system/report/group/{group}/chart-alternative/{chart-alternative}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'chart-name'
        },
        'cli_system_report_group_groupby': {
            'urls': [
                '/cli/global/system/report/group/{group}/group-by/{group-by}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'var-name'
        },
        'cli_system_route': {
            'urls': [
                '/cli/global/system/route/{route}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'seq_num'
        },
        'cli_system_route6': {
            'urls': [
                '/cli/global/system/route6/{route6}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'prio'
        },
        'cli_system_saml_fabricidp': {
            'urls': [
                '/cli/global/system/saml/fabric-idp/{fabric-idp}'
            ],
            'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
            'mkey': 'dev-id'
        },
        'cli_system_saml_serviceproviders': {
            'urls': [
                '/cli/global/system/saml/service-providers/{service-providers}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_sniffer': {
            'urls': [
                '/cli/global/system/sniffer/{sniffer}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_snmp_community': {
            'urls': [
                '/cli/global/system/snmp/community/{community}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_snmp_community_hosts': {
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_snmp_community_hosts6': {
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_snmp_user': {
            'urls': [
                '/cli/global/system/snmp/user/{user}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_socfabric_trustedlist': {
            'urls': [
                '/cli/global/system/soc-fabric/trusted-list/{trusted-list}'
            ],
            'v_range': [['7.4.0', '']],
            'mkey': 'id'
        },
        'cli_system_sql_customindex': {
            'urls': [
                '/cli/global/system/sql/custom-index/{custom-index}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'cli_system_sql_customskipidx': {
            'urls': [
                '/cli/global/system/sql/custom-skipidx/{custom-skipidx}'
            ],
            'v_range': [['6.2.1', '6.2.1'], ['6.2.3', '']],
            'mkey': 'id'
        },
        'cli_system_sql_tsindexfield': {
            'urls': [
                '/cli/global/system/sql/ts-index-field/{ts-index-field}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'category'
        },
        'cli_system_sslciphersuites': {
            'urls': [
                '/cli/global/system/global/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']],
            'mkey': 'priority'
        },
        'cli_system_syslog': {
            'urls': [
                '/cli/global/system/syslog/{syslog}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'cli_system_workflow_approvalmatrix': {
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}'
            ],
            'v_range': [['6.2.1', '6.2.9'], ['6.4.1', '6.4.7'], ['7.0.0', '7.0.2'], ['7.6.0', '']],
            'mkey': 'adom-name'
        },
        'cli_system_workflow_approvalmatrix_approver': {
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver/{approver}'
            ],
            'v_range': [['6.2.1', '6.2.9'], ['6.4.1', '6.4.7'], ['7.0.0', '7.0.2'], ['7.6.0', '']],
            'mkey': 'seq_num'
        },
        'dvmdb_adom': {
            'urls': [
                '/dvmdb/adom/{adom}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'dvmdb_device_vdom': {
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/vdom/{vdom}',
                '/dvmdb/device/{device}/vdom/{vdom}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'dvmdb_folder': {
            'urls': [
                '/dvmdb/adom/{adom}/folder/{folder}',
                '/dvmdb/folder/{folder}'
            ],
            'v_range': [['6.4.2', '']],
            'mkey': 'name'
        },
        'dvmdb_group': {
            'urls': [
                '/dvmdb/adom/{adom}/group/{group}',
                '/dvmdb/group/{group}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_chart': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_chart_drilldowntable': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/drill-down-table/{drill-down-table}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'table_id'
        },
        'report_config_chart_tablecolumns': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/table-columns/{table-columns}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'id'
        },
        'report_config_chart_variabletemplate': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/variable-template/{variable-template}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'var'
        },
        'report_config_dataset': {
            'urls': [
                '/report/adom/{adom}/config/dataset/{dataset}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_dataset_variable': {
            'urls': [
                '/report/adom/{adom}/config/dataset/{dataset_name}/variable/{variable}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'var'
        },
        'report_config_layout': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'layout_id'
        },
        'report_config_layout_component': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/component/{component}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'component_id'
        },
        'report_config_layout_component_variable': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/component/{component-id}/variable/{variable}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'var'
        },
        'report_config_layout_footer': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/footer/{footer}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'footer_id'
        },
        'report_config_layout_header': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/header/{header}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'header_id'
        },
        'report_config_layoutfolder': {
            'urls': [
                '/report/adom/{adom}/config/layout-folder/{layout-folder}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'folder_id'
        },
        'report_config_macro': {
            'urls': [
                '/report/adom/{adom}/config/macro/{macro}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_output': {
            'urls': [
                '/report/adom/{adom}/config/output/{output}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_output_emailrecipients': {
            'urls': [
                '/report/adom/{adom}/config/output/{output-name}/email-recipients/{email-recipients}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'address'
        },
        'report_config_schedule': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_schedule_addressfilter': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/address-filter/{address-filter}'
            ],
            'v_range': [['6.4.3', '']],
            'mkey': 'id'
        },
        'report_config_schedule_devices': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/devices/{devices}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'devices_name'
        },
        'report_config_schedule_filter': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/filter/{filter}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'name'
        },
        'report_config_schedule_reportlayout': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/report-layout/{report-layout}'
            ],
            'v_range': [['6.2.1', '']],
            'mkey': 'layout_id'
        }
    }

    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'log_path': {'type': 'str', 'default': '/tmp/fortianalyzer.ansible.log'},
        'version_check': {'type': 'bool', 'default': 'true'},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
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
                        'cli_system_admin_ldap_adom',
                        'cli_system_admin_profile',
                        'cli_system_admin_profile_datamaskcustomfields',
                        'cli_system_admin_profile_writepasswdprofiles',
                        'cli_system_admin_profile_writepasswduserlist',
                        'cli_system_admin_radius',
                        'cli_system_admin_tacacs',
                        'cli_system_admin_user',
                        'cli_system_admin_user_adom',
                        'cli_system_admin_user_adomexclude',
                        'cli_system_admin_user_dashboard',
                        'cli_system_admin_user_dashboardtabs',
                        'cli_system_admin_user_metadata',
                        'cli_system_admin_user_policyblock',
                        'cli_system_admin_user_policypackage',
                        'cli_system_admin_user_restrictdevvdom',
                        'cli_system_alertevent',
                        'cli_system_certificate_ca',
                        'cli_system_certificate_crl',
                        'cli_system_certificate_local',
                        'cli_system_certificate_remote',
                        'cli_system_certificate_ssh',
                        'cli_system_csf_fabricconnector',
                        'cli_system_csf_trustedlist',
                        'cli_system_ha_peer',
                        'cli_system_ha_privatepeer',
                        'cli_system_ha_vip',
                        'cli_system_interface',
                        'cli_system_interface_member',
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
                        'cli_system_report_group_chartalternative',
                        'cli_system_report_group_groupby',
                        'cli_system_route',
                        'cli_system_route6',
                        'cli_system_saml_fabricidp',
                        'cli_system_saml_serviceproviders',
                        'cli_system_sniffer',
                        'cli_system_snmp_community',
                        'cli_system_snmp_community_hosts',
                        'cli_system_snmp_community_hosts6',
                        'cli_system_snmp_user',
                        'cli_system_socfabric_trustedlist',
                        'cli_system_sql_customindex',
                        'cli_system_sql_customskipidx',
                        'cli_system_sql_tsindexfield',
                        'cli_system_sslciphersuites',
                        'cli_system_syslog',
                        'cli_system_workflow_approvalmatrix',
                        'cli_system_workflow_approvalmatrix_approver',
                        'dvmdb_adom',
                        'dvmdb_device_vdom',
                        'dvmdb_folder',
                        'dvmdb_group',
                        'report_config_chart',
                        'report_config_chart_drilldowntable',
                        'report_config_chart_tablecolumns',
                        'report_config_chart_variabletemplate',
                        'report_config_dataset',
                        'report_config_dataset_variable',
                        'report_config_layout',
                        'report_config_layout_component',
                        'report_config_layout_component_variable',
                        'report_config_layout_footer',
                        'report_config_layout_header',
                        'report_config_layoutfolder',
                        'report_config_macro',
                        'report_config_output',
                        'report_config_output_emailrecipients',
                        'report_config_schedule',
                        'report_config_schedule_addressfilter',
                        'report_config_schedule_devices',
                        'report_config_schedule_filter',
                        'report_config_schedule_reportlayout'
                    ]
                },
                'self': {'required': True, 'type': 'dict'},
                'target': {'required': True, 'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(None, None, None, module, connection, metadata=rename_metadata, task_type='rename')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
