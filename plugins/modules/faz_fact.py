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
module: faz_fact
short_description: Gather FortiAnalyzer facts.
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
    - Normally, running one module can fail when a non-zero rc is returned.
      However, you can override the conditions to fail or succeed with parameters rc_failed and rc_succeeded.
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    enable_log:
        description: Enable/Disable logging for task
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of FortiCloud managed API users, this option is available with FortiManager later than 6.4.0.
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
    facts:
        description: the top level parameters set
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: selector of the retrieved fortianalyzer facts.
                type: str
                choices:
                    - 'cli_fmupdate_analyzer_virusreport'
                    - 'cli_fmupdate_avips_advancedlog'
                    - 'cli_fmupdate_avips_webproxy'
                    - 'cli_fmupdate_customurllist'
                    - 'cli_fmupdate_diskquota'
                    - 'cli_fmupdate_fctservices'
                    - 'cli_fmupdate_fdssetting'
                    - 'cli_fmupdate_fdssetting_pushoverride'
                    - 'cli_fmupdate_fdssetting_pushoverridetoclient'
                    - 'cli_fmupdate_fdssetting_pushoverridetoclient_announceip'
                    - 'cli_fmupdate_fdssetting_serveroverride'
                    - 'cli_fmupdate_fdssetting_serveroverride_servlist'
                    - 'cli_fmupdate_fdssetting_updateschedule'
                    - 'cli_fmupdate_fwmsetting'
                    - 'cli_fmupdate_fwmsetting_upgradetimeout'
                    - 'cli_fmupdate_multilayer'
                    - 'cli_fmupdate_publicnetwork'
                    - 'cli_fmupdate_serveraccesspriorities'
                    - 'cli_fmupdate_serveraccesspriorities_privateserver'
                    - 'cli_fmupdate_serveroverridestatus'
                    - 'cli_fmupdate_service'
                    - 'cli_fmupdate_webspam_fgdsetting'
                    - 'cli_fmupdate_webspam_fgdsetting_serveroverride'
                    - 'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist'
                    - 'cli_fmupdate_webspam_webproxy'
                    - 'cli_metafields_system_admin_user'
                    - 'cli_system_admin_group'
                    - 'cli_system_admin_group_member'
                    - 'cli_system_admin_ldap'
                    - 'cli_system_admin_ldap_adom'
                    - 'cli_system_admin_profile'
                    - 'cli_system_admin_profile_datamaskcustomfields'
                    - 'cli_system_admin_profile_writepasswdprofiles'
                    - 'cli_system_admin_profile_writepasswduserlist'
                    - 'cli_system_admin_radius'
                    - 'cli_system_admin_setting'
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
                    - 'cli_system_alertconsole'
                    - 'cli_system_alertemail'
                    - 'cli_system_alertevent'
                    - 'cli_system_alertevent_alertdestination'
                    - 'cli_system_autodelete'
                    - 'cli_system_autodelete_dlpfilesautodeletion'
                    - 'cli_system_autodelete_logautodeletion'
                    - 'cli_system_autodelete_quarantinefilesautodeletion'
                    - 'cli_system_autodelete_reportautodeletion'
                    - 'cli_system_backup_allsettings'
                    - 'cli_system_centralmanagement'
                    - 'cli_system_certificate_ca'
                    - 'cli_system_certificate_crl'
                    - 'cli_system_certificate_local'
                    - 'cli_system_certificate_oftp'
                    - 'cli_system_certificate_remote'
                    - 'cli_system_certificate_ssh'
                    - 'cli_system_connector'
                    - 'cli_system_csf'
                    - 'cli_system_csf_fabricconnector'
                    - 'cli_system_csf_trustedlist'
                    - 'cli_system_dns'
                    - 'cli_system_docker'
                    - 'cli_system_fips'
                    - 'cli_system_fortiview_autocache'
                    - 'cli_system_fortiview_setting'
                    - 'cli_system_global'
                    - 'cli_system_guiact'
                    - 'cli_system_ha'
                    - 'cli_system_ha_peer'
                    - 'cli_system_ha_privatepeer'
                    - 'cli_system_ha_vip'
                    - 'cli_system_interface'
                    - 'cli_system_interface_ipv6'
                    - 'cli_system_interface_member'
                    - 'cli_system_localinpolicy'
                    - 'cli_system_localinpolicy6'
                    - 'cli_system_locallog_disk_filter'
                    - 'cli_system_locallog_disk_setting'
                    - 'cli_system_locallog_fortianalyzer2_filter'
                    - 'cli_system_locallog_fortianalyzer2_setting'
                    - 'cli_system_locallog_fortianalyzer3_filter'
                    - 'cli_system_locallog_fortianalyzer3_setting'
                    - 'cli_system_locallog_fortianalyzer_filter'
                    - 'cli_system_locallog_fortianalyzer_setting'
                    - 'cli_system_locallog_memory_filter'
                    - 'cli_system_locallog_memory_setting'
                    - 'cli_system_locallog_setting'
                    - 'cli_system_locallog_syslogd2_filter'
                    - 'cli_system_locallog_syslogd2_setting'
                    - 'cli_system_locallog_syslogd3_filter'
                    - 'cli_system_locallog_syslogd3_setting'
                    - 'cli_system_locallog_syslogd_filter'
                    - 'cli_system_locallog_syslogd_setting'
                    - 'cli_system_log_alert'
                    - 'cli_system_log_devicedisable'
                    - 'cli_system_log_fospolicystats'
                    - 'cli_system_log_interfacestats'
                    - 'cli_system_log_ioc'
                    - 'cli_system_log_maildomain'
                    - 'cli_system_log_pcapfile'
                    - 'cli_system_log_ratelimit'
                    - 'cli_system_log_ratelimit_device'
                    - 'cli_system_log_ratelimit_ratelimits'
                    - 'cli_system_log_settings'
                    - 'cli_system_log_settings_rollinganalyzer'
                    - 'cli_system_log_settings_rollinglocal'
                    - 'cli_system_log_settings_rollingregular'
                    - 'cli_system_log_topology'
                    - 'cli_system_log_ueba'
                    - 'cli_system_logfetch_clientprofile'
                    - 'cli_system_logfetch_clientprofile_devicefilter'
                    - 'cli_system_logfetch_clientprofile_logfilter'
                    - 'cli_system_logfetch_serversettings'
                    - 'cli_system_logforward'
                    - 'cli_system_logforward_devicefilter'
                    - 'cli_system_logforward_logfieldexclusion'
                    - 'cli_system_logforward_logfilter'
                    - 'cli_system_logforward_logmaskingcustom'
                    - 'cli_system_logforwardservice'
                    - 'cli_system_mail'
                    - 'cli_system_metadata_admins'
                    - 'cli_system_ntp'
                    - 'cli_system_ntp_ntpserver'
                    - 'cli_system_passwordpolicy'
                    - 'cli_system_performance'
                    - 'cli_system_report_autocache'
                    - 'cli_system_report_estbrowsetime'
                    - 'cli_system_report_group'
                    - 'cli_system_report_group_chartalternative'
                    - 'cli_system_report_group_groupby'
                    - 'cli_system_report_setting'
                    - 'cli_system_route'
                    - 'cli_system_route6'
                    - 'cli_system_saml'
                    - 'cli_system_saml_fabricidp'
                    - 'cli_system_saml_serviceproviders'
                    - 'cli_system_sniffer'
                    - 'cli_system_snmp_community'
                    - 'cli_system_snmp_community_hosts'
                    - 'cli_system_snmp_community_hosts6'
                    - 'cli_system_snmp_sysinfo'
                    - 'cli_system_snmp_user'
                    - 'cli_system_socfabric'
                    - 'cli_system_socfabric_trustedlist'
                    - 'cli_system_sql'
                    - 'cli_system_sql_customindex'
                    - 'cli_system_sql_customskipidx'
                    - 'cli_system_sql_tsindexfield'
                    - 'cli_system_sslciphersuites'
                    - 'cli_system_status'
                    - 'cli_system_syslog'
                    - 'cli_system_webproxy'
                    - 'cli_system_workflow_approvalmatrix'
                    - 'cli_system_workflow_approvalmatrix_approver'
                    - 'dvmdb_adom'
                    - 'dvmdb_device'
                    - 'dvmdb_device_haslave'
                    - 'dvmdb_device_vdom'
                    - 'dvmdb_folder'
                    - 'dvmdb_group'
                    - 'eventmgmt_alertfilter'
                    - 'eventmgmt_alertincident_stats'
                    - 'eventmgmt_alertlogs'
                    - 'eventmgmt_alertlogs_count'
                    - 'eventmgmt_alerts'
                    - 'eventmgmt_alerts_count'
                    - 'eventmgmt_alerts_export'
                    - 'eventmgmt_alerts_extradetails'
                    - 'eventmgmt_basichandlers_export'
                    - 'eventmgmt_correlationhandlers_export'
                    - 'fazsys_enduseravatar'
                    - 'fazsys_forticare_licinfo'
                    - 'fazsys_language_fonts_export'
                    - 'fazsys_language_fonts_list'
                    - 'fazsys_language_translationfile_export'
                    - 'fazsys_language_translationfile_list'
                    - 'fazsys_lograte_history'
                    - 'fazsys_monitor_logforwardstatus'
                    - 'fazsys_monitor_system_performance_status'
                    - 'fazsys_storageinfo'
                    - 'fazsys_storageinfohistory'
                    - 'fortiview_run'
                    - 'incidentmgmt_attachments'
                    - 'incidentmgmt_attachments_count'
                    - 'incidentmgmt_epeuhistory'
                    - 'incidentmgmt_incident_stats'
                    - 'incidentmgmt_incidents'
                    - 'incidentmgmt_incidents_count'
                    - 'ioc_license_state'
                    - 'ioc_rescan_history'
                    - 'ioc_rescan_run'
                    - 'logview_logfields'
                    - 'logview_logfiles_data'
                    - 'logview_logfiles_search'
                    - 'logview_logfiles_state'
                    - 'logview_logsearch'
                    - 'logview_logsearch_count'
                    - 'logview_logstats'
                    - 'logview_pcapfile'
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
                    - 'report_graphfile'
                    - 'report_graphfile_data'
                    - 'report_graphfile_list'
                    - 'report_reports_data'
                    - 'report_reports_state'
                    - 'report_run'
                    - 'report_template_export'
                    - 'report_template_language'
                    - 'report_template_list'
                    - 'soar_alert_indicator'
                    - 'soar_config_connectors'
                    - 'soar_config_playbooks'
                    - 'soar_fosconnector_automationrules'
                    - 'soar_incident_indicator'
                    - 'soar_indicator'
                    - 'soar_indicator_enrichment'
                    - 'soar_playbook_export'
                    - 'soar_playbook_monitor'
                    - 'soar_playbook_run'
                    - 'soar_playbook_runlog'
                    - 'soar_subnet_export'
                    - 'soar_task_monitor'
                    - 'sys_ha_status'
                    - 'sys_status'
                    - 'task_task'
                    - 'task_task_history'
                    - 'task_task_line'
                    - 'task_task_line_history'
                    - 'ueba_endpoints'
                    - 'ueba_endpoints_stats'
                    - 'ueba_endpoints_vuln'
                    - 'ueba_endusers'
                    - 'ueba_endusers_stats'
                    - 'ueba_otview'
            fields:
                description:
                    - Limit the output by returning only the attributes specified in the string array.
                    - If none specified, all attributes will be returned.
                type: list
                elements: raw
            filter:
                description: Filter the result according to a set of criteria.
                type: list
                elements: raw
            option:
                description:
                    - Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.
                    - See more details in FNDN API documents.
                type: raw
            sortings:
                description: Sorting rules list. Items are returned in ascending(1) or descending(-1) order of fields in the list.
                type: list
                elements: dict
            params:
                description:
                    - The parameters for each different selector, such as "loadsub", "meta field", "range".
                    - You can also specify "fields", "filter", "option" and "sortings" here.
                type: dict
            extra_params:
                description:
                    - Extra parameters for each different selector.
                    - Deprecated. You can add extra parameters directly in "params".
                type: dict
'''

EXAMPLES = '''
- name: Gathering fortianalyzer facts
  hosts: fortianalyzers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Fetch adom
      fortinet.fortianalyzer.faz_fact:
        facts:
          selector: "dvmdb_adom"
          filter:
            - - "os_ver"
              - "=="
              - "7.0"
            - "&&"
            - - "state"
              - "=="
              - "1"
          fields:
            - "name"
            - "restricted_prds"
          # option: "object member" # "count", "object member" or "syntax"
          sortings:
            - "restricted_prds": -1 # sort based on restricted_prds first (-1, descending)
            - "oid": 1 # if restricted_prds are same, then, sort based on oid (1, ascending)
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
    facts_metadata = {
        'cli_fmupdate_analyzer_virusreport': {
            'urls': [
                '/cli/global/fmupdate/analyzer/virusreport'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_avips_advancedlog': {
            'urls': [
                '/cli/global/fmupdate/av-ips/advanced-log'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_avips_webproxy': {
            'urls': [
                '/cli/global/fmupdate/av-ips/web-proxy'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '7.4.0']],
        },
        'cli_fmupdate_customurllist': {
            'urls': [
                '/cli/global/fmupdate/custom-url-list'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_diskquota': {
            'urls': [
                '/cli/global/fmupdate/disk-quota'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fctservices': {
            'urls': [
                '/cli/global/fmupdate/fct-services'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting': {
            'urls': [
                '/cli/global/fmupdate/fds-setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_pushoverride': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_pushoverridetoclient': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip',
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip/{announce-ip}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_serveroverride': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_serveroverride_servlist': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override/servlist',
                '/cli/global/fmupdate/fds-setting/server-override/servlist/{servlist}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fdssetting_updateschedule': {
            'urls': [
                '/cli/global/fmupdate/fds-setting/update-schedule'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fwmsetting': {
            'urls': [
                '/cli/global/fmupdate/fwm-setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_fwmsetting_upgradetimeout': {
            'urls': [
                '/cli/global/fmupdate/fwm-setting/upgrade-timeout'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.0.5', '7.0.12'], ['7.2.2', '']],
        },
        'cli_fmupdate_multilayer': {
            'urls': [
                '/cli/global/fmupdate/multilayer'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_publicnetwork': {
            'urls': [
                '/cli/global/fmupdate/publicnetwork'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_serveraccesspriorities': {
            'urls': [
                '/cli/global/fmupdate/server-access-priorities'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_serveraccesspriorities_privateserver': {
            'urls': [
                '/cli/global/fmupdate/server-access-priorities/private-server',
                '/cli/global/fmupdate/server-access-priorities/private-server/{private-server}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_serveroverridestatus': {
            'urls': [
                '/cli/global/fmupdate/server-override-status'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_service': {
            'urls': [
                '/cli/global/fmupdate/service'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_webspam_fgdsetting': {
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride': {
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist',
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist/{servlist}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_fmupdate_webspam_webproxy': {
            'urls': [
                '/cli/global/fmupdate/web-spam/web-proxy'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '7.4.0']],
        },
        'cli_metafields_system_admin_user': {
            'urls': [
                '/cli/global/_meta_fields/system/admin/user'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_group': {
            'urls': [
                '/cli/global/system/admin/group',
                '/cli/global/system/admin/group/{group}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_group_member': {
            'urls': [
                '/cli/global/system/admin/group/{group}/member',
                '/cli/global/system/admin/group/{group}/member/{member}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_ldap': {
            'urls': [
                '/cli/global/system/admin/ldap',
                '/cli/global/system/admin/ldap/{ldap}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_ldap_adom': {
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}/adom',
                '/cli/global/system/admin/ldap/{ldap}/adom/{adom}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_profile': {
            'urls': [
                '/cli/global/system/admin/profile',
                '/cli/global/system/admin/profile/{profile}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_profile_datamaskcustomfields': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields',
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields/{datamask-custom-fields}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_profile_writepasswdprofiles': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-profiles',
                '/cli/global/system/admin/profile/{profile}/write-passwd-profiles/{write-passwd-profiles}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.4.2', '']],
        },
        'cli_system_admin_profile_writepasswduserlist': {
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-user-list',
                '/cli/global/system/admin/profile/{profile}/write-passwd-user-list/{write-passwd-user-list}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.4.2', '']],
        },
        'cli_system_admin_radius': {
            'urls': [
                '/cli/global/system/admin/radius',
                '/cli/global/system/admin/radius/{radius}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_setting': {
            'urls': [
                '/cli/global/system/admin/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_tacacs': {
            'urls': [
                '/cli/global/system/admin/tacacs',
                '/cli/global/system/admin/tacacs/{tacacs}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user': {
            'urls': [
                '/cli/global/system/admin/user',
                '/cli/global/system/admin/user/{user}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_adom': {
            'urls': [
                '/cli/global/system/admin/user/{user}/adom',
                '/cli/global/system/admin/user/{user}/adom/{adom}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_adomexclude': {
            'urls': [
                '/cli/global/system/admin/user/{user}/adom-exclude',
                '/cli/global/system/admin/user/{user}/adom-exclude/{adom-exclude}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '7.0.2']],
        },
        'cli_system_admin_user_dashboard': {
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard',
                '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_dashboardtabs': {
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard-tabs',
                '/cli/global/system/admin/user/{user}/dashboard-tabs/{dashboard-tabs}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_metadata': {
            'urls': [
                '/cli/global/system/admin/user/{user}/meta-data',
                '/cli/global/system/admin/user/{user}/meta-data/{meta-data}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_policyblock': {
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-block',
                '/cli/global/system/admin/user/{user}/policy-block/{policy-block}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.6.0', '']],
        },
        'cli_system_admin_user_policypackage': {
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-package',
                '/cli/global/system/admin/user/{user}/policy-package/{policy-package}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_admin_user_restrictdevvdom': {
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom',
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.3']],
        },
        'cli_system_alertconsole': {
            'urls': [
                '/cli/global/system/alert-console'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_alertemail': {
            'urls': [
                '/cli/global/system/alertemail'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_alertevent': {
            'urls': [
                '/cli/global/system/alert-event',
                '/cli/global/system/alert-event/{alert-event}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_alertevent_alertdestination': {
            'urls': [
                '/cli/global/system/alert-event/{alert-event}/alert-destination',
                '/cli/global/system/alert-event/{alert-event}/alert-destination/{alert-destination}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_autodelete': {
            'urls': [
                '/cli/global/system/auto-delete'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_autodelete_dlpfilesautodeletion': {
            'urls': [
                '/cli/global/system/auto-delete/dlp-files-auto-deletion'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_autodelete_logautodeletion': {
            'urls': [
                '/cli/global/system/auto-delete/log-auto-deletion'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_autodelete_quarantinefilesautodeletion': {
            'urls': [
                '/cli/global/system/auto-delete/quarantine-files-auto-deletion'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_autodelete_reportautodeletion': {
            'urls': [
                '/cli/global/system/auto-delete/report-auto-deletion'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_backup_allsettings': {
            'urls': [
                '/cli/global/system/backup/all-settings'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_centralmanagement': {
            'urls': [
                '/cli/global/system/central-management'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_ca': {
            'urls': [
                '/cli/global/system/certificate/ca',
                '/cli/global/system/certificate/ca/{ca}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_crl': {
            'urls': [
                '/cli/global/system/certificate/crl',
                '/cli/global/system/certificate/crl/{crl}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_local': {
            'urls': [
                '/cli/global/system/certificate/local',
                '/cli/global/system/certificate/local/{local}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_oftp': {
            'urls': [
                '/cli/global/system/certificate/oftp'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_remote': {
            'urls': [
                '/cli/global/system/certificate/remote',
                '/cli/global/system/certificate/remote/{remote}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_certificate_ssh': {
            'urls': [
                '/cli/global/system/certificate/ssh',
                '/cli/global/system/certificate/ssh/{ssh}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_connector': {
            'urls': [
                '/cli/global/system/connector'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_csf': {
            'urls': [
                '/cli/global/system/csf'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.4.1', '']],
        },
        'cli_system_csf_fabricconnector': {
            'urls': [
                '/cli/global/system/csf/fabric-connector',
                '/cli/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.4.1', '']],
        },
        'cli_system_csf_trustedlist': {
            'urls': [
                '/cli/global/system/csf/trusted-list',
                '/cli/global/system/csf/trusted-list/{trusted-list}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.4.1', '']],
        },
        'cli_system_dns': {
            'urls': [
                '/cli/global/system/dns'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_docker': {
            'urls': [
                '/cli/global/system/docker'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
        },
        'cli_system_fips': {
            'urls': [
                '/cli/global/system/fips'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_fortiview_autocache': {
            'urls': [
                '/cli/global/system/fortiview/auto-cache'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_fortiview_setting': {
            'urls': [
                '/cli/global/system/fortiview/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_global': {
            'urls': [
                '/cli/global/system/global'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_guiact': {
            'urls': [
                '/cli/global/system/guiact'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']],
        },
        'cli_system_ha': {
            'urls': [
                '/cli/global/system/ha'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_ha_peer': {
            'urls': [
                '/cli/global/system/ha/peer',
                '/cli/global/system/ha/peer/{peer}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_ha_privatepeer': {
            'urls': [
                '/cli/global/system/ha/private-peer',
                '/cli/global/system/ha/private-peer/{private-peer}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_ha_vip': {
            'urls': [
                '/cli/global/system/ha/vip',
                '/cli/global/system/ha/vip/{vip}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.0.5', '']],
        },
        'cli_system_interface': {
            'urls': [
                '/cli/global/system/interface',
                '/cli/global/system/interface/{interface}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_interface_ipv6': {
            'urls': [
                '/cli/global/system/interface/{interface}/ipv6'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_interface_member': {
            'urls': [
                '/cli/global/system/interface/{interface}/member',
                '/cli/global/system/interface/{interface}/member/{member}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.4.9', '']],
        },
        'cli_system_localinpolicy': {
            'urls': [
                '/cli/global/system/local-in-policy',
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.2.0', '']],
        },
        'cli_system_localinpolicy6': {
            'urls': [
                '/cli/global/system/local-in-policy6',
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.2.0', '']],
        },
        'cli_system_locallog_disk_filter': {
            'urls': [
                '/cli/global/system/locallog/disk/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_disk_setting': {
            'urls': [
                '/cli/global/system/locallog/disk/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer2_filter': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer2_setting': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer3_filter': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer3_setting': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer_filter': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_fortianalyzer_setting': {
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_memory_filter': {
            'urls': [
                '/cli/global/system/locallog/memory/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_memory_setting': {
            'urls': [
                '/cli/global/system/locallog/memory/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_setting': {
            'urls': [
                '/cli/global/system/locallog/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd2_filter': {
            'urls': [
                '/cli/global/system/locallog/syslogd2/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd2_setting': {
            'urls': [
                '/cli/global/system/locallog/syslogd2/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd3_filter': {
            'urls': [
                '/cli/global/system/locallog/syslogd3/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd3_setting': {
            'urls': [
                '/cli/global/system/locallog/syslogd3/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd_filter': {
            'urls': [
                '/cli/global/system/locallog/syslogd/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_locallog_syslogd_setting': {
            'urls': [
                '/cli/global/system/locallog/syslogd/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_alert': {
            'urls': [
                '/cli/global/system/log/alert'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_devicedisable': {
            'urls': [
                '/cli/global/system/log/device-disable',
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.4.4', '']],
        },
        'cli_system_log_fospolicystats': {
            'urls': [
                '/cli/global/system/log/fos-policy-stats'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.0.2', '']],
        },
        'cli_system_log_interfacestats': {
            'urls': [
                '/cli/global/system/log/interface-stats'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_ioc': {
            'urls': [
                '/cli/global/system/log/ioc'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_maildomain': {
            'urls': [
                '/cli/global/system/log/mail-domain',
                '/cli/global/system/log/mail-domain/{mail-domain}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_pcapfile': {
            'urls': [
                '/cli/global/system/log/pcap-file'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.4.1', '']],
        },
        'cli_system_log_ratelimit': {
            'urls': [
                '/cli/global/system/log/ratelimit'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.4.8', '']],
        },
        'cli_system_log_ratelimit_device': {
            'urls': [
                '/cli/global/system/log/ratelimit/device',
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.4.8', '7.0.2']],
        },
        'cli_system_log_ratelimit_ratelimits': {
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits',
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.0.3', '']],
        },
        'cli_system_log_settings': {
            'urls': [
                '/cli/global/system/log/settings'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_settings_rollinganalyzer': {
            'urls': [
                '/cli/global/system/log/settings/rolling-analyzer'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_settings_rollinglocal': {
            'urls': [
                '/cli/global/system/log/settings/rolling-local'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_settings_rollingregular': {
            'urls': [
                '/cli/global/system/log/settings/rolling-regular'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_log_topology': {
            'urls': [
                '/cli/global/system/log/topology'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.4.7', '6.4.14'], ['7.0.2', '']],
        },
        'cli_system_log_ueba': {
            'urls': [
                '/cli/global/system/log/ueba'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.4.3', '']],
        },
        'cli_system_logfetch_clientprofile': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile',
                '/cli/global/system/log-fetch/client-profile/{client-profile}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logfetch_clientprofile_devicefilter': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter',
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter/{device-filter}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logfetch_clientprofile_logfilter': {
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter',
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter/{log-filter}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logfetch_serversettings': {
            'urls': [
                '/cli/global/system/log-fetch/server-settings'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logforward': {
            'urls': [
                '/cli/global/system/log-forward',
                '/cli/global/system/log-forward/{log-forward}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logforward_devicefilter': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/device-filter',
                '/cli/global/system/log-forward/{log-forward}/device-filter/{device-filter}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logforward_logfieldexclusion': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-field-exclusion',
                '/cli/global/system/log-forward/{log-forward}/log-field-exclusion/{log-field-exclusion}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logforward_logfilter': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-filter',
                '/cli/global/system/log-forward/{log-forward}/log-filter/{log-filter}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_logforward_logmaskingcustom': {
            'urls': [
                '/cli/global/system/log-forward/{log-forward}/log-masking-custom',
                '/cli/global/system/log-forward/{log-forward}/log-masking-custom/{log-masking-custom}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.0.0', '']],
        },
        'cli_system_logforwardservice': {
            'urls': [
                '/cli/global/system/log-forward-service'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_mail': {
            'urls': [
                '/cli/global/system/mail',
                '/cli/global/system/mail/{mail}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_metadata_admins': {
            'urls': [
                '/cli/global/system/metadata/admins',
                '/cli/global/system/metadata/admins/{admins}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_ntp': {
            'urls': [
                '/cli/global/system/ntp'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_ntp_ntpserver': {
            'urls': [
                '/cli/global/system/ntp/ntpserver',
                '/cli/global/system/ntp/ntpserver/{ntpserver}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_passwordpolicy': {
            'urls': [
                '/cli/global/system/password-policy'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_performance': {
            'urls': [
                '/cli/global/system/performance'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_autocache': {
            'urls': [
                '/cli/global/system/report/auto-cache'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_estbrowsetime': {
            'urls': [
                '/cli/global/system/report/est-browse-time'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_group': {
            'urls': [
                '/cli/global/system/report/group',
                '/cli/global/system/report/group/{group}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_group_chartalternative': {
            'urls': [
                '/cli/global/system/report/group/{group}/chart-alternative',
                '/cli/global/system/report/group/{group}/chart-alternative/{chart-alternative}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_group_groupby': {
            'urls': [
                '/cli/global/system/report/group/{group}/group-by',
                '/cli/global/system/report/group/{group}/group-by/{group-by}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_report_setting': {
            'urls': [
                '/cli/global/system/report/setting'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_route': {
            'urls': [
                '/cli/global/system/route',
                '/cli/global/system/route/{route}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_route6': {
            'urls': [
                '/cli/global/system/route6',
                '/cli/global/system/route6/{route6}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_saml': {
            'urls': [
                '/cli/global/system/saml'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_saml_fabricidp': {
            'urls': [
                '/cli/global/system/saml/fabric-idp',
                '/cli/global/system/saml/fabric-idp/{fabric-idp}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
        },
        'cli_system_saml_serviceproviders': {
            'urls': [
                '/cli/global/system/saml/service-providers',
                '/cli/global/system/saml/service-providers/{service-providers}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_sniffer': {
            'urls': [
                '/cli/global/system/sniffer',
                '/cli/global/system/sniffer/{sniffer}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_snmp_community': {
            'urls': [
                '/cli/global/system/snmp/community',
                '/cli/global/system/snmp/community/{community}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_snmp_community_hosts': {
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts',
                '/cli/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_snmp_community_hosts6': {
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts6',
                '/cli/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_snmp_sysinfo': {
            'urls': [
                '/cli/global/system/snmp/sysinfo'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_snmp_user': {
            'urls': [
                '/cli/global/system/snmp/user',
                '/cli/global/system/snmp/user/{user}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_socfabric': {
            'urls': [
                '/cli/global/system/soc-fabric'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['7.0.0', '']],
        },
        'cli_system_socfabric_trustedlist': {
            'urls': [
                '/cli/global/system/soc-fabric/trusted-list',
                '/cli/global/system/soc-fabric/trusted-list/{trusted-list}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['7.4.0', '']],
        },
        'cli_system_sql': {
            'urls': [
                '/cli/global/system/sql'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_sql_customindex': {
            'urls': [
                '/cli/global/system/sql/custom-index',
                '/cli/global/system/sql/custom-index/{custom-index}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_sql_customskipidx': {
            'urls': [
                '/cli/global/system/sql/custom-skipidx',
                '/cli/global/system/sql/custom-skipidx/{custom-skipidx}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.1'], ['6.2.3', '']],
        },
        'cli_system_sql_tsindexfield': {
            'urls': [
                '/cli/global/system/sql/ts-index-field',
                '/cli/global/system/sql/ts-index-field/{ts-index-field}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_sslciphersuites': {
            'urls': [
                '/cli/global/system/global/ssl-cipher-suites',
                '/cli/global/system/global/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']],
        },
        'cli_system_status': {
            'urls': [
                '/cli/global/system/status'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_syslog': {
            'urls': [
                '/cli/global/system/syslog',
                '/cli/global/system/syslog/{syslog}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'cli_system_webproxy': {
            'urls': [
                '/cli/global/system/web-proxy'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.4.8', '6.4.14'], ['7.0.3', '']],
        },
        'cli_system_workflow_approvalmatrix': {
            'urls': [
                '/cli/global/system/workflow/approval-matrix',
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.9'], ['6.4.1', '6.4.7'], ['7.0.0', '7.0.2'], ['7.6.0', '']],
        },
        'cli_system_workflow_approvalmatrix_approver': {
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver',
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver/{approver}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.9'], ['6.4.1', '6.4.7'], ['7.0.0', '7.0.2'], ['7.6.0', '']],
        },
        'dvmdb_adom': {
            'urls': [
                '/dvmdb/adom',
                '/dvmdb/adom/{adom}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'meta fields', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'dvmdb_device': {
            'urls': [
                '/dvmdb/adom/{adom}/device',
                '/dvmdb/adom/{adom}/device/{device}',
                '/dvmdb/device',
                '/dvmdb/device/{device}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'meta fields', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'dvmdb_device_haslave': {
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/ha_slave',
                '/dvmdb/adom/{adom}/device/{device}/ha_slave/{ha_slave}',
                '/dvmdb/device/{device}/ha_slave',
                '/dvmdb/device/{device}/ha_slave/{ha_slave}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'dvmdb_device_vdom': {
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/vdom',
                '/dvmdb/adom/{adom}/device/{device}/vdom/{vdom}',
                '/dvmdb/device/{device}/vdom',
                '/dvmdb/device/{device}/vdom/{vdom}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'meta fields', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'dvmdb_folder': {
            'urls': [
                '/dvmdb/adom/{adom}/folder',
                '/dvmdb/adom/{adom}/folder/{folder}',
                '/dvmdb/folder',
                '/dvmdb/folder/{folder}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.4.2', '']],
        },
        'dvmdb_group': {
            'urls': [
                '/dvmdb/adom/{adom}/group',
                '/dvmdb/adom/{adom}/group/{group}',
                '/dvmdb/group',
                '/dvmdb/group/{group}'
            ],
            'params': ['expand member', 'fields', 'filter', 'loadsub', 'meta fields', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alertfilter': {
            'urls': [
                '/eventmgmt/adom/{adom}/alertfilter'
            ],
            'params': ['alertid', 'ruleid'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alertincident_stats': {
            'urls': [
                '/eventmgmt/adom/{adom}/alert-incident/stats'
            ],
            'params': ['time-range', 'timescale', 'timezone'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'eventmgmt_alertlogs': {
            'urls': [
                '/eventmgmt/adom/{adom}/alertlogs'
            ],
            'params': ['alertid', 'limit', 'offset', 'rulename', 'time-order'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alertlogs_count': {
            'urls': [
                '/eventmgmt/adom/{adom}/alertlogs/count'
            ],
            'params': ['alertid', 'rulename'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alerts': {
            'urls': [
                '/eventmgmt/adom/{adom}/alerts'
            ],
            'params': ['filter', 'limit', 'offset', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alerts_count': {
            'urls': [
                '/eventmgmt/adom/{adom}/alerts/count'
            ],
            'params': ['filter', 'group-by', 'time-range', 'timescale', 'timezone', 'type'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'eventmgmt_alerts_export': {
            'urls': [
                '/eventmgmt/adom/{adom}/alerts/export'
            ],
            'params': ['attachment', 'data-format', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.0.0', '']],
        },
        'eventmgmt_alerts_extradetails': {
            'urls': [
                '/eventmgmt/adom/{adom}/alerts/extra-details'
            ],
            'params': ['alertids'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
        },
        'eventmgmt_basichandlers_export': {
            'urls': [
                '/eventmgmt/adom/{adom}/basic-handlers/export'
            ],
            'params': ['attachment', 'data-format', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'eventmgmt_correlationhandlers_export': {
            'urls': [
                '/eventmgmt/adom/{adom}/correlation-handlers/export'
            ],
            'params': ['attachment', 'data-format', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'fazsys_enduseravatar': {
            'urls': [
                '/fazsys/adom/{adom}/enduser-avatar'
            ],
            'params': ['user'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'fazsys_forticare_licinfo': {
            'urls': [
                '/fazsys/adom/{adom}/forticare/licinfo'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['7.2.1', '']],
        },
        'fazsys_language_fonts_export': {
            'urls': [
                '/fazsys/language/fonts/export'
            ],
            'params': ['font'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'fazsys_language_fonts_list': {
            'urls': [
                '/fazsys/language/fonts/list'
            ],
            'params': ['font'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'fazsys_language_translationfile_export': {
            'urls': [
                '/fazsys/language/translation-file/export'
            ],
            'params': ['language'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'fazsys_language_translationfile_list': {
            'urls': [
                '/fazsys/language/translation-file/list'
            ],
            'params': ['language'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'fazsys_lograte_history': {
            'urls': [
                '/fazsys/adom/{adom}/lograte/history'
            ],
            'params': ['time-range'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'fazsys_monitor_logforwardstatus': {
            'urls': [
                '/fazsys/monitor/logforward-status'
            ],
            'params': ['id'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'fazsys_monitor_system_performance_status': {
            'urls': [
                '/fazsys/monitor/system/performance/status'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'fazsys_storageinfo': {
            'urls': [
                '/fazsys/storage-info'
            ],
            'params': ['filter'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'fazsys_storageinfohistory': {
            'urls': [
                '/fazsys/adom/{adom}/storage-info-history'
            ],
            'params': ['time-range'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'fortiview_run': {
            'urls': [
                '/fortiview/adom/{adom}/{view-name}/run/{tid}'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'incidentmgmt_attachments': {
            'urls': [
                '/incidentmgmt/adom/{adom}/attachments'
            ],
            'params': ['attachtype', 'incid', 'limit', 'offset'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'incidentmgmt_attachments_count': {
            'urls': [
                '/incidentmgmt/adom/{adom}/attachments/count'
            ],
            'params': ['attachtype', 'incid'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'incidentmgmt_epeuhistory': {
            'urls': [
                '/incidentmgmt/adom/{adom}/epeu-history'
            ],
            'params': ['incid', 'limit', 'offset'],
            'jsonrpc2': True, 'v_range': [['6.4.2', '']],
        },
        'incidentmgmt_incident_stats': {
            'urls': [
                '/incidentmgmt/adom/{adom}/incident/stats'
            ],
            'params': ['filter', 'stats-item', 'time-range'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'incidentmgmt_incidents': {
            'urls': [
                '/incidentmgmt/adom/{adom}/incidents'
            ],
            'params': ['detail-level', 'filter', 'incids', 'limit', 'offset', 'sort-by'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'incidentmgmt_incidents_count': {
            'urls': [
                '/incidentmgmt/adom/{adom}/incidents/count'
            ],
            'params': ['filter', 'incids'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ioc_license_state': {
            'urls': [
                '/ioc/license/state'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ioc_rescan_history': {
            'urls': [
                '/ioc/adom/{adom}/rescan/history'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ioc_rescan_run': {
            'urls': [
                '/ioc/adom/{adom}/rescan/run'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logfields': {
            'urls': [
                '/logview/adom/{adom}/logfields'
            ],
            'params': ['devtype', 'logtype', 'subtype'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logfiles_data': {
            'urls': [
                '/logview/adom/{adom}/logfiles/data'
            ],
            'params': ['data-type', 'devid', 'filename', 'length', 'offset', 'vdom'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logfiles_search': {
            'urls': [
                '/logview/adom/{adom}/logfiles/search'
            ],
            'params': ['case-sensitive', 'devid', 'filename', 'filter', 'limit', 'logtype', 'offset', 'vdom'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logfiles_state': {
            'urls': [
                '/logview/adom/{adom}/logfiles/state'
            ],
            'params': ['devid', 'filename', 'time-range', 'timezone', 'vdom'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logsearch': {
            'urls': [
                '/logview/adom/{adom}/logsearch/{tid}'
            ],
            'params': ['limit', 'offset'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'logview_logsearch_count': {
            'urls': [
                '/logview/adom/{adom}/logsearch/count/{tid}'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['7.0.1', '']],
        },
        'logview_logstats': {
            'urls': [
                '/logview/adom/{adom}/logstats'
            ],
            'params': ['device'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
        },
        'logview_pcapfile': {
            'urls': [
                '/logview/pcapfile'
            ],
            'params': ['key-data', 'key-type'],
            'jsonrpc2': True, 'v_range': [['7.0.3', '']],
        },
        'report_config_chart': {
            'urls': [
                '/report/adom/{adom}/config/chart'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_chart_drilldowntable': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/drill-down-table'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_chart_tablecolumns': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/table-columns'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_chart_variabletemplate': {
            'urls': [
                '/report/adom/{adom}/config/chart/{chart_name}/variable-template'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_dataset': {
            'urls': [
                '/report/adom/{adom}/config/dataset'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_dataset_variable': {
            'urls': [
                '/report/adom/{adom}/config/dataset/{dataset_name}/variable'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layout': {
            'urls': [
                '/report/adom/{adom}/config/layout'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layout_component': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/component'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layout_component_variable': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/component/{component-id}/variable'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layout_footer': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/footer'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layout_header': {
            'urls': [
                '/report/adom/{adom}/config/layout/{layout-id}/header'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_layoutfolder': {
            'urls': [
                '/report/adom/{adom}/config/layout-folder'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_macro': {
            'urls': [
                '/report/adom/{adom}/config/macro'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_output': {
            'urls': [
                '/report/adom/{adom}/config/output'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_output_emailrecipients': {
            'urls': [
                '/report/adom/{adom}/config/output/{output-name}/email-recipients'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_schedule': {
            'urls': [
                '/report/adom/{adom}/config/schedule'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_schedule_addressfilter': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/address-filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.4.3', '']],
        },
        'report_config_schedule_devices': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/devices'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_schedule_filter': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/filter'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_config_schedule_reportlayout': {
            'urls': [
                '/report/adom/{adom}/config/schedule/{schedule_name}/report-layout'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'report_graphfile': {
            'urls': [
                '/report/adom/{adom}/graph-file'
            ],
            'params': ['file-name'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'report_graphfile_data': {
            'urls': [
                '/report/adom/{adom}/graph-file/data'
            ],
            'params': ['file-name'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'report_graphfile_list': {
            'urls': [
                '/report/adom/{adom}/graph-file/list'
            ],
            'params': ['file-name'],
            'jsonrpc2': True, 'v_range': [['7.2.2', '']],
        },
        'report_reports_data': {
            'urls': [
                '/report/adom/{adom}/reports/data/{tid}'
            ],
            'params': ['data-type', 'format'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'report_reports_state': {
            'urls': [
                '/report/adom/{adom}/reports/state'
            ],
            'params': ['sort-by', 'state', 'time-range', 'timezone', 'title'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'report_run': {
            'urls': [
                '/report/adom/{adom}/run/{tid}'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'report_template_export': {
            'urls': [
                '/report/adom/{adom}/template/export'
            ],
            'params': ['dev-type', 'language', 'title'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'report_template_language': {
            'urls': [
                '/report/adom/{adom}/template/language'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'report_template_list': {
            'urls': [
                '/report/adom/{adom}/template/list'
            ],
            'params': ['dev-type', 'language'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'soar_alert_indicator': {
            'urls': [
                '/soar/adom/{adom}/alert/indicator'
            ],
            'params': ['alert-id', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'soar_config_connectors': {
            'urls': [
                '/soar/adom/{adom}/config/connectors/{connector-uuid}'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.4.2', '']],
        },
        'soar_config_playbooks': {
            'urls': [
                '/soar/adom/{adom}/config/playbooks/{playbook-uuid}'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.4.2', '']],
        },
        'soar_fosconnector_automationrules': {
            'urls': [
                '/soar/adom/{adom}/fos-connector/automation-rules'
            ],
            'params': [],
            'jsonrpc2': True, 'v_range': [['6.4.2', '']],
        },
        'soar_incident_indicator': {
            'urls': [
                '/soar/adom/{adom}/incident/indicator'
            ],
            'params': ['filter', 'incident-id'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'soar_indicator': {
            'urls': [
                '/soar/adom/{adom}/indicator'
            ],
            'params': ['filter', 'limit', 'offset', 'option', 'time-range'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'soar_indicator_enrichment': {
            'urls': [
                '/soar/adom/{adom}/indicator/enrichment/{enrichment_uuid}'
            ],
            'params': ['detail-level', 'indicator-type', 'indicator-uuid', 'indicator-value'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'soar_playbook_export': {
            'urls': [
                '/soar/adom/{adom}/playbook/export'
            ],
            'params': ['attachment', 'data-format', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.0.0', '']],
        },
        'soar_playbook_monitor': {
            'urls': [
                '/soar/adom/{adom}/playbook/monitor'
            ],
            'params': ['filter', 'instance-id', 'playbook-uuid', 'sort-by', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.4.2', '7.2.1'], ['7.6.0', '']],
        },
        'soar_playbook_run': {
            'urls': [
                '/soar/adom/{adom}/playbook/run'
            ],
            'params': ['filter', 'instance-id', 'playbook-uuid', 'sort-by', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.4.2', '']],
        },
        'soar_playbook_runlog': {
            'urls': [
                '/soar/adom/{adom}/playbook/run-log/{run-id}'
            ],
            'params': ['detail-on-error'],
            'jsonrpc2': True, 'v_range': [['7.6.0', '']],
        },
        'soar_subnet_export': {
            'urls': [
                '/soar/adom/{adom}/subnet/export'
            ],
            'params': ['data-format', 'filter'],
            'jsonrpc2': True, 'v_range': [['7.0.0', '']],
        },
        'soar_task_monitor': {
            'urls': [
                '/soar/adom/{adom}/task/monitor'
            ],
            'params': ['filter', 'instance-id', 'playbook-uuid', 'sort-by', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.4.2', '7.4.3']],
        },
        'sys_ha_status': {
            'urls': [
                '/sys/ha/status'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'sys_status': {
            'urls': [
                '/sys/status'
            ],
            'params': [],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'task_task': {
            'urls': [
                '/task/task',
                '/task/task/{task}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'task_task_history': {
            'urls': [
                '/task/task/{task}/history',
                '/task/task/{task}/history/{history}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.2', '6.2.12']],
        },
        'task_task_line': {
            'urls': [
                '/task/task/{task}/line',
                '/task/task/{task}/line/{line}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '']],
        },
        'task_task_line_history': {
            'urls': [
                '/task/task/{task}/line/{line}/history',
                '/task/task/{task}/line/{line}/history/{history}'
            ],
            'params': ['fields', 'filter', 'loadsub', 'option', 'range', 'sortings'],
            'jsonrpc2': False, 'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']],
        },
        'ueba_endpoints': {
            'urls': [
                '/ueba/adom/{adom}/endpoints'
            ],
            'params': ['detail-level', 'epids', 'filter', 'limit', 'offset', 'sort-by', 'time-range'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ueba_endpoints_stats': {
            'urls': [
                '/ueba/adom/{adom}/endpoints/stats'
            ],
            'params': ['filter', 'stats-item', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ueba_endpoints_vuln': {
            'urls': [
                '/ueba/adom/{adom}/endpoints/vuln'
            ],
            'params': ['detectby', 'epids', 'filter', 'limit', 'offset', 'sort-by'],
            'jsonrpc2': True, 'v_range': [['7.4.0', '']],
        },
        'ueba_endusers': {
            'urls': [
                '/ueba/adom/{adom}/endusers'
            ],
            'params': ['detail-level', 'euids', 'filter', 'limit', 'offset', 'sort-by'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ueba_endusers_stats': {
            'urls': [
                '/ueba/adom/{adom}/endusers/stats'
            ],
            'params': ['stats-item', 'time-range', 'timezone'],
            'jsonrpc2': True, 'v_range': [['6.2.1', '']],
        },
        'ueba_otview': {
            'urls': [
                '/ueba/adom/{adom}/ot-view'
            ],
            'params': ['filter', 'group-by'],
            'jsonrpc2': True, 'v_range': [['7.4.0', '']],
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
        'facts': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(facts_metadata.keys())
                },
                'fields': {'elements': 'raw', 'type': 'list'},
                'filter': {'elements': 'raw', 'type': 'list'},
                'option': {'type': 'raw'},
                'sortings': {'elements': 'dict', 'type': 'list'},
                'params': {'type': 'dict'},
                'extra_params': {'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    faz = FortiAnalyzerAnsible(None, None, None, module, connection, metadata=facts_metadata, task_type='fact')
    faz.process()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
