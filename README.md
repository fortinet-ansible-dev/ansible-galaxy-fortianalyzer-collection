![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

# Ansible Collection - fortinet.fortianalyzer:1.5.0

FortiAnalyzer Ansible Collection includes the modules that are able to configure FortiAnalyzer.

[Documentation](https://ansible-galaxy-fortianalyzer-docs.readthedocs.io/en/latest) for the collection.

## Requirements
* Ansible 2.15.0 or newer is required to support the newer Ansible Collections format
* Python 3 is prefered when running Ansible with `fortinet.fortianalyzer` collection.

## Installation
This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/fortinet/fortianalyzer), the installation steps are as follows:

1. Install or upgrade to Ansible >= 2.15.0
2. Download this collection from galaxy: `ansible-galaxy collection install fortinet.fortianalyzer:1.5.0`

## Modules
The collection provides the following modules:

* `faz_cli_exec_fgfm_reclaimdevtunnel`  Reclaim management tunnel to device.Request without device name specified will reclaim tunnels for all managed devices.
* `faz_cli_fmupdate_analyzer_virusreport`  Send virus detection notification to FortiGuard.
* `faz_cli_fmupdate_avips_advancedlog`  Enable/disable logging of FortiGuard antivirus and IPS update packages received by FortiManagers built-in FortiGuard.
* `faz_cli_fmupdate_avips_webproxy`  Configure the web proxy for use with FortiGuard antivirus and IPS updates.
* `faz_cli_fmupdate_customurllist`  Configure the URL database for rating and filtering.
* `faz_cli_fmupdate_diskquota`  Configure disk space available for use by the Upgrade Manager.
* `faz_cli_fmupdate_fctservices`  Configure FortiGuard to provide services to FortiClient installations.
* `faz_cli_fmupdate_fdssetting`  Configure FortiGuard settings.
* `faz_cli_fmupdate_fdssetting_pushoverride`  Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
* `faz_cli_fmupdate_fdssetting_pushoverridetoclient`  Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
* `faz_cli_fmupdate_fdssetting_pushoverridetoclient_announceip`  Announce IP addresses for the device.
* `faz_cli_fmupdate_fdssetting_serveroverride`  Server override configure.
* `faz_cli_fmupdate_fdssetting_serveroverride_servlist`  Override server.
* `faz_cli_fmupdate_fdssetting_updateschedule`  Configure the schedule when built-in FortiGuard retrieves antivirus and IPS updates.
* `faz_cli_fmupdate_fwmsetting`  Configure firmware management settings.
* `faz_cli_fmupdate_fwmsetting_upgradetimeout`  Configure the timeout value of image upgrade process.
* `faz_cli_fmupdate_multilayer`  Configure multilayer mode.
* `faz_cli_fmupdate_publicnetwork`  Enable/disable access to the public FortiGuard.
* `faz_cli_fmupdate_serveraccesspriorities`  Configure priorities for FortiGate units accessing antivirus updates and web filtering services.
* `faz_cli_fmupdate_serveraccesspriorities_privateserver`  Configure multiple FortiManager units and private servers.
* `faz_cli_fmupdate_serveroverridestatus`  Configure strict/loose server override.
* `faz_cli_fmupdate_service`  Enable/disable services provided by the built-in FortiGuard.
* `faz_cli_fmupdate_webspam_fgdsetting`  Configure the FortiGuard run parameters.
* `faz_cli_fmupdate_webspam_fgdsetting_serveroverride`  Server override configure.
* `faz_cli_fmupdate_webspam_fgdsetting_serveroverride_servlist`  Override server.
* `faz_cli_fmupdate_webspam_webproxy`  Configure the web proxy for use with FortiGuard antivirus and IPS updates.
* `faz_cli_metafields_system_admin_user`  Cli meta fields system admin user.
* `faz_cli_system_admin_group`  User group.
* `faz_cli_system_admin_group_member`  Group members.
* `faz_cli_system_admin_ldap`  LDAP server entry configuration.
* `faz_cli_system_admin_ldap_adom`  Admin domain.
* `faz_cli_system_admin_profile`  Admin profile.
* `faz_cli_system_admin_profile_datamaskcustomfields`  Customized datamask fields.
* `faz_cli_system_admin_profile_writepasswdprofiles`  Profile list.
* `faz_cli_system_admin_profile_writepasswduserlist`  User list.
* `faz_cli_system_admin_radius`  Configure radius.
* `faz_cli_system_admin_setting`  Admin setting.
* `faz_cli_system_admin_tacacs`  TACACS+ server entry configuration.
* `faz_cli_system_admin_user`  Admin user.
* `faz_cli_system_admin_user_adom`  Admin domain.
* `faz_cli_system_admin_user_adomexclude`  Excluding admin domain.
* `faz_cli_system_admin_user_dashboard`  Custom dashboard widgets.
* `faz_cli_system_admin_user_dashboardtabs`  Custom dashboard.
* `faz_cli_system_admin_user_metadata`  Configure meta data.
* `faz_cli_system_admin_user_policypackage`  Policy package access.
* `faz_cli_system_admin_user_restrictdevvdom`  Restricted to these devices/VDOMs.
* `faz_cli_system_alertconsole`  Alert console.
* `faz_cli_system_alertemail`  Configure alertemail.
* `faz_cli_system_alertevent`  Alert events.
* `faz_cli_system_alertevent_alertdestination`  Alert destination.
* `faz_cli_system_autodelete`  Automatic deletion policy for logs, reports, archived, and quarantined files.
* `faz_cli_system_autodelete_dlpfilesautodeletion`  Automatic deletion policy for DLP archives.
* `faz_cli_system_autodelete_logautodeletion`  Automatic deletion policy for device logs.
* `faz_cli_system_autodelete_quarantinefilesautodeletion`  Automatic deletion policy for quarantined files.
* `faz_cli_system_autodelete_reportautodeletion`  Automatic deletion policy for reports.
* `faz_cli_system_backup_allsettings`  Scheduled backup settings.
* `faz_cli_system_centralmanagement`  Central management configuration.
* `faz_cli_system_certificate_ca`  CA certificate.
* `faz_cli_system_certificate_crl`  Certificate Revocation List.
* `faz_cli_system_certificate_local`  Local keys and certificates.
* `faz_cli_system_certificate_oftp`  OFTP certificates and keys.
* `faz_cli_system_certificate_remote`  Remote certificate.
* `faz_cli_system_certificate_ssh`  SSH certificates and keys.
* `faz_cli_system_connector`  Configure connector.
* `faz_cli_system_csf`  Add this device to a Security Fabric or set up a new Security Fabric on this device.
* `faz_cli_system_csf_fabricconnector`  Fabric connector configuration.
* `faz_cli_system_csf_trustedlist`  Pre-authorized and blocked security fabric nodes.
* `faz_cli_system_dns`  DNS configuration.
* `faz_cli_system_docker`  Docker host.
* `faz_cli_system_fips`  Settings for FIPS-CC mode.
* `faz_cli_system_fortiview_autocache`  FortiView auto-cache settings.
* `faz_cli_system_fortiview_setting`  FortiView settings.
* `faz_cli_system_global`  Global range attributes.
* `faz_cli_system_guiact`  System settings through GUI.
* `faz_cli_system_ha`  HA configuration.
* `faz_cli_system_ha_peer`  Peers.
* `faz_cli_system_ha_privatepeer`  Peer.
* `faz_cli_system_ha_vip`  VIPs.
* `faz_cli_system_interface`  Interface configuration.
* `faz_cli_system_interface_ipv6`  IPv6 of interface.
* `faz_cli_system_interface_member`  Physical interfaces that belong to the aggregate or redundant interface.
* `faz_cli_system_localinpolicy`  IPv4 local in policy configuration.
* `faz_cli_system_localinpolicy6`  IPv6 local in policy configuration.
* `faz_cli_system_locallog_disk_filter`  Filter for disk logging.
* `faz_cli_system_locallog_disk_setting`  Settings for local disk logging.
* `faz_cli_system_locallog_fortianalyzer2_filter`  Filter for FortiAnalyzer2 logging.
* `faz_cli_system_locallog_fortianalyzer2_setting`  Settings for locallog to fortianalyzer.
* `faz_cli_system_locallog_fortianalyzer3_filter`  Filter for FortiAnalyzer3 logging.
* `faz_cli_system_locallog_fortianalyzer3_setting`  Settings for locallog to fortianalyzer.
* `faz_cli_system_locallog_fortianalyzer_filter`  Filter for FortiAnalyzer logging.
* `faz_cli_system_locallog_fortianalyzer_setting`  Settings for locallog to fortianalyzer.
* `faz_cli_system_locallog_memory_filter`  Filter for memory logging.
* `faz_cli_system_locallog_memory_setting`  Settings for memory buffer.
* `faz_cli_system_locallog_setting`  Settings for locallog logging.
* `faz_cli_system_locallog_syslogd2_filter`  Filter for syslog logging.
* `faz_cli_system_locallog_syslogd2_setting`  Settings for remote syslog server.
* `faz_cli_system_locallog_syslogd3_filter`  Filter for syslog logging.
* `faz_cli_system_locallog_syslogd3_setting`  Settings for remote syslog server.
* `faz_cli_system_locallog_syslogd_filter`  Filter for syslog logging.
* `faz_cli_system_locallog_syslogd_setting`  Settings for remote syslog server.
* `faz_cli_system_log_alert`  Log based alert settings.
* `faz_cli_system_log_devicedisable`  Disable client device logging.
* `faz_cli_system_log_fospolicystats`  FortiOS policy statistics settings.
* `faz_cli_system_log_interfacestats`  Interface statistics settings.
* `faz_cli_system_log_ioc`  IoC settings.
* `faz_cli_system_log_maildomain`  FortiMail domain setting.
* `faz_cli_system_log_pcapfile`  Log pcap-file settings.
* `faz_cli_system_log_ratelimit`  Logging rate limit.
* `faz_cli_system_log_ratelimit_device`  Device log rate limit.
* `faz_cli_system_log_ratelimit_ratelimits`  Per device or ADOM log rate limits.
* `faz_cli_system_log_settings`  Log settings.
* `faz_cli_system_log_settings_rollinganalyzer`  Log rolling policy for Network Analyzer logs.
* `faz_cli_system_log_settings_rollinglocal`  Log rolling policy for local logs.
* `faz_cli_system_log_settings_rollingregular`  Log rolling policy for device logs.
* `faz_cli_system_log_topology`  Logging topology settings.
* `faz_cli_system_logfetch_clientprofile`  Log-fetch client profile settings.
* `faz_cli_system_logfetch_clientprofile_devicefilter`  List of device filter.
* `faz_cli_system_logfetch_clientprofile_logfilter`  Log content filters.
* `faz_cli_system_logfetch_serversettings`  Log-fetch server settings.
* `faz_cli_system_logforward`  Log forwarding.
* `faz_cli_system_logforward_devicefilter`  Log aggregation client device filters.
* `faz_cli_system_logforward_logfieldexclusion`  Log field exclusion configuration.
* `faz_cli_system_logforward_logfilter`  Log content filters.
* `faz_cli_system_logforward_logmaskingcustom`  Log field masking configuration.
* `faz_cli_system_logforwardservice`  Log forwarding service.
* `faz_cli_system_mail`  Alert emails.
* `faz_cli_system_metadata_admins`  Configure admins.
* `faz_cli_system_ntp`  NTP settings.
* `faz_cli_system_ntp_ntpserver`  NTP server.
* `faz_cli_system_passwordpolicy`  Password policy.
* `faz_cli_system_report_autocache`  Report auto-cache settings.
* `faz_cli_system_report_estbrowsetime`  Report estimated browse time settings.
* `faz_cli_system_report_group`  Report group.
* `faz_cli_system_report_group_chartalternative`  Chart alternatives.
* `faz_cli_system_report_group_groupby`  Group-by variables.
* `faz_cli_system_report_setting`  Report settings.
* `faz_cli_system_route`  Routing table configuration.
* `faz_cli_system_route6`  Routing table configuration.
* `faz_cli_system_saml`  Global settings for SAML authentication.
* `faz_cli_system_saml_fabricidp`  Authorized identity providers.
* `faz_cli_system_saml_serviceproviders`  Authorized service providers.
* `faz_cli_system_sniffer`  Interface sniffer.
* `faz_cli_system_snmp_community`  SNMP community configuration.
* `faz_cli_system_snmp_community_hosts`  Allow hosts configuration.
* `faz_cli_system_snmp_community_hosts6`  Allow hosts configuration for IPv6.
* `faz_cli_system_snmp_sysinfo`  SNMP configuration.
* `faz_cli_system_snmp_user`  SNMP user configuration.
* `faz_cli_system_socfabric`  SOC Fabric.
* `faz_cli_system_socfabric_trustedlist`  Pre-authorized security fabric nodes.
* `faz_cli_system_sql`  SQL settings.
* `faz_cli_system_sql_customindex`  List of SQL index fields.
* `faz_cli_system_sql_customskipidx`  List of aditional SQL skip index fields.
* `faz_cli_system_sql_tsindexfield`  List of SQL text search index fields.
* `faz_cli_system_sslciphersuites`  Configure preferred SSL/TLS cipher suites.
* `faz_cli_system_syslog`  Syslog servers.
* `faz_cli_system_webproxy`  Configure system web proxy.
* `faz_cli_system_workflow_approvalmatrix`  workflow approval matrix.
* `faz_cli_system_workflow_approvalmatrix_approver`  Approver.
* `faz_dvm_cmd_add_device`  Add a device to the Device Manager database.
* `faz_dvm_cmd_add_devlist`  Add multiple devices to the Device Manager database.
* `faz_dvm_cmd_del_device`  Delete a device.
* `faz_dvm_cmd_del_devlist`  Delete a list of devices.
* `faz_dvm_cmd_import_devlist`  Import a list of ADOMs and devices.
* `faz_dvmdb_adom`  ADOM table, most attributes are read-only and can only be changed internally.
* `faz_dvmdb_adom_objectmember`  ADOM table, most attributes are read-only and can only be changed internally.
* `faz_dvmdb_device`  Device table, most attributes are read-only and can only be changed internally.
* `faz_dvmdb_device_vdom`  Device VDOM table.
* `faz_dvmdb_folder`  Device manager database folder.
* `faz_dvmdb_group`  Device group table.
* `faz_dvmdb_group_objectmember`  Device group table.
* `faz_report_config_chart`  Config chart.
* `faz_report_config_chart_drilldowntable`  Config drill-down-table.
* `faz_report_config_chart_tablecolumns`  Config table-columns.
* `faz_report_config_chart_variabletemplate`  Config variable-template.
* `faz_report_config_dataset`  Config dataset.
* `faz_report_config_dataset_variable`  Config variable.
* `faz_report_config_layout`  Config layout.
* `faz_report_config_layout_component`  Config component.
* `faz_report_config_layout_component_variable`  Config variable.
* `faz_report_config_layout_footer`  Config footer.
* `faz_report_config_layout_header`  Config header.
* `faz_report_config_layoutfolder`  Config layout-folder.
* `faz_report_config_macro`  Config macro.
* `faz_report_config_output`  Config output.
* `faz_report_config_output_emailrecipients`  Config email-recipients.
* `faz_report_config_schedule`  Config schedule.
* `faz_report_config_schedule_addressfilter`  Config address-filter.
* `faz_report_config_schedule_devices`  Config devices.
* `faz_report_config_schedule_filter`  Config filter.
* `faz_report_config_schedule_reportlayout`  Config report-layout.
* `faz_report_configfile_import`  Import report config files.
* `faz_report_graphfile`  Handle graph files.
* `faz_report_graphfile_delete`  Handle graph files.
* `faz_report_reports_data_delete`  Handle generated reports.
* `faz_report_run`  Start report requests.
* `faz_report_run_delete`  Handle report requests by task ID.
* `faz_report_template_delete`  Delete report template language package files.
* `faz_report_template_import`  Import report templates.
* `faz_report_template_install`  Install report template language packages from files.
* `faz_sys_api_sdnconnector`  Query SDN connector data.
* `faz_sys_generate_wsdl`  Generate WSDL for specific module and objects.
* `faz_sys_login_challenge`  Answer a log in challenge question, used following a login/user or login/challenge command.
* `faz_sys_login_user`  Log into the device with user name and password.
* `faz_sys_logout`  Log out a session.
* `faz_sys_proxy_json`  Send and receive JSON request to/from managed devices.
* `faz_sys_reboot`  Restart FortiAnalyzer.
* `faz_um_image_upgrade`  The older API for updating the firmware of specific device.
* `faz_um_image_upgrade_ext`  Update the firmware of specific device.


## License

FortiManager Ansible Collection follows [GNU General Public License v3.0](LICENSE).