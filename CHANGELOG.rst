====================================
Fortinet.Fortianalyzer Release Notes
====================================

.. contents:: Topics


v1.4.0
======

Release Summary
---------------

release fortinet.fortianalyzer 1.4.0

Minor Changes
-------------

- Added deprecated warning to invalid argument name, please change the invalid argument name such as "var-name", "var name" to "var_name".
- Changed minimum required ansible-core version to 2.15.0
- Supported FortiAnalyzer 6.4.14, 7.0.11, 7.4.2

Bugfixes
--------

- Changed "revision" to "v_range" to reduce the size of the code.
- Improved the logic of plugin code.
- Renamed the input argument "message" in "faz_sys_reboot" to "faz_message".

New Modules
-----------

- fortinet.fortianalyzer.faz_cli_system_admin_profile_writepasswdprofiles - Profile list.
- fortinet.fortianalyzer.faz_cli_system_admin_profile_writepasswduserlist - User list.

v1.3.2
======

Release Summary
---------------

Update FortiAnalyzer Ansible to support newest version of FortiAnalyzer.

Bugfixes
--------

- Added missing enum values for some arguments.
- Improve logic to decide whether the local data and remote FortiAnalyzer are the same.
- Require ansible core to be at least 2.14.0
- Support FortiAnalyzer 7.0.10

v1.3.1
======

Release Summary
---------------

Update FortiAnalyzer Ansible minimum ansible core version.

Bugfixes
--------

- Require ansible core to be at least 2.13.0

v1.3.0
======

Release Summary
---------------

Update FortiAnalyzer Ansible to support newest version of FortiAnalyzer.

Minor Changes
-------------

- Add 4 new modules.
- Add module digest page in the document.
- Support newest patches from v6.2 to v7.4

Bugfixes
--------

- Fixed the bug that would report an error when providing access_token and username/password at the same time.
- Improve code robustness.

New Modules
-----------

- fortinet.fortianalyzer.faz_cli_system_csf - Add this device to a Security Fabric or set up a new Security Fabric on this device.
- fortinet.fortianalyzer.faz_cli_system_csf_fabricconnector - Fabric connector configuration.
- fortinet.fortianalyzer.faz_cli_system_csf_trustedlist - Pre-authorized and blocked security fabric nodes.
- fortinet.fortianalyzer.faz_cli_system_log_pcapfile - Log pcap-file settings.

v1.2.0
======

Release Summary
---------------

Update FortiAnalyzer Ansible to support FortiAnalyzer v7.4. Support fortianalyzer cloud and IAM access token login method.

Minor Changes
-------------

- Support Fortianalyze v7.4, 1 new modules, faz_cli_system_socfabric_trustedlist.
- Support IAM access token login method.
- Support fortianalyzer cloud.

v1.1.0
======

Release Summary
---------------

Release 1.1.0 to support all FortiAnalyzer versions in 6.2, 6.4, 7.0 and 7.2.

Major Changes
-------------

- Support all FortiAnalyzer versions in 6.2, 6.4, 7.0 and 7.2. 3 new modules.

Minor Changes
-------------

- Added param log_path to every module. You can specify the place to save the log when enable_log is True.
- faz_fact and faz_rename support more URLs.

Bugfixes
--------

- Fixed Many sanity test warnings and errors.
- Fixed an issue where some selectors in faz_fact were named incorrectly.
- Fixed version_added in the document. The value of this parameter is the version each module first supported in the FortiAnalyzer Ansible Collection.

v1.0.3
======

Release Summary
---------------

Release 1.0.3 for Automation Hub.

Major Changes
-------------

- deprecate default genrated README in plugin directory.
- update meta/runtime.yaml requirement.
- update python and ansible requirement in top-level README.

v1.0.2
======

Release Summary
---------------

Minor release of FortiAnalyzer Ansible Collection 1.0.2

Major Changes
-------------

- Fixed Many sanity test warnings and errors.
- Support API schema 7.2.0, 25 new APIs, 8 new modules.
- Supported Ansible Changelogs.

v1.0.1
======

Release Summary
---------------

FortiAnalyzer Base Release

Major Changes
-------------

- Flexible error handling mechanism.
- Full FortiAnalyzer JRPC URLs coverage (more than 170 modules).
