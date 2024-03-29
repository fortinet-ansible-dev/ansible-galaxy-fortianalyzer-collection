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
module: faz_cli_system_global
short_description: Global range attributes.
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
    cli_system_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin-lockout-duration:
                type: int
                description: 'Lockout duration(sec) for administration.'
            admin-lockout-threshold:
                type: int
                description: 'Lockout threshold for administration.'
            adom-mode:
                type: str
                description:
                 - 'ADOM mode.'
                 - 'normal - Normal ADOM mode.'
                 - 'advanced - Advanced ADOM mode.'
                choices:
                    - 'normal'
                    - 'advanced'
            adom-select:
                type: str
                description:
                 - 'Enable/disable select ADOM after login.'
                 - 'disable - Disable select ADOM after login.'
                 - 'enable - Enable select ADOM after login.'
                choices:
                    - 'disable'
                    - 'enable'
            adom-status:
                type: str
                description:
                 - 'ADOM status.'
                 - 'disable - Disable ADOM mode.'
                 - 'enable - Enable ADOM mode.'
                choices:
                    - 'disable'
                    - 'enable'
            backup-compression:
                type: str
                description:
                 - 'Compression level.'
                 - 'none - No compression.'
                 - 'low - Low compression (fastest).'
                 - 'normal - Normal compression.'
                 - 'high - Best compression (slowest).'
                choices:
                    - 'none'
                    - 'low'
                    - 'normal'
                    - 'high'
            backup-to-subfolders:
                type: str
                description:
                 - 'Enable/disable creation of subfolders on server for backup storage.'
                 - 'disable - Disable creation of subfolders on server for backup storage.'
                 - 'enable - Enable creation of subfolders on server for backup storage.'
                choices:
                    - 'disable'
                    - 'enable'
            clone-name-option:
                type: str
                description:
                 - 'set the clone object names option.'
                 - 'default - Add a prefix of Clone of to the clone name.'
                 - 'keep - Keep the original name for user to edit.'
                choices:
                    - 'default'
                    - 'keep'
            clt-cert-req:
                type: str
                description:
                 - 'Require client certificate for GUI login.'
                 - 'disable - Disable setting.'
                 - 'enable - Require client certificate for GUI login.'
                 - 'optional - Optional client certificate for GUI login.'
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            console-output:
                type: str
                description:
                 - 'Console output mode.'
                 - 'standard - Standard output.'
                 - 'more - More page output.'
                choices:
                    - 'standard'
                    - 'more'
            country-flag:
                type: str
                description:
                 - 'Country flag Status.'
                 - 'disable - Disable country flag icon beside ip address.'
                 - 'enable - Enable country flag icon beside ip address.'
                choices:
                    - 'disable'
                    - 'enable'
            create-revision:
                type: str
                description:
                 - 'Enable/disable create revision by default.'
                 - 'disable - Disable create revision by default.'
                 - 'enable - Enable create revision by default.'
                choices:
                    - 'disable'
                    - 'enable'
            daylightsavetime:
                type: str
                description:
                 - 'Enable/disable daylight saving time.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            default-logview-auto-completion:
                type: str
                description:
                 - 'Enable/disable log view filter auto-completion.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            default-search-mode:
                type: str
                description:
                 - 'Set the default search mode of log view.'
                 - 'filter-based - Filter based search mode.'
                 - 'advanced - Advanced search mode.'
                choices:
                    - 'filter-based'
                    - 'advanced'
            detect-unregistered-log-device:
                type: str
                description:
                 - 'Detect unregistered logging device from log message.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            device-view-mode:
                type: str
                description:
                 - 'Set devices/groups view mode.'
                 - 'regular - Regular view mode.'
                 - 'tree - Tree view mode.'
                choices:
                    - 'regular'
                    - 'tree'
            dh-params:
                type: str
                description:
                 - 'Minimum size of Diffie-Hellman prime for SSH/HTTPS (bits).'
                 - '1024 - 1024 bits.'
                 - '1536 - 1536 bits.'
                 - '2048 - 2048 bits.'
                 - '3072 - 3072 bits.'
                 - '4096 - 4096 bits.'
                 - '6144 - 6144 bits.'
                 - '8192 - 8192 bits.'
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            disable-module:
                description: no description
                type: list
                elements: str
                choices:
                    - 'fortiview-noc'
                    - 'siem'
                    - 'soar'
                    - 'none'
                    - 'soc'
                    - 'fortirecorder'
                    - 'ai'
                    - 'ot-view'
            enc-algorithm:
                type: str
                description:
                 - 'SSL communication encryption algorithms.'
                 - 'low - SSL communication using all available encryption algorithms.'
                 - 'medium - SSL communication using high and medium encryption algorithms.'
                 - 'high - SSL communication using high encryption algorithms.'
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'custom'
            fgfm-ca-cert:
                type: str
                description: 'set the extra fgfm CA certificates.'
            fgfm-local-cert:
                type: str
                description: 'set the fgfm local certificate.'
            fgfm-ssl-protocol:
                type: str
                description:
                 - 'set the lowest SSL protocols for fgfmsd.'
                 - 'sslv3 - set SSLv3 as the lowest version.'
                 - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                 - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                 - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the lowest version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            ha-member-auto-grouping:
                type: str
                description:
                 - 'Enable/disable automatically group HA members feature'
                 - 'disable - Disable automatically grouping HA members feature.'
                 - 'enable - Enable automatically grouping HA members only when group name is unique in your network.'
                choices:
                    - 'disable'
                    - 'enable'
            hitcount_concurrent:
                type: int
                description: 'The number of FortiGates that FortiManager polls at one time (10 - 500, default = 100).'
            hitcount_interval:
                type: int
                description: 'The interval for getting hit count from managed FortiGate devices, in seconds (60 - 86400, default = 900).'
            hostname:
                type: str
                description: 'System hostname.'
            language:
                type: str
                description:
                 - 'System global language.'
                 - 'english - English'
                 - 'simch - Simplified Chinese'
                 - 'japanese - Japanese'
                 - 'korean - Korean'
                 - 'spanish - Spanish'
                 - 'trach - Traditional Chinese'
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
            latitude:
                type: str
                description: 'fmg location latitude'
            ldap-cache-timeout:
                type: int
                description: 'LDAP browser cache timeout (seconds).'
            ldapconntimeout:
                type: int
                description: 'LDAP connection timeout (msec).'
            lock-preempt:
                type: str
                description:
                 - 'Enable/disable ADOM lock override.'
                 - 'disable - Disable lock preempt.'
                 - 'enable - Enable lock preempt.'
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum:
                type: str
                description:
                 - 'Record log file hash value, timestamp, and authentication code at transmission or rolling.'
                 - 'none - No record log file checksum.'
                 - 'md5 - Record log files MD5 hash value only.'
                 - 'md5-auth - Record log files MD5 hash value and authentication code.'
                choices:
                    - 'none'
                    - 'md5'
                    - 'md5-auth'
            log-forward-cache-size:
                type: int
                description: 'Log forwarding disk cache size (GB).'
            log-mode:
                type: str
                description:
                 - 'Log system operation mode.'
                 - 'analyzer - Operation mode is Analyzer'
                 - 'collector - Operation mode is Collector'
                choices:
                    - 'analyzer'
                    - 'collector'
            longitude:
                type: str
                description: 'fmg location longitude'
            max-aggregation-tasks:
                type: int
                description: 'Maximum number of concurrent tasks of a log aggregation session.'
            max-log-forward:
                type: int
                description: 'Maximum number of log-forward and aggregation settings.'
            max-running-reports:
                type: int
                description: 'Maximum number of reports generating at one time.'
            oftp-ssl-protocol:
                type: str
                description:
                 - 'set the lowest SSL protocols for oftpd.'
                 - 'sslv3 - set SSLv3 as the lowest version.'
                 - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                 - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                 - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the lowest version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            policy-hit-count:
                type: str
                description:
                 - 'show policy hit count.'
                 - 'disable - Disable policy hit count.'
                 - 'enable - Enable policy hit count.'
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-icon:
                type: str
                description:
                 - 'show icons of policy objects.'
                 - 'disable - Disable icon of policy objects.'
                 - 'enable - Enable icon of policy objects.'
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-in-dual-pane:
                type: str
                description:
                 - 'show policies and objects in dual pane.'
                 - 'disable - Disable polices and objects in dual pane.'
                 - 'enable - Enable polices and objects in dual pane.'
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner:
                type: str
                description:
                 - 'Enable/disable pre-login banner.'
                 - 'disable - Disable pre-login banner.'
                 - 'enable - Enable pre-login banner.'
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner-message:
                type: str
                description: 'Pre-login banner message.'
            private-data-encryption:
                type: str
                description:
                 - 'Enable/disable private data encryption using an AES 128-bit key.'
                 - 'disable - Disable private data encryption using an AES 128-bit key.'
                 - 'enable - Enable private data encryption using an AES 128-bit key.'
                choices:
                    - 'disable'
                    - 'enable'
            remoteauthtimeout:
                type: int
                description: 'Remote authentication (RADIUS/LDAP) timeout (sec).'
            search-all-adoms:
                type: str
                description:
                 - 'Enable/Disable Search all ADOMs for where-used query.'
                 - 'disable - Disable search all ADOMs for where-used queries.'
                 - 'enable - Enable search all ADOMs for where-used queries.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-low-encryption:
                type: str
                description:
                 - 'SSL low-grade encryption.'
                 - 'disable - Disable SSL low-grade encryption.'
                 - 'enable - Enable SSL low-grade encryption.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-protocol:
                description: no description
                type: list
                elements: str
                choices:
                    - 'tlsv1.3'
                    - 'tlsv1.2'
                    - 'tlsv1.1'
                    - 'tlsv1.0'
                    - 'sslv3'
            ssl-static-key-ciphers:
                type: str
                description:
                 - 'Enable/disable SSL static key ciphers.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            task-list-size:
                type: int
                description: 'Maximum number of completed tasks to keep.'
            tftp:
                type: str
                description:
                 - 'Enable/disable TFTP in `exec restore image` command (disabled by default in FIPS mode)'
                 - 'disable - Disable TFTP'
                 - 'enable - Enable TFTP'
                choices:
                    - 'disable'
                    - 'enable'
            timezone:
                type: str
                description:
                 - 'Time zone.'
                 - '00 - (GMT-12:00) Eniwetak, Kwajalein.'
                 - '01 - (GMT-11:00) Midway Island, Samoa.'
                 - '02 - (GMT-10:00) Hawaii.'
                 - '03 - (GMT-9:00) Alaska.'
                 - '04 - (GMT-8:00) Pacific Time (US & Canada).'
                 - '05 - (GMT-7:00) Arizona.'
                 - '06 - (GMT-7:00) Mountain Time (US & Canada).'
                 - '07 - (GMT-6:00) Central America.'
                 - '08 - (GMT-6:00) Central Time (US & Canada).'
                 - '09 - (GMT-6:00) Mexico City.'
                 - '10 - (GMT-6:00) Saskatchewan.'
                 - '11 - (GMT-5:00) Bogota, Lima, Quito.'
                 - '12 - (GMT-5:00) Eastern Time (US & Canada).'
                 - '13 - (GMT-5:00) Indiana (East).'
                 - '14 - (GMT-4:00) Atlantic Time (Canada).'
                 - '15 - (GMT-4:00) La Paz.'
                 - '16 - (GMT-4:00) Santiago.'
                 - '17 - (GMT-3:30) Newfoundland.'
                 - '18 - (GMT-3:00) Brasilia.'
                 - '19 - (GMT-3:00) Buenos Aires, Georgetown.'
                 - '20 - (GMT-3:00) Nuuk (Greenland).'
                 - '21 - (GMT-2:00) Mid-Atlantic (Deprecated).'
                 - '22 - (GMT-1:00) Azores.'
                 - '23 - (GMT-1:00) Cape Verde Is.'
                 - '24 - (GMT) Monrovia.'
                 - '25 - (GMT) London, Edinburgh.'
                 - '26 - (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna.'
                 - '27 - (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague.'
                 - '28 - (GMT+1:00) Brussels, Copenhagen, Madrid, Paris.'
                 - '29 - (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb.'
                 - '30 - (GMT+1:00) West Central Africa.'
                 - '31 - (GMT+2:00) Athens, Sofia, Vilnius.'
                 - '32 - (GMT+2:00) Bucharest.'
                 - '33 - (GMT+2:00) Cairo.'
                 - '34 - (GMT+2:00) Harare, Pretoria.'
                 - '35 - (GMT+2:00) Helsinki, Riga,Tallinn.'
                 - '36 - (GMT+2:00) Jerusalem.'
                 - '37 - (GMT+3:00) Baghdad.'
                 - '38 - (GMT+3:00) Kuwait, Riyadh.'
                 - '39 - (GMT+3:00) St.Petersburg, Volgograd.'
                 - '40 - (GMT+3:00) Nairobi.'
                 - '41 - (GMT+3:30) Tehran.'
                 - '42 - (GMT+4:00) Abu Dhabi, Muscat.'
                 - '43 - (GMT+4:00) Baku.'
                 - '44 - (GMT+4:30) Kabul.'
                 - '45 - (GMT+5:00) Ekaterinburg.'
                 - '46 - (GMT+5:00) Islamabad, Karachi, Tashkent.'
                 - '47 - (GMT+5:30) Calcutta, Chennai, Mumbai, New Delhi.'
                 - '48 - (GMT+5:45) Kathmandu.'
                 - '49 - (GMT+6:00) Almaty, Novosibirsk.'
                 - '50 - (GMT+6:00) Astana, Dhaka.'
                 - '51 - (GMT+5:30) Sri Jayawardenepura.'
                 - '52 - (GMT+6:30) Rangoon.'
                 - '53 - (GMT+7:00) Bangkok, Hanoi, Jakarta.'
                 - '54 - (GMT+7:00) Krasnoyarsk.'
                 - '55 - (GMT+8:00) Beijing, ChongQing, HongKong, Urumqi.'
                 - '56 - (GMT+8:00) Irkutsk, Ulaanbaatar.'
                 - '57 - (GMT+8:00) Kuala Lumpur, Singapore.'
                 - '58 - (GMT+8:00) Perth.'
                 - '59 - (GMT+8:00) Taipei.'
                 - '60 - (GMT+9:00) Osaka, Sapporo, Tokyo, Seoul.'
                 - '61 - (GMT+9:00) Yakutsk.'
                 - '62 - (GMT+9:30) Adelaide.'
                 - '63 - (GMT+9:30) Darwin.'
                 - '64 - (GMT+10:00) Brisbane.'
                 - '65 - (GMT+10:00) Canberra, Melbourne, Sydney.'
                 - '66 - (GMT+10:00) Guam, Port Moresby.'
                 - '67 - (GMT+10:00) Hobart.'
                 - '68 - (GMT+10:00) Vladivostok.'
                 - '69 - (GMT+11:00) Magadan.'
                 - '70 - (GMT+11:00) Solomon Is., New Caledonia.'
                 - '71 - (GMT+12:00) Auckland, Wellington.'
                 - '72 - (GMT+12:00) Fiji, Kamchatka, Marshall Is.'
                 - '73 - (GMT+13:00) Nukualofa.'
                 - '74 - (GMT-4:30) Caracas.'
                 - '75 - (GMT+1:00) Namibia.'
                 - '76 - (GMT-5:00) Brazil-Acre.'
                 - '77 - (GMT-4:00) Brazil-West.'
                 - '78 - (GMT-3:00) Brazil-East.'
                 - '79 - (GMT-2:00) Brazil-DeNoronha.'
                 - '80 - (GMT+14:00) Kiritimati.'
                 - '81 - (GMT-7:00) Baja California Sur, Chihuahua.'
                 - '82 - (GMT+12:45) Chatham Islands.'
                 - '83 - (GMT+3:00) Minsk.'
                 - '84 - (GMT+13:00) Samoa.'
                 - '85 - (GMT+3:00) Istanbul.'
                 - '86 - (GMT-4:00) Paraguay.'
                 - '87 - (GMT) Casablanca.'
                 - '88 - (GMT+3:00) Moscow.'
                 - '89 - (GMT) Greenwich Mean Time.'
                 - '90 - (GMT) Dublin.'
                 - '91 - (GMT) Lisbon.'
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
                    - '88'
                    - '89'
                    - '90'
                    - '91'
            tunnel-mtu:
                type: int
                description: 'Maximum transportation unit(68 - 9000).'
            usg:
                type: str
                description:
                 - 'Enable/disable Fortiguard server restriction.'
                 - 'disable - Contact any Fortiguard server'
                 - 'enable - Contact Fortiguard server in USA only'
                choices:
                    - 'disable'
                    - 'enable'
            webservice-proto:
                description: no description
                type: list
                elements: str
                choices:
                    - 'tlsv1.3'
                    - 'tlsv1.2'
                    - 'tlsv1.1'
                    - 'tlsv1.0'
                    - 'sslv3'
                    - 'sslv2'
            workflow-max-sessions:
                type: int
                description: 'Maximum number of workflow sessions per ADOM (minimum 100).'
            multiple-steps-upgrade-in-autolink:
                type: str
                description:
                 - 'Enable/disable multiple steps upgade in autolink process'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            normalized-intf-zone-only:
                type: str
                description:
                 - 'allow normalized interface to be zone only.'
                 - 'disable - Disable SSL low-grade encryption.'
                 - 'enable - Enable SSL low-grade encryption.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-cipher-suites:
                description: no description
                type: list
                elements: dict
                suboptions:
                    cipher:
                        type: str
                        description: 'Cipher name'
                    priority:
                        type: int
                        description: 'SSL/TLS cipher suites priority.'
                    version:
                        type: str
                        description:
                         - 'SSL/TLS version the cipher suite can be used with.'
                         - 'tls1.2-or-below - TLS 1.2 or below.'
                         - 'tls1.3 - TLS 1.3'
                        choices:
                            - 'tls1.2-or-below'
                            - 'tls1.3'
            gui-curl-timeout:
                type: int
                description: 'GUI curl timeout in seconds (5-300 default 30).'
            object-revision-db-max:
                type: int
                description: 'Maximum revisions for a single database (10,000-1,000,000 default 100,000).'
            object-revision-mandatory-note:
                type: str
                description:
                 - 'Enable/disable mandatory note when create revision.'
                 - 'disable - Disable object revision.'
                 - 'enable - Enable object revision.'
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-object-max:
                type: int
                description: 'Maximum revisions for a single object (10-1000 default 100).'
            object-revision-status:
                type: str
                description:
                 - 'Enable/disable create revision when modify objects.'
                 - 'disable - Disable object revision.'
                 - 'enable - Enable object revision.'
                choices:
                    - 'disable'
                    - 'enable'
            table-entry-blink:
                type: str
                description:
                 - 'Enable/disable table entry blink in GUI'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            contentpack-fgt-install:
                type: str
                description:
                 - 'Enable/disable outbreak alert auto install for FGT ADOMS .'
                 - 'disable - Disable the sql report auto outbreak auto install.'
                 - 'enable - Enable the sql report auto outbreak auto install.'
                choices:
                    - 'disable'
                    - 'enable'
            gui-polling-interval:
                type: int
                description: 'GUI polling interval in seconds (1-288000 default 5).'
            no-copy-permission-check:
                type: str
                description:
                 - 'Do not perform permission check to block object changes in different adom during copy and install.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            ssh-enc-algo:
                description: no description
                type: list
                elements: str
                choices:
                    - 'chacha20-poly1305@openssh.com'
                    - 'aes128-ctr'
                    - 'aes192-ctr'
                    - 'aes256-ctr'
                    - 'arcfour256'
                    - 'arcfour128'
                    - 'aes128-cbc'
                    - '3des-cbc'
                    - 'blowfish-cbc'
                    - 'cast128-cbc'
                    - 'aes192-cbc'
                    - 'aes256-cbc'
                    - 'arcfour'
                    - 'rijndael-cbc@lysator.liu.se'
                    - 'aes128-gcm@openssh.com'
                    - 'aes256-gcm@openssh.com'
            ssh-hostkey-algo:
                description: no description
                type: list
                elements: str
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
            ssh-kex-algo:
                description: no description
                type: list
                elements: str
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
            ssh-mac-algo:
                description: no description
                type: list
                elements: str
                choices:
                    - 'hmac-md5'
                    - 'hmac-md5-etm@openssh.com'
                    - 'hmac-md5-96'
                    - 'hmac-md5-96-etm@openssh.com'
                    - 'hmac-sha1'
                    - 'hmac-sha1-etm@openssh.com'
                    - 'hmac-sha2-256'
                    - 'hmac-sha2-256-etm@openssh.com'
                    - 'hmac-sha2-512'
                    - 'hmac-sha2-512-etm@openssh.com'
                    - 'hmac-ripemd160'
                    - 'hmac-ripemd160@openssh.com'
                    - 'hmac-ripemd160-etm@openssh.com'
                    - 'umac-64@openssh.com'
                    - 'umac-128@openssh.com'
                    - 'umac-64-etm@openssh.com'
                    - 'umac-128-etm@openssh.com'
            ssh-strong-crypto:
                type: str
                description:
                 - 'Only allow strong ciphers for SSH when enabled.'
                 - 'disable - Disable strong crypto for SSH.'
                 - 'enable - Enable strong crypto for SSH.'
                choices:
                    - 'disable'
                    - 'enable'
            admin-lockout-method:
                type: str
                description:
                 - 'Lockout method for administration.'
                 - 'ip - Lockout by IP'
                 - 'user - Lockout by user'
                choices:
                    - 'ip'
                    - 'user'
            event-correlation-cache-size:
                type: int
                description: 'Maimum event correlation cache size (GB)'
            fgfm-cert-exclusive:
                type: str
                description:
                 - 'set if the local or CA certificates should be used exclusively.'
                 - 'disable - Used certificate best-effort.'
                 - 'enable - Used certificate exclusive.'
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum-upload:
                type: str
                description:
                 - 'Enable/disable upload log checksum with log files.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            apache-mode:
                type: str
                description:
                 - 'Set apache mode.'
                 - 'event - Apache event mode.'
                 - 'prefork - Apache prefork mode.'
                choices:
                    - 'event'
                    - 'prefork'
            no-vip-value-check:
                type: str
                description:
                 - 'Enable/disable skipping policy instead of throwing error when vip has no default or dynamic mapping during policy copy'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            log-forward-plugin-workers:
                type: int
                description: 'Maximum workers for running log forward output plugins, the valid range is 2 to 20'
            fortiservice-port:
                type: int
                description: 'FortiService port (1 - 65535, default = 8013). Used by FortiClient endpoint compliance. Older versions of FortiClient used a d...'
            management-ip:
                type: str
                description: 'Management IP address of this FortiGate. Used to log into this FortiGate from another FortiGate in the Security Fabric.'
            management-port:
                type: int
                description: 'Overriding port for management connection (Overrides admin port).'
            api-ip-binding:
                type: str
                description:
                 - 'Enable/disable source IP check for JSON API request.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortianalyzers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Alert console
      fortinet.fortianalyzer.faz_cli_system_global:
        enable_log: true
        cli_system_global:
          language: english
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
        '/cli/global/system/global'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/global/{global}'
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
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'cli_system_global': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'admin-lockout-duration': {'type': 'int'},
                'admin-lockout-threshold': {'type': 'int'},
                'adom-mode': {'choices': ['normal', 'advanced'], 'type': 'str'},
                'adom-select': {'choices': ['disable', 'enable'], 'type': 'str'},
                'adom-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'backup-compression': {'choices': ['none', 'low', 'normal', 'high'], 'type': 'str'},
                'backup-to-subfolders': {'choices': ['disable', 'enable'], 'type': 'str'},
                'clone-name-option': {'choices': ['default', 'keep'], 'type': 'str'},
                'clt-cert-req': {'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                'console-output': {'choices': ['standard', 'more'], 'type': 'str'},
                'country-flag': {'choices': ['disable', 'enable'], 'type': 'str'},
                'create-revision': {'choices': ['disable', 'enable'], 'type': 'str'},
                'daylightsavetime': {'choices': ['disable', 'enable'], 'type': 'str'},
                'default-logview-auto-completion': {'v_range': [['6.2.1', '6.2.1'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-search-mode': {'choices': ['filter-based', 'advanced'], 'type': 'str'},
                'detect-unregistered-log-device': {'choices': ['disable', 'enable'], 'type': 'str'},
                'device-view-mode': {'choices': ['regular', 'tree'], 'type': 'str'},
                'dh-params': {'choices': ['1024', '1536', '2048', '3072', '4096', '6144', '8192'], 'type': 'str'},
                'disable-module': {
                    'type': 'list',
                    'choices': ['fortiview-noc', 'siem', 'soar', 'none', 'soc', 'fortirecorder', 'ai', 'ot-view'],
                    'elements': 'str'
                },
                'enc-algorithm': {'choices': ['low', 'medium', 'high', 'custom'], 'type': 'str'},
                'fgfm-ca-cert': {'v_range': [['6.2.1', '6.2.1'], ['6.2.3', '']], 'type': 'str'},
                'fgfm-local-cert': {'type': 'str'},
                'fgfm-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'ha-member-auto-grouping': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hitcount_concurrent': {'v_range': [['6.2.1', '6.4.2']], 'type': 'int'},
                'hitcount_interval': {'v_range': [['6.2.1', '6.4.2']], 'type': 'int'},
                'hostname': {'type': 'str'},
                'language': {'choices': ['english', 'simch', 'japanese', 'korean', 'spanish', 'trach'], 'type': 'str'},
                'latitude': {'type': 'str'},
                'ldap-cache-timeout': {'type': 'int'},
                'ldapconntimeout': {'type': 'int'},
                'lock-preempt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-checksum': {'choices': ['none', 'md5', 'md5-auth'], 'type': 'str'},
                'log-forward-cache-size': {'type': 'int'},
                'log-mode': {'choices': ['analyzer', 'collector'], 'type': 'str'},
                'longitude': {'type': 'str'},
                'max-aggregation-tasks': {'type': 'int'},
                'max-log-forward': {'type': 'int'},
                'max-running-reports': {'type': 'int'},
                'oftp-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'policy-hit-count': {'v_range': [['6.2.1', '6.4.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-object-icon': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-object-in-dual-pane': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-login-banner': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-login-banner-message': {'type': 'str'},
                'private-data-encryption': {'v_range': [['6.2.1', '6.2.1'], ['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remoteauthtimeout': {'type': 'int'},
                'search-all-adoms': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-low-encryption': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-protocol': {'type': 'list', 'choices': ['tlsv1.3', 'tlsv1.2', 'tlsv1.1', 'tlsv1.0', 'sslv3'], 'elements': 'str'},
                'ssl-static-key-ciphers': {'choices': ['disable', 'enable'], 'type': 'str'},
                'task-list-size': {'type': 'int'},
                'tftp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'timezone': {
                    'choices': [
                        '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
                        '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                        '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62',
                        '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83',
                        '84', '85', '86', '87', '88', '89', '90', '91'
                    ],
                    'type': 'str'
                },
                'tunnel-mtu': {'type': 'int'},
                'usg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webservice-proto': {'type': 'list', 'choices': ['tlsv1.3', 'tlsv1.2', 'tlsv1.1', 'tlsv1.0', 'sslv3', 'sslv2'], 'elements': 'str'},
                'workflow-max-sessions': {'type': 'int'},
                'multiple-steps-upgrade-in-autolink': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'normalized-intf-zone-only': {'v_range': [['6.4.7', '6.4.14'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'type': 'str'},
                        'priority': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'type': 'int'},
                        'version': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'choices': ['tls1.2-or-below', 'tls1.3'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'gui-curl-timeout': {'v_range': [['6.4.11', '6.4.14'], ['7.0.7', '7.0.11'], ['7.2.2', '']], 'type': 'int'},
                'object-revision-db-max': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'object-revision-mandatory-note': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'object-revision-object-max': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'object-revision-status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'table-entry-blink': {'v_range': [['7.0.4', '7.0.11'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'contentpack-fgt-install': {'v_range': [['7.0.5', '7.0.11'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-polling-interval': {'v_range': [['7.0.5', '7.0.11'], ['7.2.1', '']], 'type': 'int'},
                'no-copy-permission-check': {'v_range': [['7.0.8', '7.0.11'], ['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-enc-algo': {
                    'v_range': [['7.0.11', '7.0.11'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'arcfour256', 'arcfour128', 'aes128-cbc', '3des-cbc',
                        'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'rijndael-cbc@lysator.liu.se', 'aes128-gcm@openssh.com',
                        'aes256-gcm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'ssh-hostkey-algo': {
                    'v_range': [['7.0.11', '7.0.11'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': ['ssh-rsa', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'],
                    'elements': 'str'
                },
                'ssh-kex-algo': {
                    'v_range': [['7.0.11', '7.0.11'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512',
                        'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group-exchange-sha256',
                        'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
                    ],
                    'elements': 'str'
                },
                'ssh-mac-algo': {
                    'v_range': [['7.0.11', '7.0.11'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'hmac-md5', 'hmac-md5-etm@openssh.com', 'hmac-md5-96', 'hmac-md5-96-etm@openssh.com', 'hmac-sha1', 'hmac-sha1-etm@openssh.com',
                        'hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com', 'hmac-ripemd160',
                        'hmac-ripemd160@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com',
                        'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'ssh-strong-crypto': {'v_range': [['7.0.11', '7.0.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-lockout-method': {'v_range': [['7.2.2', '']], 'choices': ['ip', 'user'], 'type': 'str'},
                'event-correlation-cache-size': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'fgfm-cert-exclusive': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-checksum-upload': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'apache-mode': {'v_range': [['7.2.4', '7.2.4'], ['7.4.1', '']], 'choices': ['event', 'prefork'], 'type': 'str'},
                'no-vip-value-check': {'v_range': [['7.2.4', '7.2.4'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-forward-plugin-workers': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fortiservice-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'management-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'management-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'api-ip-binding': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module = AnsibleModule(argument_spec=modify_argument_spec(module_arg_spec, 'cli_system_global'),
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
