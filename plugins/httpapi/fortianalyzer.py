# Copyright (c) 2018-2023 Fortinet and/or its affiliates.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
name : fortianalyzer
author:
    - Xinwei Du (@dux-fortinet)
    - Link Zheng (@chillancezen)
    - Luke Weighall (@lweighall)
    - Andrew Welsh (@Ghilli3)
    - Jim Huber (@p4r4n0y1ng)
short_description: HttpApi Plugin for Fortinet FortiAnalyzer Appliance or VM.
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiAnalyzer Appliance or VM via JSON RPC API.
version_added: "1.0.0"

"""

import json
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.common import BASE_HEADERS
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.common import FAZCommon
from datetime import datetime


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self._req_id = 0
        self._sid = None
        self._url = "/jsonrpc"
        self._host = None
        self._tools = FAZCommon
        self._logged_in_user = None
        self._logged = False
        self._log = None
        self._forticloud_access_token = None
        self._access_token = None

    def log(self, msg):
        log_enabled = False
        try:
            log_enabled = self.connection.get_option("enable_log")
        except Exception:
            return
        if not log_enabled:
            return
        if not self._log:
            try:
                log_path = self.connection.get_option("log_path")
                self._log = open(log_path, "a")
            except Exception:
                self._log = open("/tmp/fortianalyzer.ansible.log", "a")
        log_message = str(datetime.now()) + ": " + str(msg) + "\n"
        self._log.write(log_message)
        self._log.flush()

    def set_become(self, become_context):
        """
        ELEVATION IS NOT REQUIRED ON FORTINET DEVICES - SKIPPED
        :param become_context: Unused input.
        :return: None
        """
        return None

    def update_auth(self, response, response_text):
        """
        TOKENS ARE NOT USED SO NO NEED TO UPDATE AUTH
        :param response: Unused input.
        :param response_data Unused_input.
        :return: None
        """
        return None

    def get_forticloud_access_token(self):
        try:
            token = self.connection.get_option("forticloud_access_token")
            return token
        except Exception:
            return None

    def get_access_token(self):
        try:
            token = self.connection.get_option("access_token")
            return token
        except Exception:
            return None

    def forticloud_login(self):
        login_data = '{"access_token": "%s"}' % (self.get_forticloud_access_token())
        rc, response_data = self.connection.send(
            path="/p/forticloud_jsonrpc_login/",
            data=login_data,
            headers=BASE_HEADERS,
        )
        result = json.loads(to_text(response_data.getvalue()))
        self.log("forticloud login response: %s" % (str(self._jsonize(result))))
        return self._set_sid(result)

    def login(self, username, password):
        """
        This function will log the plugin into FortiAnalyzer, and return the results.
        :param username: Username of FortiAnalyzer Admin
        :param password: Password of FortiAnalyzer Admin

        :return: Dictionary of status, if it logged in or not.
        """
        self.log("login begin, user: %s" % (username))
        self._logged_in_user = username
        self._access_token = self.get_access_token()
        self._forticloud_access_token = self.get_forticloud_access_token()
        if self._access_token:
            self._login_method = 'access_token'
        elif self._forticloud_access_token:
            self._login_method = 'forticloud'
            self.forticloud_login()
        else:
            self._login_method = 'username_password'
            self.send_request("exec", self._tools.format_request("exec", "sys/login/user", passwd=password, user=username))
        self.log('login method: ' + self._login_method)
        self.log(self)
        if (self.sid or self._access_token) and self.connection._url is not None:
            # If Login worked, then inspect the FortiAnalyzer for Workspace Mode, and it's system information.
            self.inspect_faz()
            self._logged = True
        else:
            err_msg = "Can't login. Your login method is %s." % (self._login_method)
            err_msg += "Please check whether you provide the correct information."
            raise AssertionError(err_msg)

    def inspect_faz(self):
        # CHECK FOR WORKSPACE MODE TO SEE IF WE HAVE TO ENABLE ADOM LOCKS
        rc, status = self.get_system_status()
        if rc == -11:
            # THE CONNECTION GOT LOST SOMEHOW, REMOVE THE SID AND REPORT BAD LOGIN
            self.logout()
            raise AssertionError("Error -11 -- the Session ID was likely malformed somehow.")
        elif rc == 0:
            self._host = status['data']["Hostname"]

    def logout(self):
        """
        This function will logout of the FortiAnalyzer.
        """
        self.log("log out, user: %s sid: %s" % (self._logged_in_user, self.sid))
        if self.sid:
            rc, response = self.send_request("exec", self._tools.format_request("exec", "sys/logout"))
            self.sid = None
            return rc, response

    def send_request(self, method, params):
        """
        Responsible for actual sending of data to the connection httpapi base plugin. Does some formatting as well.
        :param params: A formatted dictionary that was returned by self.common_datagram_params()
        before being called here.
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring

        :return: Dictionary of status, if it logged in or not.
        """
        if self.sid is None and params[0]["url"] != "sys/login/user":
            if not self.connection._connected:
                self.connection._connect()
        if params[0]["url"] == "sys/login/user" and "passwd" in params[0]["data"]:
            params[0]["data"]["passwd"] = str(params[0]["data"]["passwd"])
        self._update_request_id()
        json_request = {
            "method": method,
            "params": params,
            "session": self.sid,
            "id": self.req_id,
            "verbose": 1
        }
        data = json.dumps(json_request, ensure_ascii=False).replace('\\\\', '\\')

        # Don't log sensitive information
        if params[0]["url"] == "sys/login/user" and "passwd" in params[0]["data"]:
            json_request["params"][0]["data"]["passwd"] = "******"
        if "session" in params[0]:
            json_request["params"][0]["session"] = "******"
        log_data = json.dumps(json_request, ensure_ascii=False).replace("\\\\", "\\")
        self.log("request: %s" % (log_data))

        # Sending URL and Data in Unicode, per Ansible Specifications for Connection Plugins
        header_data = BASE_HEADERS
        if self._login_method == "access_token":
            header_data["Authorization"] = "Bearer " + self._access_token
        rc, response_data = self.connection.send(path=to_text(self._url), data=to_text(data), headers=header_data)

        # Get Unicode Response - Must convert from StringIO to unicode first so we can do a replace function below
        result = json.loads(to_text(response_data.getvalue()))
        self.log('response: %s' % (str(self._jsonize(result))))
        return self._handle_response(result)

    def _jsonize(self, data):
        ret = None
        try:
            ret = json.dumps(data, indent=3)
        except Exception:
            pass
        return ret

    def _handle_response(self, response):
        self._set_sid(response)
        if isinstance(response["result"], list):
            result = response["result"][0]
        else:
            result = response["result"]
        return result["status"]["code"], result

    def _set_sid(self, response):
        if self.sid is None and "session" in response:
            self.sid = response["session"]

    def get_system_status(self):
        """
        Returns the system status page from the FortiAnalyzer, for logging and other uses.
        return: status
        """
        rc, status = self.send_request("get", self._tools.format_request("get", "sys/status"))
        return rc, status

    @property
    def req_id(self):
        return self._req_id

    @req_id.setter
    def req_id(self, val):
        self._req_id = val

    def _update_request_id(self, reqid=0):
        self.req_id = reqid if reqid != 0 else self.req_id + 1

    @property
    def sid(self):
        return self._sid

    @sid.setter
    def sid(self, val):
        self._sid = val

    def __str__(self):
        if self.sid is not None and self.connection._url is not None:
            return "FortiAnalyzer object connected to FortiAnalyzer: " + to_text(self.connection._url)
        return "FortiAnalyzer object with no valid connection to a FortiAnalyzer appliance."
