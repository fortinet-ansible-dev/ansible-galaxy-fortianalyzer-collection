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
        self._tools = FAZCommon
        self._log = None
        self._forticloud_access_token = None
        self._access_token = None
        self._login_method = "Not set"
        self._status = {}
        self.customer_options = {}

    def set_customer_option(self, key, value):
        self.customer_options[key] = value

    def log(self, msg):
        log_enabled = self.customer_options.get("enable_log", False)
        if not log_enabled:
            return
        if not self._log:
            try:
                log_path = self.customer_options.get("log_path", "/tmp/fortianalyzer.ansible.log")
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
        token = self.customer_options.get("forticloud_access_token", None)
        return token

    def get_access_token(self):
        token = self.customer_options.get("access_token", None)
        return token

    def forticloud_login(self):
        login_data = '{"access_token": "%s"}' % (self._forticloud_access_token)
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
        self.log("log in")
        self._access_token = self.get_access_token()
        self._forticloud_access_token = self.get_forticloud_access_token()
        if self._access_token:
            self._login_method = "access_token"
        elif self._forticloud_access_token:
            self._login_method = "forticloud"
            self.forticloud_login()
        else:
            self._login_method = "username_password"
            self.send_request("exec", self._tools.format_request("exec", "sys/login/user", passwd=password, user=username))
        self.log("Login method: %s, Target: %s" % (self._login_method, to_text(self.connection._url)))
        if (self.sid or self._access_token) and self.connection._url is not None:
            # If Login worked, then inspect the FortiAnalyzer system information.
            self.log("Loading system info")
            rc, status = self.get_system_status()
            if rc == -11:
                # THE CONNECTION GOT LOST SOMEHOW, REMOVE THE SID AND REPORT BAD LOGIN
                self.logout()
                err_msg = "Can't login. Your login method is %s." % (self._login_method)
                err_msg += "Please check whether you provide the correct information."
                raise AssertionError(err_msg)
        else:
            err_msg = "Can't login. Your login method is %s." % (self._login_method)
            err_msg += "Please check whether you provide the correct information."
            raise AssertionError(err_msg)

    def logout(self):
        """
        This function will logout of the FortiAnalyzer.
        """
        self.log("log out")
        if self.sid:
            rc, response = self.send_request("exec", self._tools.format_request("exec", "sys/logout"))
            self.sid = None
            return rc, response

    def send_request(self, method, params, jsonrpc2=False):
        """
        Responsible for actual sending of data to the connection httpapi base plugin. Does some formatting as well.
        :param params: A formatted dictionary that was returned by self.common_datagram_params()
        before being called here.
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring

        :return: Dictionary of status, if it logged in or not.
        """
        request_url = params[0]["url"]
        if self.sid is None and request_url != "sys/login/user":
            if not self.connection._connected:
                self.connection._connect()
        if request_url == "sys/login/user" and "data" in params[0] and "passwd" in params[0]["data"]:
            params[0]["data"]["passwd"] = str(params[0]["data"]["passwd"])
        self._update_request_id()
        json_request = {
            "method": method,
            "params": params,
            "session": self.sid,
            "id": self.req_id,
            "verbose": 1
        }
        # FortiAnalyzer handle report API
        if request_url.startswith("/report/") or jsonrpc2:
            json_request["jsonrpc"] = "2.0"
            json_request["params"][0]["apiver"] = 3
        data = json.dumps(json_request, ensure_ascii=False).replace("\\\\", "\\")

        # Log debug data, don't log sensitive information
        if request_url == "sys/login/user" and "data" in params[0] and "passwd" in params[0]["data"]:
            json_request["params"][0]["data"]["passwd"] = "******"
        json_request["session"] = "******"
        log_data = json.dumps(json_request, ensure_ascii=False).replace("\\\\", "\\")
        self.log("request: %s" % (log_data))

        # Sending URL and Data in Unicode, per Ansible Specifications for Connection Plugins
        access_token_str = ""
        header_data = BASE_HEADERS
        if self._login_method == "access_token":
            access_token_str = "?access_token=" + self._access_token
            header_data["Authorization"] = "Bearer " + self._access_token
        rc, response_data = self.connection.send(path=to_text(self._url) + access_token_str, data=to_text(data), headers=header_data)
        header_data["Authorization"] = "******"
        self.log("header: %s" % (str(header_data)))

        # Get Unicode Response - Must convert from StringIO to unicode first so we can do a replace function below
        result = json.loads(to_text(response_data.getvalue()))
        self.log("response: %s" % (str(self._jsonize(result))))
        return self._handle_response(result, request_url)

    def _jsonize(self, data):
        ret = None
        try:
            ret = json.dumps(data, indent=4)
        except Exception:
            pass
        return ret

    def _handle_response(self, response, request_url):
        self._set_sid(response)
        error_code = 0
        if "result" not in response or response.get("jsonrpc", None) == "2.0":
            if "error" in response and "code" in response["error"]:
                error_code = response["error"]["code"]
            if "url" not in response:
                response["url"] = request_url
            return error_code, response
        if isinstance(response["result"], list):
            result = response["result"][0]
        else:
            result = response["result"]
        if "status" in result and "code" in result["status"]:
            error_code = result["status"]["code"]
        return error_code, result

    def _set_sid(self, response):
        if self.sid is None and "session" in response:
            self.sid = response["session"]

    def get_system_status(self):
        """
        Returns the system status page from the FortiAnalyzer, for logging and other uses.
        return: status
        """
        if not self.connection._connected:
            self.connection._connect()
        if self._status:
            return 0, self._status
        rc, self._status = self.send_request("get", self._tools.format_request("get", "/cli/global/system/status"))
        return rc, self._status

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
