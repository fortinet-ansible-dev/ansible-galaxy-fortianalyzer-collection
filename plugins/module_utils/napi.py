# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2020-2023 Fortinet, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import _load_params
import re


def _get_modified_name(variable_name):
    modified_name = variable_name
    for special_char in ['-', ' ', '.', '(', '+']:
        modified_name = modified_name.replace(special_char, '_')
    return modified_name


def add_aliases(schema):
    if not isinstance(schema, dict):
        return schema
    new_schema = {}
    for param_name in schema:
        if param_name != 'v_range' and param_name != 'revision' and param_name != 'api_name':
            new_content = add_aliases(schema[param_name])
            aliase_name = _get_modified_name(param_name)
            if aliase_name != param_name:
                new_content['removed_in_version'] = '2.0.0'
                new_content['removed_from_collection'] = 'fortinet.fortianalyzer'
                if aliase_name not in new_schema and "api_name" not in schema[param_name]:
                    new_content['aliases'] = [aliase_name]
            new_schema[param_name] = new_content
    return new_schema


def remove_aliases(user_params, metadata):
    if not user_params:
        return user_params
    if isinstance(user_params, str) or isinstance(user_params, int):
        return user_params
    if isinstance(user_params, list):
        new_params = []
        for item in user_params:
            new_params.append(remove_aliases(item, metadata))
        return new_params
    replace_key = {'faz_message': 'message'}
    new_params = {}
    for param_name, param_data in metadata.items():
        if user_params.get(param_name, None) is None:
            continue
        real_param_name = replace_key.get(param_name, param_name)
        if 'options' in param_data:
            new_params[real_param_name] = remove_aliases(user_params[param_name], param_data['options'])
        else:
            new_params[real_param_name] = user_params[param_name]
    return new_params


def modify_argument_spec(schema, module_level2_name):
    schema = add_aliases(schema)
    params = _load_params()
    if params and 'bypass_validation' in params and params['bypass_validation'] is True:
        top_level_schema = dict()
        for key in schema:
            if key != module_level2_name:
                top_level_schema[key] = schema[key]
            elif not params[module_level2_name] or isinstance(params[module_level2_name], dict):
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['type'] = 'dict'
            elif isinstance(params[module_level2_name], list):
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['type'] = 'list'
        return top_level_schema
    return schema


class NAPIManager(object):
    jrpc_urls = None
    perobject_jrpc_urls = None
    module_primary_key = None
    url_params = None
    module = None
    conn = None
    module_name = None
    module_level2_name = None

    def __init__(self, jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, conn,
                 metadata=None, task_type=None):
        self.jrpc_urls = jrpc_urls
        self.perobject_jrpc_urls = perobject_jrpc_urls
        self.module_primary_key = module_primary_key
        self.url_params = url_params
        self.module = module
        self.conn = conn
        self.module_name = self.module._name
        self.module_level2_name = self.module_name.split('.')[-1][4:]
        self.system_status = self.get_system_status()
        self.version_check_warnings = list()
        self.task_type = task_type
        self.metadata = metadata

    def process(self):
        if self.task_type == 'exec':
            self.process_exec()
        elif self.task_type == 'partial crud':
            self.process_partial_curd()
        elif self.task_type == 'full crud' or self.task_type == 'object member':
            self.process_curd()
        elif self.task_type == 'fact':
            self.process_fact()
        elif self.task_type == 'rename':
            self.process_rename()
        else:
            raise AssertionError('Wrong task type')

    def get_propose_method(self, default_method):
        if 'proposed_method' in self.module.params and self.module.params['proposed_method']:
            return self.module.params['proposed_method']
        return default_method

    def get_params_in_url(self, s):
        """Find contents in {}"""
        pattern = r'\{(.*?)\}'
        result = re.findall(pattern, s)
        return result

    def _version_matched(self, v_ranges):
        if not v_ranges or not self.system_status:
            # if system version is not determined, give up version checking
            return True, None

        sys_version_value = (
            int(self.system_status['Major']) * 10000
            + int(self.system_status['Minor']) * 100
            + int(self.system_status['Patch'])
        )
        b_match = False
        for vr in v_ranges:
            min_v = vr[0].split('.')
            min_vn = (
                int(min_v[0]) * 10000
                + int(min_v[1]) * 100
                + int(min_v[2])
            )
            if min_vn > sys_version_value:
                break
            if vr[1] == '':  # Empty string means no max version
                b_match = True
                break
            max_v = vr[1].split('.')
            max_vn = (
                int(max_v[0]) * 10000
                + int(max_v[1]) * 100
                + int(max_v[2])
            )
            if max_vn >= sys_version_value:
                b_match = True
                break
        if b_match:
            return True, None
        supported_v = []
        for vr in v_ranges:
            if vr[1] == '':
                vr_s = '>= %s' % (vr[0])
            else:
                vr_s = '%s-%s' % (vr[0], (vr[1]))
            supported_v.append(vr_s)
        return (
            False,
            'Current FortiAnalyzer version %s.%s.%s do not support this feature. Supported version range: %s.'
            % (self.system_status['Major'], self.system_status['Minor'], self.system_status['Patch'], supported_v),
        )

    def _get_basic_url(self, is_perobject):
        url_libs = None
        if is_perobject:
            url_libs = list(self.perobject_jrpc_urls)
        else:
            url_libs = list(self.jrpc_urls)
        the_url = None
        if 'adom' in self.url_params and not url_libs[0].endswith('{adom}'):
            adom = self.module.params['adom']
            if adom == 'global':
                for url in url_libs:
                    if '/global/' in url:
                        the_url = url
                        break
                if not the_url:
                    self.module.fail_json(msg='No global url for the request, please use other adom.')
            else:
                for url in url_libs:
                    if '/adom/{adom}/' in url:
                        the_url = url
                        break
                if not the_url:
                    self.module.fail_json(msg='No url for the requested adom:%s, please use other adom.' % (adom))
        else:
            the_url = url_libs[0]
        if not the_url:
            raise AssertionError('the_url is not expected to be NULL')
        return self._get_replaced_url(the_url)

    def _get_target_url(self, adom_value, url_list):
        target_url = None
        if adom_value is not None and not url_list[0].endswith("{adom}"):
            if adom_value == "global":
                for url in url_list:
                    if "/global/" in url and "/adom/{adom}/" not in url:
                        target_url = url
                        break
            elif adom_value:
                for url in url_list:
                    if "/adom/{adom}/" in url:
                        target_url = url
                        break
            else:
                # adom = "", choose default URL which is for all domains
                for url in url_list:
                    if "/global/" not in url and "/adom/{adom}/" not in url:
                        target_url = url
                        break
        else:
            target_url = url_list[0]
        if not target_url:
            self.module.fail_json(msg="can not find url in following sets:%s! please check params: adom" % (target_url))
        return target_url

    def _get_replaced_url(self, url_template):
        target_url = url_template
        for param in self.url_params:
            token_hint = "{%s}" % (param)
            token = ""
            modified_name = _get_modified_name(param)
            modified_token = self.module.params.get(modified_name, None)
            previous_token = self.module.params.get(param, None)
            if modified_token is not None:
                token = modified_token
            elif previous_token is not None:
                token = previous_token
            else:
                self.module.fail_json(msg="Missing input param: %s" % (modified_name))
            target_url = target_url.replace(token_hint, "%s" % (token))
        return target_url

    def _get_base_perobject_url(self, mvalue):
        url_getting = self._get_basic_url(True)
        if not url_getting.endswith('}'):
            # in case of non-regular per-object url.
            return url_getting
        last_token = url_getting.split('/')[-1]
        return url_getting.replace(last_token, str(mvalue))

    def get_object(self, mvalue):
        url_getting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_getting}]
        response = self.conn.send_request('get', params)
        return response

    def update_object(self, mvalue):
        url_updating = self._get_base_perobject_url(mvalue)
        raw_attributes = remove_aliases(self.module.params, self.metadata)
        raw_attributes = raw_attributes.get(self.module_level2_name, {})
        params = [{'url': url_updating, 'data': raw_attributes}]
        response = self.conn.send_request('update', params)
        return response

    def create_object(self):
        url_creating = self._get_basic_url(False)
        raw_attributes = remove_aliases(self.module.params, self.metadata)
        raw_attributes = raw_attributes.get(self.module_level2_name, {})
        params = [{'url': url_creating, 'data': raw_attributes}]
        return self.conn.send_request(self.get_propose_method('set'), params)

    def delete_object(self, mvalue):
        url_deleting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_deleting}]
        return self.conn.send_request('delete', params)

    def get_system_status(self):
        params = [{'url': '/cli/global/system/status'}]
        status_code, response = self.conn.send_request('get', params)
        if status_code == 0:
            if 'data' not in response:
                raise AssertionError('Error when getting system status')
            return response['data']
        return None

    def is_same_subnet(self, object_remote, object_present):
        if isinstance(object_remote, list) and len(object_remote) != 2:
            return False
        tokens = object_present.split("/")
        if len(tokens) != 2:
            return False
        try:
            subnet_number = int(tokens[1])
            if subnet_number < 0 or subnet_number > 32:
                return False
            remote_subnet_number = sum(bin(int(x)).count("1") for x in object_remote[1].split("."))
            if object_remote[0] == tokens[0] and remote_subnet_number == subnet_number:
                return True
        except Exception as e:
            return False
        return False

    def is_object_difference(self, remote_obj, local_obj):
        for key in local_obj:
            local_value = local_obj[key]
            if local_value is None:
                continue
            remote_value = remote_obj.get(key, None)
            if remote_value is None:
                return True
            if isinstance(local_value, list):
                try:
                    if isinstance(remote_value, list):
                        if str(sorted(remote_value)) == str(sorted(local_value)):
                            continue
                    # Won't update if remote = 'var' and local = ['var']
                    elif len(local_value) == 1:
                        if str(remote_value) == str(local_value[0]):
                            continue
                except Exception as e:
                    return True
                return True
            elif isinstance(local_value, dict):
                if not isinstance(remote_value, dict):
                    return True
                elif self.is_object_difference(remote_value, local_value):
                    return True
            else:  # local_value is not list or dict, maybe int, float or str
                value_string = str(local_value)
                if isinstance(remote_value, list):  # e.g., subnet
                    if self.is_same_subnet(remote_value, value_string):
                        continue
                    # Won't update if remote = ['var'] and local = 'var'
                    elif len(remote_value) != 1 or str(remote_value[0]) != value_string:
                        return True
                elif str(remote_value) != value_string:
                    return True
        return False

    def _update_required(self, robject):
        object_remote = robject['data'] if 'data' in robject else {}
        object_present = remove_aliases(self.module.params, self.metadata)
        object_present = object_present.get(self.module_level2_name, {})
        return self.is_object_difference(object_remote, object_present)

    def _process_with_mkey(self, mvalue):
        if self.module.params['state'] == 'present':
            rc, robject = self.get_object(mvalue)
            if rc == 0:
                if self._update_required(robject):
                    return self.update_object(mvalue)
                else:
                    self.module.exit_json(message='Your FortiAnalyzer is up to date, no need to update.')
            else:
                return self.create_object()
        elif self.module.params['state'] == 'absent':
            return self.delete_object(mvalue)

    def _process_without_mkey(self):
        if self.module.params['state'] == 'absent':
            self.module.fail_json(msg='this module doesn\'t not support state:absent because of no primary key.')
        return self.create_object()

    def process_generic(self, method, param):
        response = self.conn.send_request(method, param)
        self.do_exit(response)

    def process_exec(self):
        argument_specs = self.metadata
        params = remove_aliases(self.module.params, self.metadata)
        module_name = self.module_level2_name
        track = [module_name]
        if not params.get('bypass_validation', False):
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        url = self.jrpc_urls[0]  # exec method only have one url
        for param_name in self.url_params:
            token_hint = '{%s}' % (param_name)
            token = str(params[param_name])
            url = url.replace(token_hint, token)

        api_params = {'url': url}
        if module_name in params:  # except sys_logout
            api_params['data'] = params[module_name]

        response = self.conn.send_request('exec', [api_params])
        self.do_exit(response)

    def process_curd(self):
        argument_specs = self.metadata
        params = self.module.params
        module_name = self.module_level2_name
        track = [module_name]
        if not params.get('bypass_validation', False):
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        if self.module_primary_key and isinstance(params[module_name], dict):
            mvalue = params[module_name][self.module_primary_key]
            self.do_exit(self._process_with_mkey(mvalue))
        else:
            self.do_exit(self._process_without_mkey())

    def process_partial_curd(self):
        argument_specs = self.metadata
        params = remove_aliases(self.module.params, self.metadata)
        module_name = self.module_level2_name
        track = [module_name]
        if not params.get("bypass_validation", False):
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        adom_value = params.get("adom", None)
        target_url = self._get_target_url(adom_value, self.jrpc_urls)
        target_url = self._get_replaced_url(target_url)
        api_params = {'url': target_url}
        if module_name in params:
            api_params['data'] = params[module_name]
        response = self.conn.send_request(self.get_propose_method('set'), [api_params])
        self.do_exit(response)

    def process_rename(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['rename']['selector']
        url_list = metadata[selector]['urls']

        # Version check
        vrange = metadata[selector].get("v_range", None)
        matched, checking_message = self._version_matched(vrange)
        if not matched:
            self.version_check_warnings.append('faz_rename selector:%s %s' % (selector, checking_message))

        # Mkey check
        mkey = metadata[selector]['mkey']
        if mkey and mkey not in params['rename']['target']:
            self.module.fail_json(msg='Must give the primary key/value in target: %s!' % (mkey))

        # Get real url
        url = None
        given_params = set()
        if params['rename']['self']:
            given_params = set([_get_modified_name(key) for key in params['rename']['self'].keys()])
        for possible_url in url_list:
            required_params = set([_get_modified_name(key) for key in self.get_params_in_url(possible_url)])
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params in self:%s, expect params: ' % (list(params['rename']['self'].keys()))
            for i, possible_url in enumerate(url_list):
                if i:
                    error_message += ', or '
                error_message += '%s' % ([_get_modified_name(key) for key in self.get_params_in_url(possible_url)])
            self.module.fail_json(msg=error_message)
        param_names = self.get_params_in_url(url)
        for param_name in param_names:
            token_hint = '{%s}' % (param_name)
            token = ''
            modified_name = _get_modified_name(param_name)
            if modified_name in params['rename']['self']:
                token = params['rename']['self'][modified_name]
            else:
                token = params['rename']['self'][param_name]
            url = url.replace(token_hint, token)

        # Send data
        api_params = [{'url': url, 'data': params['rename']['target']}]
        response = self.conn.send_request('update', api_params)
        self.do_exit(response)

    def process_fact(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['facts']['selector']
        url_list = metadata[selector]['urls']

        # Version check
        vrange = metadata[selector].get("v_range", None)
        matched, checking_message = self._version_matched(vrange)
        if not matched:
            self.version_check_warnings.append('faz_fact selector:%s %s' % (selector, checking_message))

        # Get real url
        url = None
        given_params = set()
        if params['facts']['params']:
            given_params = set([_get_modified_name(key) for key in params['facts']['params'].keys()])
        for possible_url in url_list:
            required_params = set([_get_modified_name(key) for key in self.get_params_in_url(possible_url)])
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params: %s, expect params: ' % (list(params['facts']['params'].keys()))
            for i, possible_url in enumerate(url_list):
                if i:
                    error_message += ', or '
                error_message += '%s' % ([_get_modified_name(key) for key in self.get_params_in_url(possible_url)])
            self.module.fail_json(msg=error_message)
        param_names = self.get_params_in_url(url)
        for param_name in param_names:
            token_hint = '{%s}' % (param_name)
            token = ''
            modified_name = _get_modified_name(param_name)
            if modified_name in params['facts']['params']:
                token = params['facts']['params'][modified_name]
            else:
                token = params['facts']['params'][param_name]
            url = url.replace(token_hint, token)

        # Send data
        api_params = [{'url': url}]
        for key in ['filter', 'sortings', 'fields', 'option']:
            if params['facts'][key]:
                api_params[0][key] = params['facts'][key]
        if 'extra_params' in params['facts'] and params['facts']['extra_params']:
            for key in params['facts']['extra_params']:
                api_params[0][key] = params['facts']['extra_params'][key]
        response = self.conn.send_request('get', api_params)
        self.do_exit(response, changed=False)

    def check_versioning_mismatch(self, track, schema, params):
        if not params or not schema:
            return
        param_type = schema['type'] if 'type' in schema else None
        v_range = schema['v_range'] if 'v_range' in schema else None
        matched, checking_message = self._version_matched(v_range)
        if not matched:
            param_path = '-->'.join(track)
            self.version_check_warnings.append('param: %s %s' % (param_path, checking_message))
        if param_type == 'dict' and 'options' in schema:
            if type(params) is not dict:
                raise AssertionError()
            for sub_param_key in params:
                sub_param = params[sub_param_key]
                if sub_param_key in schema['options']:
                    sub_schema = schema['options'][sub_param_key]
                    track.append(sub_param_key)
                    self.check_versioning_mismatch(track, sub_schema, sub_param)
                    del track[-1]
        elif param_type == 'list' and 'options' in schema:
            if type(params) is not list:
                raise AssertionError()
            for grouped_param in params:
                if type(grouped_param) is not dict:
                    raise AssertionError()
                for sub_param_key in grouped_param:
                    sub_param = grouped_param[sub_param_key]
                    if sub_param_key in schema['options']:
                        sub_schema = schema['options'][sub_param_key]
                        track.append(sub_param_key)
                        self.check_versioning_mismatch(track, sub_schema, sub_param)
                        del track[-1]

    def _do_final_exit(self, rc, result, changed=True):
        # The failing conditions priority: failed_when > rc_failed > rc_succeeded.
        failed = rc != 0
        if 'response_code' in result:
            if self.module.params['rc_failed']:
                for rc_code in self.module.params['rc_failed']:
                    if str(result['response_code']) == str(rc_code):
                        failed = True
                        result['result_code_overriding'] = 'rc code:%s is overridden to failure' % (rc_code)
            elif self.module.params['rc_succeeded']:
                for rc_code in self.module.params['rc_succeeded']:
                    if str(result['response_code']) == str(rc_code):
                        failed = False
                        result['result_code_overriding'] = 'rc code:%s is overridden to success' % (rc_code)
        if self.system_status:
            result['system_information'] = self.system_status
        if len(self.version_check_warnings):
            version_check_warning = dict()
            version_check_warning['mismatches'] = self.version_check_warnings
            if not self.system_status:
                raise AssertionError()
            version_check_warning['system_version'] = 'v%s.%s.%s' % (self.system_status['Major'],
                                                                     self.system_status['Minor'],
                                                                     self.system_status['Patch'])
            warn_msg = 'Ansible has detected version mismatches between FortiAnalyzer and your playbook. '
            warn_msg += 'Version mismatches are described in version_check_warning.'
            self.module.warn(warn_msg)
            self.module.exit_json(rc=rc, meta=result, version_check_warning=version_check_warning, failed=failed, changed=changed)
        else:
            self.module.exit_json(rc=rc, meta=result, failed=failed, changed=changed)

    def do_exit(self, response, changed=True):
        rc, response_data = response
        result = dict()
        result['request_url'] = response_data['url'] if 'url' in response_data else ''
        result['response_data'] = response_data['data'] if 'data' in response_data else list()
        result['response_message'] = ''
        if 'status' in response_data:
            if 'code' in response_data['status']:
                result['response_code'] = response_data['status']['code']
            if 'message' in response_data['status']:
                result['response_message'] = response_data['status']['message']
        self._do_final_exit(rc, result, changed=changed)
