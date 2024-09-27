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


def get_ansible_format_name(api_format_name, replace_param=False):
    ansible_format_name = api_format_name
    for special_char in ['-', ' ', '.', '(', '+']:
        ansible_format_name = ansible_format_name.replace(special_char, '_')
    if replace_param:
        replace_dict = {'message': 'faz_message'}
        for key in replace_dict:
            ansible_format_name = ansible_format_name.replace(key, replace_dict[key])
    return ansible_format_name


def get_ansible_format_params(params):
    # params can be user input or api format data
    if not isinstance(params, dict):
        return params
    ansible_params = {}
    for param_name in params:
        ansible_format_name = get_ansible_format_name(param_name, replace_param=True)
        ansible_params[ansible_format_name] = get_ansible_format_params(params[param_name])
    return ansible_params


def is_basic_data_format(data):
    if isinstance(data, str):
        return True
    if isinstance(data, int):
        return True
    if isinstance(data, float):
        return True
    if isinstance(data, bool):
        return True
    return False


def remove_aliases(user_params, metadata, bypass_valid=False):
    # User input data to API format data
    if not user_params:
        return user_params
    if isinstance(user_params, list):
        new_params = []
        for item in user_params:
            new_params.append(remove_aliases(item, metadata, bypass_valid))
        return new_params
    elif isinstance(user_params, dict):
        new_params = {}
        considered_keys = set()
        for api_format_name, param_data in metadata.items():
            ansible_format_name = get_ansible_format_name(api_format_name, replace_param=True)
            considered_keys.add(api_format_name)
            considered_keys.add(ansible_format_name)
            user_data = user_params.get(api_format_name, None)
            if user_data is None:
                user_data = user_params.get(ansible_format_name, None)
            if user_data is None:
                continue
            if 'options' in param_data:
                new_params[api_format_name] = remove_aliases(user_data, param_data['options'], bypass_valid)
            else:
                new_params[api_format_name] = user_data
        if bypass_valid:
            for api_format_name, param_data in user_params.items():
                if api_format_name not in considered_keys:
                    new_params[api_format_name] = param_data
        return new_params
    # otherwise, user_params is str, int, float... return directly.
    return user_params


def modify_argument_spec(schema, module_level2_name):
    def add_aliases(schema):
        if not isinstance(schema, dict):
            return schema
        new_schema = {}
        for param_name in schema:
            if param_name != 'v_range' and param_name != 'revision' and param_name != 'api_name':
                new_content = add_aliases(schema[param_name])
                aliase_name = get_ansible_format_name(param_name)
                if aliase_name != param_name:
                    new_content['removed_in_version'] = '2.0.0'
                    new_content['removed_from_collection'] = 'fortinet.fortianalyzer'
                    if aliase_name not in new_schema and 'api_name' not in schema[param_name]:
                        new_content['aliases'] = [aliase_name]
                if param_name == 'message':
                    param_name = 'faz_message'
                new_schema[param_name] = new_content
        return new_schema

    def get_bypass(params):
        bypass = params.get('bypass_validation', False)
        if isinstance(bypass, bool):
            return bypass
        elif isinstance(bypass, str):
            return bypass.lower() in ['true', 'y', 'yes', 't', '1', 'on']
        elif isinstance(bypass, int):
            return bypass != 0
        return True

    schema = add_aliases(schema)
    params = _load_params()  # This function doesn't return params' default value.
    if not params:
        return schema
    is_bypass = get_bypass(params)  # This params are raw data, need to decide bypass manually.
    if is_bypass:
        top_level_schema = dict()
        for key in schema:
            if key != module_level2_name:
                top_level_schema[key] = schema[key]
            elif not params.get(module_level2_name, None) or isinstance(params[module_level2_name], dict):
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['type'] = 'dict'
            elif isinstance(params[module_level2_name], list):
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['type'] = 'list'
        return top_level_schema
    return schema


class FortiAnalyzerAnsible(object):
    def __init__(self, urls_list, module_primary_key, url_params, module, conn,
                 metadata=None, task_type=None):
        self.urls_list = urls_list
        self.module_primary_key = module_primary_key
        self.url_params = url_params
        self.module = module
        self.conn = conn
        self.module_name = self.module._name
        self.module_level2_name = self.module_name.split('.')[-1][4:]
        self._set_connection_options()
        self.system_status = self.get_system_status()
        self.version_check_warnings = []
        self.task_type = task_type
        self.metadata = metadata
        self.diff_data = {'before': {}, 'after': {}}
        self.allow_diff = False

    def _set_connection_options(self):
        for key in ['access_token', 'enable_log', 'log_path', 'forticloud_access_token']:
            if key in self.module.params:
                self.conn.set_customer_option(key, self.module.params[key])

    def process(self):
        if self.task_type == 'exec':
            self.process_exec()
        elif self.task_type == 'partial crud':
            self.allow_diff = True
            self.process_partial_crud()
        elif self.task_type == 'full crud' or self.task_type == 'object member':
            self.allow_diff = True
            self.process_crud()
        elif self.task_type == 'fact':
            self.process_fact()
        elif self.task_type == 'rename':
            self.process_rename()
        elif self.task_type == 'report_add':
            self.process_request_without_data_wrapper('add')
        elif self.task_type == 'report_delete':
            self.process_request_without_data_wrapper('delete')
        else:
            raise AssertionError('Wrong task type')

    def process_generic(self, method, param, jsonrpc=''):
        jsonrpc2 = (jsonrpc == '2.0')
        response = self.conn.send_request(method, param, jsonrpc2=jsonrpc2)
        self.do_exit(response)

    def process_request_without_data_wrapper(self, request_method):
        argument_specs = self.metadata
        params = self.module.params
        module_name = self.module_level2_name
        track = [module_name]
        version_check = params.get('version_check', False)
        bypass_valid = params.get('bypass_validation', False)
        if version_check and not bypass_valid:
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        target_url = self.get_target_url()
        api_params = {'url': target_url}
        if module_name in params:
            params = remove_aliases(params, self.metadata, bypass_valid)
            for param_name in params[module_name]:
                api_params[param_name] = params[module_name][param_name]
        if self.module.check_mode:
            self.do_final_exit(changed=True)
        response = self.conn.send_request(request_method, [api_params])
        self.do_exit(response)

    def process_exec(self):
        argument_specs = self.metadata
        params = self.module.params
        module_name = self.module_level2_name
        track = [module_name]
        version_check = params.get('version_check', False)
        bypass_valid = params.get('bypass_validation', False)
        if version_check and not bypass_valid:
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        target_url = self.urls_list[0]  # exec method only have one url
        target_url = self.get_replaced_url(target_url)
        api_params = {'url': target_url}
        if module_name in params:  # except sys_logout
            params = remove_aliases(params, self.metadata, bypass_valid)
            api_params['data'] = params[module_name]
        if self.module.check_mode:
            self.do_final_exit(changed=True)
        response = self.conn.send_request('exec', [api_params])
        self.do_exit(response)

    def process_crud(self):
        argument_specs = self.metadata
        params = self.module.params
        module_name = self.module_level2_name
        track = [module_name]
        version_check = params.get('version_check', False)
        bypass_valid = params.get('bypass_validation', False)
        if version_check and not bypass_valid:
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        response = (-1, {})
        state = params['state']
        if self.module_primary_key and isinstance(params[module_name], dict):
            mvalue = params[module_name][self.module_primary_key]
            if state == 'present':
                rc, remote_data = self.read_object(mvalue)
                self.diff_save_data_from_response('before', remote_data)
                rc = self.decide_rc(remote_data, rc)
                if rc == 0:
                    if self.is_force_update() or self.is_update_required(remote_data):
                        response = self.update_object(mvalue)
                    else:
                        return_msg = 'Your FortiAnalyzer is already up to date and does not need to be updated. '
                        return_msg += 'To force update, please add argument proposed_method:update'
                        self.diff_save_data_from_response('after', remote_data)
                        self.do_final_exit(changed=False, message=return_msg)
                else:
                    response = self.create_object()
            elif state == 'absent':
                self.diff_get_and_save_data('before')
                response = self.delete_object(mvalue)
        else:
            if state == 'absent':
                self.module.fail_json(msg='This module doesn\'t not support state:absent because of no primary key.')
            self.diff_get_and_save_data('before')
            response = self.create_object()
        self.diff_get_and_save_data('after')
        self.do_exit(response)

    def process_partial_crud(self):
        argument_specs = self.metadata
        params = self.module.params
        module_name = self.module_level2_name
        track = [module_name]
        version_check = params.get('version_check', False)
        bypass_valid = params.get('bypass_validation', False)
        if version_check and not bypass_valid:
            self.check_versioning_mismatch(track, argument_specs.get(module_name, None), params.get(module_name, None))
        target_url = self.get_target_url()
        api_params = {'url': target_url}
        # Try to get and compare, and skip update if same.
        try:
            rc, remote_data = self.conn.send_request('get', [api_params])
            self.diff_save_data_from_response('before', remote_data)
            if rc == 0:
                if not (self.is_force_update() or self.is_update_required(remote_data)):
                    return_msg = 'Your FortiAnalyzer is already up to date and does not need to be updated. '
                    return_msg += 'To force update, please add argument proposed_method:update'
                    self.diff_save_data_from_response('after', remote_data)
                    self.do_final_exit(changed=False, message=return_msg)
        except Exception as e:
            pass
        if module_name in params:
            params = remove_aliases(params, self.metadata, bypass_valid)
            api_params['data'] = params[module_name]
        if self.module.check_mode:
            self.diff_save_after_based_on_playbook()
            self.do_final_exit(changed=True)
        response = self.conn.send_request(self.get_propose_method('set'), [api_params])
        self.diff_get_and_save_data('after')
        self.do_exit(response)

    def process_rename(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['rename']['selector']
        url_list = metadata[selector]['urls']

        # Version check
        vrange = metadata[selector].get('v_range', None)
        matched, checking_message = self.is_version_matched(vrange)
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
            given_params = set([get_ansible_format_name(key) for key in params['rename']['self'].keys()])
        for possible_url in url_list:
            required_params = set([get_ansible_format_name(key) for key in self.get_params_in_url(possible_url)])
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params in self:%s, expect params: ' % (list(params['rename']['self'].keys()))
            for i, possible_url in enumerate(url_list):
                if i:
                    error_message += ', or '
                error_message += '%s' % ([get_ansible_format_name(key) for key in self.get_params_in_url(possible_url)])
            self.module.fail_json(msg=error_message)
        param_names = self.get_params_in_url(url)
        for param_name in param_names:
            token_hint = '{%s}' % (param_name)
            token = ''
            modified_name = get_ansible_format_name(param_name)
            if modified_name in params['rename']['self']:
                token = params['rename']['self'][modified_name]
            else:
                token = params['rename']['self'][param_name]
            url = url.replace(token_hint, token)

        # Send data
        api_params = [{'url': url, 'data': params['rename']['target']}]
        if self.module.check_mode:
            self.do_final_exit(changed=True)
        response = self.conn.send_request('update', api_params)
        self.do_exit(response)

    def process_fact(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['facts']['selector']
        url_list = metadata[selector]['urls']
        user_params = params['facts']['params']
        is_jsonrpc_2 = metadata[selector]['jsonrpc2']
        if not user_params:
            user_params = {}

        # Version check
        vrange = metadata[selector].get('v_range', None)
        matched, checking_message = self.is_version_matched(vrange)
        if not matched:
            self.version_check_warnings.append('faz_fact selector:%s %s' % (selector, checking_message))

        # Get target URL with largest fit param num.
        target_url = ''
        max_fit_param_num = -1
        given_params = set()
        if user_params:
            given_params = set([get_ansible_format_name(key) for key in user_params.keys()])
        for possible_url in url_list:
            required_params = set([get_ansible_format_name(key) for key in self.get_params_in_url(possible_url)])
            require_flag = True
            for param_name in required_params:
                if param_name not in given_params:
                    require_flag = False
                    break
            if require_flag and len(required_params) > max_fit_param_num:
                max_fit_param_num = len(required_params)
                target_url = possible_url
        if not target_url:
            error_message = 'Expect required params: '
            for i, possible_url in enumerate(url_list):
                if i:
                    error_message += ', or '
                error_message += '%s' % ([get_ansible_format_name(key) for key in self.get_params_in_url(possible_url)])
            self.module.fail_json(msg=error_message)
        url_param_names = self.get_params_in_url(target_url)
        for param_name in url_param_names:
            token_hint = '{%s}' % (param_name)
            token = ''
            modified_name = get_ansible_format_name(param_name)
            if modified_name in user_params:
                token = user_params[modified_name]
            else:
                token = user_params.get(param_name, '')
            target_url = target_url.replace(token_hint, str(token))

        # Send data
        api_params = {'url': target_url}
        for key in ['filter', 'sortings', 'fields', 'option']:
            if params['facts'][key]:
                api_params[key] = params['facts'][key]

        # Add extra param data
        used_param_names = [get_ansible_format_name(key) for key in url_param_names]
        for param in user_params:
            if get_ansible_format_name(param) in used_param_names:
                continue
            api_params[param] = user_params[param]

        # Deprecated, keep for backward compatibility. Please add new param in params.
        if 'extra_params' in params['facts'] and params['facts']['extra_params']:
            for key in params['facts']['extra_params']:
                api_params[key] = params['facts']['extra_params'][key]
        response = self.conn.send_request('get', [api_params], jsonrpc2=is_jsonrpc_2)
        self.do_exit(response, changed=False)

    def is_version_matched(self, v_ranges):
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

    def is_force_update(self):
        return 'proposed_method' in self.module.params and self.module.params['proposed_method']

    def is_same_subnet(self, list_format_data, str_format_data):
        try:
            if not isinstance(list_format_data, list):
                return False
            if len(list_format_data) != 2:
                return False
            # ['1.2.3.4', '255.255.255.0'] and '1.2.3.4 255.255.255.0'
            if ' '.join(list_format_data) == str_format_data:
                return True
            # ['1.2.3.4', '255.255.255.0'] and '1.2.3.4/24'
            tokens = str_format_data.split('/')
            if len(tokens) != 2:
                return False
            subnet_number = int(tokens[1])
            if subnet_number < 0 or subnet_number > 32:
                return False
            remote_subnet_number = sum(bin(int(x)).count('1') for x in list_format_data[1].split('.'))
            if list_format_data[0] == tokens[0] and remote_subnet_number == subnet_number:
                return True
        except Exception as e:
            pass
        return False

    def is_object_difference(self, remote_obj, local_obj):
        for param_name in local_obj:
            local_value = local_obj[param_name]
            if local_value is None:
                continue
            remote_value = remote_obj.get(param_name, None)
            if remote_value is None:
                return True
            if self.ignore_special_param(param_name, remote_value, local_value):
                continue
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

    def ignore_special_param(self, param_name, remote_data, user_data):
        if param_name in ['ca', 'certificate', 'cert']:
            if isinstance(remote_data, list) and len(remote_data):
                remote_data = remote_data[0]
            if remote_data == '"' + user_data + '"':
                return True
        if param_name in ['TTL']:
            remote_data = str(remote_data)
            user_data = str(user_data)
            if remote_data.split(' ', maxsplit=1)[0] == user_data:
                return True
        return False

    def is_update_required(self, robject):
        object_remote = robject['data'] if 'data' in robject else {}
        bypass_valid = self.module.params.get('bypass_validation', False)
        object_present = remove_aliases(self.module.params, self.metadata, bypass_valid)
        object_present = object_present.get(self.module_level2_name, {})
        return self.is_object_difference(object_remote, object_present)

    def get_system_status(self):
        status_code, response = self.conn.get_system_status()
        if status_code == 0 and 'data' in response:
            return response['data']
        return {}

    def get_propose_method(self, default_method):
        if self.is_force_update():
            return self.module.params['proposed_method']
        return default_method

    def get_params_in_url(self, s):
        '''Find contents in {}'''
        pattern = r'\{(.*?)\}'
        result = re.findall(pattern, s)
        return result

    def get_target_url(self):
        adom_value = self.module.params.get('adom', None)
        target_url_template = self.get_target_url_template(adom_value, self.urls_list)
        target_url = self.get_replaced_url(target_url_template)
        return target_url

    def get_target_url_template(self, adom_value, url_list):
        target_url = None
        if adom_value is not None:
            if adom_value == 'global':
                for url in url_list:
                    if '/global/' in url and '/adom/{adom}' not in url:
                        target_url = url
                        break
            elif adom_value:
                for url in url_list:
                    if '/adom/{adom}' in url:
                        target_url = url
                        break
            else:
                # adom = '', choose default URL which is for all domains
                for url in url_list:
                    if '/global/' not in url and '/adom/{adom}' not in url:
                        target_url = url
                        break
        else:
            target_url = url_list[0]
        if not target_url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (url_list))
        return target_url

    def get_replaced_url(self, url_template):
        target_url = url_template
        for param in self.url_params:
            token_hint = '{%s}' % (param)
            token = ''
            modified_name = get_ansible_format_name(param)
            modified_token = self.module.params.get(modified_name, None)
            previous_token = self.module.params.get(param, None)
            if modified_token is not None:
                token = modified_token
            elif previous_token is not None:
                token = previous_token
            else:
                self.module.fail_json(msg='Missing input param: %s' % (modified_name))
            target_url = target_url.replace(token_hint, str(token))
        return target_url

    def read_object(self, mvalue):
        target_url = self.get_target_url()
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += str(mvalue)
        params = [{'url': target_url}]
        response = self.conn.send_request('get', params)
        return response

    def update_object(self, mvalue):
        target_url = self.get_target_url()
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += str(mvalue)
        bypass_valid = self.module.params.get('bypass_validation', False)
        raw_attributes = remove_aliases(self.module.params, self.metadata, bypass_valid)
        raw_attributes = raw_attributes.get(self.module_level2_name, {})
        params = [{'url': target_url, 'data': raw_attributes}]
        if self.module.check_mode:
            self.diff_save_after_based_on_playbook()
            self.do_final_exit(changed=True)
        response = self.conn.send_request(self.get_propose_method('update'), params)
        return response

    def create_object(self):
        target_url = self.get_target_url()
        bypass_valid = self.module.params.get('bypass_validation', False)
        raw_attributes = remove_aliases(self.module.params, self.metadata, bypass_valid)
        raw_attributes = raw_attributes.get(self.module_level2_name, {})
        params = [{'url': target_url, 'data': raw_attributes}]
        if self.module.check_mode:
            self.diff_save_after_based_on_playbook()
            self.do_final_exit(changed=True)
        return self.conn.send_request(self.get_propose_method('set'), params)

    def delete_object(self, mvalue):
        target_url = self.get_target_url()
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += str(mvalue)
        params = [{'url': target_url}]
        if self.module.check_mode:
            self.do_final_exit(changed=True)
        return self.conn.send_request('delete', params)

    def decide_rc(self, data, default_rc):
        if data.get('jsonrpc', '') != '2.0':
            return default_rc
        # jsonrpc 2.0 has different return code
        try:
            if 'result' in data:
                result_data = data['result']
                if isinstance(result_data, list):
                    if len(result_data) == 1:
                        result_data = result_data[0]
                    else:
                        return default_rc
                if 'status' in result_data:
                    if 'code' in result_data['status']:
                        return result_data['status']['code']
            if 'error' in data:
                error_data = data['error']
                if isinstance(error_data, list):
                    if len(error_data) == 1:
                        error_data = error_data[0]
                    else:
                        return default_rc
                if 'code' in error_data:
                    return error_data['code']
        except Exception as e:
            pass
        return default_rc

    def check_versioning_mismatch(self, track, schema, params):
        if not params or not schema:
            return
        param_type = schema['type'] if 'type' in schema else None
        v_range = schema['v_range'] if 'v_range' in schema else None
        matched, checking_message = self.is_version_matched(v_range)
        if not matched:
            param_path = '-->'.join(track)
            self.version_check_warnings.append('param: %s %s' % (param_path, checking_message))
        if param_type == 'dict' and 'options' in schema:
            if not isinstance(params, dict):
                raise AssertionError()
            for sub_param_key in params:
                sub_param = params[sub_param_key]
                if sub_param_key in schema['options']:
                    sub_schema = schema['options'][sub_param_key]
                    track.append(sub_param_key)
                    self.check_versioning_mismatch(track, sub_schema, sub_param)
                    del track[-1]
        elif param_type == 'list' and 'options' in schema:
            if not isinstance(params, list):
                raise AssertionError()
            for grouped_param in params:
                if not isinstance(grouped_param, dict):
                    raise AssertionError()
                for sub_param_key in grouped_param:
                    sub_param = grouped_param[sub_param_key]
                    if sub_param_key in schema['options']:
                        sub_schema = schema['options'][sub_param_key]
                        track.append(sub_param_key)
                        self.check_versioning_mismatch(track, sub_schema, sub_param)
                        del track[-1]

    def diff_save_data_from_response(self, state, response):
        if self.allow_diff and self.module._diff:
            api_format_data = response['data'] if 'data' in response else {}
            if not api_format_data:  # [], "", ...
                api_format_data = {}
            ansible_format_data = get_ansible_format_params(api_format_data)
            self.diff_data[state] = ansible_format_data

    def diff_get_and_save_data(self, state):
        if self.allow_diff and self.module._diff:
            target_url = self.get_target_url()
            params = self.module.params
            module_name = self.module_level2_name
            if self.module_primary_key and isinstance(params[module_name], dict):
                mvalue = params[module_name][self.module_primary_key]
                if not target_url.endswith('/'):
                    target_url += '/'
                target_url += str(mvalue)
            api_params = {'url': target_url}
            rc, response = self.conn.send_request('get', [api_params])
            self.diff_save_data_from_response(state, response)

    def diff_save_after_based_on_playbook(self):
        def get_diff_after(before_data, user_data, metadata=None):
            if before_data is None:
                return user_data
            if user_data is None:
                return before_data
            if not isinstance(metadata, dict):
                metadata = {}
            if is_basic_data_format(before_data):  # int, float, str, bool
                if isinstance(user_data, list):
                    if len(user_data) == 1 and user_data[0] == before_data:
                        return before_data
                return user_data
            if isinstance(before_data, dict):
                if isinstance(user_data, dict):
                    after_data = {}
                    for param_name in before_data:
                        possible_meta_name = param_name.replace('_', '-')
                        # Mask sensitive data
                        is_sensitive_data = False
                        for var_name in [param_name, possible_meta_name]:
                            if var_name in metadata and isinstance(metadata[var_name], dict) and metadata[var_name].get('no_log', False):
                                before_data[param_name] = "<SENSITIVE_DATA>"
                                after_data[param_name] = "<SENSITIVE_DATA>"
                                is_sensitive_data = True
                        if is_sensitive_data:
                            continue
                        # Handle special params here
                        if self.ignore_special_param(param_name, before_data[param_name], user_data.get(param_name, None)):
                            after_data[param_name] = before_data[param_name]
                        else:
                            metadata_next = {}
                            if param_name in metadata:
                                metadata_next = metadata[param_name]
                            elif possible_meta_name in metadata:
                                metadata_next = metadata[possible_meta_name]
                            if isinstance(metadata_next, dict) and 'options' in metadata_next:
                                metadata_next = metadata_next['options']
                            after_data[param_name] = get_diff_after(before_data[param_name], user_data.get(param_name, None), metadata_next)
                    for param_name in user_data:
                        if param_name not in after_data:
                            after_data[param_name] = user_data[param_name]
                    return after_data
                return user_data
            elif isinstance(before_data, list):
                if is_basic_data_format(user_data):
                    # ignore ['1.2.3.4', '255.255.255.0'] and '1.2.3.4/24'
                    if self.is_same_subnet(before_data, str(user_data)):
                        return before_data
                    # ignore ['var'] and 'var'
                    if len(before_data) == 1 and str(before_data[0]) == str(user_data):
                        return before_data
                elif isinstance(user_data, list):
                    # ignore ['1', '2'] and ['2', '1']
                    try:
                        if str(sorted(before_data)) == str(sorted(user_data)):
                            return before_data
                    except Exception as e:
                        return user_data
                return user_data
            return before_data

        if not (self.allow_diff and self.module._diff):
            return
        before_data = self.diff_data['before']
        bypass_valid = self.module.params.get('bypass_validation', False)
        api_format_params = remove_aliases(self.module.params, self.metadata, bypass_valid)
        api_format_params = api_format_params.get(self.module_level2_name, {})
        ansible_format_params = get_ansible_format_params(api_format_params)
        metadata = self.metadata.get(self.module_level2_name, {}).get('options', {})
        self.diff_data['after'] = get_diff_after(before_data, ansible_format_params, metadata)

    def do_exit(self, response, changed=True):
        rc, response_data = response
        rc = self.decide_rc(response_data, rc)
        result = dict()
        result['request_url'] = response_data['url'] if 'url' in response_data else ''
        result['response_data'] = response_data['data'] if 'data' in response_data else list()
        result['response_message'] = ''
        if 'status' in response_data:
            if 'code' in response_data['status']:
                result['response_code'] = response_data['status']['code']
            if 'message' in response_data['status']:
                result['response_message'] = response_data['status']['message']
        # Additional information for REPORT API
        if response_data.get('jsonrpc') == '2.0':
            if 'result' in response_data:
                result['response_data'] = response_data['result']
            if 'error' in response_data:
                result['response_error'] = response_data['error']
        self.do_final_exit(rc=rc, result=result, changed=changed)

    def do_final_exit(self, rc=0, result=None, changed=True, message=''):
        # The failing conditions priority: failed_when > rc_failed > rc_succeeded.
        failed = rc != 0
        if changed:
            changed = rc == 0
        if result is None:
            result = {}
        return_response = {'rc': rc, 'failed': failed, 'changed': changed}
        if 'response_code' in result:
            if self.module.params.get('rc_failed', []):
                for rc_code in self.module.params['rc_failed']:
                    if str(result['response_code']) == str(rc_code):
                        failed = True
                        result['result_code_overriding'] = 'rc code:%s is overridden to failure' % (rc_code)
            elif self.module.params.get('rc_succeeded', []):
                for rc_code in self.module.params['rc_succeeded']:
                    if str(result['response_code']) == str(rc_code):
                        failed = False
                        result['result_code_overriding'] = 'rc code:%s is overridden to success' % (rc_code)
        if self.system_status:
            result['system_information'] = self.system_status
        return_response['meta'] = result
        if message:
            return_response['message'] = message
        if self.module.check_mode:
            return_response['message'] = 'Using check mode.'
            if message:
                return_response['message'] += ' ' + message
        if len(self.version_check_warnings) and self.module.params.get('version_check', True):
            version_check_warning = {}
            version_check_warning['mismatches'] = self.version_check_warnings
            if self.system_status:
                version_check_warning['system_version'] = 'v%s.%s.%s' % (self.system_status['Major'],
                                                                         self.system_status['Minor'],
                                                                         self.system_status['Patch'])
            warn_msg = 'Ansible has detected version mismatches between FortiAnalyzer and your playbook. '
            warn_msg += 'Version mismatches are described in version_check_warning.'
            self.module.warn(warn_msg)
            return_response['version_check_warning'] = version_check_warning
        if self.allow_diff and self.module._diff:
            return_response['diff'] = self.diff_data
        self.module.exit_json(**return_response)
