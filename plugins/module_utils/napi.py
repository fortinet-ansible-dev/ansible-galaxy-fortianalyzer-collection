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

CONSIDER_VERSIONS = set(['6.2.1', '6.2.2', '6.2.3', '6.2.5', '6.2.6', '6.2.7', '6.2.8', '6.2.9', '6.2.10', '6.2.11', '6.2.12',
                         '6.4.1', '6.4.2', '6.4.3', '6.4.4', '6.4.5', '6.4.6', '6.4.7', '6.4.8', '6.4.9', '6.4.10', '6.4.11', '6.4.12', '6.4.13',
                         '7.0.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8', '7.0.9',
                         '7.2.0', '7.2.1', '7.2.2', '7.2.3',
                         '7.4.0', '7.4.1'])


def remove_revision(schema):
    if not isinstance(schema, dict):
        return schema
    new_schema = {}
    for key in schema:
        if key != 'revision' and key != 'api_name':
            new_schema[key] = remove_revision(schema[key])
            # if '-' in key or ' ' in key or '.' in key:
            #     new_schema[key]['removed_in_version'] = '2.0.0'
            #     new_schema[key]['removed_from_collection'] = 'fortinet.fortianalyzer'
    return new_schema


def check_parameter_bypass(schema, module_level2_name):
    params = _load_params()
    if params and 'bypass_validation' in params and params['bypass_validation'] is True:
        top_level_schema = dict()
        for key in schema:
            if key != module_level2_name:
                top_level_schema[key] = schema[key]
            elif not params[module_level2_name] or type(params[module_level2_name]) is dict:
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['required'] = False
                top_level_schema[module_level2_name]['type'] = 'dict'
            elif type(params[module_level2_name]) is list:
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['required'] = False
                top_level_schema[module_level2_name]['type'] = 'list'
            else:
                raise Exception('Value of %s must be a dict or list' % (module_level2_name))
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

    def version_check(self, support_versions):
        # if system version is not determined, give up version checking
        if not support_versions or not self.system_status:
            return True, None

        # Error for old versions
        if int(self.system_status['Major']) <= 5:
            return False, 'not support in the major version lower than 6, please try a version at least 6.2.1'
        elif int(self.system_status['Major']) == 6:
            if self.system_status['Minor'] < 2:
                return False, 'not support in the version 6.{0}.x, please try a version at least 6.2.1'.format(self.system_status['Minor'])

        sys_version = '{0}.{1}.{2}'.format(self.system_status['Major'], self.system_status['Minor'], self.system_status['Patch'])

        if sys_version not in CONSIDER_VERSIONS or sys_version in support_versions:
            return True, None
        return False, 'not support in {0}. Support versions: {1}'.format(sys_version, list(support_versions))

    def _version_matched(self, revisions):
        if not revisions or not self.system_status:
            # if system version is not determined, give up version checking
            return True, None

        sys_version_value = int(self.system_status['Major']) * 10000 + int(self.system_status['Minor']) * 100 + int(self.system_status['Patch'])
        versions = list(revisions.keys())
        versions.sort(key=lambda x: int(x.split('.')[0]) * 10000 + int(x.split('.')[1]) * 100 + int(x.split('.')[2]))
        nearest_index = -1
        for i in range(len(versions)):
            version_value = int(versions[i].split('.')[0]) * 10000 + int(versions[i].split('.')[1]) * 100 + int(versions[i].split('.')[2])
            if version_value <= sys_version_value:
                nearest_index = i
        if nearest_index == -1:
            return False, 'not supported until in v%s' % (versions[0])
        if revisions[versions[nearest_index]] is True:
            return True, None
        latest_index = -1
        for i in range(nearest_index + 1, len(versions)):
            if revisions[versions[i]] is True:
                latest_index = i
                break
        earliest_index = nearest_index
        while earliest_index >= 0:
            if revisions[versions[earliest_index]] is True:
                break
            earliest_index -= 1
        earliest_index = 0 if earliest_index < 0 else earliest_index
        if latest_index == -1:
            return False, 'not supported since v%s' % (versions[earliest_index])
        else:
            return False, 'not supported since %s, before %s' % (versions[earliest_index], versions[latest_index])

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
        for param_name in self.url_params:
            token_hint = '{%s}' % (param_name)
            token = str(self.module.params[param_name])
            the_url = the_url.replace(token_hint, token)
        return the_url

    def _get_base_perobject_url(self, mvalue):
        url_getting = self._get_basic_url(True)
        if not url_getting.endswith('}'):
            # in case of non-regular per-object url.
            return url_getting
        last_token = url_getting.split('/')[-1]
        second_last_token = url_getting.split('/')[-2]
        if last_token.replace('-', '_') != '{' + second_last_token.replace('-', '_') + '}':
            raise AssertionError('wrong last_token received')
        return url_getting.replace('{' + second_last_token + '}', str(mvalue))

    def get_object(self, mvalue):
        url_getting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_getting}]
        response = self.conn.send_request('get', params)
        return response

    def update_object(self, mvalue):
        url_updating = self._get_base_perobject_url(mvalue)
        selector = self.module_level2_name
        raw_attributes = self.module.params[selector] if selector in self.module.params else {}
        params = [{'url': url_updating,
                   'data': self.get_tailor_attributes(raw_attributes)}]
        response = self.conn.send_request('update', params)
        return response

    def create_object(self):
        url_creating = self._get_basic_url(False)
        selector = self.module_level2_name
        raw_attributes = self.module.params[selector] if selector in self.module.params else {}
        params = [{'url': url_creating,
                   'data': self.get_tailor_attributes(raw_attributes)}]
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

    def _compare_subnet(self, object_remote, object_present):
        if type(object_remote) is not list and len(object_remote) != 2:
            return True
        tokens = object_present.split('/')
        if len(tokens) != 2:
            return True
        try:
            subnet_number = int(tokens[1])
            if subnet_number < 0 or subnet_number > 32:
                return True
            remote_subnet_number = sum(bin(int(x)).count('1') for x in object_remote[1].split('.'))
            if object_remote[0] != tokens[0] or remote_subnet_number != subnet_number:
                return True
            else:
                return False
        except Exception:
            return True
        return True

    def _check_object_difference(self, object_remote, object_present):
        for key in object_present:
            value = object_present[key]
            if not value:
                continue
            if key not in object_remote or not object_remote[key]:
                return True
            value_type = type(value)
            if value_type is list:
                return True
            elif value_type is dict:
                if type(object_remote[key]) is not dict:
                    return True
                elif self._check_object_difference(object_remote[key], value):
                    return True
            else:
                value_string = str(value)
                if type(object_remote[key]) is not list and str(object_remote[key]) != value_string:
                    return True
                elif type(object_remote[key]) is list:
                    if not self._compare_subnet(object_remote[key], value_string):
                        return False
                    elif len(object_remote[key]) > 1 or str(object_remote[key][0]) != value_string:
                        return True
        return False

    def _update_required(self, robject):
        object_status = robject[0]
        if object_status != 0:
            return False
        object_remote = robject[1]['data']
        selector = self.module_level2_name
        object_present = self.module.params[selector] if selector in self.module.params else {}
        return self._check_object_difference(object_remote, object_present)

    def _process_with_mkey(self, mvalue):
        mobject = self.get_object(mvalue)
        update_required = self._update_required(mobject)
        if self.module.params['state'] == 'present':
            if mobject[0] == 0:
                if update_required:
                    return self.update_object(mvalue)
                else:
                    self.module.exit_json(message='Object update skipped!')
            else:
                return self.create_object()
        elif self.module.params['state'] == 'absent':
            return self.delete_object(mvalue)
        raise AssertionError('Not Reachable')

    def _process_without_mkey(self):
        if self.module.params['state'] == 'absent':
            self.module.fail_json(msg='this module doesn\'t not support state:absent because of no primary key.')
        return self.create_object()

    def process_generic(self, method, param):
        response = self.conn.send_request(method, param)
        self.do_exit(response)

    def process_exec(self):
        argument_specs = self.metadata
        params = self.module.params
        selector = self.module_level2_name
        track = [selector]
        if 'bypass_validation' not in params or params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[selector] if selector in argument_specs else None,
                                           params[selector] if selector in params else None)
        url = self.jrpc_urls[0]  # exec method only have one url
        for param_name in self.url_params:
            token_hint = '{%s}' % (param_name)
            token = str(params[param_name])
            url = url.replace(token_hint, token)

        api_params = [{'url': url}]
        if selector in params:  # except sys_logout
            api_params[0]['data'] = self.get_tailor_attributes(params[selector])

        response = self.conn.send_request('exec', api_params)
        self.do_exit(response)

    def process_curd(self):
        argument_specs = self.metadata
        params = self.module.params
        selector = self.module_level2_name
        track = [selector]
        if 'bypass_validation' not in params or params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[selector] if selector in argument_specs else None,
                                           params[selector] if selector in params else None)
        has_mkey = self.module_primary_key is not None and isinstance(params[selector], dict)
        if has_mkey:
            mvalue = params[selector][self.module_primary_key]
            self.do_exit(self._process_with_mkey(mvalue))
        else:
            self.do_exit(self._process_without_mkey())

    def process_partial_curd(self):
        argument_specs = self.metadata
        params = self.module.params
        selector = self.module_level2_name
        url_list = self.jrpc_urls
        track = [selector]
        if 'bypass_validation' not in params or params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[selector] if selector in argument_specs else None,
                                           params[selector] if selector in params else None)

        # Get real url
        url = None
        given_params = set(self.url_params)
        for possible_url in url_list:
            required_params = set(self.get_params_in_url(possible_url))
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params in self:%s, expect params: ' % (list(given_params))
            error_message += ', or '.join(['%s' % (self.get_params_in_url(possible_url)) for possible_url in url_list])
            self.module.fail_json(msg=error_message)
        for param_name in given_params:
            token_hint = '{%s}' % (param_name)
            token = str(params[param_name])
            url = url.replace(token_hint, token)

        # Send data
        api_params = [{'url': url}]
        if selector in params:
            api_params[0]['data'] = self.get_tailor_attributes(params[selector])
        response = self.conn.send_request(self.get_propose_method('set'), api_params)
        self.do_exit(response)

    def process_rename(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['rename']['selector']
        url_list = metadata[selector]['urls']

        # Version check
        revisions = metadata[selector]['revision']
        matched, checking_message = self._version_matched(revisions)
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
            given_params = set(params['rename']['self'].keys())
        for possible_url in url_list:
            required_params = set(self.get_params_in_url(possible_url))
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params in self:%s, expect params: ' % (list(given_params))
            error_message += ', or '.join(['%s' % (self.get_params_in_url(possible_url)) for possible_url in url_list])
            self.module.fail_json(msg=error_message)
        for param_name in given_params:
            token_hint = '{%s}' % (param_name)
            token = str(params['rename']['self'][param_name])
            url = url.replace(token_hint, token)

        # Send data
        api_params = [{'url': url,
                       'data': params['rename']['target']}]
        response = self.conn.send_request('update', api_params)
        self.do_exit(response)

    def process_fact(self):
        metadata = self.metadata
        params = self.module.params
        selector = params['facts']['selector']
        url_list = metadata[selector]['urls']

        # Version check
        support_versions = metadata[selector]['support_versions']
        matched, checking_message = self.version_check(support_versions)
        if not matched:
            self.version_check_warnings.append('faz_fact selector:%s %s' % (selector, checking_message))

        # Get real url
        url = None
        given_params = set()
        if params['facts']['params']:
            given_params = set(params['facts']['params'].keys())
        for possible_url in url_list:
            required_params = set(self.get_params_in_url(possible_url))
            if given_params == required_params:
                url = possible_url
                break
        if not url:
            error_message = 'Given params: %s, expect params: ' % (list(given_params))
            error_message += ', or '.join(['%s' % (self.get_params_in_url(possible_url)) for possible_url in url_list])
            self.module.fail_json(msg=error_message)
        for param_name in given_params:
            token_hint = '{%s}' % (param_name)
            token = str(params['facts']['params'][param_name])
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

    def get_tailor_attributes(self, data):
        if isinstance(data, dict):
            return_data = dict()
            for param_name, value in data.items():
                if value is None:
                    continue
                return_data[param_name] = self.get_tailor_attributes(value)
            return return_data
        elif isinstance(data, list):
            return_data = list()
            for item in data:
                return_data.append(self.get_tailor_attributes(item))
            return return_data
        else:
            if data is None:
                raise AssertionError('data is expected to be not none')
            return data

    def check_versioning_mismatch(self, track, schema, params):
        if not params or not schema:
            return
        param_type = schema['type'] if 'type' in schema else None
        revisions = schema['revision'] if 'revision' in schema else None

        matched, checking_message = self._version_matched(revisions)
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
