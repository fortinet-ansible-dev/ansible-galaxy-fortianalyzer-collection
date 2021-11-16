# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2020-2021 Fortinet, Inc
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
import sys


def check_parameter_bypass(schema, module_level2_name):
    params = _load_params()
    if 'bypass_validation' in params and params['bypass_validation'] is True:
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
    top_level_schema_name = None

    def __init__(self, jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, conn, top_level_schema_name=None):
        self.jrpc_urls = jrpc_urls
        self.perobject_jrpc_urls = perobject_jrpc_urls
        self.module_primary_key = module_primary_key
        self.url_params = url_params
        self.module = module
        self.conn = conn
        self.module_name = self.module._name
        self.module_level2_name = self.module_name.split('.')[-1][4:]
        self.top_level_schema_name = top_level_schema_name
        self.system_status = self.get_system_status()
        self.version_check_warnings = list()

    def _propose_method(self, default_method):
        if 'proposed_method' in self.module.params and self.module.params['proposed_method']:
            return self.module.params['proposed_method']
        return default_method

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
            url_libs = [i for i in self.perobject_jrpc_urls]
        else:
            url_libs = [i for i in self.jrpc_urls]
        for uparam in self.url_params:
            if not self.module.params[uparam]:
                raise AssertionError('param %s MUST NOT be empty' % (uparam))
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
        _param_applied = list()
        for uparam in self.url_params:
            token_hint = '/%s/{%s}/' % (uparam, uparam)
            token = '/%s/%s/' % (uparam, self.module.params[uparam])
            if token_hint in the_url:
                _param_applied.append(uparam)
            the_url = the_url.replace(token_hint, token)
        for uparam in self.url_params:
            if uparam in _param_applied:
                continue
            token_hint = '{%s}' % (uparam)
            token = self.module.params[uparam]
            the_url = the_url.replace(token_hint, token)
        return the_url

    def _get_base_perobject_url(self, mvalue):
        url_getting = self._get_basic_url(True)
        if not url_getting.endswith('}'):
            # in case of non-regular per-object url.
            return url_getting
        last_token = url_getting.split('/')[-1]
        second_last_token = url_getting.split('/')[-2]
        if last_token != '{' + second_last_token + '}':
            raise AssertionError('wrong last_token received')
        return url_getting.replace('{' + second_last_token + '}', str(mvalue))

    def get_object(self, mvalue):
        url_getting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_getting}]
        response = self.conn.send_request('get', params)
        return response

    def update_object(self, mvalue):
        url_updating = self._get_base_perobject_url(mvalue)
        if not self.top_level_schema_name:
            raise AssertionError('top level schema name MUST NOT be NULL')
        params = [{'url': url_updating, self.top_level_schema_name: self.__tailor_attributes(self.module.params[self.module_level2_name])}]
        response = self.conn.send_request('update', params)
        return response

    def create_objejct(self):
        url_creating = self._get_basic_url(False)
        if not self.top_level_schema_name:
            raise AssertionError('top level schema name MUST NOT be NULL')
        params = [{'url': url_creating, self.top_level_schema_name: self.__tailor_attributes(self.module.params[self.module_level2_name])}]
        return self.conn.send_request(self._propose_method('set'), params)

    def delete_object(self, mvalue):
        url_deleting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_deleting}]
        return self.conn.send_request('delete', params)

    def get_system_status(self):
        params = [{'url': '/cli/global/system/status'}]
        response = self.conn.send_request('get', params)
        if response[0] == 0:
            if 'data' not in response[1]:
                raise AssertionError()
            return response[1]['data']
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
        except Exception as e:
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
        object_present = self.module.params[self.module_level2_name]
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
                return self.create_objejct()
        elif self.module.params['state'] == 'absent':
            # in case the `GET` method returns nothing... see module `fmgr_antivirus_mmschecksum`
            # if mobject[0] == 0:
            return self.delete_object(mvalue)
            # else:
            #    self.do_nonexist_exit()
        else:
            raise AssertionError('Not Reachable')

    def _process_without_mkey(self):
        if self.module.params['state'] == 'absent':
            self.module.fail_json(msg='this module doesn\'t not support state:absent because of no primary key.')
        return self.create_objejct()

    def process_generic(self, method, param):
        response = self.conn.send_request(method, param)
        self.do_exit(response)

    def process_exec(self, argument_specs=None):
        track = [self.module_level2_name]
        if 'bypass_validation' not in self.module.params or self.module.params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[self.module_level2_name] if self.module_level2_name in argument_specs else None,
                                           self.module.params[self.module_level2_name] if self.module_level2_name in self.module.params else None)
        the_url = self.jrpc_urls[0]
        if 'adom' in self.url_params and not self.jrpc_urls[0].endswith('{adom}'):
            if self.module.params['adom'] == 'global':
                for _url in self.jrpc_urls:
                    if '/global/' in _url:
                        the_url = _url
                        break
            else:
                for _url in self.jrpc_urls:
                    if '/adom/{adom}/' in _url:
                        the_url = _url
                        break
        for _param in self.url_params:
            token_hint = '{%s}' % (_param)
            token = '%s' % (self.module.params[_param])
            the_url = the_url.replace(token_hint, token)

        api_params = [{'url': the_url}]
        if self.module_level2_name in self.module.params:
            if not self.top_level_schema_name:
                raise AssertionError('top level schema name MUST NOT be NULL')
            api_params[0][self.top_level_schema_name] = self.__tailor_attributes(self.module.params[self.module_level2_name])

        response = self.conn.send_request('exec', api_params)
        self.do_exit(response)

    def __extract_renamed_urls(self, urls):
        _param_set = list()
        for url in urls:
            tokens = url.split('/')
            if len(tokens) < 2:
                continue
            token_2 = tokens[-2]
            token_1 = tokens[-1]
            if '{%s}' % (token_2) == token_1 and token_2 not in _param_set:
                _param_set.append(token_2)
        return _param_set

    def process_rename(self, metadata):
        params = self.module.params
        if params['rename']['selector'] not in metadata:
            raise AssertionError('unknown selector: %s' % (params['rename']['selector']))
        selector = params['rename']['selector']
        rename_urls = metadata[selector]['urls']
        rename_mkey = metadata[selector]['mkey']
        rename_params = metadata[selector]['params']
        for _url_param in self.__extract_renamed_urls(rename_urls):
            if _url_param not in rename_params:
                rename_params.append(_url_param)
        rename_revisions = metadata[selector]['revision']
        matched, checking_message = self._version_matched(rename_revisions)
        if not matched:
            self.version_check_warnings.append('selector:%s %s' % (selector, checking_message))
        real_params_keys = set()
        if self.module.params['rename']['self']:
            real_params_keys = set(self.module.params['rename']['self'].keys())
        if real_params_keys != set(rename_params):
            self.module.fail_json(msg='expect params in self:%s, given params:%s' % (list(rename_params), list(real_params_keys)))
        url = None
        if 'adom' in rename_params and not rename_urls[0].endswith('{adom}'):
            if params['rename']['self']['adom'] == 'global':
                for _url in rename_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            else:
                for _url in rename_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        break
        else:
            url = rename_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (rename_urls))
        _param_applied = list()
        for _param in rename_params:
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, params['rename']['self'][_param])
            if token_hint in url:
                _param_applied.append(_param)
            url = url.replace(token_hint, token)
        for _param in rename_params:
            if _param in _param_applied:
                continue
            token_hint = '{%s}' % (_param)
            token = params['rename']['self'][_param]
            url = url.replace(token_hint, token)
        if rename_mkey and rename_mkey not in params['rename']['target']:
            self.module.fail_json(msg='Must give the primary key/value in target: %s!' % (mkey))
        api_params = [{'url': url,
                       'data': params['rename']['target']}]
        response = self.conn.send_request('update', api_params)
        self.do_exit(response)

    def process_clone(self, metadata):
        if self.module.params['clone']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['clone']['selector']
        clone_params_schema = metadata[selector]['params']
        clone_urls = metadata[selector]['urls']
        clone_revisions = metadata[selector]['revision']
        matched, checking_message = self._version_matched(clone_revisions)
        if not matched:
            self.version_check_warnings.append('selector:%s %s' % (selector, checking_message))
        real_params_keys = set()
        if self.module.params['clone']['self']:
            real_params_keys = set(self.module.params['clone']['self'].keys())
        if real_params_keys != set(clone_params_schema):
            self.module.fail_json(msg='expect params in self:%s, given params:%s' % (list(clone_params_schema), list(real_params_keys)))
        url = None
        if 'adom' in clone_params_schema and not clone_urls[0].endswith('{adom}'):
            if self.module.params['clone']['self']['adom'] == 'global':
                for _url in clone_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            else:
                for _url in clone_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        break
        else:
            url = clone_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (clone_urls))
        _param_applied = list()
        for _param in clone_params_schema:
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, self.module.params['clone']['self'][_param])
            if token_hint in url:
                _param_applied.append(_param)
            url = url.replace(token_hint, token)
        for _param in clone_params_schema:
            if _param in _param_applied:
                continue
            token_hint = '{%s}' % (_param)
            token = self.module.params['clone']['self'][_param]
            url = url.replace(token_hint, token)

        mkey = metadata[selector]['mkey']
        if mkey and mkey not in self.module.params['clone']['target']:
            self.module.fail_json(msg='Must give the primary key/value in target: %s!' % (mkey))
        api_params = [{'url': url,
                       'data': self.module.params['clone']['target']}]
        response = self.conn.send_request('clone', api_params)
        self.do_exit(response)

    def process_move(self, metadata):
        if self.module.params['move']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['move']['selector']
        move_params = metadata[selector]['params']
        move_urls = metadata[selector]['urls']
        move_revisions = metadata[selector]['revision']
        matched, checking_message = self._version_matched(move_revisions)
        if not matched:
            self.version_check_warnings.append('selector:%s %s' % (selector, checking_message))
        if not len(move_urls):
            raise AssertionError('unexpected move urls set')
        real_params_keys = set()
        if self.module.params['move']['self']:
            real_params_keys = set(self.module.params['move']['self'].keys())
        if real_params_keys != set(move_params):
            self.module.fail_json(msg='expect params in self:%s, given params:%s' % (list(move_params), list(real_params_keys)))

        url = None
        if 'adom' in move_params and not move_urls[0].endswith('{adom}'):
            if self.module.params['move']['self']['adom'] == 'global':
                for _url in move_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            else:
                for _url in move_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        break
        else:
            url = move_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (move_urls))
        _param_applied = list()
        for _param in move_params:
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, self.module.params['move']['self'][_param])
            if token_hint in url:
                _param_applied.append(_param)
            url = url.replace(token_hint, token)
        for _param in move_params:
            if _param in _param_applied:
                continue
            token_hint = '{%s}' % (_param)
            token = self.module.params['move']['self'][_param]
            url = url.replace(token_hint, token)

        api_params = [{'url': url,
                       'option': self.module.params['move']['action'],
                       'target': self.module.params['move']['target']}]
        response = self.conn.send_request('move', api_params)
        self.do_exit(response)

    def process_fact(self, metadata):
        if self.module.params['facts']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['facts']['selector']
        fact_params = metadata[selector]['params']
        fact_urls = metadata[selector]['urls']
        fact_revisions = metadata[selector]['revision']
        matched, checking_message = self._version_matched(fact_revisions)
        if not matched:
            self.version_check_warnings.append('selector:%s %s' % (selector, checking_message))
        if not len(fact_urls):
            raise AssertionError('unexpected fact urls set')
        real_params_keys = set()
        if self.module.params['facts']['params']:
            real_params_keys = set(self.module.params['facts']['params'].keys())
        if real_params_keys != set(fact_params):
            self.module.fail_json(msg='expect params:%s, given params:%s' % (list(fact_params), list(real_params_keys)))
        url = None
        if 'adom' in fact_params and not fact_urls[0].endswith('{adom}'):
            if self.module.params['facts']['params']['adom'] == 'global':
                for _url in fact_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            elif self.module.params['facts']['params']['adom'] != '' and self.module.params['facts']['params']['adom'] is not None:
                for _url in fact_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        # url = _url.replace('/adom/{adom}/', '/adom/%s/' % (self.module.params['facts']['params']['adom']))
                        break
            else:
                # choose default URL which is for all domains
                for _url in fact_urls:
                    if '/global/' not in _url and '/adom/{adom}/' not in _url:
                        url = _url
                        break
        else:
            url = fact_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (fact_urls))
        _param_applied = list()
        for _param in fact_params:
            _the_param = self.module.params['facts']['params'][_param]
            if self.module.params['facts']['params'][_param] is None:
                _the_param = ''
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, _the_param)
            if token_hint in url:
                _param_applied.append(_param)
            url = url.replace(token_hint, token)
        for _param in fact_params:
            if _param in _param_applied:
                continue
            token_hint = '{%s}' % (_param)
            token = self.module.params['facts']['params'][_param] if self.module.params['facts']['params'][_param] else ''
            url = url.replace(token_hint, token)
        # Other Filters and Sorters
        filters = self.module.params['facts']['filter']
        sortings = self.module.params['facts']['sortings']
        fields = self.module.params['facts']['fields']
        options = self.module.params['facts']['option']

        api_params = [{'url': url}]
        if filters:
            api_params[0]['filter'] = filters
        if sortings:
            api_params[0]['sortings'] = sortings
        if fields:
            api_params[0]['fields'] = fields
        if options:
            api_params[0]['option'] = options

        # Now issue the request.
        response = self.conn.send_request('get', api_params)
        self.do_exit(response)

    def process_curd(self, argument_specs=None):
        if 'state' not in self.module.params:
            raise AssertionError('parameter state is expected')
        track = [self.module_level2_name]
        if 'bypass_validation' not in self.module.params or self.module.params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[self.module_level2_name] if self.module_level2_name in argument_specs else None,
                                           self.module.params[self.module_level2_name] if self.module_level2_name in self.module.params else None)
        has_mkey = self.module_primary_key is not None and type(self.module.params[self.module_level2_name]) is dict
        if has_mkey:
            mvalue = ''
            if self.module_primary_key.startswith('complex:'):
                mvalue_exec_string = self.module_primary_key[len('complex:'):]
                mvalue_exec_string = mvalue_exec_string.replace('{{module}}', 'self.module.params[self.module_level2_name]')
                # mvalue_exec_string = 'mvalue = %s' % (mvalue_exec_string)
                # exec(mvalue_exec_string)
                # On Windows Platform, exec() call doesn't take effect.
                mvalue = eval(mvalue_exec_string)
            else:
                mvalue = self.module.params[self.module_level2_name][self.module_primary_key]
            self.do_exit(self._process_with_mkey(mvalue))
        else:
            self.do_exit(self._process_without_mkey())

    def __tailor_attributes(self, data):
        if type(data) == dict:
            rdata = dict()
            for key in data:
                value = data[key]
                if value is None:
                    continue
                rdata[key] = self.__tailor_attributes(value)
            return rdata
        elif type(data) == list:
            rdata = list()
            for item in data:
                if item is None:
                    continue
                rdata.append(self.__tailor_attributes(item))
            return rdata
        else:
            if data is None:
                raise AssertionError('data is expected to be not none')
            return data

    def process_partial_curd(self, argument_specs=None):
        track = [self.module_level2_name]
        if 'bypass_validation' not in self.module.params or self.module.params['bypass_validation'] is False:
            self.check_versioning_mismatch(track,
                                           argument_specs[self.module_level2_name] if self.module_level2_name in argument_specs else None,
                                           self.module.params[self.module_level2_name] if self.module_level2_name in self.module.params else None)
        the_url = self.jrpc_urls[0]
        if 'adom' in self.url_params and not self.jrpc_urls[0].endswith('{adom}'):
            if self.module.params['adom'] == 'global':
                for _url in self.jrpc_urls:
                    if '/global/' in _url:
                        the_url = _url
                        break
            else:
                for _url in self.jrpc_urls:
                    if '/adom/{adom}/' in _url:
                        the_url = _url
                        break
        for _param in self.url_params:
            token_hint = '{%s}' % (_param)
            token = '%s' % (self.module.params[_param])
            the_url = the_url.replace(token_hint, token)
        the_url = the_url.rstrip('/')
        api_params = [{'url': the_url}]
        if self.module_level2_name in self.module.params:
            if not self.top_level_schema_name:
                raise AssertionError('top level schem name is not supposed to be empty')
            api_params[0][self.top_level_schema_name] = self.__tailor_attributes(self.module.params[self.module_level2_name])
        response = self.conn.send_request(self._propose_method('set'), api_params)
        self.do_exit(response)

    def check_versioning_mismatch(self, track, schema, params):
        if not params or not schema:
            return
        param_type = schema['type'] if 'type' in schema else None
        revisions = schema['revision'] if 'revision' in schema else None

        matched, checking_message = self._version_matched(revisions)
        if not matched:
            param_path = track[0]
            for _param in track[1:]:
                param_path += '-->%s' % (_param)
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

    def validate_parameters(self, pvb):
        for blob in pvb:
            attribute_path = blob['attribute_path']
            pointer = self.module.params
            ignored = False
            for attr in attribute_path:
                if attr not in pointer:
                    # If the parameter is not given, ignore that.
                    ignored = True
                    break
                pointer = pointer[attr]
            if ignored:
                continue
            lambda_expr = blob['lambda']
            lambda_expr = lambda_expr.replace('$', str(pointer))
            eval_result = eval(lambda_expr)
            if not eval_result:
                if 'fail_action' not in blob or blob['fail_action'] == 'warn':
                    self.module.warn(blob['hint_message'])
                else:
                    # assert blob['fail_action'] == 'quit':
                    self.module.fail_json(msg=blob['hint_message'])

    def _do_final_exit(self, rc, result):
        # XXX: as with https://github.com/fortinet/ansible-fortimanager-generic.
        # the failing conditions priority: failed_when > rc_failed > rc_succeeded.
        failed = rc != 0
        changed = rc == 0

        if 'response_code' not in result:
            raise AssertionError('response_code should be in result')
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
            self.module.warn('Ansible has detected version mismatch between FortiManager and your playbook, see more details by appending option -vvv')
            self.module.exit_json(rc=rc, meta=result, version_check_warning=version_check_warning, failed=failed, changed=changed)
        else:
            self.module.exit_json(rc=rc, meta=result, failed=failed, changed=changed)

    def do_nonexist_exit(self):
        rc = 0
        result = dict()
        result['response_code'] = -3
        result['response_message'] = 'object not exist'
        self._do_final_exit(rc, result)

    def do_exit(self, response):
        rc = response[0]
        result = dict()
        result['response_data'] = list()
        if 'data' in response[1]:
            result['response_data'] = response[1]['data']
        result['response_code'] = response[1]['status']['code']
        result['response_message'] = response[1]['status']['message']
        if 'url' in response[1]:
            result['request_url'] = response[1]['url']
        # XXX:Do further status mapping
        self._do_final_exit(rc, result)
