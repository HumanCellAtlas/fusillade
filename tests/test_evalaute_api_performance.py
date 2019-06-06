#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the API
"""
import json
import unittest
import os
import sys

from furl import furl

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts, create_test_statement

import cProfile
def profileit(name):
    def inner(func):
        def wrapper(*args, **kwargs):
            prof = cProfile.Profile()
            retval = prof.runcall(func, *args, **kwargs)
            # Note use of name from outer scope
            prof.dump_stats(name)
            return retval
        return wrapper
    return inner


import time
import logging

def profile(name, count):
    def inner(func):
        def wrap(*args, **kwargs):
            started_at = time.time()
            result = func(*args, **kwargs)
            logging.warn(f"{name}: EXECUTION TIME:{(time.time() - started_at)/count}")
            return result

        return wrap
    return inner


@unittest.skipIf(True, "Manual Teset")
class TestEvaluateApi(BaseAPITest, unittest.TestCase):

    def _run_test(self, user, headers, repeat):
        json_body=json.dumps({
                    "action": ["fus:GetUser"],
                    "resource": [f"arn:hca:fus:*:*:user/{user}/policy"],
                    "principal": user
                })
        for i in range(repeat):
            resp = self.app.post('/v1/policies/evaluate', headers=headers, data=json_body)
            resp.raise_for_status()

    def test_lookup_roles(self):
        # this looks at how lookup policy scales
        roles = [2,4,8,16,32]
        start = 0
        repeat = 100
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        role_url = furl('/v1/role')
        user_url = furl('/v1/user')
        role_ids = []
        for role in roles:
            user=f"roles_{role}"
            resp = self.app.post(user_url.url, data=json.dumps({"user_id": user}), headers=headers)
            self.assertEqual(201, resp.status_code)
            for i in range(start, role):
                role_id = f'test_{i}'
                policy = create_test_statement(role_id)
                data = json.dumps({
                    'role_id': role_id,
                    'policy': policy
                })
                resp = self.app.post(role_url.url, data=data, headers=headers)
                self.assertEqual(201, resp.status_code)
                role_ids.append(role_id)
            add_roles_url=furl(f'/v1/user/{user}/roles', query_params={'action': 'add'})
            resp = self.app.put(add_roles_url.url,headers=headers, data=json.dumps({'roles':role_ids}))
            resp.raise_for_status()
            profile(user, repeat)(self._run_test)(user, headers, repeat)
            # profileit(user)(self._run_test)(user, headers, repeat)
            start = role

    def test_lookup_roles(self):
        # this looks at how lookup policy scales
        groups = [2,4,8,16,32]
        start = 0
        repeat = 10
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        role_url = furl('/v1/role')
        user_url = furl('/v1/user')
        group_url = furl('/v1/group')
        group_ids = []
        for group in groups:
            user=f"group_{group}"
            resp = self.app.post(user_url.url, data=json.dumps({"user_id": user}), headers=headers)
            self.assertEqual(201, resp.status_code)
            for i in range(start, group):
                #create the roles
                role_id = f'rtest_{i}'
                policy = create_test_statement(role_id)
                data = json.dumps({
                    'role_id': role_id,
                    'policy': policy
                })
                resp = self.app.post(role_url.url, data=data, headers=headers)
                self.assertEqual(201, resp.status_code)

                # create the group
                group_id = f'gtest_{i}'
                data = json.dumps({
                    'group_id': group_id,
                })
                resp = self.app.post(group_url.url, data=data, headers=headers)
                self.assertEqual(201, resp.status_code)
                group_ids.append(group_id)

                #add roles to group
                add_roles_url=furl(f'/v1/group/{group_id}/roles', query_params={'action': 'add'})
                resp = self.app.put(add_roles_url.url,headers=headers, data=json.dumps({'roles':[role_id]}))
                resp.raise_for_status()
            add_groups_url=furl(f'/v1/user/{user}/groups', query_params={'action': 'add'})
            resp = self.app.put(add_groups_url.url,headers=headers, data=json.dumps({'groups':group_ids}))
            resp.raise_for_status()
            profile(user, repeat)(self._run_test)(user, headers, repeat)
            # profileit(user)(self._run_test)(user, headers, repeat)
            start = group


if __name__ == '__main__':
    unittest.main()