#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Roles API
"""
import json
import os
import sys
import unittest

from furl import furl

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts, create_test_IAMPolicy
from tests.data import TEST_NAMES_NEG, TEST_NAMES_POS
from fusillade.directory import Role
from tests.json_mixin import AssertJSONMixin


class TestRoleApi(BaseAPITest, unittest.TestCase, AssertJSONMixin):
    def tearDown(self):
        self.clear_directory(
            users=[
                service_accounts['admin']['client_email'],
                service_accounts['user']['client_email'],
            ])

    def test_positive(self):
        """
        Test Create Retrieve and Update

        1. Create a role
        2. retrieve that role
        3. modify that role
        4. retrieve modified role
        """
        role_id = 'test_positive'
        policy = create_test_IAMPolicy(role_id)
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))

        url = furl('/v1/role')
        data = json.dumps({
            'role_id': role_id,
            'policy': policy
        })
        resp = self.app.post(url.url, data=data, headers=headers)
        self.assertEqual(201, resp.status_code)

        url = furl(f'/v1/role/{role_id}')
        resp = self.app.get(url.url, headers=headers)
        self.assertEqual(200, resp.status_code)
        expected_body = {
            'role_id': role_id,
            'policies': {"IAMPolicy": policy}
        }
        self.assertEqual(expected_body, json.loads(resp.body))

        url = furl(f'/v1/role/{role_id}/policy')
        policy = create_test_IAMPolicy('ABCD')
        data = json.dumps({
            'policy': policy
        })
        resp = self.app.put(url.url, data=data, headers=headers)
        self.assertEqual(200, resp.status_code)

        url = furl(f'/v1/role/{role_id}')
        resp = self.app.get(url.url, headers=headers)
        self.assertEqual(200, resp.status_code)
        expected_body = {
            'role_id': role_id,
            'policies': {"IAMPolicy": policy}
        }
        self.assertEqual(expected_body, json.loads(resp.body))

    def test_missing_custom_claim(self):
        headers = {'Content-Type': "application/json"}
        self._test_custom_claim(self.app.get, f'/v1/roles', headers, '')

    def test_get_roles(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        for i in range(10):
            resp = self.app.post(
                '/v1/role',
                headers=headers,
                data=json.dumps({"role_id": f"test_put_role{i}",
                                 'policy': create_test_IAMPolicy("test_role")})

            )
            self.assertEqual(201, resp.status_code)
        self._test_paging(f'/v1/roles', headers, 6, 'roles')

    def test_post_role(self):
        url = furl('/v1/role')
        data = json.dumps({
            'role_id': 'test_put_role',
            'policy': create_test_IAMPolicy("test_role")
        })
        admin_auth_header = get_auth_header(service_accounts['admin'])
        tests = [
            {
                'name': '401 return when no auth headers.',
                'data': data,
                'headers': {},
                'expected_resp': 401
            },
            {
                'name': '403 return when unauthorized user.',
                'data': data,
                'headers': get_auth_header(service_accounts['user']),
                'expected_resp': 403
            },
            {
                'name': '201 returned when user is authorized.',
                'data': data,
                'headers': admin_auth_header,
                'expected_resp': 201
            },
            {
                'name': '409 returned when role already exists.',
                'data': data,
                'headers': admin_auth_header,
                'expected_resp': 409
            },
            {
                'name': '400 returned when an invalid policy is used',
                'data': json.dumps({
                    'role_id': 'test_role2',
                    'policy': 'garbage statement'
                }),
                'headers': admin_auth_header,
                'expected_resp': 400
            },
            {
                'name': '400 returned when creating a role with no name.',
                'data': json.dumps({
                    'policy': create_test_IAMPolicy("test_role")
                }),
                'headers': admin_auth_header,
                'expected_resp': 400
            },
            {
                'name': '400 returned when creating a role with no policy.',
                'data': json.dumps({
                    'role_id': 'abcd',
                }),
                'headers': admin_auth_header,
                'expected_resp': 400
            }
        ]
        tests.extend([
            {
                'name': f'201 returned when creating a role when name is {description}',
                'data': json.dumps({
                    'role_id': name,
                    'policy': create_test_IAMPolicy("test_role")
                }),
                'headers': admin_auth_header,
                'expected_resp': 201
            } for name, description in TEST_NAMES_POS
        ])
        tests.extend([
            {
                'name': f'400 returned when creating a role when name is {description}',
                'data': json.dumps({
                    'role_id': name,
                    'policy': create_test_IAMPolicy("test_role")
                }),
                'headers': admin_auth_header,
                'expected_resp': 400
            } for name, description in TEST_NAMES_NEG
        ])
        for test in tests:
            with self.subTest(test['name']):
                headers = {'Content-Type': "application/json"}
                headers.update(test['headers'])
                resp = self.app.post(url.url, data=test['data'], headers=headers)
                self.assertEqual(test['expected_resp'], resp.status_code)

    def test_get_role_id(self):
        role_id = 'test_get_role_id'
        admin_auth_header = get_auth_header(service_accounts['admin'])
        tests = [
            {
                'name': '401 return when no auth headers.',
                'headers': {},
                'role_id': role_id,
                'expected_resp': 401
            },
            {
                'name': '403 return when unauthorized user.',
                'headers': get_auth_header(service_accounts['user']),
                'role_id': role_id,
                'expected_resp': 403
            },
            {
                'name': '200 returned when user is authorized.',
                'headers': admin_auth_header,
                'role_id': role_id,
                'expected_resp': 200
            },
            {
                'name': 'error returned when role does not exist.',
                'headers': admin_auth_header,
                'role_id': 'ghost_role',
                'expected_resp': 404
            }
        ]
        tests.extend([
            {
                'name': f'200 returned when getting a role when name is {description}',
                'role_id': role_id,
                'headers': admin_auth_header,
                'expected_resp': 200
            } for name, description in TEST_NAMES_POS
        ])
        tests.extend([
            {
                'name': f'400 returned when getting a role when name is {description}',
                'role_id': role_id,
                'headers': admin_auth_header,
                'expected_resp': 400
            } for role_id, description in TEST_NAMES_NEG if role_id is not ''
        ])
        policy = create_test_IAMPolicy("test_role")
        role = Role.create(role_id, policy)
        expected_policy = policy
        [Role.create(role_id, policy) for role_id, _ in TEST_NAMES_POS]
        for test in tests:
            with self.subTest(test['name']):
                url = furl('/v1/role/{}'.format(test['role_id']))
                headers = {'Content-Type': "application/json"}
                headers.update(test['headers'])
                resp = self.app.get(url.url, headers=headers)
                self.assertEqual(test['expected_resp'], resp.status_code)
                if test['expected_resp'] == 200:
                    expected_body = {
                        'role_id': test['role_id'],
                        'policies': {'IAMPolicy': expected_policy}
                    }
                    self.assertEqual(expected_body, json.loads(resp.body))

    def test_put_role_id_policy(self):
        role_id = 'test_put_role_id_policy'
        policy_1 = create_test_IAMPolicy(role_id)
        policy_2 = create_test_IAMPolicy('ABCD')
        policy_invalid = "invalid policy"
        Role.create(role_id, policy_1)
        admin_auth_header = get_auth_header(service_accounts['admin'])
        tests = [
            {
                'name': '401 return when no auth headers.',
                'headers': {},
                'role_id': role_id,
                'data': {
                    'policy': policy_2
                },
                'expected_resp': 401
            },
            {
                'name': '403 return when unauthorized user.',
                'headers': get_auth_header(service_accounts['user']),
                'role_id': role_id,
                'data': {
                    'policy': policy_2
                },
                'expected_resp': 403
            },
            {
                'name': '200 returned when user is authorized.',
                'headers': admin_auth_header,
                'role_id': role_id,
                'data': {
                    'policy': policy_2
                },
                'expected_resp': 200
            },
            {
                'name': '400 returned when an invalid policy is used.',
                'headers': admin_auth_header,
                'role_id': role_id,
                'data': {
                    'policy': policy_invalid
                },
                'expected_resp': 400
            },
            {
                'name': '404 returned when role does not exist.',
                'headers': admin_auth_header,
                'role_id': 'ghost_role',
                'data': {
                    'policy': policy_2
                },
                'expected_resp': 404
            }
        ]
        for test in tests:
            with self.subTest(test['name']):
                headers = {'Content-Type': "application/json"}
                headers.update(test['headers'])
                url = furl(f"/v1/role/{test['role_id']}/policy")
                data = json.dumps(test['data'])
                resp = self.app.put(url.url, data=data, headers=headers)
                self.assertEqual(test['expected_resp'], resp.status_code)

    def test_delete_role(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        role_id = "role_1"

        with self.subTest("Role delete with users and groups."):
            group = "group_test_delete_role"
            user = "user_test_delete_role"
            policy = create_test_IAMPolicy("policy_04")

            resp = self.app.post(f'/v1/role',
                                 headers=headers,
                                 data=json.dumps({
                                     "role_id": role_id,
                                     "policy": policy
                                 }))
            resp.raise_for_status()
            resp = self.app.post(f'/v1/group',
                                 headers=headers,
                                 data=json.dumps({
                                     "group_id": group,
                                     "roles": [role_id]
                                 }))
            resp.raise_for_status()
            resp = self.app.post(f'/v1/user',
                                 headers=headers,
                                 data=json.dumps({
                                     "user_id": user,
                                     "roles": [role_id]}))
            resp.raise_for_status()

            resp = self.app.delete(f'/v1/role/{role_id}', headers=headers)
            self.assertEqual(resp.status_code, 200)

            resp = self.app.get(f'/v1/user/{user}/roles', headers=headers)
            roles = json.loads(resp.body)['roles']
            self.assertNotIn(role_id, roles)

            resp = self.app.get(f'/v1/group/{group}/roles', headers=headers)
            roles = json.loads(resp.body)['roles']
            self.assertNotIn(role_id, roles)

        with self.subTest("delete a role that does not exist."):
            resp = self.app.delete(f'/v1/role/ghost', headers=headers)
            self.assertEqual(resp.status_code, 404)


if __name__ == '__main__':
    unittest.main()
