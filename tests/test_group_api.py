#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Group API
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
from fusillade.directory import Role, Group, User


class TestGroupApi(BaseAPITest, unittest.TestCase):
    def tearDown(self):
        self.clear_directory(users=[
            service_accounts['admin']['client_email']
        ])

    def test_post_group(self):
        tests = [
            {
                'name': f'201 returned when creating a group',
                'json_request_body': {
                    "group_id": "test_post_group_Group0"

                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a group with role only',
                'json_request_body': {
                    "group_id": "test_post_group_Group1",
                    "roles": [Role.create("test_post_group_role_02").name]
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a group with policy only',
                'json_request_body': {
                    "group_id": "test_post_group_Group2",
                    "policy": create_test_IAMPolicy("policy_03")
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a group with role and policy',
                'json_request_body': {
                    "group_id": "test_post_group_Group3",
                    "roles": [Role.create("test_post_group_role_04").name],
                    "policy": create_test_IAMPolicy("policy_04")
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'400 returned when creating a group without group_id',
                'json_request_body': {
                    "roles": [Role.create("test_post_group_role_05").name],
                    "policy": create_test_IAMPolicy("policy_05")
                },
                'response': {
                    'code': 400
                }
            },
            {
                'name': f'409 returned when creating a group that already exists',
                'json_request_body': {
                    "group_id": "test_post_group_Group3"
                },
                'response': {
                    'code': 409
                }
            }
        ]
        tests.extend([{
            'name': f'201 returned when creating a role when name is {description}',
            'json_request_body': {
                "group_id": name
            },
            'response': {
                'code': 201
            }
        } for name, description in TEST_NAMES_POS
        ])
        tests.extend([{
            'name': f'400 returned when creating a role when name is {description}',
            'json_request_body': {
                "group_id": name
            },
            'response': {
                'code': 400
            }
        } for name, description in TEST_NAMES_NEG
        ])
        for test in tests:
            with self.subTest(test['name']):
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                if test['name'] == "400 returned when creating a group that already exists":
                    self.app.post('/v1/group', headers=headers, data=json.dumps(test['json_request_body']))
                resp = self.app.post('/v1/group', headers=headers, data=json.dumps(test['json_request_body']))
                self.assertEqual(test['response']['code'], resp.status_code)
                if resp.status_code == 201:
                    resp = self.app.get(f'/v1/group/{test["json_request_body"]["group_id"]}/', headers=headers)
                    self.assertEqual(test["json_request_body"]["group_id"], json.loads(resp.body)['group_id'])

    def test_get_group(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_get_group_Groupx"
        resp = self.app.get(f'/v1/group/{name}/', headers=headers)
        self.assertEqual(404, resp.status_code)
        Group.create(name)
        resp = self.app.get(f'/v1/group/{name}/', headers=headers)
        self.assertEqual(name, json.loads(resp.body)['group_id'])
        self.assertTrue(json.loads(resp.body)['policies'])

    def test_get_groups(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        for i in range(10):
            resp = self.app.post(
                '/v1/group',
                headers=headers,
                data=json.dumps({"group_id": f"test_get_groups_{i}",
                                 'policy': create_test_IAMPolicy("test_group")})

            )
            self.assertEqual(201, resp.status_code)
        self._test_paging('/v1/groups', headers, 6, 'groups')

    def test_put_group_roles(self):
        tests = [
            {
                'group_id': "test_put_group_roles_Group1",
                'action': 'add',
                'json_request_body': {
                    "roles": [Role.create("role_0").name]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            },
            {
                'group_id': "test_put_group_roles_Group2",
                'action': 'remove',
                'json_request_body': {
                    "roles": [Role.create("role_1").name]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            }
        ]
        for test in tests:
            with self.subTest(test['json_request_body']):
                data = json.dumps(test['json_request_body'])
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                url = furl(f'/v1/group/{test["group_id"]}/roles/')
                query_params = {
                    'group_id': test['group_id'],
                    'action': test['action']
                }
                url.add(query_params=query_params)
                group = Group.create(test['group_id'])
                if test['action'] == 'remove':
                    group.add_roles(test['json_request_body']['roles'])
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['responses'][0]['code'], resp.status_code)
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['responses'][1]['code'], resp.status_code)

    def test_get_group_roles(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_get_group_roles_group"
        key = 'roles'
        group = Group.create(name)
        resp = self.app.get(f'/v1/group/{name}/roles', headers=headers)
        group_role_names = [Role(None, role).name for role in group.roles]
        self.assertEqual(0, len(json.loads(resp.body)[key]))
        roles = [Role.create(f"test_get_group_roles_role_{i}").name for i in range(10)]
        group.add_roles(roles)
        self._test_paging(f'/v1/group/{name}/roles', headers, 5, key)

    def test_get_group_users(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_get_group_users_group"
        key = 'users'
        group = Group.create(name)
        resp = self.app.get(f'/v1/group/{name}/users', headers=headers)
        group_user_names = [User(user).name for user in group.get_users_iter()]
        self.assertEqual(0, len(json.loads(resp.body)[key]))
        users = [User.provision_user(f"test_get_group_user_{i}", groups=[name]).name for i in range(10)]
        self._test_paging(f'/v1/group/{name}/users', headers, 5, key)

    def test_put_users(self):
        users = [User.provision_user(f"test_put_user_{i}").name for i in range(11)]
        tests = [
            {
                'action': 'add',
                'json_request_body': {
                    "users": [users[0]]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            },
            {
                'action': 'remove',
                'json_request_body': {
                    "users": [users[0]]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            },
            {
                'action': 'add',
                'json_request_body': {
                    "users": users[:-1]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            },
            {
                'action': 'remove',
                'json_request_body': {
                    "users": users[:-1]
                },
                'responses': [
                    {'code': 200},
                    {'code': 304}
                ]
            },
            {
                'action': 'add',
                'json_request_body': {
                    "users": users
                },
                'responses': [
                    {'code': 400},
                    {'code': 400}
                ]
            },
            {
                'action': 'remove',
                'json_request_body': {
                    "users": users
                },
                'responses': [
                    {'code': 400},
                    {'code': 400}
                ]
            }
        ]
        for i, test in enumerate(tests):
            group_id = Group.create(f"Group{i}").name
            with self.subTest(test['json_request_body']):
                data = json.dumps(test['json_request_body'])
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                if test['action'] == 'remove':
                    url = furl(f'/v1/group/{group_id}/users', query_params={'action': 'add'})
                    resp = self.app.put(url.url, headers=headers, data=data)
                url = furl(f'/v1/group/{group_id}/users', query_params={'action': test['action']})
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['responses'][0]['code'], resp.status_code)
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['responses'][1]['code'], resp.status_code)

    def test_default_group(self):
        headers = {'Content-Type': "application/json"}
        users = ['admin', 'user']
        for user in users:
            with self.subTest(f"{user} has permission to access default_user group."):
                headers.update(get_auth_header(service_accounts[user]))
                resp = self.app.get(f'/v1/group/user_default', headers=headers)
                resp.raise_for_status()
                resp = self.app.get(f'/v1/group/user_default/roles', headers=headers)
                resp.raise_for_status()
                if user == 'admin':
                    resp = self.app.get(f'/v1/group/user_default/users', headers=headers)
                    resp.raise_for_status()

    def test_delete_group(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))

        role = Role.create("test_delete_group_role").name
        user = User.provision_user("test_delete_group_user").name
        policy = create_test_IAMPolicy("test_delete_group_policy")
        group_id = "test_delete_group_group"

        with self.subTest("Group delete with users and roles."):

            resp = self.app.post(f'/v1/group',
                     headers=headers,
                     data=json.dumps({
                         "group_id": group_id,
                         "roles": [role],
                         "policy": policy
                     }))
            resp.raise_for_status()
            resp = self.app.put(f'/v1/user/{user}/groups?action=add',
                     headers=headers,
                     data=json.dumps({"groups": [group_id]}))
            resp.raise_for_status()
            resp = self.app.delete(f'/v1/group/{group_id}', headers=headers)
            self.assertEqual(resp.status_code, 200)
            resp = self.app.get(f'/v1/user/{user}/groups', headers=headers)
            groups = json.loads(resp.body)['groups']
            self.assertNotIn(group_id, groups)

        with self.subTest("delete a group that does not exist."):
            resp = self.app.delete(f'/v1/group/{group_id}', headers=headers)
            self.assertEqual(resp.status_code, 404)


if __name__ == '__main__':
    unittest.main()
