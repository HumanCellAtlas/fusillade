#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Roles API
"""
import json
import os
import sys
import unittest
from furl import furl, quote

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests import random_hex_string, eventually

directory_name = "test_api_" + random_hex_string()
os.environ['OPENID_PROVIDER'] = "humancellatlas.auth0.com"
old_directory_name = os.getenv("FUSILLADE_DIR", None)
os.environ["FUSILLADE_DIR"] = directory_name


from tests.common import get_auth_header, service_accounts, create_test_statement
import fusillade
from fusillade import directory, User
from fusillade.clouddirectory import cleanup_directory, User, Group, Role

from tests.infra.server import ChaliceTestHarness
# ChaliceTestHarness must be imported after FUSILLADE_DIR has be set

def setUpModule():
    User.provision_user(directory, service_accounts['admin']['client_email'], roles=['admin'])

@eventually(5,1, {fusillade.errors.FusilladeException})
def tearDownModule():
    cleanup_directory(directory._dir_arn)
    if old_directory_name:
        os.environ["FUSILLADE_DIR"] = old_directory_name


class TestUserApi(unittest.TestCase):
    test_postive_names = [('helloworl12345', "alpha numerica characters"),
         ('hello@world.com', "email format") ,
        ('hello-world=_@.,ZDc', "special characters"),
        ('HellOWoRLd', "different cases"),
        ('ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'
        'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789', "== 128 characters"),
        ("1", "one character")]
    test_negative_names = [
        ("&^#$Hello", "illegal characters 1"),
        ("! <>?world", "illegal characters 2"),
        ('ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'
        'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567890', "> 128 characters"),
        ('', "empty")
    ]

    @classmethod
    def setUpClass(cls):
        cls.app = ChaliceTestHarness()

    def tearDown(self):
        directory.clear(users=[
                service_accounts['admin']['client_email']
            ])

    def test_put_new_user(self):
        tests = [
            {
                'name': f'201 returned when creating a user',
                'json_request_body': {
                    "user_id": "test_put_user0@email.com"

                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a user with group only',
                'json_request_body': {
                    "user_id": "test_put_user1@email.com",
                    "groups": [Group.create(directory, "group_01").name]
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a user with role only',
                'json_request_body': {
                    "user_id": "test_put_user2@email.com",
                    "roles": [Role.create(directory, "role_02").name]
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a user with policy only',
                'json_request_body': {
                    "user_id": "test_put_user3@email.com",
                    "policy": create_test_statement("policy_03")
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a user with group, role and policy',
                'json_request_body': {
                    "user_id": "test_put_user4@email.com",
                    "groups": [Group.create(directory, "group_04").name],
                    "roles": [Role.create(directory, "role_04").name],
                    "policy": create_test_statement("policy_04")
                },
                'response': {
                    'code': 201
                }
            },
            {
                'name': f'201 returned when creating a user without username',
                'json_request_body': {
                    "groups": [Group.create(directory, "group_05").name],
                    "roles": [Role.create(directory, "role_05").name],
                    "policy": create_test_statement("policy_05")
                },
                'response': {
                    'code': 400
                }
            },
            {
                'name': f'400 returned when creating a user that already exists',
                'json_request_body': {
                    "user_id": "test_put_user4@email.com"
                },
                'response': {
                    'code': 500
                }
            }
        ]
        tests.extend([{
            'name': f'201 returned when creating a role when name is {description}',
            'json_request_body': {
                "user_id": name
            },
            'response': {
                'code': 201
            }
        } for name, description in self.test_postive_names
        ])
        tests.extend([{
            'name': f'400 returned when creating a role when name is {description}',
            'json_request_body': {
                "user_id": name
            },
            'response': {
                'code': 400
            }
        } for name, description in self.test_negative_names
        ])
        for test in tests:
            with self.subTest(test['name']):
                headers={'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                if test['name']=="400 returned when creating a user that already exists":
                    self.app.put('/v1/users', headers=headers, data=json.dumps(test['json_request_body']))
                resp = self.app.put('/v1/users', headers=headers, data=json.dumps(test['json_request_body']))
                self.assertEqual(test['response']['code'], resp.status_code)
                if resp.status_code==201:
                    resp = self.app.get(f'/v1/users/{test["json_request_body"]["user_id"]}/', headers=headers)
                    self.assertEqual(test["json_request_body"]["user_id"], json.loads(resp.body)['name'])

    def test_get_user(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['user']))
        name = service_accounts['user']['client_email']
        resp = self.app.get(f'/v1/users/test_user_api@email.com/', headers=headers)
        self.assertEqual(403, resp.status_code)
        resp = self.app.get(f'/v1/users/{name}/', headers=headers)
        self.assertEqual(name, json.loads(resp.body)['name'])

    def test_put_user_id(self):
        tests = [
            {
                'name': "test_put_user0@email.com",
                'status': 'enabled',
                'response': {
                    'code': 200
                }
            },
            {
                'name': "test_put_user1@email.com",
                'status': 'disabled',
                'response': {
                    'code': 200
                }
            }
        ]
        for test in tests:
            with self.subTest(test["name"]):
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                url = furl(f'/v1/users/{test["name"]}')
                query_params = {
                    'user_id': test['name'],
                    'status': test['status']
                }
                url.add(query_params=query_params)
                user = User.provision_user(directory, test['name'])
                if test['status'] == 'disabled':
                    user.enable()
                resp = self.app.put(url.url, headers=headers)
                self.assertEqual(test['response']['code'], resp.status_code)

    def test_put_username_groups(self):
        tests = [
            {
                'name': "test_put_user_group0@email.com",
                'action': 'add',
                'json_request_body': {
                    "groups": [Group.create(directory, "group_0").name]
                },
                'response': {
                    'code': 200
                }
            },
            {
                'name': "test_put_user_group1@email.com",
                'action': 'remove',
                'json_request_body': {
                    "groups": [Group.create(directory, "group_1").name]
                },
                'response': {
                    'code': 200
                }
            }
        ]
        for test in tests:
            with self.subTest(test['json_request_body']):
                data = json.dumps(test['json_request_body'])
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                url = furl(f'/v1/users/{test["name"]}/groups/')
                query_params = {
                    'user_id': test['name'],
                    'action': test['action']
                }
                url.add(query_params=query_params)
                user = User.provision_user(directory, test['name'])
                if test['action'] == 'remove':
                    user.add_groups(test['json_request_body']['groups'])
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)

    def test_get_username_groups(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_user_group_api@email.com"
        user = User.provision_user(directory, name)
        resp = self.app.get(f'/v1/users/{name}/groups', headers=headers)
        self.assertEqual(0, len(json.loads(resp.body)['groups']))
        user.add_groups([Group.create(directory, "group_0").name, Group.create(directory, "group_1").name])
        resp = self.app.get(f'/v1/users/{name}/groups', headers=headers)
        self.assertEqual(2, len(json.loads(resp.body)['groups']))

    def test_put_username_roles(self):
        tests = [
            {
                'name': "test_put_user_role0@email.com",
                'action': 'add',
                'json_request_body': {
                    "roles": [Role.create(directory, "role_0").name]
                },
                'response': {
                    'code': 200
                }
            },
            {
                'name': "test_put_user_role1@email.com",
                'action': 'remove',
                'json_request_body': {
                    "roles": [Role.create(directory, "role_1").name]
                },
                'response': {
                    'code': 200
                }
            }
        ]
        for test in tests:
            with self.subTest(test['json_request_body']):
                data = json.dumps(test['json_request_body'])
                headers = {'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                url = furl(f'/v1/users/{test["name"]}/roles/')
                query_params = {
                    'user_id': test['name'],
                    'action': test['action']
                }
                url.add(query_params=query_params)
                user = User.provision_user(directory, test['name'])
                if test['action'] == 'remove':
                    user.add_roles(test['json_request_body']['roles'])
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)

    def test_get_username_roles(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_user_role_api@email.com"
        user = User.provision_user(directory, name)
        resp = self.app.get(f'/v1/users/{name}/roles', headers=headers)
        user_role_names = [Role(directory, None, role).name for role in user.roles]
        self.assertEqual(1, len(json.loads(resp.body)['roles']))
        self.assertEqual(user_role_names, ['default_user'])
        user.add_roles([Role.create(directory, "role_1").name, Role.create(directory, "role_2").name])
        resp = self.app.get(f'/v1/users/{name}/roles', headers=headers)
        self.assertEqual(3, len(json.loads(resp.body)['roles']))


if __name__ == '__main__':
    unittest.main()