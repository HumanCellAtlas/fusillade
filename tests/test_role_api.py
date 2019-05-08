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

from tests import random_hex_string, eventually

directory_name = "test_api_" + random_hex_string()
os.environ['OPENID_PROVIDER'] = "humancellatlas.auth0.com"
old_directory_name = os.getenv("FUSILLADE_DIR", None)
os.environ["FUSILLADE_DIR"] = directory_name


from tests.common import get_auth_header, service_accounts, create_test_statement
import fusillade
from fusillade import directory, User
from fusillade.clouddirectory import cleanup_directory

from tests.infra.server import ChaliceTestHarness
# ChaliceTestHarness must be imported after FUSILLADE_DIR has be set


def setUpModule():
    User.provision_user(directory, service_accounts['admin']['client_email'], roles=['admin'])


@eventually(5,1, {fusillade.errors.FusilladeException})
def tearDownModule():
    cleanup_directory(directory._dir_arn)
    if old_directory_name:
        os.environ["FUSILLADE_DIR"] = old_directory_name


class TestRoleApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = ChaliceTestHarness()

    def test_positive(self):
        """
        Test Create Retrieve and Update

        1. Create a role
        2. retrieve that role
        3. modify that role
        """
        role_id = 'test_role'
        policy = create_test_statement(role_id)
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))

        url = furl('/v1/roles')
        data = json.dumps({
            'name': role_id,
            'policy': policy
        })
        resp = self.app.put(url.url, data=data, headers=headers)
        self.assertEqual(201, resp.status_code)

        url = furl(f'/v1/roles/{role_id}')
        resp = self.app.get(url.url, headers=headers)
        self.assertEqual(200, resp.status_code)

        url = furl(f'/v1/roles/{role_id}/policy')
        data = json.dumps({
            'policy': create_test_statement('ABCD')
        })
        resp = self.app.put(url.url, data=data, headers=headers)
        self.assertEqual(200, resp.status_code)

    def test_put_role(self):
        url = furl('/v1/roles')
        data = json.dumps({
            'name': 'test_role',
            'policy': create_test_statement("test_role")
        })

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
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 201
            },
            {
                'name': '409 returned when role already exists.',
                'data': data,
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 409
            },
            {
                'name': '400 returned when an invalid policy is used',
                'data': json.dumps({
                    'name': 'test_role2',
                    'policy': 'garbage statement'
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 400
            },
            {
                'name': '201 returned when creating a role with special characters.',
                'data': json.dumps({
                    'name': 'test$%^&*())!@#role',
                    'policy': create_test_statement("test_role")
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 201
            },
            {
                'name': '201 returned when creating a role with a name == 128 characters.',
                'data': json.dumps({
                    'name': 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'
                            'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
                    'policy': create_test_statement("test_role")
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 201
            },
            {
                'name': '400 returned when creating a role with a name over 128 characters.',
                'data': json.dumps({
                    'name': 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'
                            'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567890',
                    'policy': create_test_statement("test_role")
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 400
            },
            {
                'name': '400 returned when creating a role with no name.',
                'data': json.dumps({
                    'name': '',
                    'policy': create_test_statement("test_role")
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 400
            },
            {
                'name': '400 returned when creating a role with no name.',
                'data': json.dumps({
                    'policy': create_test_statement("test_role")
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 400
            },
            {
                'name': '400 returned when creating a role with no name.',
                'data': json.dumps({
                    'name': 'abcd',
                }),
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 400
            }
        ]
        for test in tests:
            with self.subTest(test['name']):
                headers = {'Content-Type': "application/json"}
                headers.update(test['headers'])
                resp = self.app.put(url.url, data=test['data'], headers=headers)
                self.assertEqual(test['expected_resp'], resp.status_code)


    def test_get_role(self):
        pass

    def test_put_roleid(self):
        pass

    def test_get_roleid(self):
        pass
if __name__ == '__main__':
    unittest.main()
