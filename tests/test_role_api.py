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
                'name': '401 return when unauthorized user.',
                'data': data,
                'headers': get_auth_header(service_accounts['user']),
                'expected_resp': 401
            },
            {
                'name': '201 returned when user is authorized.',
                'data': data,
                'headers': get_auth_header(service_accounts['admin']),
                'expected_resp': 201
            },

        ]
        for test in tests:
            with self.subTest(test['name']):
                headers = {'Content-Type': "application/json"}
                headers.update(test['headers'])
                resp = self.app.put(url.url, data=test['data'], headers=headers)
                self.assertEqual(test['expected_resp'], resp.status_code)


if __name__ == '__main__':
    unittest.main()
