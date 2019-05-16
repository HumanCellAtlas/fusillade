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
    pass
#    User.provision_user(directory, service_accounts['admin']['client_email'], roles=['admin'])


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
        directory.clear()

    def test_put_new_user(self):
        tests = []
        tests.extend([{
                'name': f'201 returned when creating a role when name is {description}',
                'json_request_body': {
                    "user_id": name
                },
                'response': 201
            } for name, description in self.test_postive_names
        ])
        tests.extend([{
            'name': f'400 returned when creating a role when name is {description}',
            'json_request_body': {
                "user_id": name
            },
            'response': 400
        } for name, description in self.test_negative_names
        ])
        for test in tests:
            with self.subTest(test['name']):
                headers={'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                resp = self.app.put('/v1/users', headers=headers, data=json.dumps(test['json_request_body']))
                self.assertEqual(test['response'], resp.status_code)

if __name__ == '__main__':
    unittest.main()
