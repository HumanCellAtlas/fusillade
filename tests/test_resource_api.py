#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Resource API
"""
import json
import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts

admin_headers = {'Content-Type': "application/json"}
admin_headers.update(get_auth_header(service_accounts['admin']))

user_header = {'Content-Type': "application/json"}
user_header.update(get_auth_header(service_accounts['user']))


class TestApi(BaseAPITest, unittest.TestCase):

    def setUp(self):
        self.rt = resp = self.app.post(
            '/v1/resource/sample_resource',
            data=json.dumps({'actions': ['rt:get', 'rt:put', 'rt:update', 'rt:delete']}),
            headers=admin_headers)

    def test_create_resource(self):
        """A resource type is created and destroyed using the API"""
        test_resource = 'test_resource'  # the name of the resource type to create
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)
        resp = self.app.post(f'/v1/resource/{test_resource}', data=json.dumps({'actions': ['tr:action1']}),
                             headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.delete(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

    def test_access_resource(self):
        """A user does not have access to a resource when they do not have permission."""
        rt_name = 'thing'
        role_name = 'test_role'
        resp = self.app.post(f'/v1/resource/{rt_name}', data=json.dumps({'actions': ['tr:action1']}),
                             headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        with self.subTest("Permission is denied"):
            resp = self.app.get(f'/v1/resource/{rt_name}', headers=user_header)
            self.assertEqual(resp.status_code, 403)

        role_request_body = {
            "role_id": role_name,
            "policy": {
                'Statement': [{
                    'Sid': role_name,
                    'Action': [
                        "fus:DeleteResources",
                        "fus:GetResources"],
                    'Effect': 'Allow',
                    'Resource': [f"arn:hca:fus:*:*:resource/{rt_name}"]
                }]
            }
        }
        resp = self.app.post(f'/v1/role', data=json.dumps(role_request_body), headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        resp = self.app.put(f"/v1/user/{service_accounts['user']['client_email']}/roles?action=add",
                            data=json.dumps({'roles': [role_name]}),
                            headers=admin_headers,)
        self.assertEqual(resp.status_code, 200)

        with self.subTest("Permission is granted"):
            resp = self.app.get(f'/v1/resource/{rt_name}', headers=user_header)
            self.assertEqual(resp.status_code, 200)

    def test_get_resource(self):
        """Pages of resource are retrieved when using the get resource API"""
        for i in range(11):
            self.app.post(f'/v1/resource/tr{i}', data=json.dumps({'actions': ['tr:action1']}), headers=admin_headers)
        self._test_paging('/v1/resource', admin_headers, 10, 'resources')

    def test_resource_policy(self):


if __name__ == '__main__':
    unittest.main()
