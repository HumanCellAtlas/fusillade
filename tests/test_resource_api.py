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

class TestApi(BaseAPITest, unittest.TestCase):

    def test_create_resource(self):
        resp = self.app.get('/v1/resource/trPost', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)
        resp = self.app.post('/v1/resource/trPost', data=json.dumps({'actions': ['tr:action1']}), headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1/resource/trPost', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.delete('/v1/resource/trPost', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get('/v1/resource/trPost', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

    def test_get_resource(self):
        for i in range(11):
            self.app.post(f'/v1/resource/tr{i}', data=json.dumps({'actions': ['tr:action1']}), headers=admin_headers)
        self._test_paging('/v1/resource', admin_headers, 10, 'resources')


if __name__ == '__main__':
    unittest.main()
