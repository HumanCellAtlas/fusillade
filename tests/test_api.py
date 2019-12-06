#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the API
"""
import json
import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests.base_api_test import BaseAPITest


class TestApi(BaseAPITest, unittest.TestCase):

    def test_serve_swagger_ui(self):
        routes = ['/swagger.json', '/']
        for route in routes:
            with self.subTest(route):
                resp = self.app.get(route)
                resp.raise_for_status()

    def test_echo(self):
        body = 'Hello World!'
        resp = self.app.get('/echo', data=body)
        resp.raise_for_status()

    def test_version(self):
        resp = self.app.get('/internal/version')
        resp.raise_for_status()

    def test_health_check(self):
        resp = self.app.get('/internal/health')
        resp.raise_for_status()
        body = json.loads(resp.body)
        self.assertEqual(body['health_status'], 'ok')
        self.assertTrue(isinstance(body['services'], dict))


if __name__ == '__main__':
    unittest.main()
