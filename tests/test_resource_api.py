#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Resource API
"""
import json
import os
import sys
import unittest

from furl import furl

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests import eventually
from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts


class TestApi(BaseAPITest, unittest.TestCase):

    def test_post_resource(self):
        pass

    def test_get_resource(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        self._test_paging('/v1/resource', headers, 10, 'resource_types')

if __name__ == '__main__':
    unittest.main()
