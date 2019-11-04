#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the API
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

    # TODO we need a location to backup too
    # TODO we need backup format


if __name__ == '__main__':
    unittest.main()
