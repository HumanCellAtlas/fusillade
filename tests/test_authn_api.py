#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the Authn
"""
import base64
import json
import os
import sys
import unittest
from itertools import combinations, product
from uuid import uuid4

from furl import furl

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests.infra.testmode import is_integration
from tests.base_api_test import BaseAPITest


class TestAuthentication(BaseAPITest, unittest.TestCase):
    def test_login(self):
        url = furl('/login')
        query_params = {
            'state': 'ABC',
            'redirect_uri': "http://localhost:8080"
        }
        url.add(query_params=query_params)
        resp = self.app.get(url.url)
        self.assertEqual(301, resp.status_code)
        self.assertEqual(resp.headers['Location'], '/oauth/authorize')

    def test_authorize(self):
        CLIENT_ID = "qtMgNk9fqVeclLtZl6WkbdJ59dP3WeAt"
        REDIRECT_URI = "http://localhost:8080"
        path = "/oauth/authorize"
        states = [str(uuid4()), '\n\n']
        scopes_combination = [["openid", "email", "profile", "offline"], ["openid", "email", "profile", "offline"]]
        tests = product(states, scopes_combination)
        OPENID_PROVIDER = os.environ["OPENID_PROVIDER"]
        redirect_url_host = [OPENID_PROVIDER]
        query_params_client_id = {
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID
        }
        query_params = {
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
        }
        for state, scope in tests:
            _scope = ' '.join(scope)
            query_params_client_id.update(scope=_scope, state=state)
            with self.subTest(f"with client_id: {state} {scope}"):
                url = furl(path, query_params=query_params_client_id)

                resp = self.app.get(url.url)
                self.assertEqual(302, resp.status_code)
                redirect_url = furl(resp.headers['Location'])
                self.assertEqual(redirect_url.args["client_id"], CLIENT_ID)
                self.assertEqual(redirect_url.args["response_type"], 'code')
                self.assertEqual(redirect_url.args["state"], state)
                self.assertEqual(redirect_url.args["redirect_uri"], REDIRECT_URI)
                self.assertEqual(redirect_url.args["scope"], _scope)
                self.assertIn(redirect_url.host, redirect_url_host)
                self.assertTrue(str(redirect_url.path).endswith('/authorize'))

            query_params.update(scope=_scope, state=state)
            with self.subTest(f"without client_id: {state} {scope}"):
                url = furl(path, query_params=query_params)

                resp = self.app.get(url.url)
                self.assertEqual(302, resp.status_code)
                redirect_url = furl(resp.headers['Location'])
                self.assertIn('client_id', redirect_url.args)
                self.assertEqual(redirect_url.args["response_type"], 'code')
                query_params["openid_provider"] = OPENID_PROVIDER
                self.assertDictEqual(json.loads(base64.b64decode(redirect_url.args["state"])), query_params)
                redirect_uri = furl(redirect_url.args["redirect_uri"])
                self.assertTrue(redirect_uri.pathstr.endswith('/cb'))
                self.assertEqual(redirect_url.args["scope"], "openid email profile")
                self.assertIn(redirect_url.host, redirect_url_host)
                self.assertTrue(str(redirect_url.path).endswith('/authorize'))

    def test_well_know_openid_configuration(self):
        expected_keys = ['issuer']
        expected_host = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri',
                         'revocation_endpoint']
        expected_response_types_supported = ['code']
        expected_supported_scopes = ['openid', 'profile', 'email']

        with self.subTest("openid configuration returned when host is provided in header."):
            host = os.environ['API_DOMAIN_NAME']
            resp = self.app.get('/.well-known/openid-configuration', headers={'host': host})
            resp.raise_for_status()
            body = json.loads(resp.body)
            for key in expected_keys:
                self.assertIn(key, body)
            for key in expected_host:
                self.assertIn(host, body[key])
            for key in expected_supported_scopes:
                self.assertIn(key, body['scopes_supported'])
            for key in expected_response_types_supported:
                self.assertIn(key, body['response_types_supported'])

        if is_integration():
            with self.subTest("openid config is returned when no host is provided in the header"):
                resp = self.app.get('/.well-known/openid-configuration')
                self.assertEqual(200, resp.status_code)

            with self.subTest("Error return when invalid host is provided in header."):
                host = 'localhost:8080'
                resp = self.app.get('/.well-known/openid-configuration', headers={'host': host})
                self.assertEqual(403, resp.status_code)

    def test_serve_jwks_json(self):
        resp = self.app.get('/.well-known/jwks.json')
        body = json.loads(resp.body)
        self.assertIn('keys', body)
        self.assertEqual(200, resp.status_code)

    @unittest.skip("Not currently supported.")
    def test_revoke(self):
        with self.subTest("revoke denied when no token is included."):
            resp = self.app.get('/oauth/revoke')
            self.assertEqual(403, resp.status_code)  # TODO fix

    def test_userinfo(self):
        # TODO: login
        # TODO:use token to get userinfo
        tests = [
            {
                "headers": {},
                "expected_status_code": 401,
                "description": "userinfo denied when no token is included."
            }
        ]
        for test in tests:
            with self.subTest("POST " + test["description"]):
                resp = self.app.post('/oauth/userinfo', headers=test['headers'])
                self.assertEqual(test["expected_status_code"], resp.status_code)
            with self.subTest("GET " + test["description"]):
                resp = self.app.get('/oauth/userinfo', headers=test['headers'])
                self.assertEqual(test["expected_status_code"], resp.status_code)

    def test_serve_oauth_token(self):
        # TODO: login
        # TODO: get token
        with self.subTest("token denied when no query params provided."):
            resp = self.app.post('/oauth/token', headers={'Content-Type': "application/x-www-form-urlencoded"})
            self.assertEqual(401, resp.status_code)  # TODO fix

    def test_cb(self):
        resp = self.app.get('/internal/cb')
        self.assertEqual(400, resp.status_code)  # TODO fix

    def test_logout(self):
        resp = self.app.get('/logout')
        self.assertEqual(200, resp.status_code)  # TODO fix

if __name__ == '__main__':
    unittest.main()
