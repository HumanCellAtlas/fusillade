#!/usr/bin/env python
# coding: utf-8

"""
Functional Test of the API
"""
import base64
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
from fusillade import directory, User, Group, Role
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


class TestAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = ChaliceTestHarness()

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
        scopes = "openid email profile"  # Is offline_access needed for CLI
        CLIENT_ID = "qtMgNk9fqVeclLtZl6WkbdJ59dP3WeAt"
        REDIRECT_URI = "http://localhost:8080"

        from uuid import uuid4
        state = str(uuid4())
        query_params = {
            "response_type": "code",
            "state": state,
            "redirect_uri": REDIRECT_URI,
            "scope": scopes
        }
        url = furl("/oauth/authorize")
        url.add(query_params=query_params)
        url.add(query_params={"client_id": CLIENT_ID})

        with self.subTest("with client_id"):
            resp = self.app.get(url.url)
            self.assertEqual(302, resp.status_code)
            redirect_url = furl(resp.headers['Location'])
            self.assertEqual(redirect_url.args["client_id"], CLIENT_ID)
            self.assertEqual(redirect_url.args["response_type"], 'code')
            self.assertEqual(redirect_url.args["state"], state)
            self.assertEqual(redirect_url.args["redirect_uri"], REDIRECT_URI)
            self.assertEqual(redirect_url.args["scope"], scopes)
            self.assertEqual(redirect_url.host, 'humancellatlas.auth0.com')
            self.assertEqual(redirect_url.path, '/authorize')
        with self.subTest("without client_id"):
            url.remove(query_params=["client_id"])
            resp = self.app.get(url.url)
            self.assertEqual(302, resp.status_code)
            redirect_url = furl(resp.headers['Location'])
            self.assertIn('client_id', redirect_url.args)
            self.assertEqual(redirect_url.args["response_type"], 'code')
            query_params["openid_provider"] = "humancellatlas.auth0.com"
            self.assertDictEqual(json.loads(base64.b64decode(redirect_url.args["state"])), query_params)
            redirect_uri = furl(redirect_url.args["redirect_uri"])
            self.assertTrue(redirect_uri.pathstr.endswith('/cb'))
            self.assertEqual(redirect_url.args["scope"], scopes)
            self.assertEqual(redirect_url.host, 'humancellatlas.auth0.com')
            self.assertEqual(redirect_url.path, '/authorize')

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

        with self.subTest("an error is returned when no host is provided in the header"):
            resp = self.app.get('/.well-known/openid-configuration')
            self.assertEqual(400, resp.status_code)

        with self.subTest("Error return when invalid host is provided in header."):
            host = 'localhost:8080'
            resp = self.app.get('/.well-known/openid-configuration', headers={'host': host})
            self.assertEqual(400, resp.status_code)

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
        # TODO: use token to get userinfo
        with self.subTest("userinfo denied when no token is included."):
            resp = self.app.get('/oauth/userinfo')
            self.assertEqual(401, resp.status_code)  # TODO fix

    def test_serve_oauth_token(self):
        # TODO: login
        # TODO: get token
        with self.subTest("token denied when no query params provided."):
            resp = self.app.post('/oauth/token')
            self.assertEqual(400, resp.status_code)  # TODO fix

    def test_cb(self):
        resp = self.app.get('/internal/cb')
        self.assertEqual(400, resp.status_code)  # TODO fix


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = ChaliceTestHarness()

    def tearDown(self) -> None:
        directory.clear()

    def test_evaluate_policy(self):
        email = "test_evaluate_api@email.com"
        tests = [
            {
                'json_request_body': {
                    "action": ["dss:CreateSubscription"],
                    "resource": [f"arn:hca:dss:*:*:subscriptions/{email}/*"],
                    "principal": "test@email.com"
                },
                'response': {
                    'code': 200,
                    'result': False
                }
            },
            {
                'json_request_body': {
                    "action": ["fus:GetUser"],
                    "resource": [f"arn:hca:fus:*:*:user/{email}/policy"],
                    "principal": email
                },
                'response': {
                    'code': 200,
                    'result': True
                }
            }
        ]
        for test in tests:
            with self.subTest(test['json_request_body']):
                data=json.dumps(test['json_request_body'])
                headers={'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                resp = self.app.post('/v1/policies/evaluate', headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)
                self.assertEqual(test['response']['result'], json.loads(resp.body)['result'])

    def test_put_new_user(self):
        tests = [
            {
                'json_request_body': {
                    "user_id": "test_put_user0@email.com"

                },
                'response': {
                    'code': 201
                }
            },
            {
                'json_request_body': {
                    "user_id": "test_put_user1@email.com",
                    "groups": [Group.create(directory,"group_01").name]
                },
                'response': {
                    'code': 201,
                    'result': True
                }
            },
            {
                'json_request_body': {
                    "user_id": "test_put_user2@email.com",
                    "roles": [Role.create(directory,"role_02").name]
                },
                'response': {
                    'code': 201,
                    'result': True
                }
            },
            {
                'json_request_body': {
                    "user_id": "test_put_user3@email.com",
                    "policy": create_test_statement("policy_03")
                },
                'response': {
                    'code': 201,
                    'result': True
                }
            },
            {
                'json_request_body': {
                    "user_id": "test_put_user4@email.com",
                    "groups": [Group.create(directory, "group_04").name],
                    "roles": [Role.create(directory, "role_04").name],
                    "policy": create_test_statement("policy_04")
                },
                'response': {
                    'code': 201,
                    'result': True
                }
            },
            {
                'json_request_body': {
                    "groups": [Group.create(directory, "group_05").name],
                    "roles": [Role.create(directory, "role_05").name],
                    "policy": create_test_statement("policy_05")
                },
                'response': {
                    'code': 400,
                    'result': True
                }
            }
        ]
        for test in tests:
            with self.subTest(test['json_request_body']):
                data=json.dumps(test['json_request_body'])
                headers={'Content-Type': "application/json"}
                headers.update(get_auth_header(service_accounts['admin']))
                resp = self.app.put('/v1/users', headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)

    def test_get_user(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_user_api@email.com"
        User.provision_user(directory,name)
        resp = self.app.get(f'/v1/users/{name}/',headers=headers)
        self.assertEqual(name,json.loads(resp.body)['name'])
        resp.raise_for_status()

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
                resp.raise_for_status()

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
                if test['action']=='remove':
                    user.add_groups(test['json_request_body']['groups'])
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)
                resp.raise_for_status()

    def test_get_username_groups(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_user_group_api@email.com"
        User.provision_user(directory, name)
        resp = self.app.get(f'/v1/users/{name}/groups', headers=headers)
        self.assertEqual(0, len(json.loads(resp.body)['groups']))
        resp.raise_for_status()

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
                if test['action']=='remove':
                    user.add_roles(test['json_request_body']['roles'])
                resp = self.app.put(url.url, headers=headers, data=data)
                self.assertEqual(test['response']['code'], resp.status_code)
                resp.raise_for_status()

    def test_get_username_roles(self):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))
        name = "test_user_role_api@email.com"
        user = User.provision_user(directory, name)
        resp = self.app.get(f'/v1/users/{name}/roles', headers=headers)
        user_role_names = [Role(directory, None, role).name for role in user.roles]
        self.assertEqual(1, len(json.loads(resp.body)['roles']))
        self.assertEqual(user_role_names,['default_user'])
        resp.raise_for_status()

 
    def test_serve_swagger_ui(self):
        routes = ['/swagger.json', '/']
        for route in routes:
            with self.subTest(route):
                resp = self.app.get(route)
                resp.raise_for_status()

    def test_echo(self):
        body='Hello World!'
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