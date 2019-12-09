import json
import os
import sys
import unittest

from furl import furl

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from tests import eventually
from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts, create_test_ResourcePolicy, create_test_IAMPolicy

admin_headers = {'Content-Type': "application/json"}
admin_headers.update(get_auth_header(service_accounts['admin']))


class TestEvaluateApi(BaseAPITest, unittest.TestCase):

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
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))

        @eventually(5, 0.5)
        def _run_test(test):
            data = json.dumps(test['json_request_body'])
            resp = self.app.post('/v1/policies/evaluate', headers=headers, data=data)
            self.assertEqual(test['response']['code'], resp.status_code, test['response'])
            self.assertEqual(test['response']['result'], json.loads(resp.body)['result'], msg=json.loads(resp.body))

        self._test_custom_claim(self.app.post,
                                '/v1/policies/evaluate',
                                headers,
                                json.dumps(tests[1]['json_request_body']))

        for test in tests:
            with self.subTest(test['json_request_body']):
                _run_test(test)

        with self.subTest("User Disabled"):
            resp = self.app.put(furl(f"/v1/user/{email}",
                                     query_params={'user_id': email, 'status': 'disabled'}).url,
                                headers=headers)
            self.assertEqual(200, resp.status_code)
            resp = self.app.post('/v1/policies/evaluate', headers=headers,
                                 data=json.dumps(tests[1]['json_request_body']))
            self.assertEqual(200, resp.status_code)
            self.assertEqual(False, json.loads(resp.body)['result'], msg=json.loads(resp.body))

    def test_evaluate_resource_policy(self):
        resource_type = 'evaluate_test_type'
        actions = sorted(['rt:read', 'rt:write', 'rt:delete'])
        resource_id = 'protected-data'
        arn_prefix = "arn:dcp:fus:us-east-1:dev:"
        resource_arn = f'{arn_prefix}{resource_type}/{resource_id}'
        user = 'user_test_access_levels'
        group = 'user_default'

        # create a resource type
        resp = self.app.post(
            f'/v1/resource/{resource_type}',
            data=json.dumps({'actions': actions}),
            headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        # create a resource policy read
        resp = self.app.post(
            f"/v1/resource/{resource_type}/policy/read",
            data=json.dumps({'policy': create_test_ResourcePolicy(
                'read',
                actions=['rt:read'],
                resource_type=resource_type,
                effect='Allow'
            )}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 201)

        # create a resource policy rw
        resp = self.app.post(
            f"/v1/resource/{resource_type}/policy/rw",
            data=json.dumps({
                'policy': create_test_ResourcePolicy(
                    'rw',
                    actions=['rt:read', 'rt:write', 'rt:delete'],
                    resource_type=resource_type,
                    effect='Allow'
                )},
            ),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 201)

        # create a resource id
        resp = self.app.post(
            f'/v1/resource/{resource_type}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        # create a role with read
        resp = self.app.post(
            f'/v1/role',
            data=json.dumps(
                {'role_id': 'read',
                 'policy': create_test_IAMPolicy(
                     'read',
                     actions=['rt:read'],
                     resource_type=resource_type,
                     effect='Allow'
                 )}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 201)

        # create a role with rw
        resp = self.app.post(
            f'/v1/role',
            data=json.dumps(
                {'role_id': 'rw',
                 'policy': create_test_IAMPolicy(
                     'rw',
                     actions=['rt:read', 'rt:write', 'rt:delete'],
                     resource_type=resource_type,
                     effect='Allow'
                 )}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 201)

        # create a user
        resp = self.app.post(
            f'/v1/user',
            data=json.dumps({'user_id': user}),
            headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        # user fails to read resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:read'],
                 'resource': [resource_arn]}
            )
        )
        self.assertFalse(json.loads(resp.body)['result'])

        # give the user role read
        resp = self.app.put(
            f'/v1/user/{user}/roles?action=add',
            headers=admin_headers,
            data=json.dumps(
                {'roles': ['read']}
            )

        )
        self.assertEqual(resp.status_code, 200)

        # user fails to read resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:read'],
                 'resource': [resource_arn]}
            )
        )
        self.assertFalse(json.loads(resp.body)['result'])

        # give the user access level read
        request_body = [
            {'member': user,
             'member_type': 'user',
             'access_level': 'read'}
        ]
        resp = self.app.put(
            f'/v1/resource/{resource_type}/id/{resource_id}/members',
            data=json.dumps(request_body),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 200)

        # the user has read access to resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:read'],
                 'resource': [resource_arn]}
            )
        )
        self.assertTrue(json.loads(resp.body)['result'])

        # the user does not have write access to resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:write'],
                 'resource': [resource_arn]}
            )
        )
        self.assertFalse(json.loads(resp.body)['result'])

        # give the user_default group rw access to the resource
        request_body = [
            {'member': group,
             'member_type': 'group',
             'access_level': 'rw'}
        ]
        resp = self.app.put(
            f'/v1/resource/{resource_type}/id/{resource_id}/members',
            data=json.dumps(request_body),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 200)

        # the user does not have write access to resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:write'],
                 'resource': [resource_arn]}
            )
        )
        self.assertFalse(json.loads(resp.body)['result'])

        # give the group role rw
        resp = self.app.put(
            f'/v1/group/{group}/roles?action=add',
            headers=admin_headers,
            data=json.dumps(
                {'roles': ['rw']}
            )

        )
        self.assertEqual(resp.status_code, 200)

        # the user does have write access to resource
        resp = self.app.post(
            '/v1/policies/evaluate',
            headers=admin_headers,
            data=json.dumps(
                {'principal': user,
                 'action': ['rt:write'],
                 'resource': [resource_arn]}
            )
        )
        self.assertTrue(json.loads(resp.body)['result'])

if __name__ == '__main__':
    unittest.main()
