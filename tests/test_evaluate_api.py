import json
import unittest

from furl import furl

from tests import eventually
from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts


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