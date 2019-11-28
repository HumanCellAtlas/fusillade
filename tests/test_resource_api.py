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

from tests.json_mixin import AssertJSONMixin
from tests.base_api_test import BaseAPITest
from tests.common import get_auth_header, service_accounts, create_test_ResourcePolicy

admin_headers = {'Content-Type': "application/json"}
admin_headers.update(get_auth_header(service_accounts['admin']))

user_header = {'Content-Type': "application/json"}
user_header.update(get_auth_header(service_accounts['user']))


class TestApi(BaseAPITest, AssertJSONMixin, unittest.TestCase):

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
                            headers=admin_headers)
        self.assertEqual(resp.status_code, 200)

        with self.subTest("Permission is granted"):
            resp = self.app.get(f'/v1/resource/{rt_name}', headers=user_header)
            self.assertEqual(resp.status_code, 200)

    def test_get_resource(self):
        """Pages of resource are retrieved when using the get resource API"""
        for i in range(11):
            self.app.post(f'/v1/resource/tr{i}', data=json.dumps({'actions': ['tr:action1']}), headers=admin_headers)
        self._test_paging('/v1/resource', admin_headers, 10, 'resources')

    def test_get_resource_policy(self):
        """Pages of resource are retrieved when using the get resource API"""
        resp = self.app.post(f'/v1/resource/trp', data=json.dumps({'actions': ['trp:action1']}),
                      headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        for i in range(11):
            resp = self.app.post(f'/v1/resource/trp/policy/tp{i}',
                          data=json.dumps({'policy':create_test_ResourcePolicy('tp{i}', actions=['trp:action1'])}),
                          headers=admin_headers)
            self.assertEqual(resp.status_code, 201)
        self._test_paging('/v1/resource/trp/policy', admin_headers, 10, 'policies')

    def test_resource_policy(self):
        """Create delete and update a resource policy"""
        expected_actions = sorted(['rt:get', 'rt:put', 'rt:update', 'rt:delete'])
        test_resource = 'sample_resource'
        test_policy_name = 'test_policy'
        test_policy = create_test_ResourcePolicy('tp{i}', actions=expected_actions)
        self.app.post(
            f'/v1/resource/{test_resource}',
            data=json.dumps({'actions': expected_actions}),
            headers=admin_headers)

        # 400 returned when creating a policy with invalid actions
        test_policy = create_test_ResourcePolicy('tp{i}', actions=['invalid:actions'])
        resp = self.app.post(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            data=json.dumps({'policy': test_policy}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 400)
        resp = self.app.get(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 404)

        # 201 return when creating a valid resource policy
        test_policy = create_test_ResourcePolicy('tp{i}', actions=expected_actions)
        resp = self.app.post(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            data=json.dumps({'policy': test_policy}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertJSONEqual(json.loads(resp.body)['policy_document'], test_policy)

        # 200 returned when modifying the policy with valid actions
        test_policy = create_test_ResourcePolicy('tp{i}', actions=expected_actions[:2])
        resp = self.app.put(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            data=json.dumps({'policy': test_policy}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertJSONEqual(json.loads(resp.body)['policy_document'], test_policy)

        # 400 returned when modifying the policy with invalid actions
        test_policy2 = create_test_ResourcePolicy('tp{i}', actions=['invalid:actions'])
        resp = self.app.put(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            data=json.dumps({'policy': test_policy2}),
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 400)
        resp = self.app.get(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertJSONEqual(json.loads(resp.body)['policy_document'], test_policy)

        # delete the policy
        resp = self.app.delete(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get(
            f"/v1/resource/{test_resource}/policy/{test_policy_name}",
            headers=admin_headers
        )
        self.assertEqual(resp.status_code, 404)

    def test_resource_actions(self):
        """Add and remove actions from a resource type"""
        test_resource = 'sample_resource'
        expected_actions = sorted(['rt:get', 'rt:put', 'rt:update', 'rt:delete'])
        self.app.post(
            f'/v1/resource/{test_resource}',
            data=json.dumps({'actions': expected_actions}),
            headers=admin_headers)

        # Get the actions for a resource type
        resp = self.app.get(f'/v1/resource/{test_resource}/actions', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        actions = json.loads(resp.body)['actions']
        self.assertEqual(actions, expected_actions)

        # Delete actions from a resource type
        modify_actions = expected_actions[-2:]
        resp = self.app.delete(f'/v1/resource/{test_resource}/actions',
                               data=json.dumps({'actions': modify_actions}),
                               headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get(f'/v1/resource/{test_resource}/actions',
                            data=json.dumps({'actions': modify_actions}),
                            headers=admin_headers)
        actions = sorted(json.loads(resp.body)['actions'])
        self.assertEqual(actions, expected_actions[:2])

        # OK returned when deleting actions not part of a resource type
        resp = self.app.delete(f'/v1/resource/{test_resource}/actions',
                               data=json.dumps({'actions': modify_actions}),
                               headers=admin_headers)

        # Put actions into a resource type
        resp = self.app.put(f'/v1/resource/{test_resource}/actions',
                            data=json.dumps({'actions': modify_actions}),
                            headers=admin_headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get(f'/v1/resource/{test_resource}/actions',
                            data=json.dumps({'actions': modify_actions}),
                            headers=admin_headers)
        actions = sorted(json.loads(resp.body)['actions'])
        self.assertEqual(actions, expected_actions)

        # OK returned when putting actions already a part of a resource type.
        resp = self.app.put(f'/v1/resource/{test_resource}/actions',
                            data=json.dumps({'actions': modify_actions}),
                            headers=admin_headers)
        self.assertEqual(resp.status_code, 200)


if __name__ == '__main__':
    unittest.main()