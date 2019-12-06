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


class ResourceTypeName:
    rt_count = 0

    @classmethod
    def get(self):
        self.rt_count += 1
        return f'sample_rt_{self.rt_count}'


class TestResourceApi(BaseAPITest, AssertJSONMixin, unittest.TestCase):

    def test_create_resource(self):
        """A resource type is created and destroyed using the API"""
        test_resource = ResourceTypeName.get()  # the name of the resource type to create

        # the resource type should not exist yet
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

        # create the resource type
        resp = self.app.post(f'/v1/resource/{test_resource}', data=json.dumps({'actions': ['tr:action1']}),
                             headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        # the resource type exists
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)

        # delete the resource type
        resp = self.app.delete(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 200)

        # the resource type should not exist
        resp = self.app.get(f'/v1/resource/{test_resource}', headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

    def test_access_resource(self):
        """A user does not have access to a resource when they do not have permission."""
        test_resource = ResourceTypeName.get()
        role_name = 'test_role'
        resp = self.app.post(f'/v1/resource/{test_resource}', data=json.dumps({'actions': ['tr:action1']}),
                             headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        with self.subTest("Permission is denied"):
            resp = self.app.get(f'/v1/resource/{test_resource}', headers=user_header)
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
                    'Resource': [f"arn:hca:fus:*:*:resource/{test_resource}"]
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
            resp = self.app.get(f'/v1/resource/{test_resource}', headers=user_header)
            self.assertEqual(resp.status_code, 200)

    def test_get_resource(self):
        """Pages of resource are retrieved when using the get resource API"""
        for i in range(11):
            self.app.post(f'/v1/resource/{ResourceTypeName.get()}', data=json.dumps({'actions': ['tr:action1']}),
                          headers=admin_headers)
        self._test_paging('/v1/resource', admin_headers, 10, 'resources')

    def test_get_resource_policy(self):
        """Pages of resource are retrieved when using the get resource API"""
        test_resource = ResourceTypeName.get()
        resp = self.app.post(f'/v1/resource/{test_resource}', data=json.dumps({'actions': ['trp:action1']}),
                             headers=admin_headers)
        self.assertEqual(resp.status_code, 201)
        for i in range(11):
            resp = self.app.post(f'/v1/resource/{test_resource}/policy/tp{i}',
                                 data=json.dumps(
                                     {'policy': create_test_ResourcePolicy('tp{i}', actions=['trp:action1'])}),
                                 headers=admin_headers)
            self.assertEqual(resp.status_code, 201)
        self._test_paging(f'/v1/resource/{test_resource}/policy', admin_headers, 10, 'policies')

    def test_resource_policy(self):
        """Create delete and update a resource policy"""
        expected_actions = sorted(['rt:get', 'rt:put', 'rt:update', 'rt:delete'])
        test_resource = ResourceTypeName.get()
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
        test_resource = ResourceTypeName.get()
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


class TestResourceIdApi(BaseAPITest, AssertJSONMixin, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.test_resource = ResourceTypeName.get()
        cls.actions = sorted(['rt:get', 'rt:put', 'rt:update', 'rt:delete'])
        cls.app.post(
            f'/v1/resource/{cls.test_resource}',
            data=json.dumps({'actions': cls.actions}),
            headers=admin_headers)

        cls.app.post(
            f"/v1/resource/{cls.test_resource}/policy/read",
            data=json.dumps({'policy': create_test_ResourcePolicy('read', actions=['rt:get'])}),
            headers=admin_headers
        )

        cls.app.post(
            f"/v1/resource/{cls.test_resource}/policy/write",
            data=json.dumps({
                'policy': create_test_ResourcePolicy('write',
                                                     actions=['rt:get', 'rt:put', 'rt:update', 'rt:delete'])}),
            headers=admin_headers
        )

    def test_get_resource_ids(self):
        """Pages of resource ids are retrieved when using the get resource API"""
        for i in range(11):
            self.app.post(f'/v1/resource/{self.test_resource}/id/test{i}', headers=admin_headers)
        self._test_paging(f'/v1/resource/{self.test_resource}/id', admin_headers, 10, 'resource_ids')

    def test_resource_id(self):
        """Create a resource id, check that it exists, and delete it"""
        resource_id = '1234-1234-1234'

        # resource id does not exist
        resp = self.app.get(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

        # create a resource ID
        resp = self.app.post(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        # resource id exists
        resp = self.app.get(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 200)

        # cannot create twice
        resp = self.app.post(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 409)

        # delete resource id
        resp = self.app.delete(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 200)

        # resource id does not exist
        resp = self.app.get(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 404)

    def test_get_member(self):
        """Pages of resource ids are retrieved when using the get resource API"""
        test_resource = 'test_get_member'
        self.app.post(f'/v1/resource/{self.test_resource}/id/{test_resource}', headers=admin_headers)

        # make groups
        members = []
        for group in [f'rt_group{i}' for i in range(5)]:
            resp = self.app.post(
                f'/v1/group',
                data=json.dumps({'group_id': group}),
                headers=admin_headers)
            self.assertEqual(resp.status_code, 201)
            members.append({'member': group,
                            'member_type': 'group',
                            'access_level': 'read'})

        # make users
        for user in [f'rt_user{i}' for i in range(6)]:
            resp = self.app.post(
                f'/v1/user',
                data=json.dumps({'user_id': user}),
                headers=admin_headers)
            self.assertEqual(resp.status_code, 201)
            members.append({'member': user,
                            'member_type': 'user',
                            'access_level': 'read'})
        for m in members:
            resp = self.app.put(
                f'/v1/resource/{self.test_resource}/id/{test_resource}/members',
                data=json.dumps([m]),
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
        self._test_paging(f'/v1/resource/{self.test_resource}/id/{test_resource}/members', admin_headers, 10, 'members')

    def test_access_levels(self):
        """Grant access to a principal for a resource"""
        resource_id = 'protected-data'
        arn_prefix = "arn:dcp:fus:us-east-1:dev:"
        user = 'user_test_access_levels'
        group = 'group_test_access_levels'

        # create the resource to control
        resp = self.app.post(
            f'/v1/resource/{self.test_resource}/id/{resource_id}',
            headers=admin_headers)
        self.assertEqual(resp.status_code, 201)

        with self.subTest("Check that no one has access by listing who has access"):
            resp = self.app.get(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertJSONEqual(resp.body, {'members': []})

        with self.subTest("Toggle user access."):
            # create a user
            resp = self.app.post(
                f'/v1/user',
                data=json.dumps({'user_id': user}),
                headers=admin_headers)
            self.assertEqual(resp.status_code, 201)

            # give a user access
            request_body = [
                {'member': user,
                 'member_type': 'user',
                 'access_level': 'read'}
            ]
            resp = self.app.put(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                data=json.dumps(request_body),
                headers=admin_headers
            )
            self.assertEqual(resp.status_code, 200)

            # Check that the user has access by list who has access
            resp = self.app.get(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertJSONEqual(resp.body, {'members': request_body})

            # Remove access for the user
            request_body = [
                {'member': user,
                 'member_type': 'user'}
            ]
            resp = self.app.put(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                data=json.dumps(request_body),
                headers=admin_headers
            )
            self.assertEqual(resp.status_code, 200)

            # Check that the user does not have access by listing who has access
            resp = self.app.get(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertJSONEqual(resp.body, {'members': []})

        with self.subTest("Toggle group access."):
            # create a group
            resp = self.app.post(
                f'/v1/group',
                data=json.dumps({'group_id': group}),
                headers=admin_headers)
            self.assertEqual(resp.status_code, 201)

            # give a group access
            request_body = [
                {'member': group,
                 'member_type': 'group',
                 'access_level': 'read'}
            ]
            resp = self.app.put(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                data=json.dumps(request_body),
                headers=admin_headers
            )
            self.assertEqual(resp.status_code, 200)

            # Check that the group has access by list who has access
            resp = self.app.get(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertJSONEqual(resp.body, {'members': request_body})

            # Remove access for the group
            request_body = [
                {'member': group,
                 'member_type': 'group'}
            ]
            resp = self.app.put(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                data=json.dumps(request_body),
                headers=admin_headers
            )
            self.assertEqual(resp.status_code, 200)

            # Check that the group does not have access by listing who has access
            resp = self.app.get(
                f'/v1/resource/{self.test_resource}/id/{resource_id}/members',
                headers=admin_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertJSONEqual(resp.body, {'members': []})

if __name__ == '__main__':
    unittest.main()
