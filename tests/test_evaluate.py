import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.utils.json import json_equal
from fusillade.directory.authorization import get_resource_authz_parameters
from fusillade.utils.authorize import evaluate_policy
from fusillade.directory import cleanup_directory, cleanup_schema, User, clear_cd, Role
from fusillade.errors import FusilladeForbiddenException, ResourceNotFound, AuthorizationException
from fusillade.directory.resource import ResourceType
from tests.common import new_test_directory
from tests.infra.testmode import standalone


@standalone
class TestEvaluate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory, cls.schema_arn = new_test_directory()
        cls.arn_prefix = "arn:dcp:fus:us-east-1:dev:"

    @classmethod
    def tearDownClass(cls):
        cleanup_directory(cls.directory._dir_arn)
        cleanup_schema(cls.schema_arn)

    def tearDown(self):
        clear_cd(self.directory)

    def test_get_authz_params(self):
        actions = ['test:readproject', 'test:writeproject', 'test:deleteproject']
        resource_type = 'test_type'
        test_type = ResourceType.create(resource_type, actions)
        access_level = 'Reader'
        resource_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Principal": "*",
                    "Sid": "project_reader",
                    "Effect": "Allow",
                    "Action": ['test:readproject'],
                    "Resource": f"{self.arn_prefix}{resource_type}/*"
                }
            ]
        }
        test_type.create_policy(access_level, resource_policy, 'ResourcePolicy')
        user = User.provision_user('test_user')
        type_id = '1234455'
        resource = f'{self.arn_prefix}{resource_type}/{type_id}'

        with self.subTest("A user has no access when no access level set between user and resource"):
            with self.assertRaises(ResourceNotFound):
                get_resource_authz_parameters(user.name, resource)

        with self.subTest("No resource policy parameters are returned when the user tries to access a resource that "
                          "does not use resource policies"):
            params = get_resource_authz_parameters(user.name, f"{self.arn_prefix}non_acl_resource/1234")
            self.assertFalse(params.get('ResourcePolicy'))
            self.assertFalse(params.get('resources'))

        with self.subTest("The resource policy for the access level assigned to the user is returned when a user "
                          "is given access to a resource"):
            test_id = test_type.create_id(type_id)
            test_id.add_principals([user], access_level)
            params = get_resource_authz_parameters(user.name, resource)
            self.assertTrue(json_equal(params['ResourcePolicy'], resource_policy))
            self.assertEqual(['Reader'], params['resources'])

        with self.subTest("No access when the user is disabled."):
            user.disable()
            with self.assertRaises(AuthorizationException):
                get_resource_authz_parameters(user.name, resource)

    def test_auto_provision(self):
        """A user is automatically provision if the user does not exist in cloud directory, when evaluating
        permissions."""
        params = get_resource_authz_parameters("test_auto_provision", f"{self.arn_prefix}non_acl_resource/1234")
        self.assertTrue(params)


    def test_eval(self):
        actions = ['test:readproject', 'test:writeproject', 'test:deleteproject']
        resource_type = 'test_type'
        test_type = ResourceType.create(resource_type, actions)
        access_level = 'Reader'
        resource_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Principal": "*",
                    "Sid": "project_reader",
                    "Effect": "Allow",
                    "Action": ['test:readproject'],
                    "Resource": f"{self.arn_prefix}{resource_type}/*"
                }
            ]
        }
        test_type.create_policy(access_level, resource_policy, 'ResourcePolicy')
        user = User.provision_user('test_user')
        type_id = '1234455'
        resource = f'{self.arn_prefix}{resource_type}/{type_id}'

        with self.subTest("A user does not have access when they only have permitting resource_policy and no "
                          "permitting IAMPolicy"):
            test_id = test_type.create_id(type_id)
            test_id.add_principals([user], access_level)
            x = get_resource_authz_parameters(user.name, resource)
            resp = evaluate_policy(user.name, ['test:readproject'], [resource], x['IAMPolicy'], x['ResourcePolicy'])
            self.assertFalse(resp['result'])

        with self.subTest("A user has a access when they have a permitting resource policy and IAMPolicy"):
            IAMpolicy = {
                "Statement": [
                    {
                        "Sid": "project_reader",
                        "Effect": "Allow",
                        "Action": [
                            "test:readproject"
                        ],
                        "Resource": f"{self.arn_prefix}{resource_type}/*"
                    }
                ]
            }
            role = Role.create('project_reader', IAMpolicy)

            user.add_roles([role.name])
            x = get_resource_authz_parameters(user.name, resource)
            resp = evaluate_policy(user.name, ['test:readproject'], [resource], x['IAMPolicy'], x['ResourcePolicy'])
            self.assertTrue(resp['result'])


if __name__ == '__main__':
    unittest.main()
