import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.utils.json import json_equal
from fusillade.directory.authorization import get_resource_authz_parameters

from fusillade.directory import cleanup_directory, cleanup_schema, User, clear_cd
from fusillade.errors import FusilladeForbiddenException
from fusillade.directory.resource import ResourceType
from tests.common import new_test_directory
from tests.infra.testmode import standalone


@standalone
class TestEvaluate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory, cls.schema_arn = new_test_directory()

    @classmethod
    def tearDownClass(cls):
        cleanup_directory(cls.directory._dir_arn)
        cleanup_schema(cls.schema_arn)

    def tearDown(self):
        clear_cd(self.directory)

    def test_get_authz_params(self):
        actions = ['test:readproject', 'test:writeproject', 'test:deleteproject']
        arn_prefix = "arn:dcp:fus:us-east-1:dev:"
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
                    "Resource": f"{arn_prefix}{resource_type}/*"
                }
            ]
        }
        test_type.create_policy(access_level, resource_policy, 'ResourcePolicy')
        user = User.provision_user('test_user')
        type_id = '1234455'
        resource = f'{arn_prefix}{resource_type}/{type_id}'

        with self.subTest("A user has no access when no access level set between user and resource"):
            with self.assertRaises(FusilladeForbiddenException):
                get_resource_authz_parameters(user.name, resource)

        with self.subTest("No resource policy parameters are returned when the user tries to access a resource that "
                          "does not use resource policies"):
            params = get_resource_authz_parameters(user.name, f"{arn_prefix}non_acl_resource/1234")
            self.assertFalse(params.get('ResourcePolicy'))
            self.assertFalse(params.get('resources'))

        with self.subTest("The resource policy for the access level assigned to the user is returned when a user "
                          "is given access to a resource"):
            test_id = test_type.create_id(type_id)
            test_id.add_principals([user], access_level)
            params = get_resource_authz_parameters(user.name, resource)
            self.assertTrue(json_equal(params['ResourcePolicy'], resource_policy))
            self.assertEqual(['Reader'], params['resources'])


if __name__ == '__main__':
    unittest.main()
