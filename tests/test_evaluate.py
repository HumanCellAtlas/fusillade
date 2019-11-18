import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.directory.authorization import get_resource_authz_parameters
from fusillade.utils.authorize import evaluate_policy

from fusillade.directory import cleanup_directory, cleanup_schema, User, clear_cd, Role
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

    def test_eval(self):
        actions = ['test:readproject', 'test:writeproject', 'test:deleteproject']
        arn_prefix = "arn:dcp:fus:us-east-1:dev:"
        resource_type = 'test_type'
        test_type = ResourceType.create(resource_type, actions)
        access_level = 'Reader'
        test_type.create_policy(access_level,
                                {
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
                                },
                                'ResourcePolicy')
        type_id = '1234455'
        user = User.provision_user('test_user')
        resource = f'{arn_prefix}{resource_type}/{type_id}'

        # No access
        with self.assertRaises(FusilladeForbiddenException):
            get_resource_authz_parameters(user.name, resource)

        # access level only
        test_id = test_type.create_id(type_id)
        test_id.add_principals([user], access_level)
        x = get_resource_authz_parameters(user.name, resource)
        resp = evaluate_policy(user.name, ['test:readproject'], [resource], x['IAMPolicy'], x['ResourcePolicy'])
        self.assertFalse(resp['result'])

        # added Role
        role = Role.create('project_reader', {
            "Statement": [
                {
                    "Sid": "project_reader",
                    "Effect": "Allow",
                    "Action": [
                        "test:readproject"
                    ],
                    "Resource": f"{arn_prefix}{resource_type}/*"
                }
            ]
        })

        user.add_roles([role.name])
        x = get_resource_authz_parameters(user.name, resource)
        resp = evaluate_policy(user.name, ['test:readproject'], [resource], x['IAMPolicy'], x['ResourcePolicy'])
        self.assertTrue(resp['result'])


if __name__ == '__main__':
    unittest.main()
