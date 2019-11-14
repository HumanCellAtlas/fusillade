import json
import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.clouddirectory import cleanup_directory, cleanup_schema, get_json_file, \
    default_group_policy_path, User
from fusillade.errors import FusilladeBadRequestException, FusilladeNotFoundException, FusilladeHTTPException
from fusillade.resource import ResourceType
from tests.common import new_test_directory, create_test_statement
from tests.infra.testmode import standalone


@standalone
class TestResourceType(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.directory, cls.schema_arn = new_test_directory()
        cls.default_group_statement = get_json_file(default_group_policy_path)

    @classmethod
    def tearDownClass(cls):
        cleanup_directory(cls.directory._dir_arn)
        cleanup_schema(cls.schema_arn)

    def tearDown(self):
        self.directory.clear()

    def _create_resource_type(self, name='test_type', actions=None):
        actions = actions or ['readproject', 'writeproject', 'deleteproject']
        return ResourceType.create(name, actions)

    def test_create_resource_type(self):
        actions = ['readproject', 'writeproject', 'deleteproject']
        resource_type = 'test_type'
        # a resource type is created
        self._create_resource_type(resource_type, actions)
        test_type = ResourceType(resource_type)

        # cannot do twice
        with self.assertRaises(FusilladeHTTPException):
            ResourceType.create(resource_type, actions)

        # actions are set
        self.assertTrue(set(test_type.actions) == set(actions))

        # owner policy exists
        self.assertIn(f'/resource/{resource_type}/policy/Owner', test_type.list_policies()[0])

    def test_access_policy(self):
        actions = ['readproject', 'writeproject', 'deleteproject']
        resource_type = 'test_type'
        test_type = self._create_resource_type(resource_type, actions)

        # add an access policy
        expected_policy = create_test_statement("resource policy", actions)
        test_type.create_policy('Reader', expected_policy, 'ResourcePolicy')

        # retrieve a specific access policy
        test_policy = test_type.get_policy('Reader')
        self.assertDictEqual(expected_policy, json.loads(test_policy['policy_document']))
        self.assertEqual('ResourcePolicy', test_policy['policy_type'])

        # retrieve all policies
        policies, _ = test_type.list_policies()
        self.assertIn(f'/resource/{resource_type}/policy/Reader', policies)
        self.assertIn(f'/resource/{resource_type}/policy/Owner', policies)

        # update a policy
        expected_policy = create_test_statement("updated", actions[0:1])
        test_type.update_policy('Reader', expected_policy)
        self.assertDictEqual(expected_policy, json.loads(test_type.get_policy('Reader')['policy_document']))

        # invalid actions raise an exception
        with self.assertRaises(FusilladeBadRequestException) as ex:
            expected_policy = create_test_statement("updated")
            test_type.update_policy('Reader', expected_policy)

        # remove policy
        test_type.delete_policy('Reader')
        with self.assertRaises(FusilladeNotFoundException):
            test_type.delete_policy('Reader')
        with self.assertRaises(FusilladeNotFoundException):
            test_type.get_policy('Reader')

    def test_actions(self):
        actions = ['action0']
        test_type = self._create_resource_type(actions=actions)

        # add actions
        more_actions = ['action2', 'action1']
        test_type.add_actions(more_actions)
        self.assertEqual(set(test_type.actions), set(actions + more_actions))

        # adding existing actions doesn't change actions
        test_type.add_actions(more_actions)
        self.assertEqual(set(actions + more_actions), set(test_type.actions))

        # adding new and old actions only adds new actions
        new_actions = ['ABCD']
        test_type.add_actions(more_actions + new_actions)
        self.assertEqual(set(actions + more_actions + new_actions), set(test_type.actions))

        # actions can be removed
        test_type.remove_actions(more_actions)
        self.assertEqual(set(actions + new_actions), set(test_type.actions))

        # actions that don't exist will not be removed
        test_type.remove_actions(more_actions)
        self.assertEqual(set(actions + new_actions), set(test_type.actions))

    def test_resource_id(self):
        resource_type = 'test_type'
        test_type = self._create_resource_type(resource_type)

        # add an access policy
        test_type.create_policy('Reader', create_test_statement("resource policy", ['readproject']), 'ResourcePolicy')

        test_id = test_type.create_id('ABCD')

        # list ids
        test_types = test_type.list_ids()
        self.assertTrue(test_types)

        # give a user read access to the id
        user = User('public')
        test_id.add_principals([user], 'Reader')
        self.assertEqual(test_id.check_access(user), 'Reader')

        # update access
        test_type.create_policy('RW', create_test_statement("resource policy", ['readproject', 'writeproject']),
                                'ResourcePolicy')
        test_id.update_principal(user, 'RW')
        self.assertEqual(test_id.check_access(user), 'RW')

        # remove access
        test_id.remove_principals([user])
        self.assertEqual(test_id.check_access(user), None)


if __name__ == '__main__':
    unittest.main()
