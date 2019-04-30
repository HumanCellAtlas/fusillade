import unittest
import os, sys

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.errors import FusilladeException
from fusillade.clouddirectory import User, Group, cd_client, cleanup_directory, cleanup_schema, get_json_file, \
    default_group_policy_path
from tests.common import new_test_directory, create_test_statement


class TestGroup(unittest.TestCase):

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

    def test_create_group(self):
        with self.subTest("an error is returned when the group has not been created."):
            self.assertRaises(cd_client.exceptions.ResourceNotFoundException, Group, self.directory, 'not_created')

        with self.subTest("an error is returned when creating a group with an invalid statement."):
            with self.assertRaises(FusilladeException):
                group = Group.create(self.directory, "new_group1", "does things")

        with self.subTest("The group is returned when the group has been created with default valid statement"):
            group = Group.create(self.directory, "new_group2")
            self.assertEqual(group.name,  "new_group2")
            self.assertEqual(group.statement, self.default_group_statement)

        with self.subTest("The group is returned when the group has been created with specified valid statement."):
            group_name = "NewGroup1234"
            statement = create_test_statement(group_name)
            group = Group.create(self.directory, "new_group3", statement)
            self.assertEqual(group.name,  "new_group3")
            self.assertEqual(group.statement, statement)

    def test_policy(self):
        group = Group.create(self.directory, "new_group")
        with self.subTest("Only one policy is attached when lookup policy is called on a group without any roles"):
            policies = group.lookup_policies()
            self.assertEqual(len(policies), 1)
            self.assertEqual(policies[0], self.default_group_statement)

        group_name = "NewGroup1234"
        statement = create_test_statement(group_name)
        with self.subTest("The group policy changes when satement is set"):
            group.statement = statement
            policies = group.lookup_policies()
            self.assertEqual(policies[0], statement)

        with self.subTest("error raised when invalid statement assigned to group.statement."):
            with self.assertRaises(FusilladeException):
                group.statement = "invalid statement"
            self.assertEqual(policies[0], statement)

    def test_users(self):
        emails = ["test@test.com", "why@not.com", "hello@world.com"]
        users = [User(self.directory, email) for email in emails]
        with self.subTest("A user is added to the group when add_users is called"):
            group = Group.create(self.directory, "test")
            user = User(self.directory, "another@place.com")
            group.add_users([user])
            actual_users = [i[1] for i in group.get_users()]
            self.assertEqual(len(actual_users), 1)
            self.assertEqual(User(self.directory,object_ref=actual_users[0]).name, user.name)

        with self.subTest("Multiple users are added to the group when multiple users are passed to add_users"):
            group = Group.create(self.directory, "test2")
            group.add_users(users)
            actual_users = [i[1] for i in group.get_users()]
            self.assertEqual(len(actual_users), 3)

        with self.subTest("Error returned when a user is added to a group it's already apart of."):
            group = Group.create(self.directory, "test3")
            group.add_users(users)
            try:
                group.add_users(users)
            except cd_client.exceptions.BatchWriteException:
                pass
            actual_users = [i[1] for i in group.get_users()]
            self.assertEqual(len(actual_users), 3)

        with self.subTest("Error returned when adding a user that does not exist"):
            group = Group.create(self.directory, "test4")
            user = User(self.directory, "ghost_user@nowhere.com", local=True)
            try:
                group.add_users([user])
            except cd_client.exceptions.BatchWriteException:
                pass

if __name__ == '__main__':
    unittest.main()
