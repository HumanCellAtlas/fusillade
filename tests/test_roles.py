import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.errors import FusilladeHTTPException
from fusillade.directory import Role, cleanup_directory, cleanup_schema, clear_cd
from fusillade.directory.principal import default_role_path
from fusillade.utils.json import get_json_file
from tests.common import new_test_directory, create_test_statements, normalize_json, \
    create_test_IAMPolicy
from tests.infra.testmode import standalone
from tests.json_mixin import AssertJSONMixin


@standalone
class TestRole(unittest.TestCase, AssertJSONMixin):
    @classmethod
    def setUpClass(cls):
        cls.directory, cls.schema_arn = new_test_directory()
        cls.default_role_statement = normalize_json(get_json_file(default_role_path))

    @classmethod
    def tearDownClass(cls):
        cleanup_directory(cls.directory._dir_arn)
        cleanup_schema(cls.schema_arn)

    def tearDown(self):
        clear_cd(self.directory)

    def test_role_default(self):
        with self.subTest("a role is set to default policy when role.create is called without a statement."):
            role_name = "test_role_default"
            role = Role.create(role_name)
            self.assertEqual(role.name, role_name)
            self.assertJSONEqual(role.get_policy(), self.default_role_statement)

    def test_role_statement(self):
        role_name = "test_role_specified"
        statement = create_test_IAMPolicy(role_name)
        role = Role.create(role_name, statement)
        with self.subTest("a role is created with specified statement when role.create is called with a statement"):
            self.assertEqual(role.name, role_name)

        with self.subTest("a roles statement is retrieved when role.get_policy() is called"):
            self.assertJSONEqual(role.get_policy(), statement)

        with self.subTest("a roles statement is changed when role.get_policy() is assigned"):
            statement = create_test_IAMPolicy(f"UserPolicySomethingElse")
            role.set_policy(statement)
            self.assertJSONEqual(role.get_policy(), statement)

        with self.subTest("Error raised when setting policy to an invalid statement"):
            with self.assertRaises(FusilladeHTTPException):
                role.set_policy({"Statement": "Something else"})
            self.assertJSONEqual(role.get_policy(), statement)

        statement = create_test_statements(150)
        with self.subTest("an error is returned when a policy that exceeds 10 Kb for a pre-existing role"):
            with self.assertRaises(FusilladeHTTPException) as ex:
                role.set_policy(statement)

        with self.subTest("an error is returned when a policy that exceeds 10 Kb for a new role"):
            with self.assertRaises(FusilladeHTTPException) as ex:
                Role.create("test_role_specified_2", statement)


if __name__ == '__main__':
    unittest.main()
