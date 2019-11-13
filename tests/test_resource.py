import os
import sys
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.clouddirectory import cleanup_directory, cleanup_schema, get_json_file, \
    default_group_policy_path
from fusillade.errors import FusilladeHTTPException
from fusillade.resource import ResourceType
from tests.common import new_test_directory
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

    def test_create_resource_type(self):
        actions = ['readproject', 'writeproject', 'deleteproject']
        resource_type = 'project'
        # a resource type is created
        ResourceType.create(resource_type, actions)
        projects_type = ResourceType(resource_type)

        # cannot do twice
        with self.assertRaises(FusilladeHTTPException):
            ResourceType.create(resource_type, actions)
        # actions are set
        self.assertTrue(set(projects_type.actions) == set(actions))

        # owner policy exists
        self.assertIn(f'/resource/{resource_type}/policy/Owner', projects_type.list_policies()[0])
