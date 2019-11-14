import json
import os
import sys
import typing
import unittest

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from scripts import backup
from fusillade.directory import cleanup_directory, cleanup_schema, clear_cd
from tests.common import new_test_directory


class Test_Backup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory, cls.schema_arn = new_test_directory()

    @classmethod
    def tearDownClass(cls):
        cleanup_directory(cls.directory._dir_arn)
        cleanup_schema(cls.schema_arn)

    def tearDown(self):
        clear_cd(self.directory)

    def test_default(self):
        """
        Test the backup file is correct after a basic fusillade directory is initialized
        """
        contents = backup.backup()
        # check public exists in users
        self.AssertInListDict(contents['users'], {'name': 'public', 'status': 'enabled'})
        # check the default_public groups exists
        v = self.AssertInListDict(contents['groups'], {'name': 'user_default', 'status': 'enabled'})
        # check that public is in that groups
        self.assertIn('public', v['members'])
        # check the default roles are in group
        self.assertIn('default_user', v['roles'])
        # check that default_user role exists.
        self.AssertInListDict(contents['roles'], {'name': 'default_user'})

    @staticmethod
    def AssertInListDict(entries: typing.List[typing.Dict[str, typing.Any]], expected: typing.Dict[str, typing.Any]):
        for entry in entries:
            for k, v in expected.items():
                if entry[k] == v:
                    return entry
        raise AssertionError(f"{expected} not found in {entries}")


if __name__ == '__main__':
    unittest.main()
