from tests.common import normalize_json


class AssertJSONMixin:
    """This class must be added into a class that inherits unittest.TestCase"""

    def assertJSONEqual(self, expected, actual, *args, **kwargs):
        self.assertEqual(normalize_json(expected), normalize_json(actual), *args, **kwargs)

    def assertJSONListEqual(self, expected, actual, *args, **kwargs):
        "check if two lists of json objects are equal."
        expected = set([normalize_json(i) for i in expected])
        actual = set([normalize_json(i) for i in actual])
        self.assertEqual(expected, actual, *args, **kwargs)

    def assertJSONIn(self, member, group, *args, **kwargs):
        group = set([normalize_json(i) for i in group])
        member = normalize_json(member)
        self.assertIn(member, group, *args, **kwargs)