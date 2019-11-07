from tests.common import normalize_json


class AssertJSONMixin:
    """This class must be added into a class that inherits unittest.TestCase"""

    def assertJSONEqual(self, expected, actual, *args, **kwargs):
        self.assertEqual(normalize_json(expected), normalize_json(actual), *args, **kwargs)
