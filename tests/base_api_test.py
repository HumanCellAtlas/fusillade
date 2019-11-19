import json
import os

from furl import furl

from tests.common import service_accounts, new_test_directory, get_auth_header
from tests.infra.testmode import is_integration

if not is_integration():
    old_directory_name = os.getenv("FUSILLADE_DIR", None)

from fusillade import Config
from fusillade.directory import cleanup_directory, User, get_published_schema_from_directory, cleanup_schema
from fusillade.directory import clear_cd

class BaseAPITest():

    @classmethod
    def setUpClass(cls):
        if not is_integration():
            new_test_directory()

        try:
            User.provision_user(service_accounts['admin']['client_email'], roles=['fusillade_admin'])
        except Exception:
            pass

        if is_integration():
            from tests.infra.integration_server import IntegrationTestHarness
            cls.app = IntegrationTestHarness()
        else:
            from tests.infra.server import ChaliceTestHarness
            # ChaliceTestHarness must be imported after FUSILLADE_DIR has be set
            cls.app = ChaliceTestHarness()
        cls._save_state()

    @classmethod
    def _save_state(cls):
        headers = {'Content-Type': "application/json"}
        headers.update(get_auth_header(service_accounts['admin']))

        def _iterator(url, key):
            url = furl(url)
            url.add(query_params={'per_page': 30})
            resp = cls.app.get(url.url, headers=headers)
            results = json.loads(resp.body).get(key, [])
            while "Link" in resp.headers:
                next_url = resp.headers['Link'].split(';')[0][1:-1]
                resp = cls.app.get(next_url, headers=headers)
                results.extend(json.loads(resp.body)[key])
            return results

        cls.saved_groups = _iterator('/v1/groups', 'groups')
        cls.saved_users = _iterator('/v1/users', 'users')
        cls.saved_roles = _iterator('/v1/roles', 'roles')

    @classmethod
    def clear_directory(cls, **kwargs):
        kwargs["users"] = kwargs.get('users', []) + [*Config.get_admin_emails()] + cls.saved_users
        kwargs["groups"] = kwargs.get('groups', []) + cls.saved_groups
        kwargs["roles"] = kwargs.get('roles', []) + cls.saved_roles
        clear_cd(Config.get_directory(), **kwargs)

    @classmethod
    def tearDownClass(cls):
        cls.clear_directory()
        if not is_integration():
            directory_arn = Config.get_directory()._dir_arn
            schema_arn = get_published_schema_from_directory(directory_arn)
            cleanup_directory(directory_arn)
            cleanup_schema(f"{schema_arn}/0")
            if old_directory_name:
                os.environ["FUSILLADE_DIR"] = old_directory_name

    def _test_paging(self, url, headers, per_page, key):
        url = furl(url)
        url.add(query_params={'per_page': per_page})
        resp = self.app.get(url.url, headers=headers)
        self.assertEqual(206, resp.status_code)
        self.assertEqual(per_page, len(json.loads(resp.body)[key]))
        self.assertTrue("Link" in resp.headers)
        self.assertTrue ("X-OpenAPI-Pagination", resp.headers)
        self.assertEqual(resp.headers['X-OpenAPI-Paginated-Content-Key'], key)
        while "Link" in resp.headers:
            next_url = resp.headers['Link'].split(';')[0][1:-1]
            resp = self.app.get(next_url, headers=headers)
            self.assertIn(resp.status_code, [200, 206])
        else:
            self.assertEqual(200, resp.status_code)
            next_results = json.loads(resp.body)[key]
            self.assertLessEqual(len(next_results), per_page)

    def _test_custom_claim(self, func: callable, url: str, headers: dict, body: str):
        _headers = headers.copy()
        _headers.update(get_auth_header(service_accounts['admin'], email=False))
        with self.subTest("Missing Custom Claim"):
            resp = func(
                url,
                headers=_headers,
                data=body)
            self.assertEqual(403, resp.status_code)
