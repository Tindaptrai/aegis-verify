"""Only the separately built public Manager entry may become the browser shell."""
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase, override_settings


class ManagerShellTests(SimpleTestCase):
    def setUp(self):
        self.folder = TemporaryDirectory(prefix="aegis-shell-synthetic-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root / "assets").mkdir()
        (self.root / "assets/manager-test.js").write_text("// synthetic public build")
        self.html = '<!doctype html><html><head><script type="module" src="/static/manager/assets/manager-test.js"></script></head><body><div id="root"></div></body></html>'
        (self.root / "manager.html").write_text(self.html, encoding="utf-8")

    def unavailable(self, root):
        with override_settings(MANAGER_UI_ROOT=root):
            response = self.client.get("/manager/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": {"code": "manager_ui_unavailable"}})
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertNotIn(str(self.root), response.content.decode())

    def test_valid_public_shell_and_root_redirect(self):
        with override_settings(MANAGER_UI_ROOT=str(self.root)):
            response = self.client.get("/manager/")
            redirect = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), self.html)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(redirect.status_code, 302)
        self.assertEqual(redirect.url, "/manager/")

    def test_missing_manager_build_is_explicit(self):
        self.unavailable(None)
        self.unavailable(self.root / "absent")
        (self.root / "manager.html").unlink()
        self.unavailable(self.root)

    def test_invalid_build_never_falls_back_to_dashboard(self):
        for content in ("<html>dashboard</html>", '<script src="/assets/dashboard.js"></script>',
                        '<script src="/static/manager/assets/../private.js"></script>',
                        '<script src="https://example.invalid/app.js"></script>',
                        '<script src="/static/manager/assets/missing.js"></script>'):
            with self.subTest(content=content):
                (self.root / "manager.html").write_text(content)
                self.unavailable(self.root)

    def test_duplicate_reference_cannot_hide_a_private_browser_target(self):
        (self.root / "manager.html").write_text('<script src="/private/secret.js" src="/static/manager/assets/manager-test.js"></script>')
        self.unavailable(self.root)

    def test_private_files_and_mixed_dashboard_build_rejected(self):
        for name in ("index.html", "private.env", "assets/private.json"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("synthetic-private-do-not-serve")
                self.unavailable(self.root)
                path.unlink()

    def test_symlink_build_entry_and_parent_rejected(self):
        target = self.root / "assets/manager-test.js"
        target.unlink()
        outside = self.root / "outside.txt"
        outside.write_text("synthetic-private-do-not-serve")
        # The outside file must not itself invalidate the allowed root shape.
        outside.rename(self.root.parent / (self.root.name + "-outside.txt"))
        outside = self.root.parent / (self.root.name + "-outside.txt")
        self.addCleanup(outside.unlink)
        try:
            target.symlink_to(outside)
        except OSError:
            self.skipTest("Platform does not permit synthetic symlink creation")
        self.unavailable(self.root)
        target.unlink()
        target.write_text("// synthetic public build")
        alias = self.root.parent / (self.root.name + "-alias")
        alias.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(alias.unlink)
        self.unavailable(alias)
        self.unavailable(alias / "assets/..")

    def test_no_private_file_or_static_directory_routes(self):
        with override_settings(MANAGER_UI_ROOT=self.root):
            for url in ("/manager/private.env", "/manager/assets/manager-test.js", "/static/manager/manager.html", "/private/", "/indexer/"):
                self.assertEqual(self.client.get(url).status_code, 404)
            self.assertEqual(self.client.post("/manager/").status_code, 405)
