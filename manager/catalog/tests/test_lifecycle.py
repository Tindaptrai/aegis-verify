"""Real catalog API contracts; all packages and accounts are synthetic."""
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

from accounts.tests.helpers import AccountsCase


class CatalogTests(AccountsCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.settings_override = override_settings(PRIVATE_ROOT=Path(self.private.name))
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    def sample(self):
        from catalog.tests.helpers import build_sample
        return build_sample()

    def upload(self, client, raw=None):
        token = client.get('/api/v1/auth/session').json()['csrf_token']
        return client.post('/api/v1/catalog/import', {'package': SimpleUploadedFile('untrusted.zip', self.sample() if raw is None else raw)}, HTTP_X_CSRFTOKEN=token)

    def imported(self):
        client = self.login_human(self.admin)
        response = self.upload(client)
        self.assertEqual(response.status_code, 201, response.content)
        return client, response.json()

    def test_import_replay_private_storage_and_detail_contract(self):
        client, row = self.imported()
        self.assertEqual(row['scenario_id'], 'SCN-900')
        self.assertEqual(row['status'], 'draft')
        self.assertFalse(row['execution_supported'])
        self.assertEqual(row['validation'], {'valid': True, 'codes': []})
        self.assertEqual([x['action'] for x in row['audit']], ['imported'])
        self.assertEqual(self.upload(client).status_code, 200)
        detail = client.get('/api/v1/catalog/' + row['id']).json()
        self.assertEqual(detail, row)
        listing = client.get('/api/v1/catalog').json()
        self.assertEqual(listing['count'], 1)
        self.assertEqual(listing['page_size'], 50)
        self.assertNotIn('files', listing['results'][0])
        preview = client.get('/api/v1/catalog/' + row['id'] + '/file', {'path': 'README.md'})
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(set(preview.json()), {'path', 'text'})
        self.assertEqual(preview['Cache-Control'], 'no-store')
        from catalog.models import ScenarioPackageVersion
        stored = ScenarioPackageVersion.objects.get(pk=row['id'])
        self.assertTrue((Path(self.private.name) / 'catalog' / stored.storage_reference).is_file())

    def test_publication_requires_exact_digest_is_idempotent_and_retains_history(self):
        client, row = self.imported()
        route = '/api/v1/catalog/' + row['id']
        self.assertEqual(self.human_post(client, route + '/publish', {'sha256': '0' * 64}).status_code, 409)
        published = self.human_post(client, route + '/publish', {'sha256': row['sha256']})
        self.assertEqual(published.status_code, 200)
        self.assertEqual(published.json()['status'], 'published')
        self.assertEqual(self.human_post(client, route + '/publish', {'sha256': row['sha256']}).json(), published.json())
        unpublished = self.human_post(client, route + '/unpublish', {'sha256': row['sha256']}).json()
        self.assertEqual(unpublished['status'], 'unpublished')
        self.assertEqual([x['action'] for x in unpublished['audit']], ['imported', 'published', 'unpublished'])
        self.assertEqual(self.human_post(client, route + '/unpublish', {'sha256': row['sha256']}).json(), unpublished)
        self.assertEqual(unpublished['published_by'], self.admin.username)

    def test_auth_permissions_csrf_and_session_revocation(self):
        self.assertEqual(self.client.get('/api/v1/catalog').status_code, 401)
        viewer = self.login_human(self.viewer)
        self.assertEqual(viewer.get('/api/v1/catalog').status_code, 200)
        self.assertEqual(self.upload(viewer).status_code, 403)
        admin = self.login_human(self.admin)
        self.assertEqual(admin.post('/api/v1/catalog/import', {}).status_code, 403)
        self.admin.is_active = False
        self.admin.save()
        self.assertEqual(admin.get('/api/v1/catalog').status_code, 401)

    def test_invalid_upload_unknown_package_and_query_are_bounded(self):
        client = self.login_human(self.admin)
        invalid = self.upload(client, b'private-invalid-input')
        self.assertEqual(invalid.status_code, 400)
        self.assertNotIn(b'private-invalid-input', invalid.content)
        self.assertEqual(client.get('/api/v1/catalog/00000000-0000-0000-0000-000000000000').status_code, 404)
        self.assertEqual(client.get('/api/v1/catalog?page=0').status_code, 400)
        self.assertEqual(client.get('/api/v1/catalog?unknown=x').status_code, 400)
        self.assertEqual(list(Path(self.private.name).iterdir()), [])

    def test_storage_tampering_blocks_read_publish_and_file(self):
        client, row = self.imported()
        from catalog.models import ScenarioPackageVersion
        stored = ScenarioPackageVersion.objects.get(pk=row['id'])
        (Path(self.private.name) / 'catalog' / stored.storage_reference).write_bytes(b'private-tamper')
        for route in ('', '/file?path=README.md'):
            response = client.get('/api/v1/catalog/' + row['id'] + route)
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.json(), {'error': {'code': 'content_conflict'}})
        self.assertEqual(self.human_post(client, '/api/v1/catalog/' + row['id'] + '/publish', {'sha256': row['sha256']}).status_code, 409)

    def test_service_checks_fresh_permissions(self):
        from catalog.services import import_package
        self.admin.groups.clear()
        with self.assertRaises(PermissionError):
            import_package(actor=self.admin, stream=io.BytesIO(self.sample()))

    def test_failed_database_insert_removes_only_request_owned_storage(self):
        from catalog.models import ScenarioPackageVersion
        client = self.login_human(self.admin)
        with patch.object(ScenarioPackageVersion.objects, 'create', side_effect=RuntimeError('synthetic-db-failure')):
            with self.assertRaises(RuntimeError):
                self.upload(client)
        self.assertEqual(ScenarioPackageVersion.objects.count(), 0)
        self.assertEqual(list((Path(self.private.name) / 'catalog').glob('*.zip')), [])

    def test_actual_file_upload_limit_and_request_budget_before_csrf(self):
        client = self.login_human(self.admin)
        response = self.upload(client, b'x' * (20 * 1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        # Raw request overflow must be bounded even before multipart/CSRF parsing.
        response = client.post('/api/v1/catalog/import', b'x' * (21 * 1024 * 1024 + 1), content_type='application/octet-stream')
        self.assertEqual(response.status_code, 413)
        self.assertEqual(client.post('/api/v1/auth/login', b'x' * 65537, content_type='application/json').status_code, 403)

    def test_different_zip_for_same_version_is_conflict_without_overwrite(self):
        client, row = self.imported()
        from catalog.tests.helpers import package_zip, sample_members
        raw = package_zip(dict(reversed(list(sample_members().items()))))
        response = self.upload(client, raw)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {'error': {'code': 'version_conflict'}})
        self.assertEqual(client.get('/api/v1/catalog/' + row['id']).json(), row)

    def test_reader_cannot_publish_and_path_preview_is_exact(self):
        _, row = self.imported()
        viewer = self.login_human(self.viewer)
        route = '/api/v1/catalog/' + row['id']
        self.assertEqual(self.human_post(viewer, route + '/publish', {'sha256': row['sha256']}).status_code, 403)
        self.assertEqual(viewer.get(route + '/file', {'path': '../private'}).status_code, 400)
        self.assertEqual(viewer.get('/api/v1/catalog?q=SCN-900&status=draft').json()['count'], 1)
        self.assertEqual(viewer.get('/api/v1/catalog?status=published').json()['count'], 0)

    def test_unavailable_storage_is_fixed_error_and_does_not_create_row(self):
        client = self.login_human(self.admin)
        with override_settings(PRIVATE_ROOT=Path(self.private.name) / 'absent'):
            response = self.upload(client)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'error': {'code': 'storage_unavailable'}})
        from catalog.models import ScenarioPackageVersion
        self.assertEqual(ScenarioPackageVersion.objects.count(), 0)

    def test_audit_model_rejects_edits_and_deletes(self):
        self.imported()
        from catalog.models import CatalogAudit
        audit = CatalogAudit.objects.get()
        audit.action = 'published'
        with self.assertRaises(ValueError):
            audit.save()
        with self.assertRaises(ValueError):
            CatalogAudit.objects.filter(pk=audit.pk).update(action='published')
        with self.assertRaises(ValueError):
            audit.delete()
        with self.assertRaises(ValueError):
            CatalogAudit.objects.all().delete()

    def test_detail_returns_recent100_audits_without_erasing_history(self):
        client, row = self.imported()
        from catalog.models import CatalogAudit, ScenarioPackageVersion
        package = ScenarioPackageVersion.objects.get(pk=row['id'])
        CatalogAudit.objects.bulk_create([CatalogAudit(package=package, action='published', actor=self.admin, sha256=row['sha256']) for _ in range(101)])
        detail = client.get('/api/v1/catalog/' + row['id']).json()
        self.assertEqual(len(detail['audit']), 100)
        self.assertEqual(CatalogAudit.objects.count(), 102)
