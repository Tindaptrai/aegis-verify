import io
import os
import tempfile
from pathlib import Path
from unittest import skipIf
from unittest.mock import patch
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings
from catalog.errors import CatalogError
from catalog.storage import catalog_root, persist, read_upload, verify


class PrivateStorageTests(SimpleTestCase):
    def test_checkout_root_is_rejected(self):
        with override_settings(PRIVATE_ROOT=Path(__file__).resolve().parents[3]):
            with self.assertRaises(CatalogError) as caught:
                catalog_root()
        self.assertEqual(caught.exception.code, 'storage_unavailable')

    def test_public_static_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(PRIVATE_ROOT=Path(directory), STATIC_ROOT=directory):
                with self.assertRaises(CatalogError):
                    catalog_root()

    def test_final_catalog_directory_cannot_equal_public_static_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with override_settings(PRIVATE_ROOT=root, STATIC_ROOT=str(root / 'catalog')):
                with self.assertRaises(CatalogError) as caught:
                    catalog_root()
            self.assertEqual(caught.exception.code, 'storage_unavailable')

    def test_catalog_below_public_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / 'private'
            private.mkdir(mode=0o700)
            with override_settings(PRIVATE_ROOT=private, STATIC_ROOT=str(root)):
                with self.assertRaises(CatalogError):
                    catalog_root()

    def test_default_static_sibling_remains_separate_from_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with override_settings(PRIVATE_ROOT=root, STATIC_ROOT=str(root / 'static')):
                self.assertEqual(catalog_root(), root.resolve() / 'catalog')

    def test_oversized_stored_zip_is_content_conflict_while_upload_is413(self):
        raw = b'x' * (20 * 1024 * 1024 + 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with override_settings(PRIVATE_ROOT=root):
                reference = '00000000-0000-0000-0000-000000000000.zip'
                persist(reference, raw)
                with self.assertRaises(CatalogError) as caught:
                    verify(SimpleNamespace(storage_reference=reference))
                self.assertEqual((caught.exception.code, caught.exception.status), ('content_conflict', 409))
        with self.assertRaises(CatalogError) as caught:
            read_upload(io.BytesIO(raw))
        self.assertEqual((caught.exception.code, caught.exception.status), ('package_too_large', 413))

    def test_failed_atomic_replace_removes_staging_without_creating_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(PRIVATE_ROOT=Path(directory)):
                with patch('catalog.storage.os.replace', side_effect=OSError('synthetic-private-detail')):
                    with self.assertRaises(CatalogError) as caught:
                        persist('00000000-0000-0000-0000-000000000000.zip', b'synthetic')
                self.assertEqual(caught.exception.code, 'storage_unavailable')
                self.assertEqual(list((Path(directory) / 'catalog').iterdir()), [])

    @skipIf(os.name == 'nt', 'POSIX symlink/owner mode test; Windows reparse checks are covered by native path metadata')
    def test_symlink_private_root_and_unsafe_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual, link = root / 'actual', root / 'link'
            actual.mkdir(mode=0o700)
            link.symlink_to(actual, target_is_directory=True)
            with override_settings(PRIVATE_ROOT=link):
                with self.assertRaises(CatalogError):
                    catalog_root()
            actual.chmod(0o755)
            with override_settings(PRIVATE_ROOT=actual):
                with self.assertRaises(CatalogError):
                    catalog_root()
