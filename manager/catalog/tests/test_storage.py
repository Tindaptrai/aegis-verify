import io
import os
import tempfile
from pathlib import Path
from unittest import skipIf
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from catalog.errors import CatalogError
from catalog.storage import catalog_root, persist


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
