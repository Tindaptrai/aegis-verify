import os
from pathlib import Path
import tempfile
import unittest
import uuid
from django.test import override_settings
from connections import storage


@unittest.skipUnless(os.name == 'posix', 'Native Linux dirfd ownership/no-follow proof required')
class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o700)
        self.override = override_settings(PRIVATE_ROOT=Path(self.tmp.name))
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.addCleanup(self.tmp.cleanup)

    def test_exclusive_write_and_tamper(self):
        key = uuid.uuid4()
        storage.create(key, b'config', b'ca')
        self.assertEqual(storage.read(key), (b'config', b'ca'))
        with self.assertRaises(storage.StorageError):
            storage.create(key, b'other', b'ca')
        root = Path(self.tmp.name) / 'connections' / str(key)
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((root/'config.json').stat().st_mode & 0o777, 0o600)

    def test_link_parent_or_file_is_never_followed(self):
        key = uuid.uuid4()
        storage.create(key, b'config', b'ca')
        root = Path(self.tmp.name) / 'connections' / str(key)
        (root/'config.json').unlink()
        (root/'config.json').symlink_to(root/'ca.pem')
        with self.assertRaises(storage.StorageError):
            storage.read(key)
        other = uuid.uuid4()
        (root.parent/str(other)).symlink_to(root, target_is_directory=True)
        with self.assertRaises(storage.StorageError):
            storage.read(other)

    def test_cleanup_removes_only_expired_unreferenced_directory(self):
        from datetime import datetime, timezone, timedelta
        key, saved = uuid.uuid4(), uuid.uuid4()
        storage.create(key, b'config', b'ca')
        storage.create(saved, b'config', b'ca')
        storage.cleanup({str(saved)}, datetime.now(timezone.utc) + timedelta(minutes=6))
        with self.assertRaises(storage.StorageError):
            storage.read(key)
        self.assertEqual(storage.read(saved), (b'config', b'ca'))

    def test_cleanup_recovers_partial_orphan(self):
        from datetime import datetime, timezone, timedelta
        key = uuid.uuid4()
        storage.create(key,b'config',b'ca')
        root = Path(self.tmp.name)/'connections'/str(key)
        (root/'output').rmdir()
        (root/'ca.pem').unlink()
        storage.cleanup(set(),datetime.now(timezone.utc)+timedelta(minutes=6))
        self.assertFalse(root.exists())


class PlatformStorageTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows-specific fail-closed gate')
    def test_windows_does_not_silently_weaken_private_storage(self):
        with self.assertRaises(storage.StorageError):
            storage.create(uuid.uuid4(), b'config', b'ca')
