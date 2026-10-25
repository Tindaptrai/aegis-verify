import hashlib
import importlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from .helpers import forged_size, inventory, json_bytes, package_zip, sample_members

try:
    from catalog.errors import CatalogError
    from catalog.package import validate_package
except ImportError:
    CatalogError = None
    validate_package = None


class PackageTests(unittest.TestCase):
    def validate(self, raw):
        self.assertIsNotNone(validate_package, "bounded catalog validator is not implemented")
        return validate_package(io.BytesIO(raw))

    def reject(self, raw, code):
        self.assertIsNotNone(CatalogError, "bounded catalog errors are not implemented")
        with self.assertRaises(CatalogError) as caught:
            self.validate(raw)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.codes, [code])
        self.assertEqual(str(caught.exception), code)

    def test_valid_package_has_exact_content_and_digest(self):
        raw = package_zip()
        result = self.validate(raw)
        self.assertEqual(result.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.metadata["name"], "Catalog authoring sample")
        self.assertEqual(result.metadata["scenario_id"], "SCN-900")
        self.assertEqual(result.contents, sample_members())
        self.assertEqual({row["path"] for row in result.files}, set(sample_members()))
        self.assertTrue(all(row["size"] == len(result.contents[row["path"]]) for row in result.files))

    def test_closed_metadata_and_runner_contract(self):
        for field, value in [("extra", True), ("timeout_seconds", True), ("timeout_seconds", 0),
                             ("timeout_seconds", 601), ("runner", "shell"), ("platform", "linux"),
                             ("format", "other"), ("entrypoint", "README.md"),
                             ("version", "1" * 125 + ".0.0"),
                             ("cleanup", "payload/missing.ps1")]:
            with self.subTest(field=field, value=value):
                members = sample_members()
                metadata = json.loads(members["package.json"])
                metadata[field] = value
                members["package.json"] = json_bytes(metadata)
                self.reject(package_zip(members), "invalid_metadata")

    def test_identity_version_and_profile_relationships(self):
        for field, value, code in [("scenario_id", "SCN-901", "scenario_mismatch"),
                                   ("version", "0.2.0", "scenario_mismatch"),
                                   ("profile_fingerprint", "0" * 64, "profile_mismatch")]:
            with self.subTest(field=field):
                members = sample_members()
                metadata = json.loads(members["package.json"])
                metadata[field] = value
                members["package.json"] = json_bytes(metadata)
                self.reject(package_zip(members), code)

    def test_manifest_and_profile_are_validated(self):
        for name, raw, code in [("scenario.yaml", b"id: SCN-900\n", "invalid_scenario"),
                                ("profile.json", b"{}", "invalid_profile")]:
            with self.subTest(name=name):
                members = sample_members()
                members[name] = raw
                self.reject(package_zip(inventory(members)), code)
        members = sample_members()
        profile = json.loads(members["profile.json"])
        profile["scenario_fingerprint"] = "0" * 64
        members["profile.json"] = json_bytes(profile)
        self.reject(package_zip(inventory(members)), "profile_mismatch")

    def test_name_is_bounded_for_review_and_display(self):
        members = sample_members()
        members["scenario.yaml"] = members["scenario.yaml"].replace(b"Catalog authoring sample", b"A" * 513)
        self.reject(package_zip(inventory(members)), "invalid_scenario")

    def test_duplicate_json_keys_and_utf8_are_rejected(self):
        for name in ["package.json", "profile.json"]:
            members = sample_members()
            members[name] = b'{"secret-script-body":1,"secret-script-body":2}'
            self.reject(package_zip(members if name == "package.json" else inventory(members)), "invalid_json")
        for name in ["README.md", "payload/demo.ps1", "scenario.yaml", "profile.json", "package.json"]:
            members = sample_members()
            members[name] = b"\xff"
            self.reject(package_zip(members), "invalid_utf8")

    def test_inventory_missing_unlisted_and_hash_mismatch(self):
        members = sample_members()
        members["payload/extra.txt"] = b"extra"
        self.reject(package_zip(members), "inventory_mismatch")
        members = sample_members()
        del members["README.md"]
        self.reject(package_zip(members), "inventory_mismatch")
        members = sample_members()
        members["README.md"] = b"changed"
        self.reject(package_zip(members), "hash_mismatch")

    def test_paths_duplicates_case_collisions_and_special_members(self):
        for name in ["../escape", "/absolute", "C:/drive", "C:relative", "\\\\host\\share", "payload\\bad.ps1",
                     "payload//bad.ps1", "payload/./bad.ps1", "payload/a../bad.ps1", "payload/CON.txt",
                     "payload/alternate:stream", "payload/trailing. ", "payload/a\x00.txt"]:
            with self.subTest(name=name):
                members = sample_members()
                members[name] = b"text"
                self.reject(package_zip(members), "invalid_path")
        for name in ["README.md", "readme.md"]:
            info = zipfile.ZipInfo(name)
            self.reject(package_zip(extra=[(info, b"duplicate")]), "duplicate_member")
        for mode in [0o120777, 0o020600, 0o040755]:
            info = zipfile.ZipInfo("payload/special.txt")
            info.create_system = 3
            info.external_attr = mode << 16
            self.reject(package_zip(extra=[(info, b"secret-target")]), "unsupported_member")

    def test_encryption_unsupported_compression_and_archives(self):
        raw = bytearray(package_zip())
        for signature, offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:
            index = raw.index(signature)
            struct.pack_into("<H", raw, index + offset, 1)
        self.reject(bytes(raw), "encrypted_member")
        self.reject(package_zip(compression=zipfile.ZIP_BZIP2), "unsupported_compression")
        for name, content in [("payload/a.zip", b"text"), ("payload/a.txt", b"PK\x03\x04nested")]:
            members = sample_members()
            members[name] = content
            self.reject(package_zip(inventory(members)), "nested_archive")
        self.reject(b"not zip secret content", "invalid_zip")

    def test_actual_stream_member_expanded_count_and_ratio_limits(self):
        self.assertIsNotNone(validate_package, "bounded catalog validator is not implemented")
        module = importlib.import_module("catalog.package")
        for constant, limit, code in [("MAX_ZIP_BYTES", 64, "package_too_large"),
                                      ("MAX_MEMBER_BYTES", 32, "member_too_large"),
                                      ("MAX_SCENARIO_BYTES", 32, "member_too_large"),
                                      ("MAX_EXPANDED_BYTES", 64, "expanded_too_large"),
                                      ("MAX_MEMBERS", 4, "too_many_members")]:
            with self.subTest(constant=constant), patch.object(module, constant, limit):
                self.reject(package_zip(), code)
        members = sample_members()
        members["README.md"] = b"a" * (128 * 1024)
        self.reject(package_zip(inventory(members), compression=zipfile.ZIP_DEFLATED), "compression_ratio")

    def test_sample_generator_writes_deterministic_valid_zip_and_sidecar(self):
        script = Path(__file__).resolve().parents[3] / "scripts/create_catalog_sample.py"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sample.zip"
            run = subprocess.run([sys.executable, str(script), str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            raw = output.read_bytes()
            self.validate(raw)
            self.assertEqual(output.with_suffix(".zip.sha256").read_text().split()[0], hashlib.sha256(raw).hexdigest())
            subprocess.run([sys.executable, str(script), str(output)], check=True, capture_output=True)
            self.assertEqual(output.read_bytes(), raw)

    def test_actual_deflate_output_is_bounded_when_headers_lie(self):
        self.assertIsNotNone(validate_package)
        module = importlib.import_module("catalog.package")
        members = sample_members()
        members["README.md"] = bytes(range(32, 127)) * 20
        raw = forged_size(package_zip(inventory(members), compression=zipfile.ZIP_DEFLATED), "README.md", 0)
        with patch.object(module, "MAX_MEMBER_BYTES", 1024):
            self.reject(raw, "member_too_large")
        expanded_before_readme = len(members["scenario.yaml"]) + len(members["profile.json"])
        with patch.object(module, "MAX_EXPANDED_BYTES", expanded_before_readme + 100):
            self.reject(raw, "expanded_too_large")
        members["README.md"] = b"A" * 5000
        raw = forged_size(package_zip(inventory(members), compression=zipfile.ZIP_DEFLATED), "README.md", 0)
        self.reject(raw, "compression_ratio")

    def test_count_uses_actual_directory_and_zip_bytes_use_actual_stream(self):
        self.assertIsNotNone(validate_package)
        module = importlib.import_module("catalog.package")
        raw = bytearray(package_zip())
        end = raw.rindex(b"PK\x05\x06")
        struct.pack_into("<2H", raw, end + 8, 1, 1)
        with patch.object(module, "MAX_MEMBERS", 4):
            self.reject(bytes(raw), "too_many_members")

        class ChunkedStream:
            def __init__(self):
                self.remaining = 65
                self.returned = 0

            def read(self, size):
                count = min(size, 3, self.remaining)
                self.remaining -= count
                self.returned += count
                return b"x" * count

        stream = ChunkedStream()
        with patch.object(module, "MAX_ZIP_BYTES", 64), self.assertRaises(CatalogError) as caught:
            validate_package(stream)
        self.assertEqual(caught.exception.code, "package_too_large")
        self.assertEqual(caught.exception.status, 413)
        self.assertEqual(stream.returned, 65)

    def test_corrupt_member_headers_and_content_do_not_echo_private_text(self):
        raw = bytearray(package_zip())
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            offset = archive.getinfo("README.md").header_offset
        raw[offset + 6] = 1
        self.reject(bytes(raw), "invalid_zip")
        members = sample_members()
        raw = package_zip(members).replace(b"Authoring sample only.", b"Sensitive-script-body")
        self.reject(raw, "invalid_zip")

    def test_zip64_directory_hidden_in_member_comment_is_rejected_before_allocation(self):
        members = sample_members()
        members.update({f"payload/extra-{index:03}.txt": b"text" for index in range(196)})
        raw = package_zip(inventory(members))
        end = raw.rindex(b"PK\x05\x06")
        count = struct.unpack_from("<H", raw, end + 10)[0]
        size, offset = struct.unpack_from("<2L", raw, end + 12)
        directory = raw[offset:offset + size]
        name_size, extra_size = struct.unpack_from("<2H", directory, 28)
        # Outer preflight sees one record. Its comment holds a different directory
        # selected by Python's ZIP64 locator immediately before the classic EOCD.
        outer = bytearray(directory[:46 + name_size + extra_size])
        struct.pack_into("<H", outer, 32, len(directory) + 76)
        inner_offset = offset + len(outer)
        zip64_offset = inner_offset + len(directory)
        zip64 = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
                            count, count, len(directory), inner_offset)
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, zip64_offset, 1)
        outer.extend(directory + zip64 + locator)
        forged = raw[:offset] + outer + struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1,
                                                  len(outer), offset, 0)
        with zipfile.ZipFile(io.BytesIO(forged)) as archive:
            self.assertEqual(len(archive.infolist()), 201)
        self.reject(forged, "invalid_zip")
        module = importlib.import_module("catalog.package")
        with patch.object(module.zipfile, "ZipFile", side_effect=AssertionError("ZIP64 reached allocation")):
            self.reject(forged, "invalid_zip")

    def test_unsupported_extract_version_returns_bounded_error(self):
        raw = bytearray(package_zip())
        directory = raw.index(b"PK\x01\x02")
        struct.pack_into("<H", raw, directory + 6, 99)
        self.reject(bytes(raw), "invalid_zip")
