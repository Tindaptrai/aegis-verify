"""MSI authoring and build-input checks; actual MSI behavior needs Windows smoke tests."""

import hashlib
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from uuid import UUID, uuid4
from unittest.mock import patch
import xml.etree.ElementTree as ET


DRIVER = Path(__file__).with_name("msi.py")
CHECKOUT = Path(__file__).resolve().parents[2]
NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}


def load_driver():
    if not DRIVER.exists():
        return None
    spec = importlib.util.spec_from_file_location("aegis_windows_msi", DRIVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_release(root, version="0.4.0"):
    root.mkdir()
    files = {
        "aegis/aegis.exe": b"fixture executable, not an installable application",
        "aegis/_internal/runtime & resources/data.bin": b"public fixture resource",
        "LICENSES/Python/LICENSE.txt": b"fixture license",
        "QUICKSTART.md": b"fixture quickstart",
        "BUILD-INFO.json": (json.dumps({
            "kind": "aegis_windows_build", "version": "0.1.0",
            "application_version": version, "mode": "onedir", "architecture_bits": 64,
            "source_wheel_sha256": "a" * 64,
        }) + "\n").encode(),
    }
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    refresh_manifest(root)
    return root


def refresh_manifest(root):
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}\n"
             for path in sorted(root.rglob("*"))
             if path.is_file() and path.name != "SHA256SUMS.txt"]
    (root / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")


class MsiAuthoringTests(unittest.TestCase):
    def setUp(self):
        self.driver = load_driver()
        self.assertIsNotNone(self.driver, "MSI driver is missing")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = make_release(self.root / "release with spaces & unicode đ")

    def reject(self, code):
        with self.assertRaisesRegex(ValueError, "^" + code + "$"):
            self.driver.validate_release(self.release)

    def test_complete_release_is_verified_and_includes_manifest_as_payload(self):
        result = self.driver.validate_release(self.release)
        self.assertEqual(result["version"], "0.4.0")
        self.assertEqual(set(result["files"]), {
            path.relative_to(self.release).as_posix()
            for path in self.release.rglob("*") if path.is_file()
        })
        self.assertEqual(result["payload_sha256"], hashlib.sha256(
            (self.release / "SHA256SUMS.txt").read_bytes()).hexdigest())

    def test_changed_bytes_are_rejected(self):
        (self.release / "aegis/aegis.exe").write_bytes(b"tampered")
        self.reject("payload_hash_mismatch")

    def test_unlisted_file_is_rejected(self):
        (self.release / "private-extra.txt").write_text("not in reviewed release")
        self.reject("payload_inventory_mismatch")

    def test_missing_file_is_rejected(self):
        (self.release / "aegis/aegis.exe").unlink()
        self.reject("payload_inventory_mismatch")

    def test_duplicate_manifest_entries_are_rejected(self):
        manifest = self.release / "SHA256SUMS.txt"
        manifest.write_text(manifest.read_text() + manifest.read_text().splitlines()[0] + "\n")
        self.reject("invalid_payload_manifest")

    def test_unsafe_windows_paths_are_rejected(self):
        manifest = self.release / "SHA256SUMS.txt"
        for relative in ("../escape", "/absolute", "a/./b", "a//b", "a\\b", "C:/escape",
                         "a/file:stream", "a/trailing.", "a/trailing ", "a/CON.txt",
                         "a/NUL", "SHA256SUMS.txt", "a/control\tname", "a/file?name"):
            with self.subTest(relative=relative):
                manifest.write_text("a" * 64 + "  " + relative + "\n", encoding="utf-8")
                self.reject("invalid_payload_manifest")

    def test_case_colliding_manifest_entries_are_rejected(self):
        manifest = self.release / "SHA256SUMS.txt"
        manifest.write_text(manifest.read_text() + "a" * 64 + "  AEGIS/AEGIS.EXE\n")
        self.reject("invalid_payload_manifest")

    def test_manifest_must_use_exact_sha256_record_format(self):
        manifest = self.release / "SHA256SUMS.txt"
        for text in ("", "\n", "a" * 63 + "  QUICKSTART.md\n", "z" * 64 + "  QUICKSTART.md\n",
                     "a" * 64 + " QUICKSTART.md\n", "a" * 64 + "  QUICKSTART.md\n\n"):
            with self.subTest(text=text):
                manifest.write_text(text)
                self.reject("invalid_payload_manifest")

    def test_unsupported_build_metadata_is_rejected(self):
        path = self.release / "BUILD-INFO.json"
        original = json.loads(path.read_text())
        for field, value in (("mode", "onefile"), ("architecture_bits", 32),
                             ("kind", "something_else"), ("source_wheel_sha256", "wrong")):
            with self.subTest(field=field):
                path.write_text(json.dumps({**original, field: value}))
                refresh_manifest(self.release)
                self.reject("unsupported_release_metadata")

    def test_only_numeric_msi_versions_within_windows_limits_are_accepted(self):
        path = self.release / "BUILD-INFO.json"
        metadata = json.loads(path.read_text())
        for version in ("0.4", "0.4.0.1", "0.4.0rc1", "0.4.0+build", "01.4.0", "256.0.0",
                        "0.256.0", "0.0.65536", " 0.4.0", "9" * 5000 + ".0.0", 4, None):
            with self.subTest(version=str(version)[:60]):
                path.write_text(json.dumps({**metadata, "application_version": version}))
                refresh_manifest(self.release)
                self.reject("invalid_msi_version")

    def test_missing_expected_executable_is_rejected_even_when_manifest_matches(self):
        (self.release / "aegis/aegis.exe").unlink()
        refresh_manifest(self.release)
        self.reject("required_payload_missing")

    def test_hard_link_is_rejected(self):
        path = self.release / "aegis/aegis.exe"
        try:
            (self.root / "external-hardlink").hardlink_to(path)
        except OSError as error:
            self.skipTest(str(error))
        self.reject("payload_link_forbidden")

    def test_symbolic_link_is_rejected(self):
        path = self.release / "aegis/aegis.exe"
        destination = self.root / "external-executable"
        path.replace(destination)
        try:
            path.symlink_to(destination)
        except OSError as error:
            self.skipTest(str(error))
        self.reject("payload_link_forbidden")

    @unittest.skipUnless(sys.platform == "win32", "Windows junction behavior")
    def test_directory_junction_is_rejected(self):
        target = self.root / "junction-target"
        target.mkdir()
        junction = self.release / "junction"
        result = subprocess.run(["cmd.exe", "/D", "/C", "mklink", "/J", str(junction), str(target)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(lambda: junction.rmdir() if junction.exists() else None)
        self.reject("payload_link_forbidden")

    def test_xml_preserves_every_payload_path_and_escapes_source_names(self):
        document = ET.fromstring(self.driver.render_wxs(self.release, "0.4.0"))
        files = document.findall(".//w:File", NS)
        self.assertEqual(len(files), len(self.driver.validate_release(self.release)["files"]))
        self.assertEqual({Path(item.attrib["Source"]).read_bytes() for item in files},
                         {path.read_bytes() for path in self.release.rglob("*") if path.is_file()})
        for component in document.findall(".//w:Component", NS):
            self.assertEqual(UUID(component.attrib["Guid"]).version, 5)
            component_files = component.findall("w:File", NS)
            if component_files:
                self.assertEqual(len(component_files), 1)
                self.assertEqual(component_files[0].attrib["KeyPath"], "yes")

    def test_component_identity_depends_on_destination_not_staging_version_or_bytes(self):
        first = ET.fromstring(self.driver.render_wxs(self.release, "0.4.0"))
        second_root = self.root / "second location"
        shutil.copytree(self.release, second_root)
        info = second_root / "BUILD-INFO.json"
        info.write_text(json.dumps({**json.loads(info.read_text()), "application_version": "0.4.1"}))
        (second_root / "aegis/aegis.exe").write_bytes(b"next executable bytes")
        refresh_manifest(second_root)
        second = ET.fromstring(self.driver.render_wxs(second_root, "0.4.1"))
        identity = lambda tree: {node.attrib["Id"]: node.attrib["Guid"]
                                 for node in tree.findall(".//w:Component", NS)}
        self.assertEqual(identity(first), identity(second))
        self.assertEqual(first.find("w:Package", NS).attrib["UpgradeCode"],
                         second.find("w:Package", NS).attrib["UpgradeCode"])
        self.assertNotEqual(first.find("w:Package", NS).attrib["ProductCode"],
                            second.find("w:Package", NS).attrib["ProductCode"])

    def test_render_refuses_version_mismatch(self):
        with self.assertRaisesRegex(ValueError, "^release_version_mismatch$"):
            self.driver.render_wxs(self.release, "0.4.1")

    def test_msi_has_machine_scope_embedded_cab_and_transactional_major_upgrade(self):
        tree = ET.fromstring(self.driver.render_wxs(self.release, "0.4.0"))
        package = tree.find("w:Package", NS)
        self.assertEqual(package.attrib["Scope"], "perMachine")
        self.assertEqual(package.attrib["Version"], "0.4.0")
        self.assertEqual(package.find("w:MediaTemplate", NS).attrib["EmbedCab"], "yes")
        upgrade = package.find("w:MajorUpgrade", NS)
        self.assertEqual(upgrade.attrib["Schedule"], "afterInstallInitialize")
        self.assertEqual(upgrade.attrib.get("AllowDowngrades", "no"), "no")
        self.assertTrue(upgrade.attrib["DowngradeErrorMessage"])
        forbidden = {"CustomAction", "ServiceInstall", "ServiceControl", "FirewallException",
                     "RemoveFile", "RemoveFolderEx", "Permission", "PermissionEx", "Environment"}
        self.assertFalse({element.tag.rsplit("}", 1)[-1] for element in tree.iter()} & forbidden)
        self.assertEqual(tree.find(".//w:StandardDirectory[@Id='ProgramFiles64Folder']/w:Directory", NS)
                         .attrib["Name"], "AEGIS Verify")

    def test_shortcuts_are_nonadvertised_machine_menu_and_console_stays_open(self):
        tree = ET.fromstring(self.driver.render_wxs(self.release, "0.4.0"))
        menu = tree.find(".//w:StandardDirectory[@Id='ProgramMenuFolder']/w:Directory", NS)
        self.assertEqual(menu.attrib["Name"], "AEGIS Verify")
        shortcuts = tree.findall(".//w:Shortcut", NS)
        self.assertEqual(len(shortcuts), 2)
        self.assertTrue(all(item.attrib["Advertise"] == "no" for item in shortcuts))
        console = next(item for item in shortcuts if "Console" in item.attrib["Name"])
        self.assertEqual(console.attrib["Target"], "[System64Folder]cmd.exe")
        self.assertTrue(console.attrib["Arguments"].startswith('/D /K ""[#'))
        self.assertTrue(console.attrib["Arguments"].endswith(']" --help"'))
        quickstart = next(item for item in shortcuts if "Quickstart" in item.attrib["Name"])
        target_id = quickstart.attrib["Target"][2:-1]
        quickstart_file = tree.find(f".//w:File[@Id='{target_id}']", NS)
        self.assertEqual(Path(quickstart_file.attrib["Source"]).name, "QUICKSTART.md")
        registry = tree.findall(".//w:RegistryValue", NS)
        self.assertTrue(registry)
        self.assertEqual({item.attrib["Root"] for item in registry}, {"HKLM", "HKMU"})
        self.assertTrue(all(item.attrib["Key"] == r"Software\AEGIS Verify" for item in registry))
        menu_key = tree.find(".//w:Component[@Id='MenuShortcuts']/w:RegistryValue", NS)
        self.assertEqual(menu_key.attrib["Root"], "HKMU")
        self.assertEqual(menu_key.attrib["KeyPath"], "yes")
        self.assertEqual(tree.find("w:Package/w:Launch", NS).attrib["Condition"], "ALLUSERS = 1")


class MsiCommandTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-I", "-X", "utf8", str(DRIVER), *map(str, arguments)],
                              capture_output=True, text=True, encoding="utf-8", timeout=30)

    def test_help_needs_no_wix_or_release(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--release", result.stdout)
        self.assertIn("--wix", result.stdout)

    def test_existing_output_is_refused_before_inputs_are_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "keep.txt"
            marker.write_bytes(b"keep")
            result = self.invoke("--release", "missing", "--wix", "missing", "--out", root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("output_exists", result.stderr)
            self.assertEqual(marker.read_bytes(), b"keep")

    def test_output_inside_checkout_is_refused_before_creation(self):
        target = CHECKOUT / ("unwanted-msi-" + uuid4().hex)
        result = self.invoke("--release", "missing", "--wix", "missing", "--out", target)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output_inside_checkout", result.stderr)
        self.assertFalse(target.exists())

    def test_invalid_release_is_rejected_before_wix_and_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = make_release(root / "release")
            (release / "aegis/aegis.exe").write_bytes(b"tampered")
            result = self.invoke("--release", release, "--wix", root / "missing-wix.exe", "--out", root / "new")
            self.assertEqual(result.returncode, 2)
            self.assertIn("payload_hash_mismatch", result.stderr)
            self.assertFalse((root / "new").exists())

    def test_output_inside_release_is_refused_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            release = make_release(Path(directory) / "release")
            target = release / "new output"
            result = self.invoke("--release", release, "--wix", "missing", "--out", target)
            self.assertEqual(result.returncode, 2)
            self.assertIn("output_inside_release", result.stderr)
            self.assertFalse(target.exists())


class MsiBuildBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.driver = load_driver()
        self.assertIsNotNone(self.driver)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = make_release(self.root / "release")
        self.wix = self.root / "wix.exe"
        self.wix.write_bytes(b"external process boundary; never executed")
        self.output = self.root / "new output"

    def invoke_main(self, run):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(self.driver.sys, "platform", "win32"), patch.object(
                self.driver.subprocess, "run", side_effect=run), contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            status = self.driver.main(["--release", str(self.release), "--wix", str(self.wix),
                                       "--out", str(self.output)])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_wrong_wix_version_is_rejected_without_allocating_output(self):
        for version in ("5.0.1", "5.0.20", "6.0.2", "7.0.0", "banner\n5.0.2"):
            with self.subTest(version=version):
                result = self.invoke_main(lambda *args, **kwargs: subprocess.CompletedProcess(
                    args[0], 0, stdout=version, stderr=""))
                self.assertEqual(result[0], 2)
                self.assertIn("wix_version_mismatch", result[2])
                self.assertFalse(self.output.exists())

    def test_staged_payload_is_checked_again_before_wix_build(self):
        copy = shutil.copyfile

        def changing_copy(source, destination):
            result = copy(source, destination)
            if Path(source).name == "aegis.exe":
                Path(destination).write_bytes(b"changed during staging")
            return result

        def probe_only(command, **kwargs):
            self.assertEqual(command, [str(self.wix), "--version"])
            return subprocess.CompletedProcess(command, 0, stdout="5.0.2+aa65968c\n", stderr="")

        with patch.object(self.driver.shutil, "copyfile", side_effect=changing_copy):
            result = self.invoke_main(probe_only)
        self.assertEqual(result[0], 2)
        self.assertIn("payload_hash_mismatch", result[2])
        self.assertFalse((self.output / "AEGIS-Verify-0.4.0-x64.msi").exists())

    def test_build_serializes_checked_snapshot_and_distributable_hashes(self):
        # The process double stops at the external WiX boundary. Real Windows
        # CI independently proves MSI database, cabinet and lifecycle behavior.
        commands = []

        def external_wix(command, **kwargs):
            commands.append(command)
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, stdout="5.0.2+aa65968c\n", stderr="")
            self.assertEqual(command[1:4], ["build", "-arch", "x64"])
            self.assertNotIn("-sval", command)
            self.assertNotIn("-acceptEula", command)
            msi = Path(command[command.index("-o") + 1])
            authoring = Path(command[-1])
            document = ET.fromstring(authoring.read_text(encoding="utf-8"))
            self.assertTrue(all(Path(item.attrib["Source"]).resolve().is_relative_to(self.output.resolve())
                                for item in document.findall(".//w:File", NS)))
            msi.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"unit boundary only")
            return subprocess.CompletedProcess(command, 0)

        result = self.invoke_main(external_wix)
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(len(commands), 2)
        metadata = json.loads(result[1])
        self.assertEqual(metadata["version"], "0.4.0")
        self.assertEqual(Path(metadata["msi"]).name, "AEGIS-Verify-0.4.0-x64.msi")
        self.assertEqual(UUID(metadata["product_code"]).version, 5)
        info = json.loads(Path(metadata["build_info"]).read_text())
        self.assertFalse(info["signed"])
        self.assertEqual(info["source_payload_sha256"], metadata["payload_sha256"])
        self.assertNotIn(str(self.root), json.dumps(info))
        for line in Path(metadata["checksums"]).read_text().splitlines():
            digest, relative = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((self.output / relative).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
