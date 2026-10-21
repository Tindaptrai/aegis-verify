"""Build-only checks for real Windows version resource serialization."""

from pathlib import Path
import runpy
import tempfile
import unittest

from PyInstaller.utils.win32.versioninfo import load_version_info_from_text_file

BUILD = Path(__file__).with_name("build.py")


class VersionResourceTests(unittest.TestCase):
    def test_pe_version_matches_wheel_and_is_serializable(self):
        render = runpy.run_path(str(BUILD))["_version_resource"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "version.txt"
            path.write_text(render("0.4.0"), encoding="utf-8")
            resource = load_version_info_from_text_file(path)
        self.assertEqual((resource.ffi.fileVersionMS, resource.ffi.fileVersionLS), (0x00000004, 0))
        self.assertEqual((resource.ffi.productVersionMS, resource.ffi.productVersionLS), (0x00000004, 0))
        strings = {item.name: item.val for item in resource.kids[0].kids[0].kids}
        self.assertEqual(strings["ProductVersion"], "0.4.0")
        self.assertEqual(strings["OriginalFilename"], "aegis.exe")
        self.assertGreater(len(resource.toRaw()), 100)

    def test_invalid_versions_are_not_silently_truncated(self):
        render = runpy.run_path(str(BUILD))["_version_resource"]
        for value in ("0.4.0.1", "0.4.0rc1", "65536.0.0", "-1.0.0", "0.4", "0.4.0'", "00.4.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                render(value)


if __name__ == "__main__":
    unittest.main()
