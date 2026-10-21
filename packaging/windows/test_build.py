"""Build-tool safety checks; freezing itself is checked against the real artifact."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4


BUILD = Path(__file__).with_name("build.py")
CHECKOUT = Path(__file__).resolve().parents[2]


class BuildSafetyTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run(
            [sys.executable, "-I", "-X", "utf8", str(BUILD), *map(str, arguments)],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )

    def test_help_needs_no_pyinstaller_or_installed_application(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--python", result.stdout)
        self.assertIn("--wheel", result.stdout)

    def test_existing_output_is_refused_without_touching_its_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "keep.txt"
            marker.write_bytes(b"do not replace")
            wheel = root / "input.whl"
            wheel.write_bytes(b"not read before output guard")
            result = self.invoke("--python", sys.executable, "--wheel", wheel, "--out", root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("output_exists", result.stderr)
            self.assertEqual(marker.read_bytes(), b"do not replace")

    def test_output_under_checkout_is_refused_before_allocation(self):
        target = CHECKOUT / ("unwanted-freeze-" + uuid4().hex)
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "input.whl"
            wheel.write_bytes(b"not read before output guard")
            result = self.invoke("--python", sys.executable, "--wheel", wheel, "--out", target)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output_inside_checkout", result.stderr)
        self.assertFalse(target.exists())

    def test_invalid_wheel_does_not_allocate_a_build_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "input.whl"
            wheel.write_bytes(b"not a wheel")
            target = root / "new build"
            result = self.invoke("--python", sys.executable, "--wheel", wheel, "--out", target)
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid_wheel", result.stderr)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
