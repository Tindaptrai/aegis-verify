"""Build-only regression: run with setuptools installed, without live evidence."""

import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceArchiveTests(unittest.TestCase):
    def test_editable_build_needs_no_frontend_or_release_data(self):
        # Requiring staged wheel assets here would break a new backend-only
        # checkout before Node or frontend/dist has been prepared.
        with tempfile.TemporaryDirectory(prefix="aegis-editable-test-") as temporary:
            base = Path(temporary)
            source = base / "source"
            files = ["pyproject.toml", "setup.py", "MANIFEST.in", "README.md", "LICENSE", "NOTICE",
                     "packaging/public-resources.json", "scripts/stage_release_resources.py"]
            files += [p.relative_to(ROOT).as_posix() for directory in ("backend/app", "connectors")
                      for p in (ROOT / directory).rglob("*.py")]
            for name in files:
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            self.assertFalse((source / "frontend").exists())
            result = subprocess.run(
                [sys.executable, "-I", "-c",
                 "from setuptools import build_meta; import sys; build_meta.build_editable(sys.argv[1])",
                 str(base / "dist")],
                cwd=source, capture_output=True, text=True, encoding="utf-8", timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("Customization incompatible with editable install", result.stdout + result.stderr)
            editable, = (base / "dist").glob("*.whl")
            self.assertIn("editable", editable.name)
            self.assertFalse((source / "frontend").exists())

    def test_sdist_excludes_unreviewed_files_and_preserves_approved_bytes(self):
        with tempfile.TemporaryDirectory(prefix="aegis-sdist-test-") as temporary:
            base = Path(temporary)
            source = base / "source"
            selected = runpy.run_path(str(ROOT / "scripts/stage_release_resources.py"))["release_files"](ROOT)
            files = ["pyproject.toml", "setup.py", "MANIFEST.in", "README.md", "LICENSE", "NOTICE",
                     "packaging/public-resources.json", "scripts/stage_release_resources.py"]
            files += [p.relative_to(ROOT).as_posix() for p in selected.values()]
            files += [p.relative_to(ROOT).as_posix() for directory in ("backend/app", "connectors")
                      for p in (ROOT / directory).rglob("*.py")]
            for name in files:
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            for name in ("scenarios/private-unlisted.md",
                         "tests/fixtures/cli/scn005-elastic-synthetic/private-unlisted.json",
                         "frontend/dist/assets/unreferenced-private.js"):
                (source / name).write_text("TEST-ONLY-DO-NOT-SHIP", encoding="utf-8")
            result = subprocess.run([sys.executable, "-I", "setup.py", "sdist", "--dist-dir", str(base / "dist")],
                                    cwd=source, capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            archive, = (base / "dist").glob("*.tar.gz")
            with tarfile.open(archive) as package:
                names = package.getnames()
                self.assertFalse(any("private" in name for name in names if "private_fs.py" not in name))
                approved = next(name for name in names if name.endswith(
                    "tests/fixtures/cli/scn006-elastic-synthetic/filterlog.log"))
                self.assertEqual(package.extractfile(approved).read(),
                                 (ROOT / "tests/fixtures/cli/scn006-elastic-synthetic/filterlog.log").read_bytes())
                notice = [name for name in names if name.endswith("frontend/THIRD_PARTY_NOTICES.txt")]
                self.assertEqual(len(notice), 1)
                self.assertEqual(package.extractfile(notice[0]).read(),
                                 (ROOT / "frontend/THIRD_PARTY_NOTICES.txt").read_bytes())
                self.assertEqual(sum("/scenarios/SCN-" in name and name.endswith(".yaml") for name in names), 6)


if __name__ == "__main__":
    unittest.main()
