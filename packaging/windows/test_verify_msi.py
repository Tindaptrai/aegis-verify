"""Verifier refusal tests: never install a product on the development host."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4


SCRIPT = Path(__file__).with_name("verify_msi.ps1")
CHECKOUT = SCRIPT.parents[2]


@unittest.skipUnless(os.name == "nt", "Windows Installer verifier uses Windows PowerShell")
class VerifierGuardTests(unittest.TestCase):
    def invoke(self, *arguments, environment=None):
        values = os.environ.copy()
        values.pop("GITHUB_ACTIONS", None)
        values.pop("RUNNER_ENVIRONMENT", None)
        values.update(environment or {})
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        return subprocess.run(
            [str(powershell), "-NoProfile", "-File", str(SCRIPT), "-Msi", "unused.msi", *map(str, arguments)],
            env=values, capture_output=True, text=True, timeout=30,
        )

    def assert_refusal(self, result, reason):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AEGIS MSI verification: " + reason, result.stderr)

    def test_full_install_requires_explicit_acknowledgement(self):
        self.assert_refusal(self.invoke("-InstallTest"), "install_test_acknowledgement_required")

    def test_acknowledgement_does_not_enable_development_host_installation(self):
        self.assert_refusal(
            self.invoke("-InstallTest", "-AcknowledgeDisposableRunner"),
            "install_test_requires_disposable_github_runner",
        )

    def test_self_hosted_runner_is_refused(self):
        self.assert_refusal(
            self.invoke("-InstallTest", "-AcknowledgeDisposableRunner",
                        environment={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
            "install_test_requires_disposable_github_runner",
        )

    def test_existing_extraction_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "keep.txt"
            marker.write_bytes(b"existing user data")
            self.assert_refusal(self.invoke("-ExtractTo", root), "output_exists")
            self.assertEqual(marker.read_bytes(), b"existing user data")
            self.assertEqual(list(root.iterdir()), [marker])

    def test_extraction_under_checkout_is_refused_before_allocation(self):
        target = CHECKOUT / ("forbidden-msi-extraction-" + uuid4().hex)
        self.assert_refusal(self.invoke("-ExtractTo", target), "output_inside_checkout")
        self.assertFalse(target.exists())

    def test_existing_log_directory_is_not_modified_on_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            marker = logs / "keep.txt"
            marker.write_bytes(b"do not replace")
            extraction = root / "new-extraction"
            self.assert_refusal(self.invoke(
                "-ExtractTo", extraction, "-Release", root, "-LogDirectory", logs,
                "-Python", sys.executable, "-SmokeScript", CHECKOUT / "scripts/smoke_distribution.py",
            ), "output_exists")
            self.assertEqual(marker.read_bytes(), b"do not replace")
            self.assertEqual(list(logs.iterdir()), [marker])
            self.assertFalse(extraction.exists())

    def test_existing_result_is_preserved_before_package_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "result.json"
            result.write_bytes(b"previous result")
            self.assert_refusal(self.invoke("-Result", result), "result_exists")
            self.assertEqual(result.read_bytes(), b"previous result")


if __name__ == "__main__":
    unittest.main()
