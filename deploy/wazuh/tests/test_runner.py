"""Portable gate tests: missing, skipped or mismatched proof cannot qualify."""
import importlib.util
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

RUNNER = Path(__file__).resolve().parents[1] / "Run-SelfTests.py"


class RunnerTests(unittest.TestCase):
    def runner(self):
        self.assertTrue(RUNNER.is_file(), "explicit native self-test runner is missing")
        spec = importlib.util.spec_from_file_location("wazuh_selftests", RUNNER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def result(self, outcome):
        class Sample(unittest.TestCase):
            def test_required(self):
                if outcome == "skip":
                    self.skipTest("synthetic missing prerequisite")
                if outcome == "fail":
                    self.fail("synthetic failed requirement")
        result = self.runner().ProofResult(io.StringIO(), True, 0)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Sample)
        required = [next(iter(suite)).id()]
        suite.run(result)
        return result, required

    def test_missing_required_is_failure(self):
        module = self.runner()
        result = module.ProofResult(io.StringIO(), True, 0)
        self.assertFalse(module.required_results(result, ["absent"])["absent"] == "passed")

    def test_skipped_required_is_failure(self):
        result, required = self.result("skip")
        self.assertEqual(self.runner().required_results(result, required)[required[0]], "skipped")
        self.assertFalse(self.runner().qualified(result, required))

    def test_failed_required_is_failure(self):
        result, required = self.result("fail")
        self.assertFalse(self.runner().qualified(result, required))

    def test_success_requires_all_named_ids(self):
        result, required = self.result("pass")
        self.assertTrue(self.runner().qualified(result, required))
        self.assertFalse(self.runner().qualified(result, required + ["absent"]))

    def test_failure_in_subtest_cannot_be_overwritten_as_success(self):
        module = self.runner()
        class Sample(unittest.TestCase):
            def test_required(self):
                with self.subTest(phase="fixture"):
                    self.fail("synthetic failure")
        case = Sample("test_required")
        result = module.ProofResult(io.StringIO(), True, 0)
        case.run(result)
        self.assertFalse(module.qualified(result, [case.id()]))

    def test_copied_child_subtest_failure_and_error_fail_required_id_and_proof(self):
        """Model only the forked unittest state; this is not native OS proof."""
        from deploy.wazuh.tests import test_native as native
        for kind in ("failure", "error"):
            with self.subTest(kind=kind):
                module = self.runner()
                identity = module.NATIVE_MODULE + ".NativeTests.test_publication_races_preserve_evidence"
                class Sample(unittest.TestCase):
                    def id(self):
                        return identity
                    def test_required(self):
                        parent_outcome = self._outcome
                        # A real independent unittest outcome models the child's
                        # copied result. Only an escaping exception reaches parent.
                        self._outcome = unittest.case._Outcome(unittest.TestResult())
                        try:
                            boundary = getattr(native, "child_assertions", lambda _: nullcontext())
                            with boundary(self):
                                with self.subTest(timing="window"):
                                    if kind == "error":
                                        raise RuntimeError("synthetic child race error")
                                    self.assertEqual(b"wrong snapshot", b"expected snapshot")
                        finally:
                            self._outcome = parent_outcome
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "synthetic-proof.json"
                    suite = unittest.TestSuite([Sample("test_required")])
                    source = {"source_commit": "f" * 40, "files": {}}
                    with patch.dict(os.environ), patch.object(module, "REQUIRED_NATIVE", (identity,)), \
                            patch.object(module, "platform_errors", return_value=[]), \
                            patch.object(module, "source_snapshot", return_value=source), \
                            patch.object(module.unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite), \
                            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        code = module.main(["--native", "--source-commit", "f" * 40, "--output", str(output)])
                    proof = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(code, 1)
                    self.assertEqual(proof["status"], "failed")
                    self.assertEqual(proof["required"][identity], "failed" if kind == "failure" else "error")
                    self.assertEqual(proof["counts"]["failures" if kind == "failure" else "errors"], 1)

    def test_written_proof_is_sanitized_and_readable(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "proof.json"
            module.write_proof(output, {"status": "failed", "required": {"synthetic": "missing"}})
            self.assertIn('"failed"', output.read_text(encoding="utf-8"))

    def test_portable_mode_cannot_claim_native(self):
        module = self.runner()
        self.assertEqual(module.platform_errors(native=False), [])
        self.assertTrue(module.platform_errors(native=True, system="Windows"))

    def test_source_gate_rejects_wrong_head_and_uncommitted_bytes(self):
        module = self.runner()
        from deploy.wazuh.https_setup.host import KIT_FILES
        names = ["deploy/wazuh/" + name for name in KIT_FILES]
        names += ["deploy/wazuh/Run-SelfTests.py", *("deploy/wazuh/tests/" + name + ".py" for name in
                  ("test_components", "test_transaction", "test_runner", "test_native")),
                  ".github/workflows/wazuh-http-operator.yml", "docs/manager/wazuh-http-preparation.md"]
        sha = "f" * 40
        def git(argv, **kwargs):
            return SimpleNamespace(stdout=(sha + "\n").encode() if "rev-parse" in argv else b"canonical\n")
        with tempfile.TemporaryDirectory() as temporary:
            module.ROOT = Path(temporary)
            for name in names:
                path = module.ROOT / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"canonical\n")
            with patch.object(module.subprocess, "run", side_effect=git):
                source = module.source_snapshot(sha)
                self.assertEqual(set(source["files"]), set(names))
                self.assertEqual(source["source_commit"], sha)
                (module.ROOT / names[0]).write_bytes(b"canonical\r\n")
                with self.assertRaisesRegex(ValueError, "source_bytes_mismatch"):
                    module.source_snapshot(sha)
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(stdout=b"0" * 40 + b"\n")):
                with self.assertRaisesRegex(ValueError, "source_head_mismatch"):
                    module.source_snapshot(sha)

    def test_source_gate_requires_full_lowercase_commit(self):
        module = self.runner()
        for commit in (None, "HEAD", "a" * 39, "A" * 40, "a" * 41):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "source_commit_required"):
                module.source_snapshot(commit)

    def test_proof_scope_names_relocations_without_vendor_claim(self):
        module = self.runner()
        self.assertTrue(hasattr(module, "proof_scope"), "proof lacks explicit synthetic harness scope")
        native = module.proof_scope(native=True)
        self.assertFalse(native["vendor_lab_acceptance"])
        self.assertEqual(native["systemd_fixture_relocations"], ["host.INSTALL_ROOT", "host.PROFILE"])
        self.assertEqual(module.proof_scope(native=False)["systemd_fixture_relocations"], [])


class NativeFixtureSafety(unittest.TestCase):
    """Portable refusal tests only; these mocks supply no native OS proof."""
    def test_unknown_systemd_state_refuses_before_namespace_mutation(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=False), \
                patch.object(native, "command", return_value=SimpleNamespace(returncode=1, stdout=b"")):
            with self.assertRaisesRegex(AssertionError, "real_wazuh_unit_refused"):
                native.disposable_fence()

    def test_real_wazuh_path_refuses_without_host_commands(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=True), patch.object(native, "command") as commands:
            with self.assertRaisesRegex(AssertionError, "real_wazuh_footprint_refused"):
                native.disposable_fence()
            commands.assert_not_called()

    def test_real_wazuh_unit_or_package_refuses(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=False):
            with patch.object(native, "command", return_value=SimpleNamespace(returncode=0, stdout=b"loaded")):
                with self.assertRaisesRegex(AssertionError, "real_wazuh_unit_refused"):
                    native.disposable_fence()
            replies = [SimpleNamespace(returncode=0, stdout=b"not-found")] * 3
            replies += [SimpleNamespace(returncode=0, stdout=b"installed\n")]
            with patch.object(native, "command", side_effect=replies):
                with self.assertRaisesRegex(AssertionError, "real_wazuh_package_refused"):
                    native.disposable_fence()
