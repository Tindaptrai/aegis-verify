"""CI certification counts real test outcomes and refuses missing required roles."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


def gate_module():
    spec = importlib.util.spec_from_file_location("required_manager_tests", ROOT / "scripts/run_required_manager_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cases(*states):
    gate = gate_module()
    class Case(unittest.TestCase):
        def __init__(self, state, index):
            super().__init__("runTest")
            self.state, self.index = state, index
        def id(self):
            return "control.tests.test_execution_cross_language.ExecutionCrossLanguageTests.test_" + str(self.index)
        def runTest(self):
            if self.state == "skip": self.skipTest("synthetic optional prerequisite")
            if self.state == "fail": self.fail("synthetic private value must not appear in artifact")
            if self.state == "subtest":
                for value in (1, 2):
                    with self.subTest(value=value): self.assertEqual(value, 1)
    return unittest.TextTestRunner(stream=io.StringIO(), resultclass=gate.GateResult).run(
        unittest.TestSuite(Case(state, index) for index, state in enumerate(states)))


def report(result, required=("vectors",), errors=()):
    return gate_module().build_report(result, required, "a" * 40,
        "https://github.com/example/project/actions/runs/1", errors)


def test_required_role_needs_actual_nonzero_success_and_cannot_count_diagnostic_units():
    assert report(run_cases("pass"))["result"] == "passed"
    missing = report(run_cases("pass"), ("published_service",))
    assert missing["result"] == "failed"
    assert missing["categories"][0]["executed"] == 0
    assert missing["categories"][0]["result"] == "failed"
    assert report(run_cases())["result"] == "failed"


def test_required_skip_failure_and_subtest_failure_refuse_green_without_leaking_values():
    for state in ("skip", "fail", "subtest"):
        value = report(run_cases(state))
        assert value["result"] == "failed"
        assert "private value" not in str(value)
        category = value["categories"][0]
        assert category["skipped"] == (state == "skip")
        assert category["failed"] == (state != "skip")
        assert category["executed"] == (state != "skip")


def test_optional_cross_platform_skip_is_recorded_without_invalidating_required_role():
    result = run_cases("pass")
    class Optional(unittest.TestCase):
        @unittest.skip("other platform")
        def runTest(self): pass
    Optional().run(result)
    value = report(result)
    assert value["result"] == "passed"
    assert value["totals"]["skipped"] == 1
    assert value["categories"][0]["executed"] == 1


def test_decorated_required_skip_cannot_hide_behind_another_success():
    result = run_cases("pass")
    class RequiredSkipped(unittest.TestCase):
        def id(self):
            return "control.tests.test_execution_cross_language.ExecutionCrossLanguageTests.test_decorated_skip"
        @unittest.skip("synthetic required prerequisite unavailable")
        def runTest(self): pass
    RequiredSkipped().run(result)
    value = report(result)
    assert value["result"] == "failed"
    assert value["totals"] == {"executed": 1, "passed": 1, "failed": 0, "skipped": 1}
    assert value["categories"][0]["skipped"] == 1
    assert value["categories"][0]["executed"] == 1


def test_missing_prerequisites_produce_failed_zero_artifact(tmp_path):
    gate = gate_module()
    errors = gate.prerequisites(("postgres_execution", "nginx_execution", "vectors", "published_service"),
                               vendor="sqlite", environ={}, which=lambda _: None)
    assert set(errors) == {"postgresql_required", "nginx_required", "vector_harness_required", "published_cli_required", "service_package_required"}
    value = report(run_cases(), errors=errors)
    path = tmp_path / "result.json"
    gate.write_report(path, value)
    assert path.is_file() and value["result"] == "failed"
    assert value["totals"]["executed"] == 0


def test_published_roles_are_disjoint_and_use_actual_test_ids():
    gate = gate_module()
    native = "devices.tests.test_connection_agent.PublishedConnectionTests.test_native_installer_network_reconnect_reinstall_archive_and_preserving_uninstall"
    cli = "devices.tests.test_connection_agent.PublishedConnectionTests.test_cli_enrolls_over_ip_san_tls_reconnects_same_uuid_and_honors_revoke"
    diagnostic = "devices.tests.test_connection_agent.NativeDiagnosticsTests.test_recognized_closed_diagnostic_surfaces_only_fixed_stage_and_code"
    assert gate.category_for(native) == "published_service"
    assert gate.category_for(cli) == "published_presence"
    assert gate.category_for(diagnostic) is None
    assert gate.category_for("control.tests.test_execution_worker_service.WorkerServiceHarnessTests.test_wrapper") is None
    assert gate.category_for("control.tests.test_execution_worker_service.RegisteredWorkerSystemdTests.test_lifecycle") == "manager_worker_service"


def test_failure_diagnostics_include_fixed_test_and_repo_frames_without_values():
    value = report(run_cases("fail", "subtest"))
    assert len(value["diagnostics"]) == 2
    for diagnostic in value["diagnostics"]:
        assert diagnostic["test_id"].startswith("control.tests.test_execution_cross_language.ExecutionCrossLanguageTests.test_")
        assert diagnostic["exception_class"] == "AssertionError"
        assert diagnostic["frames"]
        assert all(frame["path"] == "backend/tests/test_required_manager_tests.py" and type(frame["line"]) is int
                   for frame in diagnostic["frames"])
        assert diagnostic["stage"] is None
    encoded = json.dumps(value)
    assert "synthetic private value" not in encoded
    assert "value=2" not in encoded
    assert str(ROOT) not in encoded


def test_subprocess_timeout_diagnostic_keeps_type_without_private_command_or_output():
    gate = gate_module()
    case = unittest.FunctionTestCase(lambda: None)
    case.id = lambda: 'control.tests.test_worker_health.WorkerHealthTests.test_synthetic_acl_probe'
    try:
        raise subprocess.TimeoutExpired(['PRIVATE_COMMAND', 'PRIVATE_PATH'], 10,
                                        output=b'PRIVATE_OUTPUT', stderr=b'PRIVATE_ERROR')
    except subprocess.TimeoutExpired:
        diagnostic = gate.safe_diagnostic(case, sys.exc_info())
    assert diagnostic['exception_class'] == 'TimeoutExpired'
    assert 'PRIVATE' not in json.dumps(diagnostic)


def test_diagnostics_accept_only_closed_stage_status_and_code_values():
    gate = gate_module()
    result = gate.GateResult(io.StringIO(), True, 0)
    case = unittest.FunctionTestCase(lambda: None)
    case.id = lambda: "control.tests.test_execution_worker_service.RegisteredWorkerSystemdTests.test_lifecycle"
    case.gate_stage = "unit_start"
    case.gate_codes = ["worker_process_failed", "PRIVATE_TOKEN"]
    case.gate_service_status = dict(ActiveState="failed", SubState="dead", Result="exit-code", ExecMainStatus=127,
                                    private="PRIVATE_PATH")
    case.gate_runtime_status = dict(minimal_environment_returncode=127, library_environment_returncode=0, private="PRIVATE_KEY")
    case.gate_cleanup_status = dict(role="private", operation="unlink", owner_uid=0, mode=384, private="PRIVATE_DESCENDANT")
    try:
        raise AssertionError("PRIVATE_CREDENTIAL")
    except AssertionError:
        result.addFailure(case, sys.exc_info())
    diagnostic = report(result)["diagnostics"][0]
    assert diagnostic["stage"] == "unit_start"
    assert diagnostic["codes"] == ["worker_process_failed"]
    assert diagnostic["service_status"] == dict(ActiveState="failed", SubState="dead", Result="exit-code", ExecMainStatus=127)
    assert diagnostic["runtime_status"] == dict(minimal_environment_returncode=127, library_environment_returncode=0)
    assert diagnostic["cleanup_status"] == dict(role="private", operation="unlink", owner_uid=0, mode=384)
    assert "PRIVATE" not in json.dumps(diagnostic)
    case.gate_stage = "PRIVATE_STAGE"
    case.gate_service_status = dict(ActiveState="PRIVATE", ExecMainStatus=True)
    case.gate_runtime_status = dict(minimal_environment_returncode="PRIVATE", library_environment_returncode=999999)
    case.gate_cleanup_status = dict(role="PRIVATE", operation="PRIVATE", owner_uid=True, mode=999999)
    try:
        raise AssertionError("PRIVATE")
    except AssertionError:
        result.addFailure(case, sys.exc_info())
    last = report(result)["diagnostics"][-1]
    assert last["stage"] is None and last["service_status"] == {} and last["runtime_status"] == {}
    assert last["cleanup_status"] == {}


def test_diagnostics_are_bounded_and_external_frames_custom_classes_are_withheld(tmp_path):
    gate = gate_module()
    result = gate.GateResult(io.StringIO(), True, 0)
    case = unittest.FunctionTestCase(lambda: None)
    case.id = lambda: "PRIVATE/path:token"
    custom = type("PRIVATE_TOKEN_EXCEPTION", (Exception,), {})
    space = {"failure": custom}
    exec(compile("def fail():\n    raise failure('PRIVATE_CREDENTIAL')\n", str(tmp_path / "PRIVATE_PATH.py"), "exec"), space)
    for _ in range(40):
        try:
            space["fail"]()
        except Exception:
            result.addError(case, sys.exc_info())
    value = report(result)
    assert len(value["diagnostics"]) == 32 and value["diagnostics_truncated"] is True
    assert all(item["test_id"] == "test_id_withheld" and item["exception_class"] == "OtherException"
               and len(item["frames"]) <= 8 for item in value["diagnostics"])
    assert "PRIVATE" not in json.dumps(value)


def test_deep_traceback_and_class_setup_errors_remain_bounded_without_fake_execution():
    gate = gate_module()
    class SetupFailure(unittest.TestCase):
        __module__ = "control.tests.test_execution_worker_service"
        @classmethod
        def setUpClass(cls): raise RuntimeError("PRIVATE_SETUP")
        def runTest(self): pass
    SetupFailure.__qualname__ = "SetupFailure"
    result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=gate.GateResult).run(unittest.TestSuite([SetupFailure()]))
    value = report(result)
    assert value["result"] == "failed" and value["totals"]["executed"] == 0
    assert value["suite_failures"] == 1
    assert value["diagnostics"][0]["test_id"].endswith(".setUpClass")
    def nested(depth):
        if depth: nested(depth - 1)
        else: raise RuntimeError("PRIVATE_LOCALS")
    try:
        nested(20)
    except RuntimeError:
        result.addError(SetupFailure(), sys.exc_info())
    value = report(result)
    assert len(value["diagnostics"][-1]["frames"]) == 8
    assert "PRIVATE" not in json.dumps(value)


def test_release_workflow_installs_git_before_checkout_and_checks_pure_mode():
    import yaml
    manager = yaml.safe_load((ROOT / ".github/workflows/manager-first-flow.yml").read_text())
    steps = manager["jobs"]["manager-postgres"]["steps"]
    checkout = next(index for index, step in enumerate(steps) if step.get("uses", "").startswith("actions/checkout@"))
    assert any("apt-get install" in step.get("run", "") and "git" in step["run"] for step in steps[:checkout])
    gate = next(step["run"] for step in steps if "--require postgres_execution" in step.get("run", ""))
    assert '--source-commit "$AEGIS_MANAGER_SOURCE_COMMIT"' in gate
    assert '$(git rev-parse HEAD)' not in gate
    source = next(step["run"] for step in steps if "--verify-source" in step.get("run", ""))
    assert '--workspace "$GITHUB_WORKSPACE"' in source
    assert '--requested-commit "$REQUESTED_SOURCE_COMMIT"' in source
    assert '--github-env "$GITHUB_ENV"' in source
    assert '--output "$RUNNER_TEMP/manager-postgres-source.json"' in source
    artifact = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert artifact["if"] == "always()" and "manager-postgres-source.json" in artifact["with"]["path"]
    agent = yaml.safe_load((ROOT / ".github/workflows/agent-connection.yml").read_text())
    script = next(step["run"] for step in agent["jobs"]["native-connection"]["steps"]
                  if "Test-InstallerContracts.ps1" in step.get("run", ""))
    assert "Test-InstallerContracts.ps1 -Pure" in script
    assert script.count("Test-InstallerContracts.ps1") == 2
    assert "Test-InstallerContracts.ps1 -Pure\n  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in script


def test_source_verifier_uses_only_command_scoped_exact_resolved_workspace_trust():
    gate = gate_module()
    source = ROOT.resolve().as_posix()
    expected = subprocess.check_output(["git", "-c", "safe.directory=", "-c", "safe.directory=" + source,
                                       "-C", source, "rev-parse", "--verify", "HEAD"], text=True).strip()
    environment = dict(os.environ, GIT_TEST_ASSUME_DIFFERENT_OWNER="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    refused = subprocess.run(["git", "-c", "safe.directory=", "-C", source, "rev-parse", "--verify", "HEAD"],
                             env=environment, capture_output=True, text=True)
    assert refused.returncode == 128, "Git ownership guard must be exercised without changing OS ownership"
    calls = []
    def run(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.run(arguments, env=environment, **kwargs)
    head, code = gate.verify_source_commit(ROOT, expected, run=run)
    assert (head, code) == (expected, None)
    assert calls == [["git", "-c", "safe.directory=", "-c", "safe.directory=" + source,
                      "-C", source, "rev-parse", "--verify", "HEAD"]]
    head, code = gate.verify_source_commit(ROOT, "a" * 40 if expected != "a" * 40 else "b" * 40, run=run)
    assert head is None and code == "source_commit_mismatch"


def test_source_refusal_writes_failed_artifact_and_never_propagates_unverified_sha(tmp_path, monkeypatch, capsys):
    gate = gate_module()
    monkeypatch.setattr(gate, "verify_source_commit", lambda *args, **kwargs: (None, "source_git_verification_failed"))
    path, environment = tmp_path / "source.json", tmp_path / "github-env"
    result = gate.verify_source_main(["--workspace", str(ROOT), "--requested-commit", "a" * 40,
        "--github-env", str(environment), "--output", str(path),
        "--run-url", "https://github.com/example/project/actions/runs/1"])
    value = json.loads(path.read_text())
    assert result == 1 and value["kind"] == "ci_source_verification" and value["result"] == "failed"
    assert value["source_commit"] is None and value["blocking_codes"] == ["source_git_verification_failed"]
    assert not environment.exists()
    assert str(ROOT) not in capsys.readouterr().out


def test_source_verifier_rejects_other_workspaces_and_invalid_metadata_without_git(tmp_path):
    gate = gate_module()
    def forbidden(*args, **kwargs): raise AssertionError("Git must not run outside the exact checkout")
    assert gate.verify_source_commit(tmp_path, "a" * 40, run=forbidden) == (None, "source_workspace_invalid")
    assert gate.verify_source_commit(tmp_path / "absent", "a" * 40, run=forbidden) == (None, "source_workspace_invalid")
    assert gate.verify_source_commit(ROOT, "PRIVATE_INVALID_SHA", run=forbidden) == (None, "invalid_gate_metadata")


def test_verified_source_propagates_exact_sha_and_preserves_environment_file(tmp_path, monkeypatch):
    gate = gate_module()
    monkeypatch.setattr(gate, "verify_source_commit", lambda *args, **kwargs: ("a" * 40, None))
    path, environment = tmp_path / "source.json", tmp_path / "github-env"
    environment.write_text("EXISTING=preserved\n")
    result = gate.verify_source_main(["--workspace", str(ROOT), "--requested-commit", "a" * 40,
        "--github-env", str(environment), "--output", str(path),
        "--run-url", "https://github.com/example/project/actions/runs/1"])
    assert result == 0 and json.loads(path.read_text())["source_commit"] == "a" * 40
    assert environment.read_text() == "EXISTING=preserved\nAEGIS_MANAGER_SOURCE_COMMIT=" + "a" * 40 + "\n"
