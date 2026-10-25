"""CI certification counts real test outcomes and refuses missing required roles."""
import importlib.util
import io
from pathlib import Path
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
