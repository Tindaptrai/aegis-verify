"""CI-only Django runner: certify required roles from actual unittest outcomes."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

PREFIXES = {
    "postgres_accounts": "accounts.tests.test_postgres_concurrency.",
    "postgres_control": "control.tests.test_postgres_concurrency.",
    "postgres_devices": "devices.tests.test_postgres_concurrency.",
    "postgres_catalog": "catalog.tests.test_postgres_concurrency.",
    "postgres_execution": "control.tests.test_execution_postgres.",
    "vectors": "control.tests.test_execution_cross_language.ExecutionCrossLanguageTests.",
    "manager_worker_service": "control.tests.test_execution_worker_service.RegisteredWorkerSystemdTests.",
}
PUBLISHED = "devices.tests.test_connection_agent.PublishedConnectionTests."
EXACT = {
    "nginx_execution": "control.tests.test_proxy_mtls.NginxMutualTlsTests.test_execution_exact_routes_require_verified_certificate",
    "published_service": PUBLISHED + "test_native_installer_network_reconnect_reinstall_archive_and_preserving_uninstall",
    "linux_presence_only": PUBLISHED + "test_linux_published_client_remains_presence_only_and_rejects_execution_options",
}
CATEGORIES = (*PREFIXES, *EXACT, "published_presence")
ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_STAGES = frozenset((
    "fixture_setup", "source_staging", "source_tls", "authority_setup", "environment_setup",
    "unit_enable", "unit_start", "worker_health", "service_properties", "worker_lock",
    "source_block", "source_keepalive", "unit_stop", "unit_restart", "approved_job",
    "collection_claim", "interrupted_restart", "durable_claim", "explicit_recovery",
    "failed_claim", "owner_review", "fixture_cleanup", "published_fixture", "published_authority",
    "published_tls", "published_connect", "published_status", "published_run", "published_wait",
    "published_native_install", "published_native_restart", "published_native_reinstall",
    "published_native_status", "published_native_uninstall",
))
DIAGNOSTIC_CODES = frozenset(("worker_process_failed", "published_cli_failed", "published_native_failed",
    "source_probe_failed", "wait_timeout", "gate_execution_failed", "unexpected_success"))
EXCEPTION_CLASSES = frozenset(("AssertionError", "AttributeError", "ValueError", "TypeError", "KeyError",
    "IndexError", "RuntimeError", "OSError", "PermissionError", "FileNotFoundError", "TimeoutError",
    "CalledProcessError", "TimeoutExpired", "SSLError", "ConnectionError", "OperationalError", "IntegrityError",
    "ImproperlyConfigured", "ImportError", "ModuleNotFoundError", "SystemExit", "UnicodeError"))
SERVICE_ENUMS = {
    "ActiveState": frozenset(("active", "activating", "inactive", "deactivating", "failed", "reloading", "maintenance", "refreshing")),
    "SubState": frozenset(("dead", "running", "exited", "failed", "auto-restart", "auto-restart-queued", "start", "start-pre", "start-post", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill", "reload", "reload-signal", "reload-notify", "condition", "cleaning")),
    "Result": frozenset(("success", "exit-code", "signal", "core-dump", "timeout", "watchdog", "start-limit-hit", "resources", "protocol", "oom-kill", "exec-condition", "assert", "condition")),
}


def diagnostic_id(test):
    if test is None: return "gate_setup"
    identity = test.id()
    if type(identity) is str and len(identity) <= 256:
        if re.fullmatch(r"(?:accounts|control|devices|catalog)\.tests\.[A-Za-z0-9_.]+", identity): return identity
        holder = re.fullmatch(r"(setUpClass|tearDownClass|setUpModule|tearDownModule) \(((?:accounts|control|devices|catalog)\.tests\.[A-Za-z0-9_.]+)\)", identity)
        if holder: return holder[2] + "." + holder[1]
    return "test_id_withheld"


def safe_diagnostic(test, err):
    frames = []
    traceback = err[2] if err is not None else None
    while traceback is not None:
        try:
            path = Path(traceback.tb_frame.f_code.co_filename).resolve()
            if path.is_relative_to(ROOT) and path.is_file():
                relative = path.relative_to(ROOT).as_posix()
                if len(relative) <= 240 and re.fullmatch(r"[A-Za-z0-9_./-]+", relative):
                    frames.append(dict(path=relative, line=traceback.tb_lineno))
                    frames = frames[-8:]
        except (OSError, ValueError):
            pass
        traceback = traceback.tb_next
    exception = err[0].__name__ if err is not None else "UnexpectedSuccess"
    if exception not in EXCEPTION_CLASSES and exception != "UnexpectedSuccess": exception = "OtherException"
    stage = getattr(test, "gate_stage", None)
    stage = stage if type(stage) is str and stage in DIAGNOSTIC_STAGES else None
    codes = getattr(test, "gate_codes", ())
    codes = sorted({code for code in codes[:16] if type(code) is str and code in DIAGNOSTIC_CODES}) if type(codes) in (tuple, list) else []
    service = getattr(test, "gate_service_status", None)
    service_status = {}
    if type(service) is dict:
        for name, vocabulary in SERVICE_ENUMS.items():
            value = service.get(name)
            if type(value) is str and value in vocabulary: service_status[name] = value
        status = service.get("ExecMainStatus")
        if type(status) is int and 0 <= status <= 255: service_status["ExecMainStatus"] = status
    runtime = getattr(test, "gate_runtime_status", None)
    runtime_status = {}
    if type(runtime) is dict:
        for name in ("minimal_environment_returncode", "library_environment_returncode"):
            value = runtime.get(name)
            if type(value) is int and -255 <= value <= 255: runtime_status[name] = value
    cleanup = getattr(test, "gate_cleanup_status", None)
    cleanup_status = {}
    if type(cleanup) is dict:
        for name, allowed in (("role", ("root", "source", "python", "private", "unit", "other")),
                              ("operation", ("unlink", "rmdir", "open", "scandir", "lstat", "other"))):
            value = cleanup.get(name)
            if type(value) is str and value in allowed: cleanup_status[name] = value
        for name, maximum in (("owner_uid", 2147483647), ("mode", 4095)):
            value = cleanup.get(name)
            if type(value) is int and 0 <= value <= maximum: cleanup_status[name] = value
    return dict(test_id=diagnostic_id(test), exception_class=exception, frames=frames[-8:],
                stage=stage, codes=codes, service_status=service_status, runtime_status=runtime_status,
                cleanup_status=cleanup_status)


def category_for(identity):
    for name, exact in EXACT.items():
        if identity == exact: return name
    for name, prefix in PREFIXES.items():
        if identity.startswith(prefix): return name
    if identity.startswith(PUBLISHED): return "published_presence"
    return None


class GateResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started, self.outcomes = set(), {}
        self.diagnostics, self.diagnostics_truncated = [], False

    def record_diagnostic(self, test, err):
        if len(self.diagnostics) >= 32:
            self.diagnostics_truncated = True
            return
        self.diagnostics.append(safe_diagnostic(test, err))

    def startTest(self, test):
        self.started.add(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        if self.outcomes.get(test.id()) != "failed": self.outcomes[test.id()] = "passed"
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.outcomes[test.id()] = "failed"
        self.record_diagnostic(test, err)
        super().addFailure(test, err)

    def addError(self, test, err):
        self.outcomes[test.id()] = "failed"
        self.record_diagnostic(test, err)
        super().addError(test, err)

    def addSkip(self, test, reason):
        self.outcomes[test.id()] = "skipped"
        super().addSkip(test, reason)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.outcomes[test.id()] = "failed"
            self.record_diagnostic(test, err)
        super().addSubTest(test, subtest, err)

    def addExpectedFailure(self, test, err):
        self.outcomes[test.id()] = "failed"
        self.record_diagnostic(test, err)
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.outcomes[test.id()] = "failed"
        self.record_diagnostic(test, None)
        super().addUnexpectedSuccess(test)


def counts(states):
    states = list(states)
    passed, failed, skipped = (states.count(state) for state in ("passed", "failed", "skipped"))
    return dict(executed=passed + failed, passed=passed, failed=failed, skipped=skipped)


def build_report(result, required, source_commit, run_url, errors=()):
    categories = []
    for name in sorted(set(required)):
        if name not in CATEGORIES: raise ValueError("invalid_gate_category")
        actual = counts(state for identity, state in result.outcomes.items()
                        if identity in result.started and category_for(identity) == name)
        passed = actual["executed"] > 0 and actual["passed"] == actual["executed"] and actual["failed"] == actual["skipped"] == 0
        categories.append(dict(name=name, **actual, result="passed" if passed else "failed"))
    totals = counts(state for identity, state in result.outcomes.items() if identity in result.started)
    # Setup/teardown failures may have no started test, but must still fail the gate.
    suite_failures = len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses) + len(result.expectedFailures)
    passed = bool(categories) and not errors and not suite_failures and totals["executed"] > 0 and totals["failed"] == 0 and all(c["result"] == "passed" for c in categories)
    return dict(schema_version=1, kind="required_manager_tests", required=True,
                source_commit=source_commit, run_url=run_url, result="passed" if passed else "failed",
                totals=totals, suite_failures=suite_failures, categories=categories,
                blocking_codes=sorted(set(errors)), diagnostics=list(result.diagnostics),
                diagnostics_truncated=result.diagnostics_truncated)


def prerequisites(required, *, vendor, environ, which=shutil.which):
    errors = set()
    if any(name.startswith("postgres_") or name == "manager_worker_service" for name in required) and vendor != "postgresql": errors.add("postgresql_required")
    if "nginx_execution" in required and which("nginx") is None: errors.add("nginx_required")
    for roles, variable, code, directory in (
        ({"vectors"}, "AEGIS_EXECUTION_VECTOR_TEST_EXE", "vector_harness_required", False),
        ({"published_presence", "published_service", "linux_presence_only"}, "AEGIS_CONNECTION_TEST_EXE", "published_cli_required", False),
        ({"published_service"}, "AEGIS_CONNECTION_SERVICE_PACKAGE", "service_package_required", True),
    ):
        if not set(required) & roles: continue
        value = environ.get(variable)
        path = Path(value) if value else None
        if path is None or not path.is_absolute() or not (path.is_dir() if directory else path.is_file()): errors.add(code)
    if "linux_presence_only" in required and not sys.platform.startswith("linux"): errors.add("linux_required")
    if "manager_worker_service" in required:
        if not sys.platform.startswith("linux"): errors.add("linux_required")
        if any(environ.get(name) != value for name, value in (
            ("AEGIS_MANAGER_REQUIRE_WORKER_SYSTEMD", "1"), ("AEGIS_MANAGER_DISPOSABLE_SYSTEMD_CI", "1"),
            ("AEGIS_MANAGER_CI", "1"), ("GITHUB_ACTIONS", "true"), ("CI", "true"),
        )): errors.add("disposable_systemd_required")
    return sorted(errors)


def write_report(path, value):
    path = Path(path)
    if not path.is_absolute(): raise ValueError("absolute_gate_output_required")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def verify_source_commit(workspace, requested, *, run=None):
    """Read only the exact resolved checkout, with trust lasting one Git command."""
    if type(requested) is not str or re.fullmatch(r"[0-9a-f]{40}", requested) is None:
        return None, "invalid_gate_metadata"
    try:
        path = Path(workspace)
        if not path.is_absolute(): return None, "source_workspace_invalid"
        resolved = path.resolve(strict=True)
        if resolved != ROOT or not resolved.is_dir(): return None, "source_workspace_invalid"
    except (OSError, ValueError):
        return None, "source_workspace_invalid"
    try:
        command = ["git", "-c", "safe.directory=", "-c", "safe.directory=" + resolved.as_posix(),
                   "-C", resolved.as_posix(), "rev-parse", "--verify", "HEAD"]
        result = (run or subprocess.run)(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None, "source_git_unavailable"
    if result.returncode != 0: return None, "source_git_verification_failed"
    lines = result.stdout.splitlines()
    if len(lines) != 1 or re.fullmatch(r"[0-9a-f]{40}", lines[0]) is None:
        return None, "source_head_invalid"
    if lines[0] != requested: return None, "source_commit_mismatch"
    return lines[0], None


def verify_source_main(argv):
    """Stdlib-only early CI check; refusals also get an uploadable artifact."""
    parser = argparse.ArgumentParser(description=verify_source_main.__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--requested-commit", required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args(argv)
    requested = args.requested_commit if re.fullmatch(r"[0-9a-f]{40}", args.requested_commit) else None
    url = args.run_url if re.fullmatch(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+/actions/runs/[0-9]+", args.run_url) else None
    errors, head = [], None
    if requested is None or url is None: errors.append("invalid_gate_metadata")
    if not args.github_env.is_absolute(): errors.append("source_environment_invalid")
    try:
        if not errors:
            head, code = verify_source_commit(args.workspace, requested)
            if code is not None: errors.append(code)
            if not errors:
                # Only the independently verified exact SHA enters later steps.
                with args.github_env.open("a", encoding="ascii", newline="\n") as stream:
                    stream.write("AEGIS_MANAGER_SOURCE_COMMIT=" + head + "\n")
    except Exception:
        errors.append("source_verification_failed")
    value = dict(schema_version=1, kind="ci_source_verification", required=True,
                 requested_source_commit=requested, source_commit=head if not errors else None,
                 run_url=url, result="failed" if errors else "passed", blocking_codes=sorted(set(errors)))
    try:
        write_report(args.output, value)
    except (OSError, ValueError):
        print("source_verification_artifact_failed", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 1 if errors else 0


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else list(argv)
    if arguments[:1] == ["--verify-source"]: return verify_source_main(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="append", choices=CATEGORIES, required=True)
    parser.add_argument("--settings", choices=("aegis_manager.test_settings", "aegis_manager.ci_settings"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("labels", nargs="+")
    args = parser.parse_args(arguments)
    result = GateResult(io.StringIO(), True, 0)
    runner = None
    execution_error = None
    errors = []
    commit = args.source_commit if re.fullmatch(r"[0-9a-f]{40}", args.source_commit) else None
    url = args.run_url if re.fullmatch(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+/actions/runs/[0-9]+", args.run_url) else None
    if commit is None or url is None: errors.append("invalid_gate_metadata")
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "manager"))
        os.environ["DJANGO_SETTINGS_MODULE"] = args.settings
        import django
        django.setup()
        from django.db import connection
        from django.test.runner import DiscoverRunner
        errors.extend(prerequisites(args.require, vendor=connection.vendor, environ=os.environ))
        if not errors:
            class RequiredRunner(DiscoverRunner):
                captured = None
                def get_resultclass(self): return GateResult
                def get_test_runner_kwargs(self):
                    return dict(super().get_test_runner_kwargs(), stream=io.StringIO())
                def run_suite(self, suite, **kwargs):
                    self.captured = super().run_suite(suite, **kwargs)
                    return self.captured
            runner = RequiredRunner(verbosity=0, interactive=False)
            failed = runner.run_tests(args.labels)
            if runner.captured is not None: result = runner.captured
            if failed and result.wasSuccessful(): errors.append("suite_failed")
    except Exception:
        errors.append("gate_execution_failed")
        execution_error = sys.exc_info()
    if runner is not None and runner.captured is not None: result = runner.captured
    if execution_error is not None: result.record_diagnostic(None, execution_error)
    value = build_report(result, args.require, commit, url, errors)
    try:
        write_report(args.output, value)
    except (OSError, ValueError):
        print("required_manager_gate_artifact_failed", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0 if value["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
