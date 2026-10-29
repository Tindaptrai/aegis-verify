#!/usr/bin/env python3
"""Explicit operator-only qualification; portable results never imply native proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
PORTABLE = ("deploy.wazuh.tests.test_components", "deploy.wazuh.tests.test_transaction",
            "deploy.wazuh.tests.test_runner")
NATIVE_MODULE = "deploy.wazuh.tests.test_native"
REQUIRED_NATIVE = tuple(NATIVE_MODULE + ".NativeTests." + name for name in (
    "test_openssl_signing_and_tls", "test_securefs_permissions_nofollow_and_inode",
    "test_journal_fsync_and_process_lock", "test_renameat2_publication_and_refusal",
    "test_publication_races_preserve_evidence", "test_nft_allowed_denied_sources",
    "test_systemd_every_start_guard"))


class ProofResult(unittest.TextTestResult):
    """Record IDs only: tracebacks/command output never enter the public proof."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.setdefault(test.id(), "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = "failed"

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = "error"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test.id()] = "skipped"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.outcomes[test.id()] = "failed"


def required_results(result, required):
    return {name: result.outcomes.get(name, "missing") for name in required}


def qualified(result, required):
    return (result.wasSuccessful() and not result.skipped and
            all(value == "passed" for value in required_results(result, required).values()))


def platform_errors(*, native, system=None):
    if not native:
        return []
    errors = []
    if (system or platform.system()) != "Linux":
        return ["linux_required"]
    if sys.version_info[:2] != (3, 12):
        errors.append("python312_required")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        errors.append("root_required")
    if not Path("/run/systemd/system").is_dir():
        errors.append("systemd_required")
    for tool in ("openssl", "nft", "ip", "systemctl", "systemd-analyze", "busctl"):
        if not shutil.which(tool):
            errors.append(tool.replace("-", "_") + "_required")
    return errors


def proof_scope(*, native):
    return {"intended_scope": "synthetic_linux" if native else "portable",
            "vendor_lab_acceptance": False,
            "systemd_fixture_relocations": ["host.INSTALL_ROOT", "host.PROFILE"] if native else []}


def source_snapshot(commit):
    """Compare executed bytes to Git blobs, including the gate itself."""
    from deploy.wazuh.https_setup.host import KIT_FILES
    if not re.fullmatch("[0-9a-f]{40}", commit or ""):
        raise ValueError("source_commit_required")
    prefix = "deploy/wazuh/"
    names = [prefix + name for name in KIT_FILES]
    names += [prefix + "Run-SelfTests.py", *(prefix + "tests/" + name + ".py" for name in
              ("test_components", "test_transaction", "test_runner", "test_native")),
              ".github/workflows/wazuh-http-operator.yml", "docs/manager/wazuh-http-preparation.md"]
    def git(*args):
        return subprocess.run(["git", "-c", "safe.directory=" + str(ROOT), *args], cwd=ROOT,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=20).stdout
    if git("rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("source_head_mismatch")
    hashes = {}
    for name in names:
        blob = git("show", commit + ":" + name)
        current = (ROOT / name).read_bytes()
        if blob != current:
            raise ValueError("source_bytes_mismatch")
        hashes[name] = hashlib.sha256(blob).hexdigest()
    return {"source_commit": commit, "files": hashes}


def write_proof(path, proof):
    """Publish only sanitized JSON as 0644, separate from root-only fixtures."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".proof-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(proof, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="required Linux native qualification")
    parser.add_argument("--source-commit", help="exact 40-character checked-out commit; required for native")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    errors = platform_errors(native=args.native)
    source = None
    if args.native or args.source_commit:
        try:
            source = source_snapshot(args.source_commit)
        except (ValueError, OSError, subprocess.SubprocessError):
            errors.append("source_verification_failed")
    proof = {"schema_version": 1, "mode": "native" if args.native else "portable",
             "platform": {"system": platform.system(), "python": platform.python_version()},
             "scope": proof_scope(native=args.native),
             "source": source, "status": "failed", "errors": errors,
             "native_observations": {},
             "counts": {"run": 0, "failures": 0, "errors": 0, "skipped": 0},
             "required": {name: "missing" for name in REQUIRED_NATIVE} if args.native else {}}
    if not errors:
        if args.native:
            os.environ["AEGIS_REQUIRE_NATIVE"] = "1"
            os.environ["AEGIS_NATIVE_SOURCE_COMMIT"] = args.source_commit
        else:
            os.environ.pop("AEGIS_REQUIRE_NATIVE", None)
        suite = unittest.defaultTestLoader.loadTestsFromNames((*PORTABLE, *((NATIVE_MODULE,) if args.native else ())))
        result = unittest.TextTestRunner(verbosity=1, resultclass=ProofResult).run(suite)
        proof["counts"] = dict(run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
        proof["required"] = required_results(result, REQUIRED_NATIVE) if args.native else {}
        if args.native:
            proof["native_observations"] = getattr(sys.modules.get(NATIVE_MODULE), "OBSERVATIONS", {})
        proof["status"] = "passed" if qualified(result, REQUIRED_NATIVE if args.native else ()) else "failed"
        # Catch accidental source mutation by tests as well as pre-run drift.
        if source is not None:
            try:
                if source_snapshot(args.source_commit) != source:
                    raise ValueError
            except (ValueError, OSError, subprocess.SubprocessError):
                proof["status"] = "failed"
                errors.append("source_changed_during_tests")
    write_proof(args.output, proof)
    print(json.dumps({"status": proof["status"], "mode": proof["mode"], "counts": proof["counts"]}, sort_keys=True))
    return 0 if proof["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
