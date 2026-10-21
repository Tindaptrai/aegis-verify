"""Public demo replay from a packaged layout, without a source checkout."""

from hashlib import sha256
from importlib import metadata
import json
from pathlib import Path
import shutil
import sys
import threading
import types
import urllib.request

import pytest

from aegis_verify import cli
from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.dashboard import make_server


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = (
    "scn002-lab-sanitized", "scn003-lab-sanitized",
    "scn004-lab-c-sanitized", "scn005-elastic-synthetic",
    "scn006-elastic-synthetic",
)


@pytest.fixture
def resources(tmp_path, monkeypatch):
    root = tmp_path / "installed resources"
    root.mkdir()
    shutil.copytree(ROOT / "scenarios", root / "scenarios")
    for name in FIXTURES:
        shutil.copytree(ROOT / "tests/fixtures/cli" / name, root / "fixtures" / name)
    reports = root / "dashboard-reports"
    reports.mkdir()
    for name in ("before-false-negative.json", "after-detected.json"):
        shutil.copyfile(ROOT / "tests/fixtures/dashboard" / name, reports / name)
    static = root / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>Packaged dashboard</title>")
    (root / "licenses").mkdir()
    shutil.copyfile(ROOT / "frontend/THIRD_PARTY_NOTICES.txt", root / "licenses/frontend.txt")
    # Only package discovery is replaced; intake, parsers, engine and HTTP are real.
    module = types.ModuleType("aegis_verify.resources")
    module.resource_root = lambda: root
    monkeypatch.setitem(sys.modules, "aegis_verify.resources", module)
    return root


def hashes(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def test_demo_replays_eight_cases_and_keeps_evidence_links(resources, tmp_path, capsys):
    before = hashes(resources)
    output = tmp_path / "new demo đ"
    assert cli.main(["demo", "--out", str(output)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    summary = json.loads(captured.out)
    assert summary["kind"] == "demo_summary"
    assert summary["network_access"] is False
    assert summary["scenario_execution"] is False
    expected = {
        "scn002-control": "Inconclusive", "scn002-block": "Prevented",
        "scn003-detected": "Detected", "scn004-block-siem": "Prevented",
        "scn004-block": "Inconclusive", "scn004-sensor-down": "Inconclusive",
        "scn005-synthetic": "Detected", "scn006-synthetic": "Detected",
    }
    assert {item["case"]: item["final_status"] for item in summary["evaluations"]} == expected
    for item in summary["evaluations"]:
        report = json.loads((output / item["report"]).read_bytes())
        assert item["final_status"] == report["evaluation"]["final_status"]
        assert item["evidence_ids"] == [entry["event_id"]
                                       for entry in report["evaluation"]["evidence_index"]]
        assert item["evidence_ids"]
        assert all(entry["raw_event_ref"] for entry in report["evaluation"]["evidence_index"])
    assert {item["case"]: item["status"] for item in summary["comparisons"]} == {
        "scn002-control-to-block": "Inconclusive", "synthetic-gap-to-fix": "Regression Passed"}
    direct = evaluate_bundle(resources / "scenarios/SCN-003-internal-deception.yaml",
                             resources / "fixtures/scn003-lab-sanitized",
                             profile=resources / "scenarios/profiles/scn-003/profile.json")
    assert json.loads((output / "reports/scn003-detected.json").read_bytes()) == direct
    provenance = json.loads((output / "provenance.json").read_bytes())
    for entry in provenance["files"]:
        assert sha256((output / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    assert provenance["synthetic_data"]
    assert provenance["sanitized_derivatives"]
    assert (output / "README.md").is_file()
    assert (output / "licenses/frontend.txt").read_bytes() == (
        ROOT / "frontend/THIRD_PARTY_NOTICES.txt").read_bytes()
    assert hashes(resources) == before


def test_demo_never_overwrites_an_existing_directory(resources, tmp_path, capsys):
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep.txt").write_bytes(b"existing user data")
    before = hashes(output)
    assert cli.main(["demo", "--out", str(output)]) == 2
    assert capsys.readouterr().out == ""
    assert hashes(output) == before


def test_demo_failure_removes_only_its_new_directory(resources, tmp_path, capsys):
    # An actual evidence hash mismatch must abort the kit, not publish partial verdicts.
    broken = resources / "fixtures/scn002-lab-sanitized/control"
    inputs = json.loads((broken / "inputs.json").read_bytes())
    path = broken / inputs["files"][0]["path"]
    path.write_bytes(path.read_bytes() + b" ")
    unrelated = tmp_path / "keep.txt"
    unrelated.write_bytes(b"untouched")
    output = tmp_path / "failed demo"
    assert cli.main(["demo", "--out", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hash_mismatch" in captured.err
    assert not output.exists()
    assert unrelated.read_bytes() == b"untouched"


@pytest.mark.parametrize("arguments", [
    ["demo", "--out", "one", "--out", "two"],
    ["dashboard", "--reports", "one", "--scenarios", "two", "--scenarios=three"],
    ["dashboard", "--reports", "one", "--bundled", "--bundled"],
])
def test_duplicate_standalone_options_fail_before_writes(arguments, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid_arguments" in captured.err
    assert list(tmp_path.iterdir()) == []


def test_version_uses_installed_distribution_metadata(capsys):
    assert cli.main(["--version"]) == 0
    captured = capsys.readouterr()
    assert metadata.version("aegis-verify") in captured.out
    assert captured.err == ""


def test_bundled_dashboard_serves_packaged_static_and_six_scenarios(resources, tmp_path, monkeypatch, capsys):
    reports = tmp_path / "reports"
    reports.mkdir()
    shutil.copyfile(resources / "dashboard-reports/after-detected.json", reports / "sample.json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    observed = {}

    def check_server(reports_dir, **kwargs):
        kwargs.pop("announce")
        server = make_server(reports_dir, **kwargs)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:" + str(server.server_address[1])
        try:
            with opener.open(base + "/", timeout=2) as response:
                observed["html"] = response.read()
            with opener.open(base + "/api/scenarios", timeout=2) as response:
                observed["scenarios"] = json.load(response)
            with opener.open(base + "/api/reports/sample.json", timeout=2) as response:
                observed["report"] = json.load(response)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        return 0

    monkeypatch.setattr(cli, "serve", check_server)
    assert cli.main(["dashboard", "--reports", str(reports), "--port", "0", "--bundled"]) == 0
    assert b"Packaged dashboard" in observed["html"]
    assert len(observed["scenarios"]["scenarios"]) == 6
    assert observed["report"] == json.loads((reports / "sample.json").read_bytes())
    assert capsys.readouterr().err == ""


def test_bundled_dashboard_explicit_paths_take_precedence(resources, tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    explicit_static = tmp_path / "custom static"
    explicit_static.mkdir()
    explicit_scenarios = tmp_path / "custom scenarios"
    explicit_scenarios.mkdir()
    received = {}

    def serve(_reports_dir, **kwargs):
        received.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "serve", serve)
    assert cli.main(["dashboard", "--reports", str(reports), "--bundled",
                     "--static", str(explicit_static), "--scenarios", str(explicit_scenarios)]) == 0
    assert Path(received["static_dir"]) == explicit_static
    assert Path(received["scenarios_dir"]) == explicit_scenarios


def test_dashboard_without_bundled_keeps_api_only_defaults(resources, tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    received = {}

    def serve(_reports_dir, **kwargs):
        received.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "serve", serve)
    assert cli.main(["dashboard", "--reports", str(reports)]) == 0
    assert received["static_dir"] is None
    assert received["scenarios_dir"] is None
