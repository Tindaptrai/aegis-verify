"""Scenario overview and system status for the dashboard: read-only joins of manifests and reports."""

import json
import os
from pathlib import Path
import shutil
import threading
import urllib.error
import urllib.request

import pytest

from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.compare import compare_reports
from aegis_verify.dashboard import ReportStore, make_server
from aegis_verify.dashboard.overview import (
    ScenarioRegistry, build_scenario_detail, build_scenario_index, build_system_status, OverviewError,
)

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "scenarios"
CLI = ROOT / "tests" / "fixtures" / "cli"
DASHBOARD = ROOT / "tests" / "fixtures" / "dashboard"
NOW = "2026-10-01T06:00:00Z"


def _evaluate(scenario, bundle, profile):
    return evaluate_bundle(str(SCENARIOS / scenario), str(CLI / bundle), profile=str(SCENARIOS / profile))


@pytest.fixture(scope="module")
def lab_reports():
    """Real engine output for the sanitized lab bundles; nothing is hand-written."""
    control = _evaluate("SCN-002-attempted-exfiltration.yaml", "scn002-lab-sanitized/control",
                        "profiles/scn-002/profile.json")
    block = _evaluate("SCN-002-attempted-exfiltration.yaml", "scn002-lab-sanitized/block",
                      "profiles/scn-002/profile.json")
    scn003 = _evaluate("SCN-003-internal-deception.yaml", "scn003-lab-sanitized", "profiles/scn-003/profile.json")
    return {"scn002-control.json": control, "scn002-block.json": block, "scn003.json": scn003,
            "scn002-compare.json": compare_reports(before=control, after=block)}


def _write(directory, reports, mtime=1790000000):
    directory.mkdir(parents=True, exist_ok=True)
    for offset, (name, report) in enumerate(sorted(reports.items())):
        path = directory / name
        path.write_text(json.dumps(report), encoding="utf-8")
        os.utime(path, (mtime + offset, mtime + offset))
    return directory


def _scenarios(tmp_path, *, edit=None):
    target = tmp_path / "scenarios"
    target.mkdir()
    for path in SCENARIOS.glob("SCN-*.yaml"):
        text = path.read_text(encoding="utf-8")
        if edit is not None:
            text = edit(path.name, text)
        (target / path.name).write_text(text, encoding="utf-8")
    return target


def _copy_fixture(name, directory, mtime=1789990000):
    target = directory / name
    shutil.copy(DASHBOARD / name, target)
    os.utime(target, (mtime, mtime))


@pytest.fixture
def lab(tmp_path, lab_reports):
    reports_dir = _write(tmp_path / "reports", lab_reports)
    _copy_fixture("after-detected.json", reports_dir)
    _copy_fixture("malformed-truncated.json", reports_dir)
    return ScenarioRegistry(_scenarios(tmp_path)), ReportStore(reports_dir)


def test_index_lists_every_manifest_including_never_run(lab):
    registry, store = lab
    index = build_scenario_index(registry, store)
    assert index["kind"] == "scenario_index"
    assert index["registry"]["configured"] is True and index["registry"]["errors"] == []
    rows = {row["id"]: row for row in index["scenarios"]}
    assert set(rows) == {"SCN-001", "SCN-002", "SCN-003"}
    assert rows["SCN-001"]["run_state"] == "not_run"
    assert rows["SCN-001"]["latest_run"] is None and rows["SCN-001"]["run_count"] == 0
    assert rows["SCN-001"]["status"] == "draft" and rows["SCN-001"]["expected_outcome"] == "detected"
    assert rows["SCN-003"]["run_state"] == "run"
    assert rows["SCN-003"]["latest_run"]["final_status"] == "Detected"


def test_latest_run_is_chosen_by_run_window_end_and_counts_come_from_the_report(lab, lab_reports):
    registry, store = lab
    row = {r["id"]: r for r in build_scenario_index(registry, store)["scenarios"]}["SCN-002"]
    assert row["run_count"] == 2 and row["comparison_count"] == 1
    latest = row["latest_run"]
    assert latest["name"] == "scn002-block.json" and latest["final_status"] == "Prevented"
    block = lab_reports["scn002-block.json"]
    assert latest["window_end"] == block["comparison_inputs"]["context"]["end"]
    assert latest["assertions"] == {"total": 4, **block["evaluation"]["counts"]}
    assert latest["evidence_referenced"] == block["counts"]["referenced"]
    assert latest["collection_assurance"] == {"unknown": 4}
    assert latest["profile_id"] == block["evaluation"]["profile_id"]
    assert latest["sources"] == {"pfsense": 1, "suricata": 1, "wazuh": 2}


def test_kpis_count_scenarios_by_their_latest_run(lab):
    registry, store = lab
    kpi = build_scenario_index(registry, store)["kpi"]
    assert kpi == {"total": 3, "run": 2, "not_run": 1, "by_status": {
        "Detected": 1, "Prevented": 1, "False negative": 0, "Missing telemetry": 0, "Inconclusive": 0, "Other": 0}}


def test_reports_without_manifest_and_unreadable_reports_are_listed_not_hidden(lab):
    registry, store = lab
    index = build_scenario_index(registry, store)
    assert [group["scenario_id"] for group in index["unregistered"]] == ["SCN-999"]
    assert index["unregistered"][0]["reports"] == ["after-detected.json"]
    assert index["report_errors"] == [
        {"name": "malformed-truncated.json", "code": "invalid_json", "stage": "inputs", "field": None}]


def test_missing_run_window_stays_null_and_is_not_replaced_by_file_time(tmp_path, lab_reports):
    report = json.loads(json.dumps(lab_reports["scn003.json"]))
    del report["comparison_inputs"]["context"]["end"]
    store = ReportStore(_write(tmp_path / "reports", {"scn003.json": report}))
    row = {r["id"]: r for r in build_scenario_index(ScenarioRegistry(_scenarios(tmp_path)), store)["scenarios"]}
    latest = row["SCN-003"]["latest_run"]
    assert latest["window_end"] is None
    assert latest["file_modified"] == "2026-09-21T14:13:20Z"


def test_report_of_a_changed_manifest_is_history_not_the_current_result(tmp_path, lab_reports):
    bump = lambda name, text: text.replace("version: 0.1.0", "version: 0.2.0") if name.startswith("SCN-003") else text
    registry = ScenarioRegistry(_scenarios(tmp_path, edit=bump))
    store = ReportStore(_write(tmp_path / "reports", {"scn003.json": lab_reports["scn003.json"]}))
    row = {r["id"]: r for r in build_scenario_index(registry, store)["scenarios"]}["SCN-003"]
    assert row["run_state"] == "stale_only" and row["latest_run"] is None
    assert row["run_count"] == 0 and row["stale_run_count"] == 1
    detail = build_scenario_detail(registry, store, "SCN-003")
    assert [(run["name"], run["manifest_match"], run["mismatch"]) for run in detail["runs"]] == [
        ("scn003.json", False, "version")]
    kpi = build_scenario_index(registry, store)["kpi"]
    assert kpi["run"] == 0 and kpi["not_run"] == 3


def test_edited_manifest_with_same_version_is_detected_by_fingerprint(tmp_path, lab_reports):
    edit = lambda name, text: text.replace("Internal Deception", "Internal Deception Edited") \
        if name.startswith("SCN-003") else text
    registry = ScenarioRegistry(_scenarios(tmp_path, edit=edit))
    store = ReportStore(_write(tmp_path / "reports", {"scn003.json": lab_reports["scn003.json"]}))
    detail = build_scenario_detail(registry, store, "SCN-003")
    assert detail["run_state"] == "stale_only"
    assert detail["runs"][0]["mismatch"] == "fingerprint"


def test_detail_has_manifest_runs_newest_first_and_comparisons(lab, lab_reports):
    registry, store = lab
    detail = build_scenario_detail(registry, store, "SCN-002")
    assert detail["kind"] == "scenario_detail"
    scenario = detail["scenario"]
    assert scenario["id"] == "SCN-002" and scenario["expected_outcome"] == "prevented"
    assert [a["id"] for a in scenario["assertions"]] == [f"SCN-002-A0{i}" for i in range(1, 5)]
    assert scenario["safety"]["destructive"] is False and scenario["file"] == "SCN-002-attempted-exfiltration.yaml"
    assert [run["name"] for run in detail["runs"]] == ["scn002-block.json", "scn002-control.json"]
    assert all(run["manifest_match"] and run["mismatch"] is None for run in detail["runs"])
    assert detail["latest_run"]["name"] == "scn002-block.json"
    assert [(c["name"], c["comparison_status"]) for c in detail["comparisons"]] == [
        ("scn002-compare.json", lab_reports["scn002-compare.json"]["comparison"]["status"])]
    assert detail["comparisons"][0]["before_run_id"] == lab_reports["scn002-control.json"]["evaluation"]["run_id"]


def test_detail_of_unknown_or_invalid_scenario_id_is_not_found(lab):
    registry, store = lab
    for scenario_id in ("SCN-999", "../etc", "scn-001"):
        with pytest.raises(OverviewError) as caught:
            build_scenario_detail(registry, store, scenario_id)
        assert caught.value.code == "scenario_not_found"


def test_invalid_and_duplicate_manifests_are_reported(tmp_path, lab_reports):
    scenarios = _scenarios(tmp_path)
    (scenarios / "SCN-004-broken.yaml").write_text("id: SCN-004\nname: [unterminated\n", encoding="utf-8")
    shutil.copy(scenarios / "SCN-001-powershell-execution.yaml", scenarios / "SCN-001-copy.yaml")
    (scenarios / "notes.txt").write_text("ignored", encoding="utf-8")
    store = ReportStore(_write(tmp_path / "reports", {}))
    index = build_scenario_index(ScenarioRegistry(scenarios), store)
    assert sorted((e["file"], e["code"]) for e in index["registry"]["errors"]) == [
        ("SCN-001-copy.yaml", "duplicate_scenario_id"),
        ("SCN-001-powershell-execution.yaml", "duplicate_scenario_id"),
        ("SCN-004-broken.yaml", "invalid_scenario")]
    assert {row["id"] for row in index["scenarios"]} == {"SCN-002", "SCN-003"}


def test_without_registry_reports_are_grouped_but_nothing_is_claimed(tmp_path, lab_reports):
    store = ReportStore(_write(tmp_path / "reports", lab_reports))
    index = build_scenario_index(None, store)
    assert index["registry"] == {"configured": False, "error": None, "manifest_count": 0, "errors": []}
    assert index["scenarios"] == [] and index["kpi"]["total"] == 0
    assert [group["scenario_id"] for group in index["unregistered"]] == ["SCN-002", "SCN-003"]
    with pytest.raises(OverviewError) as caught:
        build_scenario_detail(None, store, "SCN-002")
    assert caught.value.code == "not_configured"


def _component(status, component_id):
    return {c["id"]: c for c in status["components"]}[component_id]


def test_system_status_degraded_by_unreadable_report_and_unregistered_scenario(lab):
    registry, store = lab
    status = build_system_status(registry, store, None, now=NOW)
    assert status["kind"] == "system_status" and status["generated_at"] == NOW
    assert status["overall"]["status"] == "degraded"
    assert {(r["component"], r["status"]) for r in status["overall"]["reasons"]} == {
        ("report_storage", "degraded"), ("scenario_registry", "degraded")}
    storage = _component(status, "report_storage")
    assert storage["details"] == {"files": 6, "readable": 5, "unreadable": 1}
    assert storage["last_activity"] == "2026-09-21T14:13:23Z"
    assert _component(status, "scenario_registry")["details"]["unregistered_reports"] == 1
    assert _component(status, "api")["status"] == "healthy"


def test_connectors_and_engine_are_never_claimed_healthy_without_live_data(lab):
    registry, store = lab
    status = build_system_status(registry, store, None, now=NOW)
    for source in ("wazuh", "suricata", "pfsense", "cowrie"):
        component = _component(status, f"connector_{source}")
        assert component["status"] == "not_configured"
    seen = _component(status, "connector_cowrie")["details"]["seen_in_reports"]
    assert seen == {"report": "scn003.json", "parsed": 2,
                    "window_end": json.loads((store.root / "scn003.json").read_text())["comparison_inputs"]["context"]["end"]}
    engine = _component(status, "validation_engine")
    assert engine["status"] == "unknown" and engine["details"]["report_engine_versions"] == ["0.1.0"]
    assert _component(status, "evidence_collection")["status"] == "not_configured"


def test_overall_status_not_configured_and_no_data(tmp_path):
    empty = ReportStore(_write(tmp_path / "reports", {}))
    assert build_system_status(None, empty, None, now=NOW)["overall"]["status"] == "not_configured"
    configured = build_system_status(ScenarioRegistry(_scenarios(tmp_path)), empty, None, now=NOW)
    assert configured["overall"]["status"] == "no_data"
    assert _component(configured, "report_storage")["status"] == "no_data"


def test_overall_status_error_when_scenario_directory_disappears(tmp_path, lab_reports):
    scenarios = _scenarios(tmp_path)
    registry = ScenarioRegistry(scenarios)
    shutil.rmtree(scenarios)
    store = ReportStore(_write(tmp_path / "reports", lab_reports))
    status = build_system_status(registry, store, None, now=NOW)
    assert _component(status, "scenario_registry")["status"] == "error"
    assert status["overall"]["status"] == "error"
    assert build_scenario_index(registry, store)["registry"]["error"] == "registry_unreadable"


class _Jobs:
    def __init__(self, jobs, blocked=None):
        self._jobs, self.blocked_code = jobs, blocked

    def list_jobs(self):
        return self._jobs


class _Operations:
    def __init__(self, jobs, *, indexer=True):
        self.jobs = jobs
        self.config = type("Config", (), {"indexer": object() if indexer else None})()


@pytest.mark.parametrize("jobs, blocked, expected, activity", [
    ([], None, "unknown", None),
    ([{"state": "completed", "finished_at": "2026-10-01T05:00:00Z", "created_at": "2026-10-01T04:59:00Z",
       "error_code": None}], None, "healthy", "2026-10-01T05:00:00Z"),
    ([{"state": "completed", "finished_at": "2026-10-01T05:00:00Z", "created_at": "2026-10-01T04:59:00Z",
       "error_code": None},
      {"state": "failed", "finished_at": "2026-10-01T05:30:00Z", "created_at": "2026-10-01T05:29:00Z",
       "error_code": "collection_failed"}], None, "degraded", "2026-10-01T05:30:00Z"),
    ([{"state": "running", "finished_at": None, "created_at": "2026-10-01T05:59:00Z", "error_code": None}],
     None, "unknown", None),
    ([], "storage_failed", "error", None),
])
def test_evidence_collection_status_follows_the_job_store(lab, jobs, blocked, expected, activity):
    registry, store = lab
    status = build_system_status(registry, store, _Operations(_Jobs(jobs, blocked)), now=NOW)
    component = _component(status, "evidence_collection")
    assert component["status"] == expected and component["last_activity"] == activity
    assert _component(status, "connector_wazuh")["status"] == expected


def test_collection_without_indexer_is_not_configured(lab):
    registry, store = lab
    status = build_system_status(registry, store, _Operations(_Jobs([]), indexer=False), now=NOW)
    assert _component(status, "evidence_collection")["status"] == "not_configured"
    assert _component(status, "connector_wazuh")["status"] == "not_configured"


@pytest.fixture
def served(tmp_path, lab_reports):
    reports = _write(tmp_path / "reports", lab_reports)
    _copy_fixture("malformed-truncated.json", reports)
    server = make_server(reports, port=0, scenarios_dir=_scenarios(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_http_endpoints_serve_index_detail_and_status(served):
    status, index = _get(served + "/api/scenarios")
    assert status == 200 and index["kind"] == "scenario_index" and index["kpi"]["total"] == 3
    status, detail = _get(served + "/api/scenarios/SCN-002")
    assert status == 200 and detail["scenario"]["id"] == "SCN-002"
    status, system = _get(served + "/api/system/status")
    assert status == 200 and system["overall"]["status"] == "degraded"
    for path in ("/api/scenarios/SCN-999", "/api/scenarios/..%2F..%2Fsecret", "/api/scenarios/"):
        status, body = _get(served + path)
        assert status == 404 and body["kind"] == "error"


def test_http_detail_without_registry_is_not_configured(tmp_path, lab_reports):
    server = make_server(_write(tmp_path / "reports", lab_reports), port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        status, body = _get(f"http://{host}:{port}/api/scenarios/SCN-002")
        assert status == 404 and body["error"]["code"] == "not_configured"
        status, index = _get(f"http://{host}:{port}/api/scenarios")
        assert status == 200 and index["registry"]["configured"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_cli_passes_scenarios_directory_to_the_server(tmp_path, monkeypatch):
    import aegis_verify.cli as cli
    seen = {}
    monkeypatch.setattr(cli, "serve", lambda reports, **kwargs: seen.update(kwargs, reports=reports) or 0)
    scenarios = _scenarios(tmp_path)
    assert cli.main(["dashboard", "--reports", str(tmp_path), "--scenarios", str(scenarios)]) == 0
    assert seen["scenarios_dir"] == str(scenarios) and seen["reports"] == str(tmp_path)
    assert cli.main(["dashboard", "--reports", str(tmp_path)]) == 0
    assert seen["scenarios_dir"] is None


def test_cli_rejects_a_missing_scenarios_directory_before_serving(tmp_path):
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-m", "aegis_verify", "dashboard", "--reports", str(tmp_path),
                             "--scenarios", str(tmp_path / "missing"), "--port", "0"],
                            capture_output=True, text=True, check=False, timeout=60)
    assert result.returncode == 2 and result.stdout == ""
