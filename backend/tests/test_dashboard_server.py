"""Read-only dashboard server: index, report retrieval, malformed and error states."""

import json
from pathlib import Path
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

from aegis_verify.dashboard import build_index, make_server, ReportStore

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "dashboard"


@pytest.fixture
def served(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    for name in ("before-false-negative.json", "after-detected.json",
                 "comparison-regression-passed.json", "malformed-truncated.json", "unsupported-kind.json"):
        (reports / name).write_bytes((FIXTURES / name).read_bytes())
    (reports / "ignored.txt").write_text("not json", encoding="utf-8")
    static = tmp_path / "dist"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>shell</title>", encoding="utf-8")
    (static / "app.js").write_text("console.log('ok')", encoding="utf-8")
    server = make_server(reports, port=0, static_dir=static)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}", reports
    finally:
        server.shutdown()
        server.server_close()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.headers.get("Content-Type"), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Content-Type"), error.read()


def test_index_lists_reports_with_summaries_and_names_malformed_ones(served):
    base, _ = served
    status, content_type, body = _get(base + "/api/reports")
    assert status == 200 and content_type.startswith("application/json")
    index = json.loads(body)
    assert index["kind"] == "report_index"
    by_name = {entry["name"]: entry for entry in index["reports"]}
    assert set(by_name) == {"before-false-negative.json", "after-detected.json",
                            "comparison-regression-passed.json", "malformed-truncated.json",
                            "unsupported-kind.json"}
    assert by_name["after-detected.json"]["kind"] == "evaluation"
    assert by_name["after-detected.json"]["run_id"] == "synthetic-run-after-fix"
    assert by_name["after-detected.json"]["final_status"] == "Detected"
    assert by_name["before-false-negative.json"]["final_status"] == "False negative"
    assert by_name["comparison-regression-passed.json"]["comparison_status"] == "Regression Passed"
    assert by_name["comparison-regression-passed.json"]["run_id"] is None
    assert by_name["malformed-truncated.json"]["error"]["code"] in {"invalid_json", "invalid_input", "invalid_inputs"}
    assert by_name["malformed-truncated.json"]["kind"] is None
    assert by_name["unsupported-kind.json"]["error"]["field"] == "kind"


def test_report_is_returned_unchanged_and_ordered_timeline_is_present(served):
    base, reports = served
    status, _, body = _get(base + "/api/reports/after-detected.json")
    assert status == 200
    served_report = json.loads(body)
    assert served_report == json.loads((reports / "after-detected.json").read_text(encoding="utf-8"))
    timeline = served_report["timeline"]
    assert timeline["order"] == "timestamp_then_event_id"
    stamps = [event["timestamp"] for event in timeline["events"]]
    assert stamps == sorted(stamps)
    assert {event["event_id"] for event in timeline["events"]} == {
        entry["event_id"] for entry in served_report["evaluation"]["evidence_index"]}


def test_malformed_report_is_422_without_partial_body(served):
    base, _ = served
    status, _, body = _get(base + "/api/reports/malformed-truncated.json")
    assert status == 422
    payload = json.loads(body)
    assert payload["kind"] == "error"
    assert "scenario" not in payload


@pytest.mark.parametrize("path", [
    "/api/reports/missing.json", "/api/reports/ignored.txt", "/api/reports/..%2Fserver.py",
    "/api/reports/../pyproject.toml", "/api/other", "/api",
])
def test_unknown_or_unsafe_names_are_404(served, path):
    base, _ = served
    status, _, body = _get(base + path)
    assert status == 404
    assert json.loads(body)["error"]["code"] == "not_found"


def test_static_shell_and_assets_are_served_without_directory_escape(served):
    base, _ = served
    status, content_type, body = _get(base + "/")
    assert status == 200 and content_type.startswith("text/html") and b"shell" in body
    status, content_type, _ = _get(base + "/app.js")
    assert status == 200 and content_type.startswith("text/javascript")
    status, _, _ = _get(base + "/runs/anything")
    assert status == 200  # client route falls back to the shell
    status, _, _ = _get(base + "/missing.css")
    assert status == 404
    status, _, _ = _get(base + "/../pyproject.toml")
    assert status == 404


def test_write_methods_are_rejected(served):
    base, _ = served
    request = urllib.request.Request(base + "/api/reports", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(request, timeout=5)
    assert raised.value.code == 405


def test_store_rejects_unsafe_names_and_index_is_pure(tmp_path):
    (tmp_path / "a.json").write_text('{"kind": "evaluation"}', encoding="utf-8")
    store = ReportStore(tmp_path)
    assert store.names() == ["a.json"]
    with pytest.raises(Exception):
        store.load("../a.json")
    index = build_index(store)
    assert index["reports"][0]["kind"] == "evaluation"
    assert index["reports"][0]["run_id"] is None


def test_cli_dashboard_rejects_bad_port_and_missing_directory(tmp_path):
    result = subprocess.run([sys.executable, "-m", "aegis_verify", "dashboard", "--reports", str(tmp_path),
                             "--port", "70000"], capture_output=True, text=True, check=False)
    assert result.returncode == 2 and result.stdout == "" and "invalid_arguments" in result.stderr
    result = subprocess.run([sys.executable, "-m", "aegis_verify", "dashboard", "--reports",
                             str(tmp_path / "missing")], capture_output=True, text=True, check=False)
    assert result.returncode == 2 and result.stdout == ""
