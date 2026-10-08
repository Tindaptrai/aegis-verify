"""Scenario overview and system status for the dashboard, read-only.

Joins reviewed scenario manifests with the CLI reports in the report directory.
Every count, outcome and status is copied from a report or a manifest; nothing is
re-evaluated here. A field that is missing or has an unexpected type stays
``None``, and file times are labelled as file times, never as run times.

The system status describes whether AEGIS has the data it needs (manifests,
readable reports, a configured collector). It is not a statement about the
security of the monitored environment, and components without live data are
reported as ``not_configured`` or ``unknown`` rather than healthy.
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re

from .._scenario_yaml import MAX_BYTES as MAX_SCENARIO_BYTES
from ..intake import IntakeError, local_path, read_local
from ..scenario_loader import ScenarioLoadError, parse_scenario_yaml
from ..validation import scenario_fingerprint
from ..validation.results import EvaluationResult

OVERVIEW_VERSION = "0.1.0"
MAX_MANIFESTS = 100
FINAL_STATUSES = ("Detected", "Prevented", "False negative", "Missing telemetry", "Inconclusive")
OUTCOME_KEYS = ("satisfied", "false_negative", "missing_telemetry", "inconclusive")
CONNECTOR_SOURCES = ("wazuh", "suricata", "snort", "pfsense", "opnsense", "cowrie")
_SCENARIO_ID = re.compile(r"^SCN-[0-9]{3}$")
_MANIFEST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$")
_ENGINE_VERSION = EvaluationResult.model_fields["engine_semantics_version"].default


class OverviewError(Exception):
    """A request the overview cannot answer, with a fixed code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _text(value):
    return value if type(value) is str else None


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _dict(value):
    return value if type(value) is dict else {}


def _list(value):
    return value if type(value) is list else []


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _instant(value):
    """Parse an ISO-8601 time for ordering only; unparseable values sort last."""
    if type(value) is not str:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


class ScenarioRegistry:
    """Top-level ``*.yaml`` manifests of one directory, re-read on every request."""

    def __init__(self, scenarios_dir):
        self.path = Path(scenarios_dir)
        local_path(self.path, directory=True, stage="scenario")

    def load(self) -> dict:
        try:
            root = local_path(self.path, directory=True, stage="scenario")
            names = sorted(p.name for p in root.iterdir() if p.is_file() and _MANIFEST_NAME.match(p.name))
        except (IntakeError, OSError):
            return {"error": "registry_unreadable", "manifests": [], "errors": []}
        if len(names) > MAX_MANIFESTS:
            return {"error": "resource_limit", "manifests": [], "errors": []}
        parsed, errors = [], []
        for name in names:
            try:
                raw = read_local(root / name, limit=MAX_SCENARIO_BYTES, stage="scenario")
                manifest = parse_scenario_yaml(raw.decode("utf-8"), source_name=name)
            except IntakeError as error:
                errors.append({"file": name, "code": error.code})
                continue
            except (UnicodeError, ScenarioLoadError):
                errors.append({"file": name, "code": "invalid_scenario"})
                continue
            parsed.append((name, manifest))
        by_id = Counter(manifest.id for _, manifest in parsed)
        manifests = []
        for name, manifest in parsed:
            if by_id[manifest.id] > 1:
                errors.append({"file": name, "code": "duplicate_scenario_id"})
            else:
                manifests.append(_manifest(name, manifest))
        errors.sort(key=lambda item: (item["file"], item["code"]))
        return {"error": None, "manifests": sorted(manifests, key=lambda m: m["id"]), "errors": errors}


def _manifest(name, manifest) -> dict:
    data = manifest.model_dump(mode="json")
    return {"id": data["id"], "name": data["name"], "version": data["version"], "status": data["status"],
            "description": data["description"], "expected_outcome": data["expected_outcome"],
            "expected_sources": list(data["expected_sources"]), "assertions": list(data["assertions"]),
            "tags": None if data.get("tags") is None else list(data["tags"]), "safety": data["safety"],
            "file": name, "fingerprint": scenario_fingerprint(manifest)}


def _evaluation_record(name, report, modified) -> dict:
    scenario, evaluation = _dict(report.get("scenario")), _dict(report.get("evaluation"))
    counts = _dict(evaluation.get("counts"))
    assertions = evaluation.get("assertions")
    assurance = Counter(_text(_dict(item).get("collection_assurance")) for item in _list(assertions))
    assurance.pop(None, None)
    sources = Counter()
    for entry in _list(_dict(report.get("intake")).get("ledger")):
        entry = _dict(entry)
        if entry.get("status") == "parsed" and _text(entry.get("source_type")) is not None:
            sources[entry["source_type"]] += 1
    context = _dict(_dict(report.get("comparison_inputs")).get("context"))
    return {
        "name": name, "kind": "evaluation",
        "scenario_id": _text(scenario.get("id")), "scenario_version": _text(scenario.get("version")),
        "scenario_fingerprint": _text(evaluation.get("scenario_fingerprint")),
        "run_id": _text(evaluation.get("run_id")), "final_status": _text(evaluation.get("final_status")),
        "profile_id": _text(evaluation.get("profile_id")), "profile_version": _text(evaluation.get("profile_version")),
        "engine_semantics_version": _text(evaluation.get("engine_semantics_version")),
        "assertions": {"total": len(assertions) if type(assertions) is list else None,
                       **{key: _count(counts.get(key)) for key in OUTCOME_KEYS}},
        "evidence_referenced": _count(_dict(report.get("counts")).get("referenced")),
        "collection_assurance": dict(sorted(assurance.items())),
        "sources": dict(sorted(sources.items())),
        "window_start": _text(context.get("start")), "window_end": _text(context.get("end")),
        "file_modified": modified,
    }


def _comparison_record(name, report, modified) -> dict:
    scenario, comparison = _dict(report.get("scenario")), _dict(report.get("comparison"))
    before, after = _dict(report.get("before")), _dict(report.get("after"))
    return {
        "name": name, "kind": "comparison",
        "scenario_id": _text(scenario.get("id")), "scenario_version": _text(scenario.get("version")),
        "comparison_status": _text(comparison.get("status")),
        "before_run_id": _text(before.get("run_id")), "after_run_id": _text(after.get("run_id")),
        "before_status": _text(before.get("final_status")), "after_status": _text(after.get("final_status")),
        "window_end": _text(_dict(after.get("context")).get("end")),
        "file_modified": modified,
    }


def _read_reports(store) -> dict:
    """Readable report records, unreadable files and the newest file time."""
    try:
        names = store.names()
    except IntakeError as error:
        return {"error": error.code, "records": [], "errors": [], "files": 0, "latest_modified": None}
    except OSError:
        return {"error": "storage_unreadable", "records": [], "errors": [], "files": 0, "latest_modified": None}
    records, errors, latest = [], [], None
    for name in names:
        try:
            stamp = (store.root / name).stat().st_mtime
            report = store.load(name)
        except IntakeError as error:
            errors.append({"name": name, "code": error.code, "stage": error.stage, "field": error.field})
            continue
        except OSError:
            errors.append({"name": name, "code": "storage_unreadable", "stage": "inputs", "field": None})
            continue
        latest = stamp if latest is None else max(latest, stamp)
        build = _evaluation_record if report.get("kind") == "evaluation" else _comparison_record
        records.append(build(name, report, _utc(stamp)))
    if errors:
        for item in errors:
            try:
                stamp = (store.root / item["name"]).stat().st_mtime
            except OSError:
                continue
            latest = stamp if latest is None else max(latest, stamp)
    return {"error": None, "records": records, "errors": errors, "files": len(names),
            "latest_modified": None if latest is None else _utc(latest)}


def _newest_first(records):
    """Order by run window end (parsed), then name; records without a window go last."""
    floor = datetime.min.replace(tzinfo=timezone.utc)
    return sorted(records, key=lambda r: (_instant(r.get("window_end")) is not None,
                                          _instant(r.get("window_end")) or floor, r["name"]), reverse=True)


def _match(record, manifest):
    if record["scenario_version"] != manifest["version"]:
        return "version"
    if record.get("scenario_fingerprint") != manifest["fingerprint"]:
        return "fingerprint"
    return None


def _scenario_runs(manifest, records):
    runs = []
    for record in _newest_first(r for r in records if r["kind"] == "evaluation" and r["scenario_id"] == manifest["id"]):
        mismatch = _match(record, manifest)
        runs.append({**record, "manifest_match": mismatch is None, "mismatch": mismatch})
    current = [run for run in runs if run["manifest_match"]]
    state = "run" if current else ("stale_only" if runs else "not_run")
    comparisons = _newest_first(r for r in records if r["kind"] == "comparison" and r["scenario_id"] == manifest["id"])
    return runs, current, state, comparisons


def _load_registry(registry) -> dict:
    return registry.load() if registry is not None else {"error": None, "manifests": [], "errors": []}


def build_scenario_index(registry, store) -> dict:
    return _index(registry, _load_registry(registry), _read_reports(store))


def _index(registry, loaded, reports) -> dict:
    manifests = loaded["manifests"]
    known = {manifest["id"] for manifest in manifests}
    rows, by_status = [], Counter()
    for manifest in manifests:
        runs, current, state, comparisons = _scenario_runs(manifest, reports["records"])
        latest = current[0] if current else None
        if latest is not None:
            status = latest["final_status"]
            by_status[status if status in FINAL_STATUSES else "Other"] += 1
        rows.append({**{k: manifest[k] for k in ("id", "name", "version", "status", "description",
                                                  "expected_outcome", "expected_sources", "tags", "file",
                                                  "fingerprint")},
                     "run_state": state, "latest_run": latest, "run_count": len(current),
                     "stale_run_count": len(runs) - len(current), "comparison_count": len(comparisons)})
    groups = {}
    for record in reports["records"]:
        if record["scenario_id"] not in known:
            groups.setdefault(record["scenario_id"], []).append(record)
    unregistered = []
    for scenario_id in sorted(groups, key=lambda value: (value is None, value or "")):
        evaluations = [r for r in groups[scenario_id] if r["kind"] == "evaluation"]
        unregistered.append({"scenario_id": scenario_id, "reports": sorted(r["name"] for r in groups[scenario_id]),
                             "latest_run": (_newest_first(evaluations) or [None])[0]})
    run = sum(1 for row in rows if row["run_state"] == "run")
    return {
        "kind": "scenario_index", "version": OVERVIEW_VERSION,
        "registry": {"configured": registry is not None, "error": loaded["error"],
                     "manifest_count": len(manifests), "errors": loaded["errors"]},
        "kpi": {"total": len(rows), "run": run, "not_run": len(rows) - run,
                "by_status": {key: by_status.get(key, 0) for key in (*FINAL_STATUSES, "Other")}},
        "scenarios": rows, "unregistered": unregistered,
        "report_errors": reports["errors"], "report_storage_error": reports["error"],
        "last_report_modified": reports["latest_modified"],
    }


def build_scenario_detail(registry, store, scenario_id) -> dict:
    if registry is None:
        raise OverviewError("not_configured")
    if type(scenario_id) is not str or not _SCENARIO_ID.match(scenario_id):
        raise OverviewError("scenario_not_found")
    loaded = registry.load()
    manifest = next((m for m in loaded["manifests"] if m["id"] == scenario_id), None)
    if manifest is None:
        raise OverviewError("scenario_not_found")
    reports = _read_reports(store)
    runs, current, state, comparisons = _scenario_runs(manifest, reports["records"])
    return {"kind": "scenario_detail", "version": OVERVIEW_VERSION, "scenario": manifest,
            "run_state": state, "latest_run": current[0] if current else None, "runs": runs,
            "comparisons": comparisons, "report_errors": reports["errors"]}


def _component(component_id, name, status, summary, *, source, last_activity=None, reason=None, details=None):
    return {"id": component_id, "name": name, "status": status, "summary": summary, "source": source,
            "last_activity": last_activity, "reason": reason, "details": details or {}}


def _collection(operations):
    if operations is None:
        return "not_configured", None, "dashboard_started_without_operations", {}
    if operations.jobs.blocked_code:
        return "error", None, operations.jobs.blocked_code, {}
    if operations.config.indexer is None:
        return "not_configured", None, "indexer_not_configured", {}
    jobs = [job for job in operations.jobs.list_jobs() if type(job) is dict]
    if not jobs:
        return "unknown", None, "no_collection_jobs", {"jobs": 0}
    latest = max(jobs, key=lambda job: (_text(job.get("created_at")) or ""))
    state = _text(latest.get("state"))
    details = {"jobs": len(jobs), "latest_state": state}
    if state == "completed":
        return "healthy", _text(latest.get("finished_at")), None, details
    if state in ("failed", "interrupted"):
        return "degraded", _text(latest.get("finished_at")), _text(latest.get("error_code")) or state, details
    return "unknown", None, "collection_running" if state == "running" else "unknown_job_state", details


_SEVERITY = {"error": 4, "degraded": 3, "not_configured": 2, "no_data": 1, "healthy": 0}


def build_system_status(registry, store, operations, *, now=None) -> dict:
    reports = _read_reports(store)
    index = _index(registry, _load_registry(registry), reports)
    components = [_component("api", "Dashboard API", "healthy", "endpoint_responding", source="this_response")]

    registry_info = index["registry"]
    unregistered = sum(len(group["reports"]) for group in index["unregistered"])
    if registry is None:
        registry_component = ("not_configured", "dashboard_started_without_scenarios")
    elif registry_info["error"] is not None:
        registry_component = ("error", registry_info["error"])
    elif registry_info["errors"] or unregistered:
        registry_component = ("degraded", "invalid_manifests" if registry_info["errors"] else "unregistered_reports")
    elif registry_info["manifest_count"] == 0:
        registry_component = ("no_data", "no_manifests")
    else:
        registry_component = ("healthy", None)
    components.append(_component(
        "scenario_registry", "Scenario registry", registry_component[0], "scenario_manifests",
        source="scenarios_directory", reason=registry_component[1],
        details={"manifests": registry_info["manifest_count"], "invalid": len(registry_info["errors"]),
                 "unregistered_reports": unregistered if registry is not None else None}))

    readable, unreadable = len(reports["records"]), len(reports["errors"])
    if reports["error"] is not None:
        storage = ("error", reports["error"])
    elif unreadable:
        storage = ("degraded", "unreadable_reports")
    elif reports["files"] == 0:
        storage = ("no_data", "no_reports")
    else:
        storage = ("healthy", None)
    components.append(_component(
        "report_storage", "Report storage", storage[0], "cli_reports", source="reports_directory",
        last_activity=reports["latest_modified"], reason=storage[1],
        details={"files": reports["files"], "readable": readable, "unreadable": unreadable}))

    engine_versions = sorted({r["engine_semantics_version"] for r in reports["records"]
                              if r["kind"] == "evaluation" and r["engine_semantics_version"] is not None})
    components.append(_component(
        "validation_engine", "Validation engine", "unknown", "engine_not_run_by_dashboard", source="reports",
        reason="dashboard_does_not_run_engine",
        details={"backend_engine_version": _ENGINE_VERSION, "report_engine_versions": engine_versions}))

    collection_status, activity, reason, details = _collection(operations)
    collection = _component("evidence_collection", "Evidence collection", collection_status,
                            "operations_indexer_collection", source="operations_job_store",
                            last_activity=activity, reason=reason, details=details)
    components.append(collection)

    evaluations = _newest_first(r for r in reports["records"] if r["kind"] == "evaluation")
    for source in CONNECTOR_SOURCES:
        seen = next(({"report": r["name"], "parsed": r["sources"][source], "window_end": r["window_end"]}
                     for r in evaluations if r["sources"].get(source)), None)
        if source == "wazuh" and operations is not None:
            status, src, why, last = collection_status, "operations_job_store", reason, activity
        else:
            status, src, why, last = "not_configured", "none", "no_live_connector", None
        components.append(_component(f"connector_{source}", source, status, "connector", source=src,
                                     last_activity=last, reason=why, details={"seen_in_reports": seen}))

    considered = [c for c in components if c["id"] in ("scenario_registry", "report_storage")]
    if collection_status in ("healthy", "degraded", "error"):
        considered.append(collection)
    worst = max(considered, key=lambda c: _SEVERITY.get(c["status"], 0))
    overall = worst["status"] if _SEVERITY.get(worst["status"], 0) > 0 else "healthy"
    reasons = [{"component": c["id"], "status": c["status"], "reason": c["reason"]}
               for c in considered if _SEVERITY.get(c["status"], 0) > 0]
    stamp = now if now is not None else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"kind": "system_status", "version": OVERVIEW_VERSION, "generated_at": stamp,
            "overall": {"status": overall, "reasons": reasons}, "components": components}
