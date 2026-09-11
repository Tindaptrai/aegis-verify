"""Bounded, deterministic rendering for CLI diagnostics and evaluations."""

import json
from itertools import chain
import unicodedata

from ..intake import IntakeError


CLI_REPORT_VERSION = "0.1.0"
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


def error_report(error: IntakeError) -> dict:
    return {
        "cli_report_version": CLI_REPORT_VERSION,
        "kind": "error",
        "error": {
            "code": error.code,
            "stage": error.stage,
            "file_index": error.file_index,
            "field": error.field,
            "line": error.line,
            "hint": error.hint,
        },
    }


def render_error(error: IntakeError, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            error_report(error), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ) + "\n"
    return f"error: {error.code} [{error.stage}]: {error.hint}\n"


def _safe_text(value) -> str:
    text = str(value)
    return "".join(
        f"\\u{ord(character):04x}"
        if unicodedata.category(character).startswith("C")
        else character
        for character in text
    )


def _bounded(chunks) -> str:
    rendered = []
    size = 0
    for chunk in chunks:
        encoded = chunk.encode("utf-8")
        size += len(encoded)
        if size > MAX_OUTPUT_BYTES:
            raise IntakeError("resource_limit", stage="output")
        rendered.append(chunk)
    return "".join(rendered)


def _json_report(report: dict) -> str:
    encoder = json.JSONEncoder(
        ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return _bounded(chain(encoder.iterencode(report), ("\n",)))


def _text_report(report: dict) -> str:
    if report["kind"] == "comparison":
        return _text_compare(report)

    scenario = report["scenario"]
    evaluation = report["evaluation"]
    counts = report["counts"]
    lines = [
        f"Scenario: {_safe_text(scenario['id'])} - {_safe_text(scenario['name'])} ({_safe_text(scenario['version'])})",
        f"Run: {_safe_text(evaluation['run_id'])}",
    ]
    for assertion in evaluation["assertions"]:
        lines.extend(
            (
                f"Assertion: {_safe_text(assertion['assertion_id'])} {_safe_text(assertion['outcome'])} {_safe_text(assertion['reason_code'])}",
                "  Evidence IDs: " + ", ".join(_safe_text(item) for item in assertion["evidence_ids"]),
                "  Unevaluable IDs: " + ", ".join(
                    _safe_text(item) for item in assertion["unevaluable_evidence_ids"]
                ),
                f"  Assurance: {_safe_text(assertion['collection_assurance'])}",
            )
        )
    warnings = sorted(
        {
            warning
            for entry in report["intake"]["ledger"]
            for warning in entry["warnings"]
        }
    )
    lines.extend(
        (
            f"Final status: {_safe_text(evaluation['final_status'])}",
            f"Counts: parsed={counts['parsed']} referenced={counts['referenced']} skipped={counts['skipped']}",
            "Warnings: " + (", ".join(_safe_text(item) for item in warnings) or "none"),
        )
    )
    return _bounded(("\n".join(lines), "\n"))


def _text_compare(report: dict) -> str:
    scenario = report["scenario"]
    comparison = report["comparison"]
    before = report["before"]
    after = report["after"]

    lines = [
        f"Scenario: {_safe_text(scenario['id'])} - {_safe_text(scenario['name'])} ({_safe_text(scenario['version'])})",
        f"Before run: {_safe_text(before['run_id'])} ({_safe_text(before['final_status'])})",
        f"After run: {_safe_text(after['run_id'])} ({_safe_text(after['final_status'])})",
        f"Comparison status: {_safe_text(comparison['status'])}",
    ]
    counts = comparison["assertion_state_counts"]
    lines.append(
        "Assertion states: "
        + ", ".join(
            f"{label}={_safe_text(value)}" for label, value in (
                ("unchanged_pass", counts["unchanged_pass"]),
                ("unchanged_fail", counts["unchanged_fail"]),
                ("improvement", counts["improvement"]),
                ("regression", counts["regression"]),
                ("unchanged_unknown", counts["unchanged_unknown"]),
                ("unknown_changed", counts["unknown_changed"]),
                ("became_evaluable", counts["became_evaluable"]),
                ("became_unevaluable", counts["became_unevaluable"]),
            )
        )
    )
    for item in comparison["assertions"]:
        before_evidence_ids = ", ".join(_safe_text(i) for i in item["before"]["evidence_ids"]) if item["before"][
            "evidence_ids"
        ] else "none"
        after_evidence_ids = ", ".join(_safe_text(i) for i in item["after"]["evidence_ids"]) if item["after"][
            "evidence_ids"
        ] else "none"
        before_refs = ", ".join(
            f"{_safe_text(entry['event_id'])}->{_safe_text(entry['raw_event_ref'])}"
            for entry in item["before"]["evidence_refs"]
        ) or "none"
        after_refs = ", ".join(
            f"{_safe_text(entry['event_id'])}->{_safe_text(entry['raw_event_ref'])}"
            for entry in item["after"]["evidence_refs"]
        ) or "none"
        lines.extend(
            (
                f"Assertion: {_safe_text(item['assertion_id'])} {_safe_text(item['state'])}",
                f"  Before: {_safe_text(item['before']['outcome'])} {_safe_text(item['before']['reason_code'])}",
                f"  Before Evidence IDs: {before_evidence_ids}",
                f"  After: {_safe_text(item['after']['outcome'])} {_safe_text(item['after']['reason_code'])}",
                f"  After Evidence IDs: {after_evidence_ids}",
                "  Before/After evidence refs:",
                f"    before: {before_refs}",
                f"    after: {after_refs}",
                "  Added Evidence IDs: " + (", ".join(_safe_text(i) for i in item["evidence_changes"]["added"]) or "none"),
                "  Removed Evidence IDs: " + (", ".join(_safe_text(i) for i in item["evidence_changes"]["removed"]) or "none"),
                "  Before Unevaluable IDs: " + (", ".join(_safe_text(i) for i in item["before"]["unevaluable_evidence_ids"]) or "none"),
                "  After Unevaluable IDs: " + (", ".join(_safe_text(i) for i in item["after"]["unevaluable_evidence_ids"]) or "none"),
            )
        )
    return _bounded(("\n".join(lines), "\n"))


def render_report(report: dict, output_format: str) -> str:
    """Fully encode and enforce the output budget before stdout is touched."""
    if output_format == "json":
        return _json_report(report)
    if output_format == "text":
        return _text_report(report)
    raise IntakeError("invalid_arguments")
