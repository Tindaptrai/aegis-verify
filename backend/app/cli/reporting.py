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


def render_report(report: dict, output_format: str) -> str:
    """Fully encode and enforce the output budget before stdout is touched."""
    if output_format == "json":
        return _json_report(report)
    if output_format == "text":
        return _text_report(report)
    raise IntakeError("invalid_arguments")
