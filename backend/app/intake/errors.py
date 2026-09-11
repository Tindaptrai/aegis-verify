"""Closed, safe-to-render diagnostics for the offline intake boundary."""

from dataclasses import dataclass, FrozenInstanceError


_HINTS = {
    "invalid_arguments": "Use 'aegis validate --help' and provide each required option once.",
    "invalid_scenario": "Provide one reviewed scenario YAML document.",
    "invalid_profile": "Provide one valid evaluation profile JSON object.",
    "invalid_context": "Provide one valid evaluation context JSON object.",
    "environment_mismatch": "Use a bundle and evaluation context for the same environment.",
    "invalid_input": "Review the selected input and try again.",
    "invalid_json": "Provide one valid UTF-8 JSON object with unique keys.",
    "invalid_number": "Use bounded integer values; floating values are unsupported.",
    "input_too_large": "Reduce the selected file to the documented size limit.",
    "input_too_deep": "Reduce JSON nesting to the documented depth limit.",
    "resource_limit": "Reduce the input to the documented resource limits.",
    "invalid_path": "Select an unambiguous local regular file path.",
    "input_io": "Check that the selected local path exists and is readable.",
    "invalid_manifest": "Review the bundle manifest fields and parser context.",
    "unknown_parser": "Select one documented fixture parser key.",
    "duplicate_source_ref": "Use a unique source_ref for every bundle file.",
    "duplicate_file": "List each physical evidence file only once.",
    "hash_mismatch": "Recompute the declared SHA-256 from the exact evidence bytes.",
    "parser_error": "Review the evidence format and its declared parser context.",
    "collection_conflict": "Review unsupported records or use unknown collection assurance.",
    "invalid_collection_declaration": "Bind collection declarations to supported detection assertions.",
    "unsupported_version": "Use the documented schema versions for every selected input.",
    "profile_binding": "Bind the selected profile to the exact reviewed scenario.",
    "assertion_binding": "Bind one evaluation rule to every scenario assertion.",
    "invalid_predicate": "Review the selected profile predicates and bindings.",
    "invalid_correlation": "Review the selected profile correlation contract.",
    "missing_binding": "Provide every target binding required by the selected profile.",
    "duplicate_evidence_id": "Use evidence records with unique canonical event IDs.",
    "internal_error": "Retry the command; if the error persists, request human review.",
    "output_error": "Check the output destination and available output capacity.",
}
_STAGES = frozenset({"scenario", "inputs", "profile", "context", "evidence", "collection", "output"})
_FIELDS = frozenset(
    {
        "bundle_schema_version",
        "environment_id",
        "files",
        "path",
        "source_ref",
        "parser",
        "sha256",
        "context",
        "ingested_at",
        "collection_mode",
        "deployment_mode",
        "sensor_id",
        "source_year",
        "source_utc_offset",
        "scenario",
        "profile",
        "context_fingerprint",
        "profile_fingerprint",
        "scope_fingerprint",
        "event_set_fingerprint",
        "declarations",
        "assertions",
        "rules",
        "bindings",
        "events",
    }
)
_INTERPRETER_EXCEPTION_STATE = frozenset(
    {"__traceback__", "__cause__", "__context__", "__suppress_context__", "__notes__"}
)


@dataclass(init=False)
class IntakeError(ValueError):
    """Immutable diagnostic whose public values come only from fixed allowlists."""

    code: str
    stage: str
    file_index: int | None
    field: str | None
    line: int | None
    hint: str

    def __setattr__(self, name: str, value: object) -> None:
        if name not in _INTERPRETER_EXCEPTION_STATE:
            raise FrozenInstanceError(f"cannot assign to field {name!r}")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name not in _INTERPRETER_EXCEPTION_STATE:
            raise FrozenInstanceError(f"cannot delete field {name!r}")
        object.__delattr__(self, name)

    def __init__(
        self,
        code: str,
        *,
        stage: str = "inputs",
        file_index: int | None = None,
        field: str | None = None,
        line: int | None = None,
    ):
        safe_code = code if type(code) is str and code in _HINTS else "invalid_input"
        safe_stage = stage if type(stage) is str and stage in _STAGES else "inputs"
        safe_file_index = (
            file_index
            if type(file_index) is int and 0 <= file_index < 100
            else None
        )
        safe_field = field if type(field) is str and field in _FIELDS else None
        safe_line = line if type(line) is int and 1 <= line <= 20_000 else None
        hint = _HINTS[safe_code]

        object.__setattr__(self, "code", safe_code)
        object.__setattr__(self, "stage", safe_stage)
        object.__setattr__(self, "file_index", safe_file_index)
        object.__setattr__(self, "field", safe_field)
        object.__setattr__(self, "line", safe_line)
        object.__setattr__(self, "hint", hint)

        coordinates = []
        if safe_file_index is not None:
            coordinates.append(f"file_index={safe_file_index}")
        if safe_field is not None:
            coordinates.append(f"field={safe_field}")
        if safe_line is not None:
            coordinates.append(f"line={safe_line}")
        location = f" ({', '.join(coordinates)})" if coordinates else ""
        ValueError.__init__(self, f"{safe_code} [{safe_stage}]{location}: {hint}")
