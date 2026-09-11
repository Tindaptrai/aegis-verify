"""Stable diagnostics without input values or arbitrary field names."""

ERROR_CODES = frozenset({"invalid_input", "unsupported_version", "profile_binding", "assertion_binding",
    "invalid_predicate", "invalid_correlation", "missing_binding", "duplicate_evidence_id",
    "invalid_collection_declaration", "resource_limit"})
SAFE_PATH_FIELDS = frozenset({"manifest", "events", "profile", "context", "rules", "assertions", "bindings",
    "declarations", "scope", "match", "correlation", "join_pairs", "field", "op", "value", "values", "binding",
    "start", "end", "timestamp", "ingested_at", "schema_version", "profile_schema_version", "event_id",
    "source_type", "event_provider", "assertion_id", "anchor_assertion_id", "coverage_start", "coverage_end",
    "profile_fingerprint", "scope_fingerprint", "event_set_fingerprint", "scenario_fingerprint"})


class ValidationEngineError(ValueError):
    def __init__(self, code: str, path: tuple[str | int, ...] = ()):
        self.code = code if code in ERROR_CODES else "invalid_input"
        self.path = tuple(item if type(item) is int and item >= 0 else
                          item if type(item) is str and item in SAFE_PATH_FIELDS else "input" for item in path)
        super().__init__(self.code + (": " + ".".join(map(str, self.path)) if self.path else ""))
