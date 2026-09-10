"""Fixed-vocabulary Cowrie diagnostics that never echo source values."""

from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2


_CODES = frozenset(
    """
    input_type input_too_large invalid_encoding invalid_unicode invalid_json
    duplicate_key invalid_number max_depth max_nodes invalid_root missing_source
    invalid_field missing_field unsupported_profile missing_event_time
    invalid_event_time invalid_context canonical_validation io_error
    """.split()
)
_FIELDS = frozenset(
    {
        "source_ref",
        "environment_id",
        "sensor_id",
        "ingested_at",
        "_source",
        "_source.id",
        "_source.timestamp",
        "_source.data",
        "_source.rule",
        "_source.rule.id",
        "_source.rule.level",
        "_source.rule.groups",
        "_source.agent",
        "_source.agent.id",
        "_source.agent.name",
        "_source.agent.ip",
        "_source.manager",
        "_source.manager.name",
        *("_source.data." + field for field in (
            "eventid", "timestamp", "src_ip", "src_port", "dst_ip",
            "dst_port", "protocol", "session", "sensor", "uuid", "arch",
            "username", "input",
        )),
        *("canonical." + field for field in CanonicalEventV2.model_fields),
    }
)


def _safe_positive(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


@dataclass(frozen=True, slots=True)
class CowrieDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None
    column: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "code", self.code if type(self.code) is str and self.code in _CODES else "invalid_field"
        )
        object.__setattr__(
            self,
            "field_path",
            self.field_path if type(self.field_path) is str and self.field_path in _FIELDS else None,
        )
        object.__setattr__(
            self,
            "record_index",
            self.record_index if type(self.record_index) is int and self.record_index > 0 else 1,
        )
        object.__setattr__(self, "line", _safe_positive(self.line))
        object.__setattr__(self, "column", _safe_positive(self.column))


class CowrieParseError(ValueError):
    """Public parse failure carrying only allowlisted diagnostics."""

    def __init__(
        self,
        code: object,
        field_path: object = None,
        *,
        line: object = None,
        column: object = None,
        record_index: object = 1,
    ) -> None:
        self.diagnostic = CowrieDiagnostic(
            code=code,
            field_path=field_path,
            record_index=record_index,
            line=line,
            column=column,
        )
        message = self.diagnostic.code
        if self.diagnostic.field_path is not None:
            message += f": {self.diagnostic.field_path}"
        super().__init__(message)

    @property
    def code(self) -> str:
        return self.diagnostic.code

    @property
    def field_path(self) -> str | None:
        return self.diagnostic.field_path

    @property
    def line(self) -> int | None:
        return self.diagnostic.line

    @property
    def column(self) -> int | None:
        return self.diagnostic.column

    @property
    def record_index(self) -> int:
        return self.diagnostic.record_index
