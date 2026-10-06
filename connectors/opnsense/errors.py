"""Fixed-vocabulary OPNsense diagnostics that never echo source values."""

from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2


_CODES = frozenset(
    """
    input_type input_too_large total_input_too_large max_records invalid_encoding
    invalid_bom malformed_header invalid_field missing_field unsupported_value
    invalid_timestamp invalid_context canonical_validation io_error
    """.split()
)
_FIELDS = frozenset(
    {
        "source_ref",
        "environment_id",
        "sensor_id",
        "ingested_at",
        "source_year",
        "source_utc_offset",
        "pri",
        "timestamp",
        "hostname",
        "program",
        "rule_number",
        "subrule",
        "anchor",
        "label",
        "interface",
        "reason",
        "action",
        "direction",
        "ip_version",
        "tos",
        "ecn",
        "ttl",
        "ip_id",
        "offset",
        "ip_flags",
        "traffic_class",
        "flow_label",
        "hop_limit",
        "protocol_id",
        "protocol_text",
        "length",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "data_length",
        "tcp_flags",
        "sequence",
        "ack",
        "window",
        "urg",
        "tcp_options",
        *("canonical." + field for field in CanonicalEventV2.model_fields),
    }
)


@dataclass(frozen=True, slots=True)
class OpnSenseDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "code",
            self.code if type(self.code) is str and self.code in _CODES else "invalid_field",
        )
        object.__setattr__(
            self,
            "field_path",
            self.field_path
            if type(self.field_path) is str and self.field_path in _FIELDS
            else None,
        )
        object.__setattr__(
            self,
            "record_index",
            self.record_index
            if type(self.record_index) is int and self.record_index > 0
            else 1,
        )
        object.__setattr__(
            self,
            "line",
            self.line if type(self.line) is int and self.line > 0 else None,
        )


class OpnSenseParseError(ValueError):
    """Public parse failure carrying only allowlisted diagnostics."""

    def __init__(
        self,
        code: object,
        field_path: object = None,
        *,
        line: object = None,
        record_index: object = 1,
    ) -> None:
        safe_code = code if type(code) is str and code in _CODES else "invalid_field"
        safe_field = (
            field_path
            if type(field_path) is str and field_path in _FIELDS
            else None
        )
        self.diagnostic = OpnSenseDiagnostic(
            code=safe_code,
            field_path=safe_field,
            record_index=(
                record_index
                if type(record_index) is int and record_index > 0
                else 1
            ),
            line=line if type(line) is int and line > 0 else None,
        )
        super().__init__(
            safe_code + (f": {safe_field}" if safe_field is not None else "")
        )

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
    def record_index(self) -> int:
        return self.diagnostic.record_index
