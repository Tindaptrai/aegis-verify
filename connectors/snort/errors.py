"""Fixed-vocabulary diagnostics: never include source values or local paths."""
from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2

# The Lab C logger configuration pins this field list and order (Snort 3 alert_json).
PINNED_FIELDS = ('seconds', 'timestamp', 'pkt_num', 'proto', 'pkt_gen', 'pkt_len', 'dir',
                 'src_addr', 'src_port', 'dst_addr', 'dst_port', 'service', 'rule',
                 'action', 'msg', 'class', 'priority')

_CODES = frozenset((
    'input_type input_too_large total_input_too_large max_records invalid_bom '
    'invalid_encoding invalid_unicode invalid_json duplicate_key invalid_number '
    'max_depth max_nodes invalid_root unsupported_profile invalid_field '
    'invalid_event_time invalid_context canonical_validation io_error').split())
_FIELDS = frozenset({
    'source_ref', 'environment_id', 'ingested_at', 'deployment_mode', 'sensor_id',
    *PINNED_FIELDS,
    *('canonical.' + k for k in CanonicalEventV2.model_fields),
})


@dataclass(frozen=True, slots=True)
class SnortDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None
    column: int | None = None


class SnortParseError(ValueError):
    def __init__(self, code, field_path=None, *, line=None, column=None, record_index=1):
        code = code if type(code) is str and code in _CODES else 'invalid_field'
        field_path = field_path if type(field_path) is str and field_path in _FIELDS else None
        self.diagnostic = SnortDiagnostic(
            code, field_path, record_index=record_index if type(record_index) is int and record_index > 0 else 1,
            line=line if type(line) is int and line > 0 else None,
            column=column if type(column) is int and column > 0 else None,
        )
        super().__init__(code + (f': {field_path}' if field_path else ''))
