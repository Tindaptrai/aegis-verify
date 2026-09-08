"""Fixed-vocabulary diagnostics: never include source values or local paths."""
from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2

_CODES = frozenset('input_type input_too_large invalid_encoding invalid_unicode invalid_json duplicate_key invalid_number max_depth max_nodes invalid_root missing_source invalid_field unsupported_profile missing_event_time invalid_event_time invalid_context canonical_validation io_error'.split())
_FIELDS = frozenset({
    'source_ref', 'environment_id', 'ingested_at', 'deployment_mode',
    '_source', '_source.id', '_source.data', '_source.rule', '_source.rule.id',
    '_source.rule.level', '_source.rule.groups', '_source.agent', '_source.manager',
    '_source.manager.name',
    *('_source.agent.' + k for k in ('id', 'name', 'ip')),
    *('_source.data.' + k for k in ('timestamp', 'event_type', 'alert', 'src_ip',
       'dest_ip', 'src_port', 'dest_port', 'proto', 'flow_id', 'app_proto', 'in_iface')),
    *('_source.data.alert.' + k for k in ('action', 'signature_id', 'severity',
       'gid', 'rev', 'signature', 'category')),
    *('canonical.' + k for k in CanonicalEventV2.model_fields),
})


@dataclass(frozen=True, slots=True)
class SuricataDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None
    column: int | None = None


class SuricataParseError(ValueError):
    def __init__(self, code, field_path=None, *, line=None, column=None):
        code = code if type(code) is str and code in _CODES else 'invalid_field'
        field_path = field_path if type(field_path) is str and field_path in _FIELDS else None
        self.diagnostic = SuricataDiagnostic(
            code, field_path,
            line=line if type(line) is int and line > 0 else None,
            column=column if type(column) is int and column > 0 else None,
        )
        super().__init__(code + (f': {field_path}' if field_path else ''))
