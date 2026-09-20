"""Public diagnostics contain vocabulary, never source data or filesystem paths."""

from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2

_CODES = frozenset({
    'input_type', 'input_too_large', 'invalid_encoding', 'invalid_unicode',
    'invalid_json', 'duplicate_key', 'invalid_number', 'max_depth', 'max_nodes',
    'invalid_root', 'missing_source', 'invalid_field', 'unsupported_profile',
    'missing_event_time', 'invalid_event_time', 'invalid_context',
    'canonical_validation', 'io_error', 'incomplete_script', 'unsupported_fragmentation',
})
_FIELDS = frozenset({
    'source_ref', 'environment_id', 'ingested_at', 'collection_mode',
    'id', 'agent', 'agent.id', 'agent.name', 'manager', 'manager.name',
    'rule', 'rule.id', 'rule.level', 'data', 'data.win',
    'data.win.system', 'data.win.eventdata',
    *('data.win.system.' + field for field in
      ('providerName', 'channel', 'eventID', 'computer', 'eventRecordID')),
    *('data.win.eventdata.' + field for field in
      ('utcTime', 'protocol', 'sourceIp', 'destinationIp', 'sourcePort',
       'destinationPort', 'processId', 'image', 'user', 'processGuid')),
    '_source', '_source.id', '_source.agent', '_source.agent.id', '_source.agent.name',
    '_source.manager', '_source.manager.name', '_source.rule', '_source.rule.id',
    '_source.rule.level', '_source.data', '_source.data.win',
    '_source.data.win.system', '_source.data.win.eventdata',
    *('_source.data.win.system.' + field for field in
      ('systemTime', 'providerName', 'channel', 'eventID', 'computer', 'processID', 'eventRecordID')),
    *('_source.data.win.eventdata.' + field for field in
      ('subjectUserName', 'newProcessName', 'newProcessId', 'parentProcessName', 'commandLine',
       'processId', 'image', 'parentImage', 'user', 'processGuid', 'parentProcessGuid',
       'parentProcessId', 'path', 'scriptBlockId', 'messageNumber', 'messageTotal', 'scriptBlockText')),
    *('canonical.' + field for field in CanonicalEventV2.model_fields),
})


@dataclass(frozen=True, slots=True)
class WazuhDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None
    column: int | None = None


class WazuhParseError(ValueError):
    def __init__(self, code, field_path=None, *, line=None, column=None):
        code = code if type(code) is str and code in _CODES else 'invalid_field'
        field_path = field_path if type(field_path) is str and field_path in _FIELDS else None
        self.diagnostic = WazuhDiagnostic(
            code, field_path,
            line=line if type(line) is int and line > 0 else None,
            column=column if type(column) is int and column > 0 else None,
        )
        super().__init__(code + (f': {field_path}' if field_path else ''))
