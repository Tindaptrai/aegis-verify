"""Fixed public diagnostics. Source values and private paths are never messages."""

from dataclasses import dataclass

from aegis_verify.models import CanonicalEventV2


_CODES = frozenset({
    "input_type", "input_too_large", "invalid_encoding", "invalid_unicode",
    "invalid_json", "duplicate_key", "invalid_number", "max_depth", "max_nodes",
    "invalid_root", "missing_source", "invalid_field", "unsupported_profile",
    "missing_event_time", "invalid_event_time", "invalid_context", "invalid_xml",
    "xml_entities_forbidden", "invalid_xml_namespace", "duplicate_xml_field",
    "identity_conflict", "incomplete_script", "unsupported_fragmentation",
    "canonical_validation",
})
_FIELDS = frozenset({
    "source_ref", "environment_id", "ingested_at", "_index", "_id", "_source",
    "event", "event.original", "event.kind", "event.code", "event.provider", "event.ingested",
    "@timestamp", "winlog", "winlog.event_id", "winlog.record_id", "winlog.provider_name",
    "winlog.channel", "winlog.computer_name", "winlog.process.pid", "host", "host.id",
    "host.name", "host.hostname", "agent", "agent.id", "agent.name", "agent.type",
    "fields", "fields.environment_id", "process", "process.pid", "process.executable",
    "process.entity_id", "process.command_line", "process.parent", "process.parent.pid",
    "process.parent.executable", "process.parent.entity_id", "source", "source.ip", "source.port",
    "destination", "destination.ip", "destination.port", "network", "network.transport",
    "powershell", "powershell.sequence", "powershell.total", "powershell.file",
    "powershell.file.script_block_id", "powershell.file.script_block_text",
    "windows.System", "windows.EventData", "windows.Provider", "windows.Channel",
    "windows.EventID", "windows.EventRecordID", "windows.Computer", "windows.SystemTime",
    "windows.Execution.ProcessID", "windows.UtcTime", "windows.ProcessId", "windows.Image",
    "windows.ProcessGuid", "windows.ParentProcessId", "windows.ParentImage",
    "windows.ParentProcessGuid", "windows.CommandLine", "windows.User", "windows.Protocol",
    "windows.SourceIp", "windows.SourcePort", "windows.DestinationIp", "windows.DestinationPort",
    "windows.MessageNumber", "windows.MessageTotal", "windows.ScriptBlockText",
    "windows.ScriptBlockId", "windows.Path", "kibana.alert", "kibana.alert.start",
    "kibana.alert.original_time", "kibana.alert.rule.rule_id", "kibana.alert.rule.revision",
    "kibana.alert.uuid", "kibana.alert.severity", "kibana.alert.risk_score",
    "kibana.alert.ancestors", "kibana.alert.ancestors.index", "kibana.alert.ancestors.id",
    "kibana.alert.ancestors.type", "kibana.alert.ancestors.depth",
    "kibana.alert.original_event.code", "kibana.alert.original_event.provider",
    "kibana.alert.original_event.original",
    "kibana.alert.original_event.kind", "kibana.alert.rule.parameters",
    "kibana.alert.rule.parameters.rule_id",
    *("canonical." + field for field in CanonicalEventV2.model_fields),
})


@dataclass(frozen=True, slots=True)
class ElasticDiagnostic:
    code: str
    field_path: str | None
    record_index: int = 1
    line: int | None = None
    column: int | None = None


class ElasticParseError(ValueError):
    def __init__(self, code, field_path=None, *, line=None, column=None):
        code = code if type(code) is str and code in _CODES else "invalid_field"
        path = field_path if type(field_path) is str and field_path in _FIELDS else None
        self.diagnostic = ElasticDiagnostic(
            code, path, line=line if type(line) is int and line > 0 else None,
            column=column if type(column) is int and column > 0 else None,
        )
        super().__init__(code + (": " + path if path else ""))
