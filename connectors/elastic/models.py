"""Immutable source provenance; unknown source fields remain in exact raw bytes."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegis_verify.models import CanonicalEventV2


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class ElasticAncestor(_Frozen):
    source_index: str
    source_document_id: str
    ancestor_type: str
    depth: int


class ElasticProvenance(_Frozen):
    mapping_version: Literal["elastic-sysmon1-v1", "elastic-sysmon3-v1",
                             "elastic-powershell4104-v1", "elastic-security-alert-v1"]
    timestamp_basis: Literal["windows.systemTime", "kibana.alert.start"]
    timestamp_policy: Literal["lossless-nanosecond-v2"] = "lossless-nanosecond-v2"
    source_fraction_digits: int
    source_ref: str
    record_index: Literal[1] = 1
    line_start: Literal[1] = 1
    line_end: int
    raw_event_ref: str
    raw_event_hash: str
    event_id: str
    source_index: str
    source_document_id: str
    windows_event_id: Literal["1", "3", "4104"]
    windows_record_id: str
    windows_provider: str
    windows_channel: str
    windows_system_time: str
    sysmon_utc_time: str | None = None
    sysmon_clock_delta_ns: int | None = None
    normalized_timestamp: str | None = None
    source_ingested_at: str | None = None
    collector_agent_id: str | None = None
    collector_agent_name: str | None = None
    collector_agent_type: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    script_block_id: str | None = None
    message_number: Literal[1] | None = None
    message_total: Literal[1] | None = None
    alert_original_time: str | None = None
    alert_uuid: str | None = None
    rule_revision: int | None = None
    alert_severity: str | None = None
    risk_score: int | None = None
    ancestors: tuple[ElasticAncestor, ...] = ()
    warnings: tuple[str, ...] = ()


class ElasticParseResult(_Frozen):
    event: CanonicalEventV2
    provenance: ElasticProvenance
