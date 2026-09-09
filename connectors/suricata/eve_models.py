"""Outcomes include skipped lines so ingestion never silently drops records."""
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegis_verify.models import CanonicalEventV2, PreciseTimestamp


class SuricataEveProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True, hide_input_in_errors=True)
    mapping_version: Literal['suricata-eve-v1'] = 'suricata-eve-v1'
    input_profile: Literal['suricata-eve-jsonl-v1'] = 'suricata-eve-jsonl-v1'
    timestamp_basis: Literal['eve.timestamp'] | None = None
    event_type: str | None = None
    source_fraction_digits: int | None = None
    action_scope: Literal['alert_rule', 'flow'] | None = None
    source_ref: str
    sensor_id: str
    deployment_mode: Literal['ids', 'ips', 'unknown']
    record_index: int
    line_start: int
    line_end: int
    event_id: str | None = None
    raw_event_hash: str
    raw_event_ref: str
    flow_id_raw: str | None = None
    signature_id: str | None = None
    signature_gid: str | None = None
    signature_rev: str | None = None
    signature_text: str | None = None
    signature_category: str | None = None
    app_proto: str | None = None
    in_iface: str | None = None
    source_alert_action: str | None = None
    source_flow_action: str | None = None
    source_src_port: int | None = None
    source_dst_port: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    flow_start: PreciseTimestamp | None = None
    flow_end: PreciseTimestamp | None = None
    flow_state: str | None = None
    flow_reason: str | None = None
    flow_alerted: bool | None = None
    flow_pkts_toserver: int | None = None
    flow_pkts_toclient: int | None = None
    flow_bytes_toserver: int | None = None
    flow_bytes_toclient: int | None = None
    warnings: tuple[Literal['ids_blocked_action_requires_review'], ...] = ()


class SuricataEveRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    status: Literal['parsed', 'skipped']
    reason: Literal['blank_line', 'unsupported_event_type'] | None = None
    event: CanonicalEventV2 | None = None
    provenance: SuricataEveProvenance
