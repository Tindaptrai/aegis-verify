"""Outcomes include skipped lines so ingestion never silently drops records."""
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegis_verify.models import CanonicalEventV2


class SnortAlertJsonProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True, hide_input_in_errors=True)
    mapping_version: Literal['snort3-alert-json-v1'] = 'snort3-alert-json-v1'
    input_profile: Literal['snort3-alert-json-v1'] = 'snort3-alert-json-v1'
    timestamp_basis: Literal['alert_json.seconds'] | None = None
    source_ref: str
    sensor_id: str
    deployment_mode: Literal['ids', 'ips', 'unknown']
    record_index: int
    line_start: int
    line_end: int
    event_id: str | None = None
    raw_event_hash: str
    raw_event_ref: str
    source_seconds: int | None = None
    source_fraction_digits: int | None = None
    signature_id: str | None = None
    signature_gid: str | None = None
    signature_rev: str | None = None
    signature_text: str | None = None
    signature_category: str | None = None
    app_proto: str | None = None
    direction: Literal['C2S', 'S2C', 'UNK'] | None = None
    pkt_gen: str | None = None
    pkt_len: int | None = None
    pkt_num: int | None = None
    source_alert_action: str | None = None
    source_priority: int | None = None
    warnings: tuple[Literal['ids_blocked_action_requires_review'], ...] = ()


class SnortAlertJsonRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    status: Literal['parsed', 'skipped']
    reason: Literal['blank_line', 'no_ip_header'] | None = None
    event: CanonicalEventV2 | None = None
    provenance: SnortAlertJsonProvenance
