"""Immutable parsing result; provenance is not a security verdict."""
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegis_verify.models import CanonicalEventV2


class SuricataProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True, hide_input_in_errors=True)
    mapping_version: Literal['suricata-wazuh-alert-v1'] = 'suricata-wazuh-alert-v1'
    input_profile: Literal['wazuh-suricata-alert-v1'] = 'wazuh-suricata-alert-v1'
    timestamp_basis: Literal['suricata.data.timestamp'] = 'suricata.data.timestamp'
    action_scope: Literal['alert_rule'] = 'alert_rule'
    source_record_namespace: Literal['wazuh.alert.id'] = 'wazuh.alert.id'
    source_fraction_digits: int
    deployment_mode: Literal['ids', 'ips', 'unknown']
    source_ref: str
    record_index: Literal[1] = 1
    line_start: Literal[1] = 1
    line_end: int
    event_id: str
    raw_event_hash: str
    collector_agent_id: str | None = None
    collector_agent_name: str | None = None
    collector_agent_ip: str | None = None
    collector_manager_name: str | None = None
    wazuh_rule_id: str | None = None
    wazuh_rule_level: int | None = None
    signature_id: str | None = None
    signature_gid: str | None = None
    signature_rev: str | None = None
    signature_text: str | None = None
    signature_category: str | None = None
    app_proto: str | None = None
    in_iface: str | None = None
    source_alert_action: str | None = None
    flow_id_raw: str | None = None
    warnings: tuple[Literal['ids_blocked_action_requires_review'], ...] = ()


class SuricataParseResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    event: CanonicalEventV2
    provenance: SuricataProvenance
