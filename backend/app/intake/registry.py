"""Fixed adapters from explicit registry keys to reviewed connector byte APIs."""

from dataclasses import dataclass

from ..connectors.cowrie import (
    CowrieParseError,
    parse_cowrie_jsonl,
    parse_cowrie_wazuh_document,
)
from ..connectors.pfsense import PfSenseParseError, parse_pfsense_filterlog
from ..connectors.suricata import (
    SuricataParseError,
    parse_suricata_eve_jsonl,
    parse_suricata_wazuh_document,
)
from ..connectors.wazuh import (
    WazuhParseError, parse_wazuh_document,
    parse_wazuh_sysmon1_document, parse_wazuh_powershell4104_document,
    parse_wazuh_sysmon3_archive_record, parse_wazuh_suricata_alert_record,
    parse_wazuh_cowrie_alert_record,
)
from ..models import CanonicalEventV2
from .contracts import BundleFile
from .errors import IntakeError


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    source_ref: str
    parser: str
    source_type: str
    line_start: int
    line_end: int
    raw_event_ref: str
    raw_event_hash: str
    event_id: str | None
    status: str
    reason: str | None
    warnings: tuple[str, ...]


_SOURCE_TYPES = {
    "wazuh-win4688-v2": "wazuh",
    "wazuh-sysmon1-v1": "wazuh",
    "wazuh-powershell4104-v1": "wazuh",
    "wazuh-sysmon3-archive-v1": "wazuh",
    "wazuh-suricata-alert-v1": "wazuh",
    "wazuh-cowrie-alert-v1": "wazuh",
    "suricata-wazuh-alert-v1": "suricata",
    "suricata-eve-jsonl-v1": "suricata",
    "pfsense-filterlog-bsd-ipv4-tcp-udp-v1": "pfsense",
    "cowrie-wazuh-v1": "cowrie",
    "cowrie-jsonl-v1": "cowrie",
}


def _physical_lines(raw: bytes) -> int:
    return raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))


def _ledger(entry, source_type, outcome, *, line_start=None, line_end=None):
    event = outcome.event
    provenance = outcome.provenance
    return LedgerEntry(
        source_ref=entry.source_ref,
        parser=entry.parser,
        source_type=source_type,
        line_start=line_start if line_start is not None else provenance.line_start,
        line_end=line_end if line_end is not None else provenance.line_end,
        raw_event_ref=event.raw_event_ref if event is not None else provenance.raw_event_ref,
        raw_event_hash=event.raw_event_hash if event is not None else provenance.raw_event_hash,
        event_id=event.event_id if event is not None else None,
        status=getattr(outcome, "status", "parsed"),
        reason=getattr(outcome, "reason", None),
        warnings=tuple(getattr(provenance, "warnings", ())),
    )


def _parse(raw: bytes, entry: BundleFile, environment_id: str):
    context = entry.context.model_dump(mode="python")
    common = {
        "source_ref": entry.source_ref,
        "environment_id": environment_id,
    }
    if entry.parser == "wazuh-win4688-v2":
        return parse_wazuh_document(raw, **common, **context)
    if entry.parser == "wazuh-sysmon1-v1":
        return parse_wazuh_sysmon1_document(raw, **common, **context)
    if entry.parser == "wazuh-powershell4104-v1":
        return parse_wazuh_powershell4104_document(raw, **common, **context)
    if entry.parser == "wazuh-sysmon3-archive-v1":
        return parse_wazuh_sysmon3_archive_record(raw, **common, **context)
    if entry.parser == "wazuh-suricata-alert-v1":
        return parse_wazuh_suricata_alert_record(raw, **common, **context)
    if entry.parser == "wazuh-cowrie-alert-v1":
        return parse_wazuh_cowrie_alert_record(raw, **common, **context)
    if entry.parser == "suricata-wazuh-alert-v1":
        return parse_suricata_wazuh_document(raw, **common, **context)
    if entry.parser == "suricata-eve-jsonl-v1":
        return parse_suricata_eve_jsonl(raw, **common, **context)
    if entry.parser == "pfsense-filterlog-bsd-ipv4-tcp-udp-v1":
        return parse_pfsense_filterlog(raw, **common, **context)
    if entry.parser == "cowrie-wazuh-v1":
        return parse_cowrie_wazuh_document(raw, **common, **context)
    if entry.parser == "cowrie-jsonl-v1":
        return parse_cowrie_jsonl(raw, **common, **context)
    raise IntakeError("unknown_parser", stage="evidence", field="parser")


def parse_entry(
    raw: bytes, entry: BundleFile, environment_id: str
) -> tuple[tuple[CanonicalEventV2, ...], tuple[LedgerEntry, ...]]:
    """Run exactly the selected parser and reduce outcomes to a safe ledger."""
    source_type = _SOURCE_TYPES.get(entry.parser)
    if source_type is None:
        raise IntakeError("unknown_parser", stage="evidence", field="parser")
    try:
        parsed = _parse(raw, entry, environment_id)
    except (WazuhParseError, SuricataParseError, PfSenseParseError, CowrieParseError) as error:
        diagnostic = error.diagnostic
        raise IntakeError(
            "parser_error", stage="evidence", line=diagnostic.line
        ) from None

    if entry.parser == "wazuh-win4688-v2":
        event = parsed.event
        ledger = _ledger(
            entry,
            source_type,
            parsed,
            line_start=1,
            line_end=_physical_lines(raw),
        )
        return (event,), (ledger,)
    if entry.parser in {"suricata-wazuh-alert-v1", "cowrie-wazuh-v1",
                        "wazuh-sysmon1-v1", "wazuh-powershell4104-v1",
                        "wazuh-sysmon3-archive-v1", "wazuh-suricata-alert-v1",
                        "wazuh-cowrie-alert-v1"}:
        return (parsed.event,), (_ledger(entry, source_type, parsed),)

    outcomes = tuple(parsed)
    events = tuple(item.event for item in outcomes if item.event is not None)
    ledger = tuple(_ledger(entry, source_type, item) for item in outcomes)
    return events, ledger


def canonical_source_type(parser: str) -> str | None:
    """Return the fixed canonical source type for a registry key."""
    return _SOURCE_TYPES.get(parser)
