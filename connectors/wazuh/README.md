# Wazuh connector

V0 implemented profile: one sanitized Wazuh JSON search-hit document containing
Windows Security-Auditing / Security / 4688. Outputs canonical v2 plus immutable
mapping/collector provenance; preserves exact event time and hashes exact bytes.

Public API: `aegis_verify.connectors.wazuh.parse_wazuh_document` and
`load_wazuh_document`. Source parsing lives here, not in the validation engine.

Read [the Vietnamese guide](../../docs/WAZUH_FIXTURE_PARSER.md) for runnable examples,
mapping, limits, collection topology and human lab comparison. Other profiles,
CSV and generic multi-record exports are not implemented by that parser.

Issue #11 adds a bounded read-only Indexer collector for the reviewed Windows
4688, Sysmon 1 and PowerShell 4104 profiles. It reuses the fixture parsers and
retains original response bytes plus traceable hit derivatives. See
[setup, limits and lab validation](../../docs/WAZUH_LIVE_CONNECTOR.md).
Live lab validation and human review remain pending.

## Offline Sysmon 3 manager archives (issue #50)

`parse_wazuh_sysmon3_archive_record` accepts **one manager archive JSON object**
as bytes, not an Indexer search hit, arbitrary `_source` wrapper, JSON array or
multi-record JSONL export. Keep the original bytes outside Git for verification.
The function performs no file/network access, collection or scenario execution.

```python
from aegis_verify.connectors.wazuh import parse_wazuh_sysmon3_archive_record

result = parse_wazuh_sysmon3_archive_record(
    raw,  # exact bytes from an operator-selected archive record
    source_ref='archive-record-1', environment_id='lab',
    ingested_at='2026-01-01T00:01:00Z', collection_mode='unknown',
)
event = result.event
provenance = result.provenance
```

This profile supports Sysmon Event 3, lowercase `udp` and IPv4 address fields.
TCP/IPv6 are rejected. Missing optional facts remain null; malformed present
facts are rejected. Decimal string ports become integers in 0..65535; booleans,
floats and guessed values are not accepted. Missing ports do not become zero.
Path/user strings are preserved after normal JSON decode, not unescaped again.

Canonical time comes only from `data.win.eventdata.utcTime` (Sysmon UTC), with
0..9 fractional digits preserved. Windows `systemTime` and manager `timestamp`
remain in the raw evidence, never substituted for missing source time.
`ingested_at` is explicit caller context. `collection_mode='direct'` is a caller
declaration, not a discovery: only that mode maps collector agent ID to asset ID.

The raw hash covers exact input bytes including BOM, whitespace and newline.
`raw_event_ref` and immutable provenance trace that input as record 1. Limits
are the shared bounded decoder's 256 KiB, depth 20 and 10000 nodes. Duplicate
keys, non-finite numbers and invalid Unicode fail with safe diagnostics.
Unknown fields/full_log remain raw-only; callers must retain the raw artifact.

`event_action='observed'` is telemetry, not proof of allowance, blocking or
detection. Rule ID/severity are mapped only when explicitly present, never
inferred from a description. Archive presence does not attest to completeness,
Indexer availability, clock alignment, NAT mapping or multi-source correlation.

The existing live collector, snapshot adapter, intake registry and CLI profile
allowlists are unchanged; they do not auto-dispatch Sysmon 3 through this API.
The fixture in `tests/fixtures/wazuh/network-telemetry/` is explicitly invented,
not a derivative of private lab evidence or a scenario acceptance result.
