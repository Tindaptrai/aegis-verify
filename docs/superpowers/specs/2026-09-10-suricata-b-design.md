# Suricata B: direct EVE JSONL

User authorized B after supplying four local EVE exports on 2026-09-10. A remains
on its reviewed branch; B branches from A commit f872eb2 so both changes can be
reviewed separately. No external publication, merge, schema or ground-truth change.

## Observed inputs

WAN 56 lines / 41 alerts; LAN 10598 / 199; MGMT 10697 / 1411; DMZ 1185 / 0.
All four parse as JSON objects. None has event_type=flow. Nested alert.flow is NOT
a standalone flow record. Commit only selected sanitized derivatives; unit flow
fixtures are explicitly artificial. Real flow validation remains an open lab gate.

## Architecture and APIs

Same CanonicalEventV2; flow identity stays in separate provenance. Extend alert
mapping with a field-path prefix argument defaulting to A's prefix. Extract shared
caller-context validation into _context.py without altering A behavior. B uses the
bounded existing JSON decoder directly, not A's Wazuh wrapper/selector. Add eve.py
for streaming framing/dispatch/evidence, _eve_mapping.py for direct semantics, and
eve_models.py for frozen outcomes/provenance. A public API and identity unchanged.

`parse_suricata_eve_jsonl(raw: bytes, *, source_ref, environment_id, sensor_id,
ingested_at, deployment_mode) -> tuple[SuricataEveRecord, ...]`.
`iter_suricata_eve_file(path: str | Path, *, same context) -> Iterator[SuricataEveRecord]`.
The tuple API is atomic on error. Iterator is lazy: prior yielded results remain
available if a later line fails; callers must mark such ingestion incomplete. It
opens rb, reads at most MAX_BYTES+1 per line, closes on exhaustion/error/generator
close. No snapshot guarantee for actively changing source files; use copied fixtures.

Context source_ref/environment/ingested/mode matches A. sensor_id is an explicit
ASCII label with same syntax/limit as source_ref, identifying one sensor instance;
do not infer it from in_iface. Ingest defaults/clock/mode inference prohibited.

## Framing and errors

LF / CRLF JSONL, one object per physical line, optional final LF. Bare CR is not a
record delimiter. First-line UTF8 BOM accepted and hashed; later BOM is invalid_bom.
Blank ASCII-whitespace lines yield skipped reason blank_line with raw ref/hash.
Every other line must pass bounded JSON validation even if unsupported. Missing,
null or invalid event_type errors; event_type ASCII [a-z][a-z0-9_]{0,63}. alert/flow
mapped; all other valid names yield skipped reason unsupported_event_type and no
canonical event. No silent drops. Valid JSON is not full source validation for skips.

Limits: 256 KiB per line including terminator; depth20/nodes10000/numeric128 per
record; 32 MiB total input; 100000 physical lines. Empty file returns empty tuple.
Bytes API type strict bytes; loader rejects numeric file descriptors. Safe diagnostic
vocabulary extends A with invalid_bom, max_records and total_input_too_large. Error
line/record_index is physical file line; fixed field_path never includes source data.
No raw payload or local filesystem path in str(error) or diagnostic.

## Mapping

Source type/provider suricata. Timestamp is top-level timestamp normalized compact
offset in memory preserving 0..9 digits; no fallback to flow.start/end. Alert fields
reuse A mapping. Direct records never use Wazuh rule/id/agent fields: rule_id and
source_record_id null. Flow record requires flow object, maps top-level network and
timestamp only; alert fields ignored. Optional absent fields null, malformed present
mapped fields error. Raw unknowns retained by reference to exact source bytes.

For direct EVE, flow_id is optional strict nonnegative JSON int <=128 digits; keep
str(int) in provenance without float conversion. No claim global uniqueness:
correlation requires environment + sensor scope and capture/time context, not flow_id
alone. No grouping/dedup/engine in B. Do not add canonical fields implicitly.

ICMP/ICMPv6/IPv6-ICMP (case-insensitive exact names) has no transport ports: validate
present src_port/dest_port by A rules, retain them as source_src_port/source_dst_port
provenance but canonical ports null. Keep icmp_type/code as optional integers 0..255.
Other protocols use A mapping. A behavior itself unchanged.

Flow metadata (also optional nested flow on alert): start/end parsed exact source
times, state/reason optional UTF8, alerted strict bool, four packet/byte counters
strict nonnegative JSON int <=128 digits. flow.action optional pass/drop only, kept
raw; for flow record maps pass->allowed, drop->blocked, absent->null; action_scope=flow.
Alert action_scope=alert_rule, canonical action always from alert.action, not flow.action.
ids+canonical blocked emits ids_blocked_action_requires_review. No prevented/detected
conclusion from either action or flow.alerted. Start/end never replace event timestamp.

## Immutable outputs / evidence

SuricataEveRecord: status parsed/skipped; reason null/blank_line/unsupported_event_type;
event CanonicalEventV2|null; provenance present for every physical line. Provenance
contains mapping_version=suricata-eve-v1, input_profile=suricata-eve-jsonl-v1, event_type,
timestamp_basis=eve.timestamp, source_fraction_digits, deployment_mode, action_scope,
source_ref, sensor_id, record_index=line_start=line_end=physical line, event_id,
raw_event_hash, raw_event_ref, plus mapped metadata above and signature metadata
from A. No Wazuh collector identity. Skips have event_id null, timestamp metadata null.

Hash exact line bytes INCLUDING retained newline/BOM. Reference source_ref#Ln-Ln.
Parsed event ID = suricata:eve-evidence-v1: + SHA256(compact ensure_ascii JSON array
[suricata-eve-evidence-v1,environment_id,sensor_id,source_ref,line,raw_hash]). Changes
to ingest/mode don't change identity. Raw source remains caller-owned. No source
record identifier is fabricated from flow ID. Repeated bytes on different lines
remain distinct evidence records. Sanitized derivative renumbering is described in
fixture manifest linking original export line to derivative line.

## Verification and limits

Real sanitized WAN ICMP, LAN TCP, MGMT UDP alerts plus DMZ DNS skip. Artificial flow
tests cover semantics without implying real flow coverage. Test framing/bounds,
malformed and unsupported records, line/hash/identity, timestamp, nulls/type rejection,
source vs collector, warning and action scopes, loader/error cleanup. Full A suite
green; fresh wheel import and tests; independent review and user comparison before
integration. Version reference is official Suricata 8.0 EVE format documentation,
not a claim that the lab runs 8.0.
