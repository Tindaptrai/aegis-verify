# Issue #6 B: native Cowrie JSONL

## Scope and authorization

Continue the user's approved native/offline direction B and autonomous completion
request after delivery of the native export. A remains compatible. This is not a
live connector, UI, scenario change, or canonical schema expansion. Human review
and lab acceptance remain required before merge; no automatic push or merge.

## Evidence intake

Four local native files match both collection manifests. Collection start/end:
2026-09-11T04:39:42Z. Aggregate intake: 582 JSON objects, 159 distinct session
values; 12 sessions contain connection, login, command input, and close kinds.
This establishes sample coverage, not attack success or forensic completeness.
Keep originals outside Git. Derivatives must remove credentials and identifying
values, preserve order, timestamps, numeric tokens and absent/null distinctions,
and record original file hash and line numbers separately from derivative hashes.

## Design

Reuse Cowrie A's mapping with a configurable internal diagnostic prefix (A default
unchanged). Add native.py for framing/API and native_models.py for immutable
outcomes. Prefer this to wrapping native input in invented Wazuh records (false
provenance), or a broad shared connector refactor (unnecessary Issue #6 scope).

Expose parse_cowrie_jsonl(bytes, *, source_ref, environment_id, sensor_id,
ingested_at) returning a tuple of CowrieNativeRecord and iter_cowrie_file(path,
same keywords) yielding records lazily. Neither API guesses the ingestion clock.
Native input is one JSON object per LF-delimited physical line, accepts CRLF and
an unterminated last line. UTF-8 BOM is allowed only at file start. Hash each
exact physical line including its ending and initial BOM. Coordinates count blank
lines; raw_event_ref is source_ref#L{n}-L{n}. Empty input returns no records.

Reuse strict JSON decoding: 256 KiB maximum physical line, depth 20, 10000 nodes,
128-character number tokens. Total limit 32 MiB; maximum 100000 physical lines.
Bytes API is atomic: malformed input raises, never returns a partial tuple.
File iterator may yield earlier valid records then raise; import is incomplete
unless exhausted successfully. Bounded readline; close iterator on early stop.

Every line produces parsed or skipped, or a sanitized exception. Blank lines
skip with blank_line. Well-formed objects with eventid matching
`cowrie\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*` (maximum 128 chars), outside
the six supported A kinds, skip with unsupported_event_type. Missing/invalid
eventid is an error, not a skip. Unsupported payloads are JSON-validated only;
skip does not certify their field schema. No raw values in diagnostics.

Supported kinds and mapping remain A's six kinds. Native timestamp comes only
from timestamp, preserving 0-9 fractional digits and explicit offset. Session,
authentication outcome, source sensor/UUID/arch remain in provenance; absent
fields null, no session enrichment from neighbors. Native source_record_id is
null: Cowrie UUID is not assumed to uniquely identify an event. Unknown data and
passwords are never copied into canonical/provenance, remaining in the local raw
reference only. Do not execute command text or fetch referenced URLs.

All outcomes have environment/sensor/source labels, physical coordinates, hash,
reference and deterministic evidence ID:
`cowrie:native-evidence-v1:` + SHA256 of compact ensure_ascii JSON UTF-8 array
`["cowrie-native-evidence-v1", environment_id, sensor_id, source_ref, n, raw_hash]`.
Parsed events share this ID. Session key reuses A's cowrie-session-v1 namespace,
independent of input profile, source file, line, hash and ingestion timestamp.
Different sensor/environment namespaces remain isolated. Same session value in
unrelated imports is not proof of same actual session; callers must scope sensor
identity appropriately, and A/B fixture alias namespaces must not be conflated.

Native provenance literals: mapping_version=cowrie-native-v1,
input_profile=cowrie-jsonl-v1, payload_basis=cowrie.native,
timestamp_basis=cowrie.timestamp for parsed records, null for skipped records.
Require strict positive equal line_start/line_end/record_index, validated labels,
hash, ID and reference relationships; parsed/skipped status/event/reason and
kind/action/outcome/session/precision relationships cannot contradict each other.

## Acceptance and limits

Test real sanitized native sequences, all six kinds, missing/null fields,
malformed/hostile input, framing limits, exact-byte identities, A/B session-key
compatibility, namespace isolation and unchanged A behavior. Test wheel imports.
Session/authentication assertions by the validation engine remain unavailable
until a separately approved canonical change; parser facts are not verdicts.
