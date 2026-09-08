# Suricata A: Wazuh-exported alert to canonical v2

User approved direction A on 2026-09-09 after reviewing the proposal prepared
2026-09-08. This is the precise implementation contract, not approval to push/merge.
Issue #4 remains partial: no direct EVE/JSONL, standalone flow record or engine yet.

## Architecture and scope

`connectors/suricata/parser.py` owns wrapper selection, Wazuh collector metadata,
caller context, evidence identity and local loader. `_mapping.py` owns Suricata
alert field validation only and must not read Wazuh wrapper fields. `_fields.py`
contains strict source-value validators. `models.py` defines immutable result and
provenance. `errors.py` contains safe fixed-vocabulary errors.

The A wrapper reuses the existing bounded Wazuh JSON decoder ONLY, translates its
errors to Suricata errors and does not call the Windows mapper. No Wazuh refactor
or duplicate JSON decoder; B can replace this wrapper without changing A's API.
No canonical schema, ground truth, production event fabrication, dependencies,
live access, config/secrets or unrelated code changes.

## Public API

`parse_suricata_wazuh_document(raw: bytes, *, source_ref: str, environment_id: str,
ingested_at: datetime | str | PreciseTimestamp, deployment_mode: str) -> SuricataParseResult`
and `load_suricata_wazuh_document(path: str | Path, *, same context)`.
`SuricataParseResult(event: CanonicalEventV2, provenance: SuricataProvenance)` frozen.
No clock or default mode: ids/ips/unknown are explicit caller descriptions, not inferred.
source_ref ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; environment_id nonblank UTF8,
max128 UTF8 bytes (bounded caller context). Ingest uses canonical strict time syntax.
File path accepts only str or Path, never numeric file descriptors; read rb limit+1,
translate OS/type/value errors without actual filesystem paths; no writes or sandbox.

## Input selection / budgets

One UTF8 JSON object search-hit, optional single BOM retained in raw hash. Existing
limits: 256 KiB, depth20, nodes10,000, numeric tokens128; duplicates/nonfinite/bad
Unicode rejected throughout unknown fields too. Source `_source` and `data` objects
required; rule object and groups array of strings required as profile markers.
`data.event_type` must be string alert, rule.groups must contain exact `suricata`.
Other text event types / missing Suricata group -> unsupported_profile; wrong
selector/container type -> invalid_field; missing/null _source -> missing_source.
Source data.alert object required. Wazuh agent/manager optional objects; absent/null
means no collector context. Source id/rule id/level are optional independently.

## Mapping (paths relative to _source.data unless noted)

Canonical source_type and event_provider = suricata. timestamp only data.timestamp:
strict string required, normalize trailing +/-HHMM to +/-HH:MM in memory, then use
PreciseTimestamp. Accept 0..9 digits, preserve zeroes, reject naive, invalid dates,
unknown negative zero offsets and >9 digits; missing/null -> missing_event_time.
No fallback Wazuh timestamp/fields/sort/flow.start; preserve original bytes.

src_ip/dst_ip <- src_ip/dest_ip strict IP text; no bool/int, CIDR, whitespace or zone
ID. src_port/dst_port <- src_port/dest_port strict int or ASCII decimal string
1..128 digits, 0..65535. protocol <- proto optional UTF8 string, preserve case;
not app_proto. Missing/null optionals -> null, wrong types reject, never flow fallback.
signature_id <- alert.signature_id strict nonnegative int or ASCII digit string
1..128 digits, preserving leading zeroes on text. rule_id <- _source.rule.id
optional arbitrary UTF8 string or strict nonnegative int <=128 digits -> string.
severity <- alert.severity strict int/decimal string >=0 <=128 digits, source scale.
source_record_id <- _source.id optional string, not flow ID. All host/asset/user/
process/file/technique fields null. agent IP is collector metadata only.

event_action <- alert.action optional string allowed/blocked; any other value errors.
Its scope is alert-rule action, NEVER final firewall verdict or a security conclusion.
With ids + blocked preserve source field and emit fixed warning
`ids_blocked_action_requires_review`; no rewriting, promotion to IPS or silent pass.

Provenance: mapping_version=suricata-wazuh-alert-v1, input_profile=wazuh-suricata-alert-v1,
timestamp_basis=suricata.data.timestamp, source_fraction_digits, deployment_mode,
action_scope=alert_rule, source_ref, record_index=1, line_start/end, event_id/raw_hash,
source_record_namespace=wazuh.alert.id, collector_agent_id/name/ip, collector_manager_name,
wazuh_rule_id/level, signature_id/gid/rev/text/category, app_proto, in_iface,
source_alert_action, flow_id_raw, warnings immutable tuple (empty unless conflict).
Metadata strings optional UTF8; gid/rev same strict decimal ID rule as SID.
flow_id_raw: optional nonnegative JSON int <=128 decimal digits -> string; or ASCII
string digits optionally followed by dot and 1..9 zeros, total length<=128. Preserve
exact text incl leading/trailing zeros, reject float/bool/negative/scientific/nonzero
fraction. No conversion via float or claim that original upstream precision is recovered.
All metadata containers/fields used must validate; unknown fields remain raw only.

## Identity and line reference

SHA256 exact entire sanitized input bytes. ID is `suricata:evidence-v1:` plus SHA256
of compact ensure_ascii JSON UTF8 array [suricata-evidence-v1,environment_id,source_ref,1,raw_hash].
Ingestion/mode/mapping do not change evidence ID. No dedup between A and B.
Reference `source_ref#L1-LN`; N is physical line count of whole JSON document,
including surrounding whitespace, splitting LF/CRLF/lone CR only, not Unicode
line separators inside strings. A final newline does not add a phantom last line.
This references a whole wrapper, not a fabricated EVE line. Caller retains raw file.

## Fixture and limits of the milestone

Use reviewed Downloads/aegis-suricata-review/suricata-wazuh-alert-001.sanitized.json
byte-for-byte; SHA256 9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c.
92 lines, IP substitutions consistent. 14 leaf replacements and three payload
omissions were documented; do not add the original. No incident/SCN-002 association.
flow_id remains provenance, not a new canonical field; B must resolve engine
correlation separately. No claim full Issue #4 complete. Human fixture/lab review
and green tests precede any integration.
