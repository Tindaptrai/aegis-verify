# Sysmon 3 Archive Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse one offline Wazuh manager archive UDP Sysmon 3 record into canonical v2 with traceable, unchanged raw evidence.

**Architecture:** Add an explicit archive entry point, not a search-hit wrapper.
Reuse bounded JSON decoding, context validation, canonical validation and evidence
identity. Keep source-specific normalization in the new connector module.

**Tech Stack:** Python 3.11+, existing Pydantic and pytest; no new dependency.

**Spec:** `docs/superpowers/specs/2026-09-20-scn002-archive-parser-design.md` (owner approved).

## Global Constraints

- "Không sửa live collector, manager snapshot, dashboard, quyền Indexer, firewall,
  Sysmon, SCN-001 hoặc executable ground truth."
- "Không gửi traffic, không thêm dependency."
- "Không xây JSONL batch runner hoặc SSH collector trong issue này."
- "Optional thiếu/null giữ null; optional sai kiểu từ chối".
- "Không parse hoặc thực thi full_log để bù field thiếu."
- 256 KiB, depth 20, nodes 10000: reuse `decode_document`, do not relax limits.
- Profile is UDP/IPv4 only; timestamp comes from Sysmon utcTime, no fallback.
- Raw evidence remains private. Test fixtures are explicitly synthetic, not lab proof.
- Existing canonical schema, parser entry points and live allowlists stay unchanged.

## Review Focus

1. Archive with `_source` plus valid root fields must fail, not choose one silently (Task 1).
2. UDP record with absent ports must remain null, not become port zero (Task 2).
3. utcTime invalid/missing must fail even when systemTime is valid (Task 2).
4. Double backslashes and unknown fields must survive in raw without generic unescaping (Task 2).
5. Source values in validation errors must not leak through exception strings or diagnostics (Task 2).

## Workspace and issue

- [ ] Confirm a dedicated implementation issue containing this scope and acceptance;
  keep readiness #49 separate and do not close its missing Indexer/LAN gates.
- [ ] Use an isolated `codex/scn002-archive-parser` branch/worktree. Preserve the
  untracked readiness guide and unrelated work; no reset/clean/stash of user work.
- [ ] Read AGENTS.md, PRD, architecture, approved spec and this plan. Use Native
  execution (previously selected); one final independent review after tests.
- [ ] Use the worktree venv. Commands below use `python` to mean that interpreter,
  not a global Python. In PowerShell invoke `& ./.venv/Scripts/python.exe`.

## File structure

- Create `connectors/wazuh/network_telemetry.py`: archive-only parser/result/provenance.
- Modify `connectors/wazuh/errors.py`: add only static archive field-path vocabulary.
- Modify `connectors/wazuh/__init__.py`: explicit exports, no auto-dispatch.
- Create `backend/tests/test_wazuh_network_telemetry.py`: synthetic contract tests.
- Create `tests/fixtures/wazuh/network-telemetry/sysmon3-archive.synthetic.json`
  and `README.md`: synthetic origin and source-shape description, no private values.
- Modify `connectors/wazuh/README.md`: API and supported/unsupported envelopes.

## Task 1 — Strict archive envelope and minimal canonical result

**Interfaces:** consumes `decode_document(raw)`, `_context(...)`, `hash_raw_event`,
`CanonicalEventV2`, `PreciseTimestamp`, `WazuhParseError`. Produces frozen
`NetworkTelemetryResult(event, provenance)` and
`parse_wazuh_sysmon3_archive_record(raw: bytes, *, source_ref, environment_id,
ingested_at, collection_mode) -> NetworkTelemetryResult`.

- [ ] Create the synthetic fixture from this structure (JSON encode, do not
  copy the private record). All fixture identities are invented:

```python
document = {
    'id': 'synthetic-archive-record',
    'timestamp': '2026-01-01T00:00:04Z',
    'agent': {'id': '901', 'name': 'synthetic-endpoint'},
    'manager': {'name': 'synthetic-manager'},
    'data': {'win': {
        'system': {
            'providerName': 'Microsoft-Windows-Sysmon',
            'channel': 'Microsoft-Windows-Sysmon/Operational',
            'eventID': '3', 'eventRecordID': '101',
            'computer': 'synthetic-endpoint',
            'systemTime': '2026-01-01T00:00:03.1234567Z'},
        'eventdata': {
            'utcTime': '2026-01-01 00:00:01.123', 'protocol': 'udp',
            'sourceIp': '192.0.2.10', 'sourcePort': '49152',
            'destinationIp': '198.51.100.20', 'destinationPort': '45002',
            'processId': '4242', 'image': r'C:\Synthetic\sender.exe',
            'user': r'SYNTHETIC\operator',
            'processGuid': '{00000000-0000-0000-0000-000000000001}'}}}}
```

- [ ] Write RED tests using public lookup, so a missing API fails as an assertion:

```python
def parse(raw, **overrides):
    api = getattr(wazuh, 'parse_wazuh_sysmon3_archive_record', None)
    assert callable(api), 'missing archive parser'
    context = dict(source_ref='synthetic-archive', environment_id='synthetic-env',
                   ingested_at='2026-01-01T00:01:00Z', collection_mode='direct')
    return api(raw, **(context | overrides))

def test_minimal_archive(sample):
    result = parse(sample)
    assert result.event.timestamp.isoformat() == '2026-01-01T00:00:01.123Z'
    assert result.event.source_type == 'wazuh'
    assert result.event.event_action == 'observed'
    assert result.event.asset_id == '901'
    assert result.event.rule_id is None
    assert result.provenance.envelope == 'manager_archive'

def test_reject_search_hit(sample):
    doc = json.loads(sample)
    for value in ({'_source': doc}, dict(doc, _source=None)):
        with pytest.raises(wazuh.WazuhParseError):
            parse(json.dumps(value).encode())
```

- [ ] Run `python -m pytest backend/tests/test_wazuh_network_telemetry.py -q`.
  Expected RED for missing new API, not environment/import dependency failure.
- [ ] Implement explicit envelope/profile checks before mapping. Reject any
  `_source` key, array/multiple records and wrong provider/channel/event code.
  Reuse strict optional object/string helpers and context checks, with archive
  paths in diagnostics. Define frozen result/provenance via Pydantic with
  `extra='forbid', hide_input_in_errors=True`.
- [ ] Implement source timestamp conversion without floats:

```python
match = re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,9})?', value)
if match is None:
    raise WazuhParseError('invalid_event_time', 'data.win.eventdata.utcTime')
timestamp = PreciseTimestamp.parse(value.replace(' ', 'T') + 'Z')
```

  First require a non-null string. Convert calendar/precision errors to safe
  WazuhParseError without source values. Map source/host/context exactly as spec.
- [ ] Run the focused command again: expected GREEN. Commit only task files as
  `feat: add explicit Sysmon 3 archive parser contract`.

## Task 2 — Full mapping, provenance and adversarial cases

**Interfaces:** consumes Task 1 public API; completes tuple/process mapping and
`NetworkTelemetryProvenance` with mapping version, timestamp basis/precision,
source_ref, record_index=1, line_start=1, line_end, raw reference/hash, event ID,
collection_mode, collector IDs/names, windows_event_id='3', windows_record_id,
process_guid. Mapping version is `wazuh-sysmon3-archive-udp-v1`.

- [ ] Add RED parameterized tests for ports and absent fields:

```python
@pytest.mark.parametrize('value', ['0', '65535', None])
def test_port_values(document, value):
    document['data']['win']['eventdata']['sourcePort'] = value
    event = parse(json.dumps(document).encode()).event
    assert event.src_port == (None if value is None else int(value))

@pytest.mark.parametrize('value', [True, 42, '', ' 42', '-1', '65536', '1.5', '９'])
def test_bad_port(document, value):
    document['data']['win']['eventdata']['sourcePort'] = value
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(document).encode())

def test_no_time_fallback(document):
    del document['data']['win']['eventdata']['utcTime']
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(document).encode())
```

- [ ] Run focused tests; expected new mapping assertions fail before implementation.
- [ ] Map ports/PID using ASCII decimal strings only, bounded by existing
  MAX_NUMERIC_CHARS; ports 0..65535, PID nonnegative. IP strings validate via
  `IPv4Address`; reject IPv6/scope/numeric/bool. Missing/null IP remains null.
  Require protocol `udp`; reject other protocols rather than claim support.
  Preserve image/user decoded strings exactly. Map optional rule.id string or
  nonnegative integer to string and rule.level nonnegative integer (not bool).
  No rule => null id/severity. Unmapped canonical fields remain null.
- [ ] Evidence identity follows the existing `wazuh-evidence-v1` convention:

```python
raw_hash = hash_raw_event(raw)
identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
encoded = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode()
event_id = 'wazuh:evidence-v1:' + hash_raw_event(encoded)
```

  raw_event_ref is source_ref + '#record=1'. Compute line_end by existing
  WindowsTelemetry convention; never hash reserialized JSON instead of raw.
- [ ] Add exact assertions for full fixture tuple/process, all nullable fields,
  three collection modes, 0/1/3/7/9 timestamp fractional digits and invalid dates.
  Unknown fields remain raw-only; add newline/unknown field and verify hash/ID
  changes. Same bytes/context must yield identical frozen result.
- [ ] Add RED boundary tests for decoder limits, duplicates, malformed UTF-8,
  NaN/Infinity, malformed structures, booleans/numeric types and missing parents.
  Use valid objects for depth/node tests to isolate each boundary.
- [ ] Pin unescaping and redaction explicitly:

```python
def test_preserve_path(document):
    value = r'C:\\Synthetic\\sender.exe'
    document['data']['win']['eventdata']['image'] = value
    assert parse(json.dumps(document).encode()).event.process_name == value

def test_safe_error(document):
    document['data']['win']['eventdata']['sourcePort'] = 'sensitive-source-text'
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse(json.dumps(document).encode())
    assert 'sensitive-source-text' not in str(caught.value)
    assert 'sensitive-source-text' not in repr(caught.value.diagnostic)
```

- [ ] Add only fixed archive field names to errors.py whitelist; translate
  canonical validation errors using input-free field locations. Fix new failures
  with source-specific helpers in network_telemetry.py, not schema relaxation.
- [ ] Run focused suite: expected GREEN. Commit as
  `feat: map bounded UDP archive telemetry with evidence provenance`.

## Task 3 — Regression, documentation and private smoke check

**Files:** connector README, fixture README, completed test file.
**Interfaces:** consumes frozen public parser, no new CLI or live integration.

- [ ] Document the public invocation and the supported archive-only envelope:

```python
result = parse_wazuh_sysmon3_archive_record(
    raw, source_ref='operator-selected-reference', environment_id='lab',
    ingested_at='2026-01-01T00:01:00Z', collection_mode='unknown')
```

  Explain UDP/IPv4 limitation, null policy, source time, raw retention, no
  completeness attestation, and that observed does not mean prevented/detected.
  Synthetic README labels fixtures invented, source shape informed by private
  inspection; no raw provenance values or private source hashes copied to Git.
- [ ] Add regression assertions that legacy Sysmon1 parser rejects the raw archive
  and existing live/snapshot profile sets still exclude Sysmon3. Read their
  actual public contracts before assertions; do not extend them to pass tests.
- [ ] Run `python -m pytest backend/tests/test_wazuh_network_telemetry.py backend/tests/test_windows_telemetry.py backend/tests/test_windows_telemetry_intake.py backend/tests/test_wazuh_json.py backend/tests/test_wazuh_parser.py backend/tests/test_wazuh_manager_snapshot.py backend/tests/test_wazuh_live.py backend/tests/test_canonical_event_v2.py backend/tests/test_precise_timestamp.py -q`.
  Expected GREEN; investigate real failures, never weaken resource/security tests.
- [ ] Run `python -m pytest backend/tests -q`. Expected GREEN or an explicitly
  diagnosed environment blocker, never mark complete from a partial run.
- [ ] Optional private smoke check uses the previously verified raw file path
  supplied outside Git. Verify its recorded SHA-256 first, invoke parser, assert
  provider/record/time/tuple match that file, and print only check status. Do not
  commit the sample or invent a fixture from it without sanitization review.
- [ ] Run `git diff --check`, inspect staged paths/diff for raw values and secrets.
  Commit docs/tests as `docs: explain offline archive telemetry boundaries`.
- [ ] Final independent whole-branch review, fix important findings with RED/GREEN
  tests. Request human review. No merge, lab change, or SCN-002 completion claim.

## Handoff

Native execution is preserved from the owner's earlier choice: implement the
three sequential tasks here, one final independent review. This plan awaits
owner review before implementation. No further per-task approval is required
within the reviewed scope; new security-sensitive lab actions remain separate.
