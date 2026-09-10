# pfSense Filterlog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Issue #5 offline IPv4 TCP/UDP pass/block parsing with canonical v2 events and explicit evidence provenance.

**Architecture:** A pfSense-only connector validates caller time context, reads bounded physical lines, parses BSD filterlog fields and emits canonical events inside audit envelopes. Unsupported profiles produce explicit skips; malformed supported records fail. No live collection or changes to other connectors.

**Tech Stack:** Python >=3.11, existing Pydantic 2.13.5, pytest 9.1.1, standard library only; existing PreciseTimestamp and hash_raw_event.

**Spec:** [Approved design](../specs/2026-09-10-pfsense-filterlog-design.md), sections 1–11 are normative.

## Global Constraints

- Worktree: `I:/AEGIS-VERIFY/.worktrees/issue-5-pfsense-fixture-parser`.
- Branch: `codex/issue-5-pfsense-fixture-parser`; base main `370cd2a`.
- Profile: `pfsense-filterlog-bsd-ipv4-tcp-udp-v1`.
- 256 KiB per line, 32 MiB per file, 100,000 physical lines, 128-character numeric tokens.
- Canonical Event v2 only; absent optional fields null; no inferred NAT, asset identity, severity or verdict.
- Source year and fixed UTC offset are mandatory caller context, never inferred from filenames/mtime/clock.
- Raw logs and reverse alias maps stay outside Git; synthetic pass tests are not lab evidence.
- No dependency additions, scenario changes, live endpoints, unrelated refactors, push or merge in this plan without the relevant user authorization.
- Future protocol/syslog expansion is a separate design checkpoint, not part of this implementation.

## File ownership

| File | Responsibility |
| --- | --- |
| `connectors/pfsense/__init__.py` | Public exports only |
| `connectors/pfsense/errors.py` | Safe diagnostic code/field/line, no input echo |
| `connectors/pfsense/models.py` | Immutable context, provenance and parsed/skipped envelopes |
| `connectors/pfsense/_context.py` | Caller labels, year, offset and ingestion timestamp |
| `connectors/pfsense/_fields.py` | Source token validators |
| `connectors/pfsense/_mapping.py` | BSD timestamp/header, CSV positions, mapping and classification |
| `connectors/pfsense/parser.py` | Byte framing, bounds, identity, atomic/streaming APIs |
| `backend/tests/test_pfsense_context.py` | Context and timestamp rules |
| `backend/tests/test_pfsense_mapping.py` | Source mapping and strict negatives |
| `backend/tests/test_pfsense_parser.py` | Framing, IDs, errors, streaming and limits |
| `backend/tests/test_pfsense_fixtures.py` | Reviewed derivative fixtures and manifest consistency |
| `tests/fixtures/pfsense/` | Sanitized fixtures, manifest and README |
| `docs/PFSENSE_FIXTURE_PARSER.md` | Usage, profile, time/coverage limitations |
| `pyproject.toml` | Add `aegis_verify.connectors.pfsense` package entry only |

## Task 1: Explicit context and safe model boundary

**Interfaces:** `make_context(*, source_ref, environment_id, sensor_id, ingested_at,
source_year, source_utc_offset) -> PfSenseContext`; `source_timestamp(text: str,
context: PfSenseContext) -> PreciseTimestamp`. Context stores validated caller
fields unchanged; year is strict int, offset validated ASCII string. Define
`PfSenseParseError` with safe `code`, `field_path`, `line`, `record_index`.

- [ ] Create a dedicated venv; do not use the old baseline wheel for new code.

```powershell
cd 'I:/AEGIS-VERIFY/.worktrees/issue-5-pfsense-fixture-parser'
& 'I:/AEGIS-VERIFY/.worktrees/issue-4-suricata-direct-eve/.venv/Scripts/python.exe' -m venv .venv
& '.venv/Scripts/python.exe' -m pip install -e '.[test]'
& '.venv/Scripts/python.exe' -c 'import aegis_verify; print(aegis_verify.__file__)'
```

- [ ] Add red tests before implementation. A representative synthetic test:

```python
def test_explicit_year_offset_preserves_second_precision():
    ctx = make_context(source_ref='unit-log', environment_id='unit-env',
        sensor_id='unit-fw', ingested_at='2026-09-10T15:00:00Z',
        source_year=2026, source_utc_offset='+07:00')
    value = source_timestamp('Sep 10 21:01:41', ctx)
    assert value.isoformat() == '2026-09-10T14:01:41Z'
    assert value.fractional_digits == 0
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_pfsense_context.py -q` and record the expected missing-symbol failure.
- [ ] Implement context validation from spec §4/§7 and source_timestamp using a fixed English month table, ASCII regex, calendar validation and explicit offset. Construct RFC3339 text with seconds, then call PreciseTimestamp.parse; never use datetime.now.

```python
# Core conversion after validating and extracting year/month/day/time:
wire = f'{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}{offset}'
timestamp = PreciseTimestamp.parse(wire)
```

- [ ] Parameterize invalid tests: True/0/10000 year, -00:00/bad offsets, February 30, non-leap February 29, 24:00:00, second 60, invalid UTF-8 context, invalid labels, UTC boundary overflow, naive ingestion datetime. Verify exceptions contain neither secret marker nor raw input.
- [ ] Add model invariants: parsed requires event and matching event_id/hash/ref; skipped requires event/event_id null and a valid skip reason. Include invalid direct model construction through normal validators in tests.
- [ ] Run the context suite green, inspect diff, commit only task files: `feat(pfsense): validate explicit fixture context`.

## Task 2: BSD header and IPv4 TCP/UDP mapping

**Interfaces:** `map_filterlog_line(text: str, context: PfSenseContext) -> tuple[dict | None, dict, str | None]`.
Tuple is canonical field map, source metadata, skip reason. None fields means
skip, not a fabricated event. Framing strips newline/BOM before this function;
raw bytes stay untouched outside it. Source timestamp function remains public
within the connector and must not use local machine time.

- [ ] Add synthetic mapping tests, including this pass record (not real evidence):

```python
SYNTHETIC_PASS = ('Sep 10 21:01:41 fixture-fw filterlog[1]: '
    '4,,,1000000001,fixture0,match,pass,in,4,0x0,,64,1,0,none,17,udp,'
    '69,192.0.2.1,198.51.100.1,5353,5353,49')

def test_pass_mapping(context):
    fields, metadata, reason = map_filterlog_line(SYNTHETIC_PASS, context)
    assert reason is None
    assert fields['event_action'] == 'allowed'
    assert fields['protocol'] == 'udp'
    assert fields['src_port'] == 5353
    assert fields['rule_id'] == '1000000001'
    assert metadata['interface'] == 'fixture0'
    assert metadata['nat_context'] is None
```

- [ ] Run the mapping test red; implement anchored BSD header parsing and preserve empty payload cells via `payload.split(',')`. Reject embedded quote/control/newline tokens. Validate common fields before classifying; metadata keys use the exact names in this test plus spec §6.
- [ ] Implement TCP/UDP field indexes from Netgate layout: common 0..8, IPv4 9..16, length 17, IPs 18/19, ports 20/21, payload length 22; TCP tail 23..28. Check field counts, protocol number/text, ASCII number syntax/ranges from spec §5. Null applies only to empty optional cells, never a missing column or bad token.

```python
action_map = {'pass': 'allowed', 'block': 'blocked'}
# After strict source validation, not as a fallback for unknown values:
fields = dict(source_type='pfsense', event_provider='pfSense-filterlog',
              timestamp=timestamp, hostname=hostname,
              event_action=action_map[action], protocol=protocol,
              src_ip=src_ip, dst_ip=dst_ip,
              src_port=src_port, dst_port=dst_port, rule_id=tracker)
```

- [ ] Test TCP block, UDP block/pass, empty ports/tracker/IP null, port zero, all absent process/user/severity null after canonical construction. Reject port 65536, signed/float tokens, protocol mismatches, wrong version/address, missing/extra cells, overlong numbers and unknown action/direction.
- [ ] Test valid-header IPv6/IGMP skips separately from malformed supported TCP/UDP failures. Add narrow newsyslog size-rotation notice recognition; unrelated non-filterlog messages fail. Skips are not protocol-specific validity claims.
- [ ] Run context+mapping suites green; commit `feat(pfsense): map bounded IPv4 firewall records`.

## Task 3: Bounded ingestion and evidence provenance

**Interfaces:** public `parse_pfsense_filterlog(raw: bytes, *, source_ref,
environment_id, sensor_id, ingested_at, source_year, source_utc_offset)
-> tuple[PfSenseRecord, ...]` and `iter_pfsense_filterlog_file(path: str | Path,
*, same keyword context) -> Iterator[PfSenseRecord]`. Export both plus error
and outcome types in `__init__.py`; no network I/O.

- [ ] Write red tests for one-line parsing and exact byte hash:

```python
def test_exact_bytes_identity(parser_kwargs):
    raw = (SYNTHETIC_PASS + '\r\n').encode('utf-8')
    first = parse_pfsense_filterlog(raw, **parser_kwargs)[0]
    again = parse_pfsense_filterlog(raw, **parser_kwargs)[0]
    assert first.event.event_id == again.event.event_id
    assert first.event.raw_event_hash == hash_raw_event(raw)
    assert first.event.raw_event_ref == 'unit-log#L1-L1'
    assert first.event.schema_version == '2.0'
```

- [ ] Run red; implement binary readline(MAX_LINE_BYTES+1), per-file/per-line/count budgets, strict UTF-8 and first-line-only BOM, blank-line outcome. Both public APIs share the line reader; bytes API tuple-materializes it atomically. Streaming closes files and exposes late errors safely.

```python
identity = ['pfsense-filterlog-evidence-v1', ctx.environment_id,
            ctx.sensor_id, ctx.source_ref, line_index, raw_hash,
            ctx.source_year, ctx.source_utc_offset]
digest = sha256(json.dumps(identity, ensure_ascii=True,
                          separators=(',', ':')).encode('utf-8')).hexdigest()
event_id = 'pfsense:filterlog-evidence-v1:' + digest
```

- [ ] Construct CanonicalEventV2 normally, never model_construct/model_copy bypasses. Attach provenance version/profile, line index/ref/hash, source fields, context and year/offset warning. Map internal errors to fixed safe field names with no input or chained exception disclosure.
- [ ] Test duplicate lines, environment/sensor/ref changes, year/offset changes, ingestion-time-only replay, LF/CRLF/BOM changes, last line without LF, empty/skip-only input, limits at/beyond boundaries, invalid bytes, unsupported headers, I/O failures and late streaming errors.
- [ ] Add source package entry in pyproject, reinstall editable and verify pfsense module resolves inside this worktree. Run all three pfsense suites green and commit `feat(pfsense): add bounded offline ingestion APIs`.

## Task 4: Sanitized derivatives and real-file comparison

**Inputs:** original file remains outside Git; SHA and counts from spec §3.
**Outputs:** reviewed minimal derivative fixture set, manifest, README and
fixture tests. No production-generated events or fake lab pass records.

- [ ] Verify full original hash before extraction. Select at least one real UDP block, TCP block, IPv6 skip, IGMP skip and rotation notice with original physical line numbers. Extract only after reading raw records locally; keep output sanitized.
- [ ] Red-test manifest hash and fixture roundtrip before creating derivatives:

```python
def test_derivative_hashes_and_schema():
    manifest = json.loads((FIXTURE_DIR / 'manifest.json').read_text(encoding='utf-8'))
    for entry in manifest['fixtures']:
        raw = (FIXTURE_DIR / entry['file']).read_bytes()
        assert hash_raw_event(raw) == entry['derivative_sha256']
        context = dict(manifest['parser_context'], source_ref=entry['source_ref'])
        records = parse_pfsense_filterlog(raw, **context)
        assert len(records) == 1
        if records[0].event is not None:
            event = records[0].event
            assert parse_canonical_event_json(event.model_dump_json()) == event
```

- [ ] Create derivatives using apply_patch, consistent documentation-range address/host/interface/tracker aliases; preserve action, timestamp, column structure and empty fields. Manifest entries include file, source_ref, original source line number/hash, derivative_sha256 and transformation list, never sensitive reverse aliases. Store original file SHA once. Give each derivative its own immutable source_ref, a file-safe label.
- [ ] Document that pass is synthetic in backend tests, not observed lab evidence. Verify each derivative against the original permitted transformations locally; only emit counts/hash results. Never commit or echo all original lines.
- [ ] Run fixture suite then full original-file parser locally. Expect 1,403 parsed and 189 skipped; inspect each discrepancy instead of changing validation to force the count. Verify line refs/hashes and null fields across parsed outcomes, not just totals.
- [ ] Commit only reviewed fixture/test/README files: `test(pfsense): add sanitized firewall evidence fixtures`.

## Task 5: Verification, documentation and human checkpoint

- [ ] Create usage docs with exact public signatures, parser context, time warning, supported/unsupported profile, null/NAT rules, provenance identity, input limits, skip accounting and INCOMPLETE streaming contract. Include synthetic pass and unknown historical clock limitations.
- [ ] Run full suite and dependency check with a fresh temp directory; build exists before pytest creates its child:

```powershell
New-Item -ItemType Directory -Force -Path build | Out-Null
$aegisTestTemp = 'build/pytest-issue5-' + [guid]::NewGuid().ToString('N')
& '.venv/Scripts/python.exe' -m pytest backend/tests -q -p no:cacheprovider --basetemp $aegisTestTemp
& '.venv/Scripts/python.exe' -m pip check
```

- [ ] Build a wheel in a fresh output folder with default build isolation; install into a separate fresh venv and verify imports resolve from site-packages outside checkout. Run the tests against that installation, including package exports. Do not reuse old wheel baseline as verification of new code.
- [ ] Run `git diff --check`, inspect staged names and diff for raw logs, secrets, placeholders, scope creep and accidental scenario/schema changes. Record exact test counts, runtime, original-file comparison, wheel checks and remaining gaps in usage docs.
- [ ] Use requesting-code-review workflow before merge; review source validation, timestamps, nulls, hash/ID stability, skip/error boundaries and fixture sanitization. Address findings with regression tests, then rerun verification.
- [ ] Commit verified docs. Give the user exact PowerShell commands in this worktree for independent comparison. Stop for human/lab review; do not close issue or merge automatically.

## Self-review coverage

Spec §4 time/context -> Task 1; §5 source validation -> Task 2;
§6 mapping/NAT -> Task 2; §7 APIs and bounded framing -> Task 3;
§8 identity -> Task 3 and sanitization -> Task 4; §9 test/AC -> Tasks 1–5;
§10 review gates and §11 isolated runtime -> Tasks 1 and 5.
Future protocols/syslog remain out of scope. No implementation task has been
marked complete by creation of this plan.
