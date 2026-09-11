# Cowrie Wazuh Fixture Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the user's approved direction A for Issue #6: offline Wazuh-exported Cowrie documents with schema-valid events and preserved evidence/session metadata.

**Architecture:** One bounded document API plus a bounded file loader emit an immutable canonical event/provenance pair. Source fields are read exclusively from `_source.data`; a reusable Cowrie mapping module keeps future native JSONL separate. Canonical v2 is unchanged.

**Tech Stack:** Python >=3.11, existing pinned Pydantic/PyYAML/pytest only.

**Spec:** docs/superpowers/specs/2026-09-10-cowrie-fixture-design.md

## Global Constraints

- Read AGENTS.md, docs/PRD.md and docs/ARCHITECTURE.md before modifying code.
- Source-specific parsing stays in connectors/cowrie/; validation consumes only canonical events.
- No canonical schema, scenario ground truth, detection rules, live dependency or unrelated connector changes.
- Use CanonicalEventV2 and PreciseTimestamp (0–9 fractional digits); no timestamp fallback or wall-clock reads.
- All credentials and unsanitized evidence stay outside Git; no password in result, diagnostic or report.
- Preserve unknown fields through exact-byte raw evidence reference; absent mapped fields stay null.
- Runtime input is one Wazuh search-hit; native JSONL/CSV are not accepted by this API.
- Run checks in this worktree's .venv, using a fresh basetemp and -p no:cacheprovider.
- Do not push, merge, close issues or edit files in the user's Downloads.

## Task 1: Bounded Cowrie parser, mappings and unit tests

**Files:** Create connectors/cowrie/{__init__,parser,_mapping,_fields,_context,models,errors}.py; create backend/tests/test_cowrie_parser.py and test_cowrie_mapping.py; modify pyproject.toml only to register aegis_verify.connectors.cowrie.

**Interfaces:**
```python
parse_cowrie_wazuh_document(raw: bytes, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp) -> CowrieParseResult
load_cowrie_wazuh_document(path: str | Path, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp) -> CowrieParseResult
# CowrieParseResult: event: CanonicalEventV2, provenance: CowrieProvenance
# CowrieProvenance: mapping_version='cowrie-wazuh-v1', input_profile='wazuh-cowrie-v1',
# payload_basis='wazuh._source.data', timestamp_basis='cowrie.data.timestamp',
# source_record_namespace='wazuh.alert.id', environment_id, sensor_id, source_ref,
# record_index=1, line_start=1, line_end, event_id, raw_event_hash, raw_event_ref,
# source_event_type, session, session_key, source_sensor, source_uuid, arch,
# source_fraction_digits, authentication_outcome ('success'|'failure'|None),
# wazuh_timestamp (PreciseTimestamp|None), wazuh_rule_id, wazuh_rule_level,
# collector_agent_id/name/ip, collector_manager_name (optional).
# CowrieParseError ValueError: diagnostic, code, field_path, line, column,
# record_index. Fixed allowlist diagnostics, no raw values on direct construction.
```

- [x] Write meaningful failing tests before implementation. Public import occurs inside the test after an assertion on find_spec or hasattr, so missing API causes an explicit test failure rather than unrelated collection error. Use synthetic test payloads with no real credentials.

```python
def test_public_parser_exists():
    import importlib
    module = importlib.import_module('aegis_verify.connectors.cowrie')
    assert callable(getattr(module, 'parse_cowrie_wazuh_document', None))

def test_login_failed_is_a_fact_with_preserved_session():
    result = parse(raw_document(eventid='cowrie.login.failed', session='test-session'))
    assert result.event.source_type == 'cowrie'
    assert result.event.event_action == 'login'
    assert result.provenance.authentication_outcome == 'failure'
    assert result.provenance.session == 'test-session'
    assert result.provenance.session_key.startswith('cowrie:session-v1:')
```

- [x] Run focused pytest and record expected RED output in report before creating runtime code.
- [x] Implement six kinds: session.params/connect/closed -> observed; login.success/failed -> login plus outcome; command.input -> command. eventid/timestamp required. Preserve source eventid as provenance.source_event_type, not unique ID. Map peer fields on every type, username only on login, input only on command. Optional missing/null stay null; wrong present types fail. Text values remain exact; session present must be nonblank. protocol accepts ssh/telnet or null. Ports accept bounded ASCII decimal strings or strict integers, reject bool/float; IP accepts unscoped textual IPv4/IPv6 only.
- [x] Context: source_ref/sensor_id ASCII label `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; environment UTF-8 nonblank <=128 bytes; ingestion timestamp provided explicitly. Do not use regex `$` where trailing newline could pass; use fullmatch. Validate before reading files, including empty input and I/O failure cases.
- [x] Reuse existing bounded JSON decoder through an error adapter; limit 256 KiB, 20 nesting levels, 10k nodes, 128-character numeric tokens. Reject arrays/missing wrapper/group/not Cowrie/unsupported kinds. Load reads limit+1; exceptions never reveal I/O path or input values. Validate group array types and optional collector metadata.
- [x] Hash entire original bytes including BOM/newlines; line range counts physical LF/CRLF/CR lines as existing document parser convention. Event ID is `cowrie:wazuh-evidence-v1:` + sha256(compact JSON `["cowrie-wazuh-evidence-v1", environment_id, sensor_id, source_ref, 1, raw_hash]`, ensure_ascii=True). Session key is `cowrie:session-v1:` + sha256(compact JSON `["cowrie-session-v1", environment_id, sensor_id, session]`); absent session -> null. Session key is independent of event source_ref/hash/ingested_at.
- [x] Result/provenance models are immutable, extra-forbid and strict where supported; constructors reject mismatched event/provenance hash/ref/ID/environment, wrong action/outcome/kind, invalid ranges and session/key relationship. Preserve data.source_uuid separately; never use UUID as identity. Password and message are not result fields. Fields unknown to mapping remain solely in raw reference.
- [x] Add independent tests: all six types; connect/login/command/closed synthetic sequence same session; two sensors/environments isolate sessions; missing session null; wrong-type/nonblank fields; source time 0/6/9 digits and +0000/-HHMM/+HH:MM/Z; malformed/no zone; no data fallback from full_log/agent/collector; login username absent with full_log present; unknown fields/credentials not copied to result; exact hash/ref/BOM/CRLF/CR; stability and namespace; malformed JSON/duplicates/depth/nodes/NaN/overflow/Unicode/size; invalid public diagnostics; file load/oversize/I/O/context ordering. Literal expectations must be independent of production helper functions.
- [x] Run focused tests GREEN; self-review; full suite once and pip check; commit only Task 1 files. Include RED/GREEN commands and output, final commit range and concerns in the report.

## Task 2: Sanitized evidence, integration tests and Vietnamese handoff

**Files:** tests/fixtures/cowrie/*.json, manifest.json, README.md, .gitattributes; backend/tests/test_cowrie_fixtures.py; connectors/cowrie/README.md; docs/COWRIE_FIXTURE_PARSER.md; update this plan's completed steps and README status for Cowrie branch only.

**Consumes:** Task 1 public APIs and model fields above. Controller-prepared derivative candidates/audit live in build/; source files are read-only in user Downloads. Coordinate with controller before handling candidates; no secret/raw file may be staged.

**Produces:** Nine reviewed derivative documents for original params and 1–8.json, manifest with original SHA-256, derivative SHA-256, file names, transformation descriptions, parser context and expected kind/action/outcome. No reverse identifier map. source_ref = 'cowrie-' + derivative hash (under 128 chars). Retain 5/6 session relationship. Do not synthesize a full session from unrelated records.

- [x] First write a failing fixture coverage test that requires manifest and all six event types; record RED before final fixtures are added.
```python
def test_manifest_covers_profile():
    assert (Path('tests/fixtures/cowrie') / 'manifest.json').is_file()
    # Once manifest exists, compare its parsed outputs to hand-derived expectations
    # for all six kinds, including login success username null and command pair.
```
- [x] Integrate reviewed candidates with exact line endings pinned to LF in .gitattributes; preserve absence/null and timestamp values, ports, event kinds, outcomes and command structure except declared safe alias/redaction substitutions. Credentials become removed/redacted consistently at every duplicate location, never invented. Sanitization is fixture preparation only, never runtime behavior. Keep source raw bytes unchanged and verify before/after hashes.
- [x] Test every derivative bytes/hash/source_ref, line range and public parser output against manifest expected values; test 5/6 share session_key and distinct event IDs, other input records are not invented as one session. Verify remaining absent username in derivative of 3.json remains null. Data/full_log duplicate mapped fields match aside from known numeric display normalization. Assert no password keys or auth credential fragments survive and URLs/identifiers use safe aliases. Do not run log commands/URLs.
- [x] Document runnable Windows sample using manifest context, safe fields only, parser limits/null/error/evidence/session namespace, A vs native JSONL boundary, unresolved canonical-only engine limitation and pass/fail claim limits. Map all Issue #6 acceptance items to implementation/tests with boundary caveats. Report how many real samples and synthetic sequences, without calling synthetic sequences lab validation.
- [x] Focused fixture tests GREEN, full suite, pip check, wheel build/install in fresh local build/venv and tests with imports verified from installed wheel. Commit owned files only; no push/merge. Report exact verification outputs and source integrity.

## Review and handoff

Each task receives spec and code-quality review; whole branch receives final review
against 664880d. Fix actionable findings with regression tests before handoff.
Human receives test commands for this worktree and final limitations. Do not
claim Issue #6 closed or A as native-file support. No new authorization question
is needed merely to execute these already approved tasks.
