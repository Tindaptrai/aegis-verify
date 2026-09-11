# Cowrie Native JSONL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Issue #6 with a bounded native Cowrie JSONL offline parser and traceable real fixtures.

**Architecture:** Keep A intact and reuse source mapping; native framing and models are separate. All parsed events use CanonicalEventV2; provenance retains session and outcome without engine/schema changes.

**Tech Stack:** Existing Python 3.13, Pydantic 2, pytest; no new dependency.

**Spec:** docs/superpowers/specs/2026-09-11-cowrie-native-jsonl-design.md

## Global Constraints

- Only Issue #6, offline; no live access, UI, ground truth edits, canonical schema change, new dependencies, push or merge.
- A API/identities/mapping remain compatible. Source-specific code stays inside connectors/cowrie/.
- Never commit unsanitized evidence, passwords, credentials or reverse alias maps; never execute logged commands or URLs.
- Missing canonical values remain null; parsed events use CanonicalEventV2. Session/outcome remain provenance and are not engine assertions.
- Native JSONL limits: 256 KiB per physical line, 32 MiB total, 100000 lines; preserve 0-9 timestamp fractional digits.

### Task 1: Native framing, immutable outcomes and parser tests

**Files:**
- Create: connectors/cowrie/native.py, connectors/cowrie/native_models.py
- Modify: connectors/cowrie/_mapping.py, _context.py, errors.py, __init__.py
- Test: backend/tests/test_cowrie_native_parser.py

**Interfaces:**
- Consume map_cowrie_event(data, prefix="_source.data.") (add optional prefix), validate_context, session_key, strict Wazuh decode_document, CanonicalEventV2 and PreciseTimestamp.
- Produce parse_cowrie_jsonl(raw: bytes, *, source_ref: str, environment_id: str, sensor_id: str, ingested_at: datetime | str | PreciseTimestamp) -> tuple[CowrieNativeRecord, ...].
- Produce iter_cowrie_file(path: str | Path, same keywords) -> Iterator[CowrieNativeRecord].
- Export CowrieNativeRecord and CowrieNativeProvenance. Add native_evidence_id(environment_id, sensor_id, source_ref, record_index, raw_event_hash) in _context.py.
- CowrieNativeRecord: status parsed|skipped, reason null|blank_line|unsupported_event_type, event CanonicalEventV2|null, provenance CowrieNativeProvenance. Provenance follows all exact fields, literals and relationships in spec. Safe failures use CowrieParseError; add native field allowlist and invalid_bom/max_records/total_input_too_large codes.

- [ ] Write first failing API test (import inside test so missing public API fails the assertion):

```python
def test_native_api_is_available():
    import aegis_verify.connectors.cowrie as cowrie
    assert callable(getattr(cowrie, "parse_cowrie_jsonl", None))
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_cowrie_native_parser.py -q -p no:cacheprovider` and record expected RED.
- [ ] Implement API/model skeleton and then repeat RED/GREEN for behavior groups. Framing core algorithm:

```python
raw = stream.readline(MAX_BYTES + 1)
# Stop at EOF; increment physical index and total bytes before accepting a line.
# Enforce limits, validate BOM position, compute exact-line hash and ID.
# Blank -> explicit skip; decode strict object -> validate eventid grammar.
# Unsupported -> explicit skip; supported -> shared mapping with prefix="".
# Construct canonical event and immutable provenance/outcome, translating errors.
```

- [ ] Tests with literal expectations cover all six kinds and login outcomes; missing/null/wrong types; strict ports/IPs/protocol; timestamps compact offset/UTC/0..9 digits/>9/naive; native source_record_id null; password ignored; malicious unknown strings never echoed; no enrichment across lines; deterministic ID separately hand-hashed; changed line/source/context/raw ending changes ID, ingestion does not; A/B session keys match with same context/session but evidence IDs differ.
- [ ] Framing tests cover LF/CRLF/final no newline, initial BOM/BOM later, blank/empty, duplicate keys including nested, UTF-8/surrogates/nonfinite/depth/nodes/number-token failures, wrong root, mixed supported/unsupported/invalid kind, error coordinates, line/total/count boundaries, lazy partial results/close/IO errors, atomic bytes failure. Model tests reject bool/float coordinates, inconsistent status/event/reason/ID/hash/ref/session/outcome/precision.
- [ ] Run focused Cowrie tests then full backend suite once, pip check, git diff --check. Self-review and commit only owned code/tests. Report RED/GREEN evidence and exact commands.

### Task 2: Native real fixtures, integration tests and handoff guide

**Files:**
- Create: tests/fixtures/cowrie/native/session-sequence.sanitized.jsonl, manifest.json
- Create: backend/tests/test_cowrie_native_fixtures.py
- Create: .gitattributes with `tests/fixtures/cowrie/native/*.jsonl text eol=lf` only, preserving exact derivative bytes across Windows checkout.
- Modify: docs/COWRIE_FIXTURE_PARSER.md, connectors/cowrie/README.md
- Create: docs/COWRIE_NATIVE_INTAKE.md

**Interfaces:**
- Consume parse_cowrie_jsonl and iter_cowrie_file from Task 1.
- Controller supplies audited candidates at build/cowrie-native-candidates/ with native source hashes and selected line coordinates, sanitization rules and derivative hashes. These are REAL derivatives, not unit-test synthetic evidence. Copy only audited candidate content, preserving bytes.
- Produce packaged regression fixtures and human instructions with local PowerShell commands and explicit pending review/merge status.

- [ ] Write a failing fixture test before installing candidate fixtures:

```python
def test_real_sequence_is_available():
    from pathlib import Path
    fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/cowrie/native/session-sequence.sanitized.jsonl"
    assert fixture.is_file()
```

- [ ] Run focused test and record missing-file RED. Install audited candidates via apply_patch. Verify resulting hashes equal candidate manifest (newline fidelity matters).
- [ ] Add meaningful integrations: native evidence hashes equal physical bytes; all mapped canonical facts match independently read sanitized input; session key stable across sequence; six kinds covered; retained missing fields not enriched; real unsupported records explicitly skipped if included; full sequence connect/login/command/close, exact source line mapping, derivative hashes and password/PII sanitization constraints.
- [ ] Update Vietnamese guide: native API example with fixed caller ingestion time, physical line reference/hash behavior, tuple atomic vs iterator incomplete behavior, bounds/skips/error codes, credentials/commands treated as inert sensitive data, alias scope, no forensic-completeness claim, no engine session/outcome claims, how user reruns pytest/pip check and what remains for human review.
- [ ] Run fixture/focused tests then full backend suite once, pip check, git diff --check. Self-review fixture fields and staged diff; commit only owned fixtures/tests/docs. Report exact RED/GREEN results.

## Controller verification after both tasks

- [ ] Independent source hash recheck, aggregate native parsing with no sensitive output, full suite, pip check, fresh wheel/install/import verification.
- [ ] Task reviews then final whole-branch review; address findings, keep human/lab review gate and do not push/merge.
