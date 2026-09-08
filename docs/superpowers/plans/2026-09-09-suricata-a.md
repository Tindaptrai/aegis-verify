# Suricata A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for sequential inline execution; decoder, mapping and result are tightly coupled. Steps use checkbox syntax.

**Goal:** Map reviewed Suricata alert in a Wazuh export to canonical v2 and safe provenance.
**Architecture:** Wrapper/evidence adapter separate from Suricata source-field mapper; reuse bounded JSON decoding without Windows mapping. No B/C implementation.
**Tech Stack:** Python>=3.11, existing Pydantic2.13.5/PyYAML6.0.3/pytest9.1.1; no new dependency.
**Spec:** ../specs/2026-09-09-suricata-a-design.md

## Global Constraints

- Worktree codex/issue-4-suricata-wazuh-alert; preserve root and all older worktrees.
- 256 KiB/depth20/nodes10,000/numeric128, canonical v2, exact source time.
- Single Wazuh wrapper with alert + rule.groups suricata; no live/flow/JSONL/CSV.
- Missing optional null; malformed values fail safe; stable byte hash and physical line range.
- No schema/ground-truth edit; no source guessing, prevention claim or unreviewed evidence.
- Explicit source_ref/environment_id/ingested_at/deployment_mode; IDS conflict is warning.

## Task 1: Source mapping, wrapper and tests

Files: create connectors/suricata/{__init__,parser,_mapping,_fields,models,errors}.py;
backend/tests/test_suricata_wazuh.py; fixture+provenance README/.gitattributes;
modify pyproject.toml package list only.

Interfaces: the two public APIs and immutable output fields are specified in spec.
Mapping callable `_mapping.map_alert(data: dict) -> tuple[dict,dict]` returns canonical
source fields and source metadata; errors use fixed `_source.data.*` paths. Wrapper
adds context, Wazuh metadata, identity and line spans. B does not import the wrapper.

- [x] Copy approved sanitized fixture preserving bytes; verify hash and staged blob.
- [x] Write tests, run RED before production API exists:

```python
def test_exact_source_time(sample, context):
    from aegis_verify.connectors.suricata import parse_suricata_wazuh_document
    result = parse_suricata_wazuh_document(sample, **context)
    assert result.event.timestamp.isoformat() == '2026-04-29T17:18:09.338512Z'
    assert result.event.src_port == 55237
    assert result.provenance.flow_id_raw == '100000000000001.000000'
```

- [x] Add table-driven source/container/context negatives, time0..9, no fallback,
  ids+blocked warning, separate rule/SID/severity, IPs/ports, raw preservation and
  line boundaries (LF,CRLF,CR,Unicode separator) before mapping implementation.
- [x] Implement fixed diagnostics; strict primitive validators; source-only mapping:

```python
normalized = re.sub(r'([+-][0-9]{2})([0-9]{2})$', r'\1:\2', value)
timestamp = PreciseTimestamp.parse(normalized)
# Numeric strings: ASCII fullmatch, <=128 chars, then int; never float.
```

- [x] Implement wrapper + bounded loader; decoder errors translated from None:

```python
identity = ['suricata-evidence-v1', environment_id, source_ref, 1, raw_hash]
event_id = 'suricata:evidence-v1:' + hash_raw_event(
    json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8'))
```

- [x] Add package path; install editable in this venv; focused GREEN then full suite
  and pip check with fresh build/pytest-* basetemp; commit only scope files.

## Task 2: Documentation, packaged verification and review

Files: docs/SURICATA_WAZUH_ALERT.md, docs/superpowers/plans/2026-09-09-suricata-a-verification.md,
connectors/suricata/README.md and root README status. No production scope expansion.

- [x] Explain source vs collector, rule vs SID, exact timestamp, alert action vs
  prevention, nulls and provenance; runnable example uses sanitized fixture only.
- [x] Run example and literal assertions; build wheel in fresh build/wheels-a,
  install [test] into new build/package-check venv and run all tests from build
  using --import-mode=importlib. Check imports resolve in site-packages.
- [x] Request independent read-only review against spec/base; reproduce findings
  with RED tests, fix and re-review before handoff.
- [x] Record counts/hashes/limits and tomorrow B checklist (direct EVE alert+flow,
  source types, line refs, no cross-export dedup, schema flow ID decision).
- [x] Full fresh checks and commit docs, retain branch locally for human comparison;
  no push/merge/Issue #4 closure until requested and evidence reviewed.

## Preflight / progress

Baseline: 650 tests passed on isolated branch. Initial venv setup briefly pointed
at root; corrected editable install to this worktree before baseline or changes.
Spec/plan self-check: Task1 produces the APIs consumed by Task2 examples; source
mapper does not consume Wazuh fields. Budget and metadata rules match across both.
Wazuh decoder reuse is limited to the A wrapper; B does not inherit Wazuh selectors.
