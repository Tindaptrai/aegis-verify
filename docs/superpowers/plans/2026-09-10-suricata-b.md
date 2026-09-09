# Suricata B Implementation Plan

> For agentic workers: execute inline with test-driven-development and review checkpoints.

Goal: parse direct EVE JSONL alert/flow while preserving A and exact evidence.
Spec: ../specs/2026-09-10-suricata-b-design.md
Architecture: shared primitive/mapping/context; isolated JSONL framing and direct semantics.
Tech: Python>=3.11, existing Pydantic/pytest; no new dependencies.

## Global constraints

Canonical v2 unchanged. 256KiB per line, 32MiB total, 100000 lines; JSON depth20,
nodes10000,numeric128. Explicit sensor/context. No live access, cross-export dedup,
ground truth change or publication. Real exports have NO standalone flow records.

## Task 1 — reviewed fixtures and mapping

Files: tests/fixtures/suricata/eve-*.sanitized.jsonl and manifest;
backend/tests/test_suricata_eve.py; connectors/suricata/{_context,_mapping,_eve_mapping,eve_models,errors}.py.

- [x] Prepare deterministic derivatives from WAN1/LAN15/MGMT7/DMZ1; consistent IP/flow
  aliases, remove packet/payload/metadata/DNS sensitive subtrees, manifest exact edits.
- [x] Write failing public-API test: fixture timestamp 2026-04-03T14:33:28.714277Z,
  SID2100366, ICMP canonical ports null; watcher RED before production changes.
- [x] Add flow artificial test: top-level event timestamp, flow pass/drop mapping,
  start/end exact provenance, alerted bool not conclusion. Assert A's sample unchanged.
- [x] Implement reusable context extraction, prefix-aware map_alert; B source mapping
  keeps direct flow ID integer-only, validates flow metadata and ICMP representation.

## Task 2 — bounded JSONL APIs

Files: connectors/suricata/eve.py, __init__.py; backend/tests/test_suricata_eve.py.
Public APIs: parse_suricata_eve_jsonl(raw, *, context)->tuple; iter_suricata_eve_file(path, *, context)->iterator.

- [x] RED framing tests: mixed parsed/skipped, blank lines, CRLF/BOM, repeated lines,
  unknown source types, malformed trailing line, oversized line/file and record count.
- [x] Implement shared line consumer yielding frozen outcomes, exact SHA256 per line
  and explicit sensor-scoped event ID. Raise safe line-aware errors from None.
- [x] RED loader tests for bounded read, invalid paths and late failure; implement rb
  readline(MAX_BYTES+1), try/finally close; validate context before opening on iteration.
- [x] Run focused suite and all previous tests with fresh build/pytest-* basetemp.

## Task 3 — handoff

Files: docs/SURICATA_EVE_JSONL.md; docs/superpowers/plans/2026-09-10-suricata-b-verification.md;
README.md; connectors/suricata/README.md.

- [x] Independently review committed diff against base f872eb2. Fix actual findings
  with regression tests; no need second implementation team.
- [x] Parse all user exports locally, output aggregate counts only; don't commit raw
  exports. Confirm lack of flow and fail/skip counts.
- [x] Build wheel into fresh build directory; install in new venv, run full suite from
  build using importlib, verify import paths and pip check. Run documented example.
- [x] Document source-time vs flow-time, ICMP ports, stream partial-failure contract,
  sensor/flow identity scope, synthetic flow test boundary and user next commands.
- [x] Commit reviewed changes locally; leave A/B branches for human/lab integration.

Execution note: initial fixture/API and table-driven tests were written before B
implementation; public API RED confirmed the missing feature. Additional resource
boundary tests hardened the green implementation. Review finding received its own
two-case RED/GREEN cycle. Independent reviewer confirmed the correction.
