# SCN-001 Collection Review Implementation Plan

> **For agentic workers:** Use executing-plans, sequential; no subagents, commits or lab changes.

**Goal:** Bind explicit caller collection approval to a verified unknown snapshot transport and verified run, returning a separate context without modifying evidence.

**Architecture:** Read-only demo API recomputes request from verified bytes. Approval references the exact request SHA256. Existing engine calculates outcomes; reference strings remain operator declarations, never authenticated native proof.

**Tech Stack:** Existing Python/Pydantic/JSON/SHA256; no dependencies.

**Spec:** ../specs/2026-09-14-scn001-offline-evidence-design.md, sections 3,6,7,8.

## Constraints

- Keep engine, canonical schema, scenario and lab unchanged. One declaration for SCN-001-A03 only.
- Revalidate study/run inputs with verify_run, snapshot with verify_snapshot_bundle; profile bytes and context must match run, scope agent/host must match bindings.
- A request pins completion bytes, all run input hashes, profile/scope/event-set fingerprints and coverage. No automatic true flags.
- Approval is bounded closed JSON: kind/version, request_sha256, confirmed_by, reference, coverage_start/end, collected_at/reviewed_at, three required strict boolean confirmations plus health/filter/rotation/backlog/native/time references. All must be supplied; false or null does not authorize attestation. coverage_end <= collected_at <= reviewed_at.
- Rebuild and compare request bytes on approval; stale inputs fail, never auto-update approval. Return context bytes separately; no filesystem output or final lab verdict.
- Native run-binding verification and final CLI remain separate work. Caller-attested context is not a lab-verified report.

## Task 1: Bound request and explicit context

Files: create backend/app/demo/collection_review.py, backend/tests/test_scn001_collection_review.py.

Interfaces:
```python
prepare_collection_request(bundle, *, run_inputs) -> bytes
approve_collection_request(bundle, *, run_inputs, request: bytes, approval: bytes) -> bytes
```

- [x] Write synthetic roundtrip and stale/false/malformed approval tests. Use existing synthetic study fixture and actual snapshot adapter; never execute payload.
- [x] Run RED (stub NotImplementedError), implement request recomputation, strict approval and separate context.
- [x] Test changing bundle, profile, context, source bytes, run receipt; snapshots empty/missing telemetry must not become pass. Test engine Inconclusive -> False negative only with explicit confirmations, original context remains unknown.

```python
request = prepare_collection_request(bundle, run_inputs=inputs)
context = approve_collection_request(bundle, run_inputs=inputs, request=request, approval=operator_bytes)
assert json.loads(context)['declarations'][0]['status'] == 'complete_for_scope'
assert json.loads((bundle / 'context.json').read_bytes())['declarations'] == []
```

## Task 2: Verify and handoff

- [x] Focused tests, full backend/tests with fresh build basetemp, pip check, diff --check.
- [x] Document exact API/approval fields, trust limits, remaining native binding and CLI work; checkpoint results. No commit/push/merge.

## Verification record

- Baseline: 140 passed in 18.00s (study/run + snapshot transport).
- Initial RED: 47 failed against NotImplementedError stubs after shortening pytest IDs (an oversized parameter ID initially caused two test setup errors on Windows).
- Initial GREEN: 47 passed in 36.38s; extra contract boundary tests: 57 passed in 45.40s, already green under implemented guards.
- Collection/review time extension: one positive test RED on missing schema fields; after adding fields, two ordering tests RED with DID NOT RAISE, then implemented ordering guard.
- Final focused: 62 passed in 44.95s. Full backend: 2421 passed, 1 skipped in 146.85s. FIFO unavailable on Windows at test_intake_io.py:452.
- pip check clean, git diff --check exit 0; new-file no-index whitespace check only LF/CRLF warnings. No wheel build, independent review, formal lab A/B/C or remote changes.

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-collection-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```
