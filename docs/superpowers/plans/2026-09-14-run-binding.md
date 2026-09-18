# SCN-001 Run Binding Implementation Plan

> **For agentic workers:** executing-plans sequential, no subagent/commit/push/merge.

**Goal:** Detect ambiguous or missing run binding without changing engine verdicts, and compare a separately supplied native review declaration.

**Architecture:** Demo-only read-only API consumes verified run/bundle and existing canonical/provenance fields. Native review is closed caller metadata, not a new EVTX parser or remote authentication. Keep source parsing in connectors and ground truth unchanged.

**Tech Stack:** Existing Python/Pydantic/intake/predicates, no new dependency.

**Spec:** ../specs/2026-09-14-scn001-offline-evidence-design.md section 6.

## Rules

- Reuse verified study/run and snapshot request pins; no caller-constructed model bypass. Profile A01/A02 conditions retain unknown semantics.
- Candidate evidence includes all true/unknown matches, plus records using runner child PID; unrelated definite false records remain in bundle, not binding witnesses.
- Multiple candidates per telemetry root, a known different PID, wrong label-specific path/command, or event outside launch..exit -> conflict. Unknown predicate/PID/provenance -> unknown. Missing telemetry -> unknown. Conflict takes precedence, never choose a convenient witness.
- Require one Sysmon and one PowerShell candidate, child PID both, parent PID equals runner, process GUID and script block ID and Windows record IDs present; counters 1/1. IDs exact (no GUID/case/path normalization).
- Native receipt: kind/version, request_sha256, confirmed_by/reference, reviewed_at, records (exact pair). Each record supplies evidence_id, hostname, provider, windows_record_id, event_time, process_id, process_guid or script_block_id (other null). Root payload_path/payload_sha256 and full_script_reviewed=true link operator native content review to frozen run. No automatic native receipt or content proof.
- Missing native receipt remains unknown; matching receipt yields caller_reviewed, NOT lab_verified/Detected/collection complete. Malformed/stale receipt is an input error. Valid receipt inconsistent with candidate is conflict.
- Return bounded JSON bytes with run/request pins, status/reason codes and evidence IDs/raw refs/hashes. No writes, no verdict mutation.

## Task 1: Canonical and provenance binding

Create backend/app/demo/run_binding.py and backend/tests/test_scn001_run_binding.py.

```python
review_run_binding(bundle, *, run_inputs, native_review=None) -> bytes
assert json.loads(review_run_binding(bundle, run_inputs=inputs))['status'] == 'unknown'
```

- [x] Test RED at stub: no-native unknown, duplicate/wrong/null PID, missing GUID/record, wrong original/renamed, launch time conflict, no telemetry. Unrelated-event guard also covered by later test.
- [x] Implement candidate selection and conflict/unknown precedence, preserving all evidence references and engine behavior.

## Task 2: Native declaration and handoff

- [x] Tests RED: matching native declaration -> caller_reviewed, false content review unknown, stale request error, malformed receipt error, wrong metadata/payload conflict, no production receipt generation.
- [x] Implement closed receipt validation and exact metadata cross-check, document caller trust limits.
- [x] Focused and full tests, pip check, diff check, checkpoint. Native extraction/CLI orchestration and formal lab A/B/C remain separate. Independent human review before merge.

## Verification

- Baseline: 86 passed in 7.45s. Initial stub RED: 34 failed; implementation GREEN: 34 passed in 31.03s.
- Edge tests: 1 failed, 56 passed in 49.30s (blank GUID incorrectly became native mismatch). Unified blank-as-missing check; regression 1 passed in 1.07s.
- Final focused: 60 passed in 52.19s. Full backend: 2481 passed, 1 skipped in 188.36s; FIFO unavailable on Windows at test_intake_io.py:452.
- pip check and git diff --check exit 0; new files no-index whitespace check only LF/CRLF warnings. No independent review or wheel build. Extra guards already green were not independently RED.

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-binding-full-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```
