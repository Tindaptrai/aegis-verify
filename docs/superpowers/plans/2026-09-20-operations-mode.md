# Local Operations Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in local collection and Wazuh agent inventory without changing evidence evaluation or report-only defaults.

**Architecture:** Extend the stdlib dashboard through a separately testable operations service. Reuse the existing canonical Indexer collector; keep Server API inventory separate from events. Ship three dependent implementation issues and a final acceptance issue, each reviewed separately.

**Tech Stack:** Python >=3.11, stdlib HTTP/threading, existing Pydantic, React/TypeScript/Vitest, PowerShell launcher. No new runtime dependencies.

**Spec:** [Approved design](../specs/2026-09-20-operations-mode-design.md). User approved the written spec on 2026-09-20; this plan still requires review and execution-method selection.

## Global Constraints

- Report-only remains default; operations requires `--operations-config <local-file>`.
- Local single operator, loopback only; no scenario execution, administration, attestation or ground-truth changes.
- Config agent allowlist: 1..100. Collection window: at most 24 hours, end not future.
- Request body: at most 8 KiB. One collection worker, no queue. At most 100 persisted jobs per root; admission requires at least 2 GiB free.
- Collector retains 100 records/leaf and existing adaptive/TLS/cleanup bounds.
- Inventory: page size 50, at most 10 pages, 1 MiB/response, 5 MiB total, 10-second socket timeout, 60-second deadline checked between requests.
- Manual inventory refresh only, one in flight, minimum interval 30 seconds; snapshot stale after 60 seconds or refresh failure.
- UI polling no faster than every 2 seconds, stops on terminal state or page exit.
- Owner-only private output outside reports/static/source; no secrets, CA files or raw lab evidence committed.
- Fixture-first. Security conclusions retain evidence IDs; collection success is not a detection verdict.
- Follow AGENTS.md: one scoped GitHub issue per implementation PR, focused branch, human review and lab validation before merge.

## Review Focus

1. Windows provider/UNC/reparse paths and ACL inspection failure: reject before network or writes (Task 1).
2. Browser retry/double-click and process restart: no duplicate collection or silent replay (Task 2).
3. Chunked/ambiguous HTTP framing and cross-origin reads: reject before application dispatch (Task 3).
4. Agent disappearance or pagination change: preserve old snapshot and expose failure, never invent disconnected (Task 4).
5. Late browser response after switching pages or restarting server: no stale overwrite or automatic mutation retry (Task 5).

## Delivery and file map

Create issues only after this plan is approved. Suggested titles/acceptance boundaries:

1. **Opt-in operations service and collection API** — Tasks 1–3, default-off, safe local boundary, persisted single-job collection.
2. **Read-only Wazuh inventory adapter** — Task 4, complete bounded snapshots and stale/error semantics; depends on issue 1.
3. **Operations UI and launcher** — Task 5, capabilities, collection and Agents UI; depends on issues 1–2.
4. **Operations lab acceptance and MVP handoff** — Task 6, evidence-backed acceptance, documentation, final human decision.

Use the existing isolated worktree for design/planning; execution creates a focused `codex/` branch/worktree for each issue. Record actual issue numbers in PRs, not invented numbers here. Do not change the user's running dashboard or dirty original checkout.

New backend modules live under existing `backend/app/dashboard/` package (no packaging-list change needed): `operations_config.py`, `operations_storage.py`, `operations_jobs.py`, `operations_security.py`, `operations_api.py`. Inventory source integration is `connectors/wazuh/inventory.py`. Keep `server.py` as routing/lifecycle glue.

## Task 1: Configuration and private storage preflight

**Files:** Create `backend/app/dashboard/operations_config.py`, `backend/app/dashboard/operations_storage.py`, `backend/tests/test_operations_config.py`, `backend/tests/test_operations_storage.py`.

**Interfaces:**
- `load_operations_config(path: Path, *, environ: Mapping[str, str], reports_root: Path, static_root: Path | None, source_root: Path) -> OperationsConfig`.
- Frozen `OperationsConfig`: `environment_id: str`, `agent_ids: tuple[str, ...]`, `index: str`, `output_root: Path`, `indexer: ConnectionConfig | None`, `server_api: ConnectionConfig | None`.
- Frozen `ConnectionConfig`: `endpoint: str`, `ca_file: Path`, `username: str`, `password: str`; secret fields excluded from repr.
- `OperationsError(code: str)` carries a fixed safe code only.
- `verify_private_root(root: Path, *, excluded_roots: tuple[Path, ...]) -> None`; `JobStore(root: Path)` supplies `load() -> list[dict]`, `save(record: dict) -> None`, `new_output(job_id: str) -> Path`.

- [ ] Write tests using temporary local directories and injected ACL results. JSON config version is integer `1`; keys are `version`, `environment_id`, `agent_ids`, `index`, `output_root`, optional `indexer` and `server_api` (each only `endpoint`, `ca_file`). Reject unknown keys, wrong types, duplicate IDs and malformed HTTPS URLs. Credential environment names are `WAZUH_INDEXER_USERNAME/PASSWORD` and `WAZUH_API_USERNAME/PASSWORD`. Neither pair is copied to the other source.

```python
def test_config_rejects_unknown_keys(tmp_path):
    import json
    import pytest
    from aegis_verify.dashboard.operations_config import load_operations_config, OperationsError
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'version': 1, 'unexpected': True}))
    with pytest.raises(OperationsError):
        load_operations_config(config, environ={}, reports_root=tmp_path / 'reports',
                               static_root=None, source_root=tmp_path / 'source')
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_operations_config.py backend/tests/test_operations_storage.py -q`; observe missing-module/behavior failure before code.
- [ ] Implement strict frozen config, safe fixed errors and root validation. Reject network/provider syntax before filesystem calls; check path components for traversal/reparse/symlink and excluded-root overlap. Use argument-safe read-only Windows ACL inspection; fail closed on inspection errors. Missing credentials disable that source, not report viewing. Never mutate ACLs.

```python
# Admission order: syntax -> local path components -> overlap -> ACL -> writes.
# JobStore.new_output uses UUID-only names and mkdir(exist_ok=False).
# JobStore.save writes one bounded JSON record to an exclusive temp file,
# flushes it, then os.replace within the same verified root.
```

- [ ] Test real temp-directory roundtrip, malformed/oversized metadata, 100-job bound, source/report overlap, inaccessible ACL and atomic-write interruption. Metadata max 16 KiB per job, scan only the dedicated metadata directory; any corrupt/excess entry disables submit. No credential repr/log output.
- [ ] Re-run both tests on Windows; add POSIX permission cases to CI. Commit only these files: `feat: validate private operations configuration`.

## Task 2: Persisted single-worker collection

**Files:** Create `backend/app/dashboard/operations_jobs.py`, `backend/tests/test_operations_jobs.py`; consume existing `connectors/wazuh/live.py` unchanged unless a separately tested adapter requirement is proven.

**Interfaces:**
- `CollectionRequest(agent_id: str, start: str, end: str, adaptive: bool, request_id: str)` is frozen and strictly validated; request ID is UUID.
- `JobService(config: OperationsConfig, store: JobStore, *, collect_fn: Callable, now: Callable, free_bytes: Callable)`.
- Methods `submit(request: CollectionRequest) -> dict`, `list_jobs() -> list[dict]`, `get_job(job_id: str) -> dict`, `shutdown() -> None`.
- Job JSON fields: `id`, `request_id`, `agent_id`, `start`, `end`, `adaptive`, `state`, `created_at`, `finished_at`, `result`, `error_code`. Result contains only `record_count`, `query_complete`, `collection_assurance`, `cleanup_failed`; timestamps UTC, missing values null.

- [ ] Add fake collector blocked by a threading Event and injected fixed clock/disk provider. Test same request returns same ID while concurrent different request conflicts; changed input under same request ID conflicts even after completion.

```python
def test_request_keeps_agent_identity():
    from aegis_verify.dashboard.operations_jobs import CollectionRequest
    request = CollectionRequest('012', '2026-01-01T00:00:00Z',
                                '2026-01-01T00:01:00Z', True,
                                '00000000-0000-4000-8000-000000000001')
    assert request.agent_id == '012'
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_operations_jobs.py -q` and observe RED.
- [ ] Implement atomic admission under lock, persist running before launching worker, call `collect`/`collect_adaptive` using existing `Config` built solely from approved config and request window. Reserve job directory with UUID; choose a fresh child bundle path required by collector. Validate result completeness before terminal success. Do not expose raw exception strings.

```python
# Worker semantics:
# query_complete is True -> completed, including record_count == 0.
# cleanup_failed is True -> completed with explicit warning metadata.
# exception or incomplete -> failed with fixed error_code, artifacts retained.
# recovered running -> interrupted; never schedule recovered work.
```

- [ ] Add restart recovery, disk threshold, 101st-job rejection, concurrent submit, forced persistence failure, adaptive child failure, cleanup warning and no-secret assertions. Use the actual collector with a synthetic fake transport in one integration test to check canonical bundle output.
- [ ] Re-run job/config/storage plus `test_wazuh_live.py` and `test_wazuh_adaptive.py`; commit `feat: orchestrate bounded collection jobs`.

## Task 3: Protected opt-in HTTP surface

**Files:** Create `backend/app/dashboard/operations_security.py`, `backend/app/dashboard/operations_api.py`, `backend/tests/test_operations_http.py`; modify `backend/app/dashboard/server.py`, `backend/app/cli/__init__.py` at the existing dashboard parser/dispatch (locate with `rg -n dashboard backend/app/cli`).

**Interfaces:** `OperationsAPI(config: OperationsConfig, jobs: JobService)` owns session token and later inventory service. `dispatch(method: str, path: str, headers: Mapping[str,str], body: bytes) -> tuple[int, dict]`. Extend `make_server`/`serve` with optional `operations_config=None`; defaults unchanged.

- [ ] Write real localhost HTTP tests: default-off namespace returns 404, report reads unchanged, wrong Host/custom header/Origin/token rejected, bootstrap never exposes endpoint or credentials.

```python
def test_default_server_has_no_operations(tmp_path):
    import threading
    from urllib.error import HTTPError
    from urllib.request import urlopen
    import pytest
    from aegis_verify.dashboard.server import make_server
    server = make_server(tmp_path, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(HTTPError) as error:
            urlopen(f'http://127.0.0.1:{server.server_port}/api/operations/bootstrap')
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_operations_http.py -q`; add opt-in success tests so RED proves the feature is absent, not merely that existing default-off works.
- [ ] Implement exact Host, `X-Aegis-Client: operations-v1`, reject cross-site Fetch Metadata, no CORS. Bootstrap GET returns token; other operations require `X-Aegis-Session`. Mutations additionally require exact Origin and JSON. Reject duplicate Content-Length, Transfer-Encoding, absent/invalid mutation length, >8192 bytes and unknown fields; bound socket reads and close rejected requests. Use constant-time token comparison.
- [ ] Implement listed spec routes with fixed status mapping: invalid input 400, forbidden 403, not found 404, conflict 409, oversized 413, malformed media 415, rate limit 429, unavailable 503; accepted jobs/refresh 202. GET agents may initially return not_configured. Protect response token with no-store and redact request headers from logs.
- [ ] Add two independent server sessions, token restart invalidation, cross-origin bootstrap, encoded traversal, slow/incomplete body and report-root evidence exposure tests. Shutdown stops admission then drains bounded worker; no auto retry.
- [ ] Run operations tests and `backend/tests/test_dashboard_server.py`, review issue-1 diff and full CI; commit `feat: expose guarded local operations API`. Request human review; do not merge automatically.

## Task 4: Independent inventory source and snapshots

**Files:** Create `connectors/wazuh/inventory.py`, `backend/app/dashboard/operations_inventory.py`, `backend/tests/test_wazuh_inventory.py`, `backend/tests/test_operations_inventory.py`; wire through `operations_api.py`.

**Interfaces:** Frozen `AgentRecord(environment_id, agent_id, name, os_name, os_version, source_status, last_keepalive, fetched_at)` string-or-null fields except required identity/time. `InventoryConfig(endpoint: str, ca_file: Path, username: str, password: str)` belongs to the source adapter. `fetch_agents(connection: InventoryConfig, environment_id: str, agent_ids: tuple[str,...], *, transport=None, now=None) -> tuple[AgentRecord,...]`. Source adapter must not import dashboard types: translate `ConnectionConfig` into `InventoryConfig` at service boundary. `InventoryService.refresh() -> dict` starts one worker; `snapshot() -> dict` returns `state`, `agents`, `fetched_at`, `error_code`, `refreshing`.

- [ ] Verify exact GET agents/authentication and RBAC contract against official Wazuh documentation and lab version; save sanitized response fixtures, never live credentials. Test pagination success, null fields and unknown status without canonical-event fabrication.

```python
def test_inventory_absent_name_stays_null():
    from aegis_verify.connectors.wazuh.inventory import parse_agent
    record = parse_agent({'id': '012', 'status': 'active'},
                         environment_id='fixture-lab', fetched_at='2026-01-01T00:00:00Z')
    assert record.name is None
    assert record.source_status == 'active'
```

- [ ] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_wazuh_inventory.py backend/tests/test_operations_inventory.py -q`; observe RED.
- [ ] Implement `InventoryConfig(endpoint, ca_file, username, password)`, `parse_agent(raw: dict, *, environment_id: str, fetched_at: str) -> AgentRecord`, verified TLS/no ambient proxies/no redirect transport, memory-only authentication token. Authentication failure returns a fixed code; one reauthentication on expired token per refresh, counted inside bounds, no retry loop.
- [ ] Implement exact allowlist query, cumulative response/page/deadline bounds from spec, duplicate/failed-items/total checks before snapshot publication. Do not infer missing agents; changed membership yields incomplete-refresh error and preserves prior snapshot.
- [ ] Implement refresh lock, injected clock/rate-limit, stale-on-failure, unavailable-without-snapshot. Test token expiry, 401/403/429, partial response, missing allowlisted agent, source status unknown, clock boundary, two concurrent refreshes and collection independence. Test no auto source requests on GET agents.
- [ ] Re-run inventory/operations suite, full backend and CI; commit `feat: add bounded read-only agent inventory`; request separate issue-2 PR review.

## Task 5: Capability-gated UI and launcher

**Files:** Create `frontend/src/operations/contracts.ts`, `frontend/src/operations/api.ts`, `frontend/src/operations/AgentsView.tsx`, `frontend/src/operations/CollectionsView.tsx`, `frontend/src/operations/operations.test.tsx`; modify `frontend/src/App.tsx`, `frontend/src/components/Sidebar.tsx`, `frontend/src/route.ts`, `frontend/src/styles.css`, `Start-Aegis.ps1`, `backend/tests/test_dashboard_launcher.py`; create `docs/OPERATIONS.md`.

**Interfaces:** Separate `OperationsClient` methods `bootstrap`, `agents`, `refreshAgents`, `collections`, `submitCollection`, `collection`; responses runtime-validated against Task 2/4 fields. Token private to client closure. Keep existing report `ApiClient` unchanged. Extend route with optional `page: 'reports' | 'agents' | 'collections'` and optional job ID, never secrets or connection config.

- [ ] Add frontend tests using mock fetch and fake timers: unavailable bootstrap hides operations navigation while reports still work; invalid input never submits; double-click uses one request ID; unknown/stale status is explicit.

```tsx
import { expect, it } from 'vitest';
import { parseJob } from './contracts';
it('rejects a forged collection verdict', () => {
  expect(parseJob({ state: 'Detected', record_count: 4 }).ok).toBe(false);
});
```

- [ ] Run `npm --prefix frontend test -- src/operations/operations.test.tsx`; observe RED before implementing components.
- [ ] Implement contracts/client/views and accessible labels. Collections displays agent, explicit UTC range, adaptive toggle, confirmation and confirmed metadata only; no evaluation verdict and no raw artifact download. Agents shows source status, source keepalive and fetch time separately, manual refresh only. Read endpoints remain read-only; no auto resubmit when token expires.
- [ ] Add tests for late response after navigation, server session change, abort/unmount cleanup, 2-second polling stop at terminal state, keyboard use, 0-record success, cleanup warning and safe fixed error messages. Keep synthetic UI data strictly in tests.
- [ ] Add optional launcher `OperationsConfig` parameter, validate its local path and forward as distinct argument; test missing/nonlocal/config paths with spaces, unchanged report-only invocation. Documentation includes credential environment names and no passwords/examples pointing to real lab hosts.
- [ ] Run `npm --prefix frontend test`, `npm --prefix frontend run build`, `.venv/Scripts/python.exe -m pytest backend/tests/test_dashboard_launcher.py -q`, then full CI. Inspect rendered UI with synthetic fixtures at a free port without replacing the existing lab server. Commit `feat: add local collections and agents workspace`; request issue-3 review.

## Task 6: Lab acceptance and final MVP decision

**Files:** Create `docs/OPERATIONS_ACCEPTANCE.md`; update `docs/OPERATIONS.md` and `README.md`. Keep raw lab proof and credentials outside Git.

- [ ] Run final verification on exact proposed release tree:

```powershell
& .venv/Scripts/python.exe -m pytest -q -rs
npm --prefix frontend test
npm --prefix frontend run build
git diff --check
```

- [ ] Verify hosted Windows/Linux CI and obtain independent code review under the review skill. Resolve findings with failing regression tests first. No merge until human/evidence review.
- [ ] Ask operator only for missing local setup: least-privilege Server API credentials/CA supplied to backend process, approved agent allowlist and owner-only root. Never request passwords in chat or broaden permissions automatically.
- [ ] With operator-authorized configuration, open a separate local operations instance; perform one manual inventory refresh and one short historical collection. Compare identity/status/time with source, verify bundle counts/provenance and that browser responses contain no secrets. Do not run payloads or change Wazuh rules.
- [ ] Record pass/fail/blocked plus private evidence references for each acceptance item, cleanup the temporary test server and preserve collected evidence. Missing source credentials means blocked live acceptance, not a fake pass.
- [ ] Audit original PRD separately: three scenarios, four fixture connectors, canonical/validation/timeline/regression, reproducible evidence-linked demo. Inventory files alone are not evidence of acceptance. List any unverified criterion explicitly; no change of ground truth or expansion to four live connectors.
- [ ] Prepare handoff with setup/run/stop/recovery, tested commit, known limitations (manual evaluation after collection, no scenario execution, local single operator, stale inventory semantics). Request human decision to merge and tag; do not label production-ready or final MVP before acceptance is reviewed.

## Estimate and stop line

Planning estimate, not a timing guarantee: Tasks 1–3 roughly 1–2 working days; Tasks 4–5 roughly 1–2 working days; Task 6 roughly half to one working day if lab access is ready. Total approximately 3–5 working days including regression fixes/review, excluding time waiting for credentials/approvals or unexpected legacy defects.

The agreed final target is the local operational MVP, not a fully automated end-to-end scenario runner. Stop adding features after these acceptance criteria. If the original PRD audit finds a substantive missing requirement, report it with evidence and ask for a separate scoped decision rather than silently declaring completion or extending this plan.
