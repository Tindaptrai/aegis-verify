# Device Archival and Automatic IP Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #157: archive paired devices with revocation/history and automatically report Windows/Linux IPs.
**Architecture:** Add nullable inventory metadata and append-only archival, versioned inventory APIs and a separate authenticated network heartbeat. Retain the old wire contracts and native identity lifecycle. Upgrade Manager/nginx before shipping 0.2.0 clients and their UI.
**Tech Stack:** Existing Django/PostgreSQL, React/TypeScript, dependency-free .NET 10, nginx, Windows SCM/Linux systemd.
**Spec:** `docs/superpowers/specs/2026-10-25-device-archive-ip-design.md` (owner approved 2026-10-25).
**Issue:** https://github.com/Tindaptrai/aegis-verify/issues/157
**Execution:** Owner authorized implementation after prior delegation/review workflow; proceed continuously through scoped reviews. No new approval round for this mechanical plan.

## Global Constraints

- Follow AGENTS.md; no new dependency, hard-coded deployment IP/URL/secret, canonical event or ground-truth changes.
- Archive only paired_presence; retain Device, PairingCode, jobs/evidence/audit; legacy remains read-only.
- Archive atomically revokes with database constraint archived_at implies revoked; retries are idempotent.
- Archive lock order: AccountMutationLock → DispatchLock → Device → related Jobs sorted by UUID.
- Job eligibility is exactly the two allowlists in spec 4.2; all other combinations fail device_busy.
- manage_devices and current active account checked on every mutation; view for inventory/history; web mutations require CSRF.
- Separate IP claims from proxy observation; null is unknown/unavailable, [] is successful empty; no guessed primary IP.
- Maximum 32 normalized addresses; exclude loopback, unspecified, multicast, IPv4/IPv6 link-local; IPv4-mapped IPv6 normalize to IPv4.
- Collect at most 2 seconds, at most one outstanding OS read, discard late results; heartbeat remains 15 seconds with existing backoff.
- Preserve old v1 inventory DTO and enrollment/heartbeat 2.0; old inventory excludes archived devices.
- New network heartbeat protocol 2.1 at /agent/v2/network-heartbeat with 16KiB/depth4 closed contract; only 404 enables process-lifetime fallback.
- Preserve existing keys, UUID, generation, certificate, CA pin and boot startup; package 0.2.0. Existing state 0.1.0 remains readable and is not rewritten just to add IPs.
- No live VM mutation, live scenario, merge or release publication; draft PR/public review artifacts and human lab gate only.

## Review Focus

1. IPv4-mapped IPv6, scoped IPv6, multicast/link-local, duplicate normalization and truncated=true inconsistencies: reject malformed reports without refreshing presence.
2. Archive versus heartbeat, job processing, and two archive requests: transaction/row-lock tests on PostgreSQL, audit once and no resurrection.
3. Delayed search/poll responses and account permission loss during a dialog: wrong UUID must never be archived or reintroduced by stale UI state.
4. Collector stuck beyond timeout and old-server 404 versus 403/5xx: at most one OS task, presence remains bounded, never downgrade authentication or auto-enroll.
5. Old identity/new binary and new identity/old binary rollback: preserve old state, require Manager-first rollout and never restore a revoked identity to active.

## File/Interface Map

- `manager/control/models.py`, `manager/control/migrations/0005_device_archived_at_device_archived_by_id_and_more.py`, `manager/devices/migrations/0002_alter_enrollmentaudit_action.py`: Device metadata, archived/revoked constraint and audit action.
- `manager/devices/archive.py`: eligibility, atomic archive and audit. `inventory.py`: v2 DTO/query/history. Existing `views.py`/`urls.py` and root URL routing expose them.
- `manager/devices/network.py`: normalization, network payload and peer-header validation. Existing `services.py` applies authenticated snapshots; contracts/identity layer remain bounded.
- `agent/connection/Aegis.Connection/NetworkInventory.cs`: single-flight collector and normalization; `NetworkHeartbeat.cs` or focused AgentClient methods: 2.1 request/response/fallback.
- `frontend/src/manager/contracts.ts` and `types.ts`, with a new focused device module if needed: closed v2 DTO; API helper adds v2 device routes while account/pairing APIs stay v1.
- `DevicesPage.tsx`, focused detail/history/dialog components and `styles.css`: IP, managed/archive inventory and actions.
- Existing native tests, packaging builder/runtime manifests, nginx template and runbook carry integration and 0.2.0 release evidence.

### Task 1: Manager inventory, archival and immutable history

**Files:** Modify `manager/control/models.py`, `admin.py`, `jobs.py`, `manager/devices/models.py`, `contracts.py`, `views.py`, `urls.py`, `services.py`, `manager/aegis_manager/urls.py`; create `devices/archive.py`, `inventory.py`, next additive migration(s), `devices/tests/test_archive.py`, `test_inventory_v2.py`; extend `test_postgres_concurrency.py`.

**Interfaces:** `archive_device(*, actor, device_id) -> None`; `archive_block_reason(device, jobs=None) -> str|None`; `device_v2_dto(device) -> dict`; v2 GET list/detail/history and POST archive per spec. V2 DTO retains existing DeviceDTO fields and adds all spec metadata, `archived_at`, `archived_by_id`, `can_archive`, `archive_block_reason`. Status archived only in v2. History rows: `action,created_at,actor_id,code_id,device_id`; envelope `results,count,page,page_size`. Scope defaults managed. No username lookup dependency.

- [ ] Write failing functional tests, including:
```python
def test_archive_retains_identity_and_history_once():
    # Authenticate admin, enroll synthetic device, archive twice with real CSRF.
    # Assert 204 twice, revoked + archived, identical original archive actor/time,
    # exactly one new revoke + archive audit, retained consumed code and device row,
    # hidden in v1/managed, visible in archived/detail/history, next heartbeat 403.
    ...
```
Also test every busy/allowed job combination, viewer/operator/disabled account, missing UUID/body, legacy denial, database constraint, Admin readonly, history closure and concurrent archive/heartbeat/job claim.
- [ ] Run targeted tests under `aegis_manager.test_settings`; observe behavior failures before code.
- [ ] Implement interfaces and all metadata fields from spec 5.2 with nullable/default semantics. Preserve old DTO shape. Archived guards also apply to current authorization paths. Add exact-IP search initially against metadata fields to be populated by Task 2.
- [ ] Run `python manager/manage.py test devices.tests --settings=aegis_manager.test_settings`; migration drift check. PostgreSQL-only tests may skip locally, must be mandatory in CI.
- [ ] Self-review, commit only Task 1 files and report RED/GREEN commands, migration name, JSON DTO example with synthetic values and risks.

### Task 2: Network heartbeat, proxy provenance and rollout compatibility

**Files:** Create `manager/devices/network.py`, `tests/test_network.py`; modify `contracts.py`, `services.py`, `identity.py`, `views.py`, `urls.py`, `deploy/manager/nginx.conf.example`, `manager/control/tests/test_proxy_mtls.py`, device PostgreSQL tests and enrollment version tests.

**Consumes:** Task 1 metadata and DTO. **Produces:** exact network request/response spec 6.1; `normalize_ip(value) -> str`, `network_heartbeat_input(data) -> dict`, safe peer-IP extraction; service updates after identity validation. New enrollment accepts versions 0.1.0/0.2.0 without changing response 2.0. Old heartbeat clears reported metadata to unknown/null/false (including received-at/version) and updates observed IP independently.

- [ ] Write failing tests: new heartbeat 200/protocol2.1, normalized multi-IP and IPv6 exact search; [] vs unavailable/null; malformed payload does not touch presence; scoped/mapped/link-local/oversize/truncated rules; missing header vs forged/multi-header; old heartbeat with/without IP header; revoked/archived denial.
```python
def test_bad_network_report_does_not_refresh_presence_or_snapshot():
    # Record previous values, send invalid scoped IP using real authenticated
    # fixture identity, assert 400 and every previous value unchanged.
    ...
```
- [ ] Verify RED targeted tests, implement focused parser/service without relaxing old JSON contracts; peer header only trusted loopback HTTPS mTLS paths.
- [ ] Extend nginx real proxy tests to verify header replacement, new route mTLS enforcement and v1 regression. Keep deployment-specific port/PKI/CRL configuration outside source.
- [ ] Run targeted Manager, proxy and old pairing tests; commit/report exact route/DTO contracts for client and UI tasks.

### Task 3: Cross-platform agent network collection and heartbeat negotiation

**Files:** Create focused `NetworkInventory.cs`, `NetworkHeartbeat.cs` if appropriate, corresponding `Aegis.Connection.Tests/NetworkTests.cs`; modify `AgentClient.cs`, `HeartbeatLoop.cs`, `Protocol.cs`, `StateStore.cs`, version in csproj, test harness and CLI/transport/state tests.

**Consumes:** Task 2 new endpoint and response; all spec limits verbatim. **Produces:** native collector, protocol 2.1 transport, original protocol 2.0 fallback only on 404; actual running version in network.agent_version; compatible state validation for enrolled 0.1.0 and new 0.2.0 state. No network fields added to protected state.

- [ ] Write failing injected-interface/clock/transport tests for exact normalization/order/32 cap, zero addresses, unavailable, late/stuck task, DHCP change, 404 lifetime fallback and reset after restart; 400/401/403/429/5xx/TLS/invalid response cannot trigger fallback. Use deterministic completion signals, not wall-clock sleeps mirroring implementation.
```csharp
// Native fixture task starts once, stays unresolved past two-second injected
// deadline; repeated heartbeats return unavailable without starting task two.
// Complete it late and assert its addresses are never published as a new sample.
```
- [ ] Observe RED, implement native API collection with one outstanding task and validated bounded payload, preserving existing authenticated error/backoff behavior.
- [ ] Add actual TLS tests for new and old server routes, state preservation, new version enrollment, rejection after archive; unknown outcomes remain one enrollment attempt.
- [ ] Run dependency-free .NET suite and corresponding real published CLI fixture tests where available. Do not run native installers on user's host.
- [ ] Self-review, commit/report commands, observed counts and which native gates require CI.

### Task 4: Manager UI for IP, archive inventory and identity history

**Files:** Modify `frontend/src/manager/api.ts`, existing contract module (discover exact path), `DevicesPage.tsx`, `styles.css`; create focused IP/detail/history/dialog components as useful; update `DevicesPage.test.tsx`, API/contract tests and add targeted component tests.

**Consumes:** Task 1 v2 DTO/archive/history routes and Task 2 network semantics. Keep auth/pairing calls on v1. API helper supports version selection without loosening response validators. **Produces:** managed/archived scopes, IP column/two visible IPs/full list, UUID-selected details/history and delete confirmation using exact spec copy.

- [ ] Write failing tests with synthetic v2 records: both IP sources and times, unknown/unavailable/empty/truncated/Offline labels, IPv6 search, archived history, legacy/busy disabled action, permission loss, stale polling/search and duplicate hostname selecting exact UUID.
- [ ] Observe RED, implement components using existing design system; no bulk, permanent deletion, restore or job/evidence portal.
- [ ] Test CSRF and expected statuses, fixed error messages, keyboard dialog and malicious labels; account login/logout/pairing remain working.
- [ ] Run `npm test`, `npm run typecheck`, `npm run build:manager`; inspect fixture-only UI visually if tooling allows, never fake lab devices in production.
- [ ] Self-review, commit/report targeted/full checks and UI screenshots only with synthetic data.

### Task 5: Native integration, 0.2.0 packages and upgrade runbook

**Files:** `.github/workflows/agent-connection.yml`, Manager workflow as necessary, `scripts/stage_agent_connection.py`, packaging tests, native service helpers/tests, `manager/devices/tests/test_connection_agent.py`, `docs/manager/AGENT_CONNECTION_RUNBOOK.md` and related protocol docs.

**Consumes:** completed feature commits. **Produces:** deterministic public 0.2.0 win-x64/linux-x64 packages with exact-HEAD metadata/licenses/notices, native SCM/systemd and PostgreSQL/proxy evidence, Manager-first upgrade/runbook and human lab checklist.

- [ ] Add integration assertions that native service account publishes valid network metadata and remains same identity through reinstall/restart; old-client wire regression and archive denies future heartbeat without changing protected local identity.
- [ ] Update package version pins/tests and license inventory only as required; preserve .NET runtime pin 10.0.13 and no extra payload files. RED packaging mismatch before GREEN.
- [ ] Run local Manager/agent/frontend/packaging gates, then publish draft PR against parent pairing branch, attach PR to chat and read exact-head CI. New source branch push/draft PR is authorized by implementation workflow; no merge/release/live deployment.
- [ ] Native Linux/PostgreSQL/nginx tests require real CI; skipped local tests are not evidence of their pass. Resolve required gate failures, retain diagnostics.
- [ ] Run whole-branch independent review and its defined fix wave. Prepare verified public review packages in Downloads and document unexecuted owner lab checks. Never include real config, certificate, identity state or evidence.
- [ ] End with PR, verification summary, package/guide links and outstanding owner lab acceptance. Do not mark reboot-before-login for 0.2.0 executed based on the prior 0.1.0 owner result.
