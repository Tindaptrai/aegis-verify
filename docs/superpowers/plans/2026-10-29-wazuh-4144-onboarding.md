# Wazuh 4.14.4 Guided Connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver issue #163: private, verified Wazuh source setup and versioned integration help through Manager, ending at an inactive candidate.

**Architecture:** A new Django `connections` app owns private expiring drafts and managed source metadata linked to immutable registrations. Source-specific probe/policy-enforced HTTPS stays in the Wazuh connector; React consumes closed, secret-free contracts. A separate registry worker waits safely; legacy collection remains unchanged.

**Tech Stack:** Existing Python/Django/cryptography, React/TypeScript/Vitest; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-29-wazuh-web-connections-design.md` (owner approved 2026-10-29).

## Global Constraints

- Wazuh 4.14.4 self-managed only in this slice; Elastic offline remains distinct and Splunk stays planned.
- No source activation, binding migration, agent change, execution, automatic rule change or ground-truth change.
- Root-owned exact endpoint/IP/port policy; HTTPS chain and SAN verification; no proxy, redirects or insecure mode.
- Draft TTL 5 minutes; request limit 96 KiB; CA limit 64 KiB; per-probe total deadline 10 seconds and response cap 64 KiB.
- New managed source versions get new registration UUID/revision 1; old registrations/files/jobs are not overwritten.
- `manage_connections` gates all connection API data/actions; existing human session-generation and CSRF protections apply.
- Never return/log/store credentials in browser storage, DTOs, audit, evidence or Git. Secrets are private files under PRIVATE_ROOT.
- Candidate selection is explicit and optimistic; a candidate does not imply worker healthy, execution Ready or least-privilege proof.
- No fabricated SIEM screenshots or unverified lab/compatibility claims; guide images unavailable honestly labelled.
- Native Linux checks/lab checks unavailable on this host must be reported as pending, never simulated as native evidence.

## Review Focus

- Slow DNS and rebinding: bounded resolver, every connected address approved, original hostname kept for TLS.
- Existing technical binding APIs must reject managed registrations while activation is deferred.
- Session rotation/permission revocation during I/O: no reusable draft or save success for stale authority.
- Crash/file races/concurrent save: exclusive private files, no followed symlinks, immutable registration and one idempotent publication.
- Stale UI responses after a field edit or logout cannot resurrect a tested draft or expose credential data.

## Shared API contract

All routes live under `/api/v1/connections/`, authenticated JSON/no-store, fixed diagnostic codes.

- `GET /`: query `page` only. `{results: SourceDTO[], count, page, page_size:50, candidate_id:UUID|null}`.
- `POST /wazuh/test`: `{name, environment_id, endpoint, index, username, password, ca_pem, source_id:UUID|null, expected_version:int|null}`. Fields are closed. `source_id` null creates a new logical source. A rotated version requires exact latest logical version.
- Test success 201: `{draft_id, expires_at, tested_at, checks:{policy:'passed',tls:'passed',authentication:'passed',query:'passed'}, summary:{name,environment_id,endpoint,index,ca_sha256,source_id,version}}`.
- `POST /wazuh/save`: `{draft_id, idempotency_key:UUID}`; 201 new / 200 idempotent replay; returns `SourceDTO`.
- `POST /<UUID>/prepare`: UUID is saved source version ID, body `{expected_candidate_id:UUID|null}`; returns `{source:SourceDTO,candidate_id:UUID}`. Requires original tested snapshot still within TTL; no binding/activation.
- `SourceDTO` exact fields: `id,source_id,version,name,kind,product,product_version,environment_id,endpoint,index,ca_sha256,status,worker_state,tested_at,created_at`.
- Managed DTO: kind=`managed`, product=`wazuh`, product_version=`4.14.4`, status=`saved|candidate`, worker_state=`waiting_configuration`. IDs UUID, version positive int, timestamps UTC ISO. Legacy DTO: same shape, kind/status/worker_state=`legacy`, product_version/endpoint/index/ca_sha256/tested_at nullable; derive safe metadata without reading legacy credentials. No connection config paths, usernames/passwords or raw probe errors.
- Error shape existing `{error:{code}}`; vocabulary `invalid_request`, `permission_denied`, `connection_unavailable`, `policy_denied`, `invalid_ca`, `tls_failed`, `authentication_failed`, `query_denied`, `query_failed`, `draft_expired`, `draft_conflict`, `source_conflict`, `candidate_conflict`, `storage_unavailable`, `rate_limited`. Existing auth codes remain unchanged.
- Name cap 80 chars; username 128; password 1024; CA 65536 bytes; index must satisfy existing reader config syntax; environment existing validator; endpoint HTTPS origin only. Cap per-session pending drafts and concurrent probes to avoid unbounded secret storage/threads.
- Browser API lives in separate `connectionsApi.ts`; does not extend existing AccountsApi object and break unrelated fixtures. Receive current CSRF via Manager session state; handle `ApiError`/authority invalidation according to existing page conventions.

## Root policy contract

`AEGIS_MANAGER_CONNECTION_POLICY` references a non-symlink root-owned file, no group/other writes, outside PRIVATE_ROOT and checkout. Missing/invalid policy fails closed only new onboarding. Schema `{schema_version:1,targets:[{origin:"https://indexer.example:9200",addresses:["<approved IP>"],indices:["<allowed index pattern>"]}]}`; examples are placeholders, no lab values. Exact origin and requested index must match policy entry. Reject loopback/link-local/metadata/unspecified/multicast even if listed. Re-read policy and pin allowed IPs before network connection; validation cannot be followed by an implicit second DNS lookup. Non-root CI can inject synthetic trusted-policy provider in unit tests; actual ownership gates need native tests/clear skip on Windows.

### Task 1: Secure connector, private draft/source API and execution boundary

**Files:**
- Create: `connectors/wazuh/onboarding.py` (fixed probe only; bounded DNS/TLS/HTTP).
- Create: `manager/connections/{__init__,apps,models,policy,storage,services,views,urls}.py`, migrations and tests.
- Modify: `manager/aegis_manager/base.py`, `test_settings.py`, `urls.py`, `settings.py` for app/routes/optional policy path.
- Modify: `manager/control/execution_services.py` to fence managed registration in `_connection()` (no binding admission through technical API).
- Test: `manager/connections/tests/test_{policy,probe,storage,services,api,boundary,postgres}.py` and connector-specific tests as needed.

**Interfaces:**
- Produces API above and `connections.services.managed_candidate() -> dict | None` for Task 3, keys `candidate_id,source_id,version,status,connection_id,connection_revision`, status=`waiting_configuration`; returns None if unselected. No secret data in this helper.
- Produces `connections.services.is_managed_registration(connection_id) -> bool` for the deferred activation fence.
- Source-specific transport must not import Django. Policy loader returns immutable validated target data; adapter receives allowed addresses and total deadline.

- [ ] Write failing tests for unknown/malicious URL, malformed/expired/non-CA PEM/private-key blocks, rebinding to unapproved IP and slow DNS timeout.
- [ ] Run new tests, record expected failure before implementing corresponding behavior.
- [ ] Implement fixed HTTPS probe preserving original SNI/SAN, reading only the bounded zero-hit query response; no scroll/events or writes. Refuse encoded/oversized/redirected/malformed responses; distinguish safe auth/TLS/query errors without body leakage.
- [ ] Write failing Django tests for RBAC/session/CSRF, expired/session-rotated draft, edit/retest, duplicate fields, over-limit body, cross-actor draft and field caps.
- [ ] Implement private draft creation/test and late authority revalidation. Hold no DB transaction over network. Snapshot HMAC/private digest, actor/session binding and TTL; closed DTO above.
- [ ] Write failing tests for exclusive publication, idempotent save, source version conflict, candidate optimistic conflict, parent/file link, tampered config/CA and orphan recovery.
- [ ] Implement durable private files + immutable saved metadata/registration; create output root server-side. No overwriting old versions; mark orphan safe/non-active and clean expired unreferenced drafts only.
- [ ] Write failing boundary test: saved/candidate registration cannot be set on a device by existing binding API; legacy flow unaffected. Implement fence without changing machine wire protocol or legacy authorization.
- [ ] Run targeted tests and migration drift check, record native/Windows limits; commit Task 1 files only.

### Task 2: Manager Connections UI and versioned integration guides

**Files:**
- Create: `frontend/src/manager/{connectionsTypes,connectionsApi,ConnectionsPage,IntegrationGuides}.ts[x]` and focused tests/style file.
- Modify: `ManagerApp.tsx` and relevant navigation/session tests.
- Create: `docs/manager/wazuh-4.14.4-integration.md` and guide metadata/content resources if needed.

**Interfaces:**
- Consumes Task 1 closed API and current CSRF/session authority. `ConnectionsPage` receives `canManage`, CSRF token and authority-error callback; guides are available to existing `view` users, connection data only to `manage_connections`.
- Public guide content is packaged data/UI, no arbitrary HTML/script, commands or remote content execution.

- [ ] Write failing tests for closed contracts, malformed/error responses, CSRF request headers, no persisted secret and unavailable future SIEM capabilities.
- [ ] Implement dedicated API decoder/client consistent with existing error/session handling.
- [ ] Write failing React tests for navigation permissions, three-step input/test/confirm/save, field edit invalidating test, stale async result, cancellation/logout, candidate selection and fixed-code guide link.
- [ ] Implement UI matching existing Manager theme/logo. Connection form includes name/environment/HTTPS/index/username/password/CA upload. CA upload only reads bounded public file locally; no insecure mode. Clear password on close/success; no browser persistent storage. Do not mislabel candidate as ready.
- [ ] Write guide content tests for version/deployment, scoped role, CA-versus-key distinction, expected statuses, official references and unavailable screenshots.
- [ ] Implement separate guide view and contextual account/CA links, retaining vendor/version/step. Wazuh 4.14.4 self-managed guide explains Indexer vs Dashboard; create technical internal user → role scoped to reviewed index → mapped user; `read` plus reviewed scroll/clear context permissions, no admin credentials supplied to AEGIS. Document exact effective permission review and native acceptance still pending; do not claim a successful read proves no write privilege.
- [ ] Guide CA step uses configured HTTP CA path (default `/etc/wazuh-indexer/certs/root-ca.pem` only as deployment example), safe read-only openssl inspection, trusted fingerprint transfer/SAN checks, no private key export. Include expiry/rotation/revoke and troubleshooting. Screenshots must be real sanitized provenance or explicit unavailable placeholder; do not fabricate them.
- [ ] Run targeted UI tests, full typecheck/build:manager and docs checks; commit Task 2 files only.

### Task 3: Safe waiting worker and deployment handoff

**Files:**
- Create: `manager/connections/management/commands/managed_connection_worker.py`, worker helper/tests.
- Create: `deploy/manager/managed-connections-worker.service`, root-policy example and nginx exact upload-location example, and setup/rollback notes.
- Modify: guide handoff docs and CI workflow to include new app tests/native Linux gates where current workflow omits them.

**Interfaces:**
- Consumes `managed_candidate()`; never turns it into an active registered collection worker in this slice.
- Service uses fixed executable/project/environment paths filled by installer/operator, same unprivileged identity, Restart=on-failure, no application sudo/systemctl.

- [ ] Write failing tests for no candidate, candidate selected, restart/signal/--once and registration drift. Expected state is waiting_configuration, never healthy collection lease, no process_one/network query/job/binding changes.
- [ ] Implement bounded registry-mode waiting loop, graceful SIGTERM/SIGINT and safe fixed status codes. Reject any active pointer until later reviewed activation exists; no implicit latest-row selection.
- [ ] Add root policy template with no usable addresses/secrets and scoped nginx body-limit example (96k only test endpoint); explain one-time root-owned policy provisioning and restrictive parent permissions.
- [ ] Add systemd template/setup guide that verifies root policy/installed paths and checks service waiting state; never auto enable or mutate live units from the web.
- [ ] Add CI/native Linux tests for POSIX ownership/symlink gates, TLS/SAN/IP dial behavior and private persistence. Follow existing job style; no network lab dependency. CI concurrency tests use PostgreSQL where required.
- [ ] Run relevant tests/checks. Record backup/migration/dry-run/upgrading/rollback and lab validation checklist. Commit Task 3 files only.

## Final integration and review

- [ ] Fresh per-task review after each commit range: spec and quality verdicts; fix Important/Critical before next task.
- [ ] Run complete Django suite including connections, fixture/backend suite, frontend tests/typecheck/build and migration drift check; summarize skipped native-only checks honestly.
- [ ] Fresh whole-branch review of issue #163 and exact base..HEAD; remediate findings with reviewed fixes.
- [ ] Save reproducible review/build artifact and checksums if all gates pass. No lab switch, push, PR merge or scenario execution inferred by this request; give concrete handoff and remaining native acceptance gates.
