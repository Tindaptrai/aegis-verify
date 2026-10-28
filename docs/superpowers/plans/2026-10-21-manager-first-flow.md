# Manager v1 first flow implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an authenticated, bounded first flow from one Manager to one Windows foreground agent and through the existing Wazuh collector and evidence evaluation engine.

**Architecture:** A separate Django application owns durable jobs, human approval, machine identity, execution receipts and audit. A .NET 10 foreground agent polls outbound over mTLS and executes only the existing, locally pinned SCN-001 runner. A separate worker collects bounded Wazuh data and calls the installed AEGIS engine; execution success never supplies a detection verdict or collection attestation.

**Tech Stack:** Python 3.11+, Django 5.2.18 LTS, cryptography 50.0.2, psycopg 3.3.6, PostgreSQL, Gunicorn 26.2.0 on Linux, nginx TLS proxy, .NET 10 without third party NuGet libraries, installed aegis-verify 0.4.0.

**Spec:** `docs/superpowers/specs/2026-10-21-manager-v1-agent-pilot-design.md`, approved by the owner on 2026-10-21. Scope for this implementation is its reduced first-flow milestone, not full pilot acceptance.

## Global constraints

- One Manager, one specifically approved Windows VM (`Windows Admin Soc` selected by owner), one SCN-001 runner. Other VM roles remain unconfirmed.
- Never modify scenario ground truth, the reviewed runner, historical acceptance, canonical schema or core verdict semantics.
- Keep source parsing in `connectors/`; reuse installed `aegis_verify.connectors.wazuh.live.collect` and `aegis_verify.cli.service.evaluate_bundle`.
- Agent receipts describe execution only. Wazuh evidence retains original bytes, hashes, raw references and evidence IDs. Collection assurance defaults to unknown.
- Manual certificate enrollment and an interactive foreground agent are first-flow limits. Automatic CSR enrollment, service/MSI, multi-PC campaigns, full RBAC/React UI and complete recovery campaign remain later v1 tasks.
- Django admin supplies authenticated, CSRF-protected owner approval and the first run list. Do not expose the old dashboard HTTP server on a LAN.
- PostgreSQL is required for lab deployment. SQLite is explicitly test/development only and must not imply production queue concurrency guarantees.
- No real keys, certificates, credentials, connector URLs or raw lab evidence in git. Private configuration is outside the source checkout.
- Manager dependencies are isolated from the existing core wheel. Django provides mature auth/CSRF/ORM, cryptography interoperable job signing and certificate parsing, psycopg PostgreSQL, Gunicorn Linux WSGI. These justify each new dependency.
- Agent uses default OS TLS chain and hostname verification and a client certificate with private key in Windows CurrentUser/My for this foreground milestone. No TLS bypass, shell supplied by a job, execution-policy bypass or arbitrary download.
- Signed transport contract is `docs/manager/FIRST_FLOW_PROTOCOL.md`; changes to that contract require coordinated tests in Manager and agent.
- First-flow execution is single flight globally, including collection. Ambiguous delivery/launch is never requeued automatically; owner reconciles it and approves a new job.

## Review focus

1. A copied/revoked certificate, wrong agent/generation or spoofed proxy identity must not authorize work.
2. Retry after a lost HTTP response or process crash must not execute a job again; uncertain launches remain unknown.
3. Tampered/oversized/expired jobs, altered local files, paths through reparse points and foreign parameters must fail before process creation.
4. A missing Wazuh alert, delayed data, failed query or empty collection must not be converted to a false negative or Pass.
5. Timeout/stop must terminate the owned process tree while preserving unrelated processes and the evidence store.

## File structure

- `manager/requirements.txt`, `manage.py`, `aegis_manager/{settings,urls,wsgi}.py`: separate deployment/runtime.
- `manager/control/{models,admin,identity,signing,jobs,views,urls}.py`, migrations: durable approval and narrow machine API.
- `manager/control/{worker,collection}.py`, management commands: independent Wazuh collection and evaluation.
- `manager/control/tests/`: real ORM/API, signature, collector/evaluation and integration tests using explicitly synthetic data only.
- `agent/windows/Aegis.Agent/`: focused .NET protocol, configuration, transport, journal, SCN-001 catalog and owned process runner.
- `agent/windows/Aegis.Agent.Tests/`: dependency-free executable test harness; no live safe-demo payload on the host.
- `deploy/manager/`: nginx/systemd templates with placeholders, no real certificates or endpoints.
- `docs/manager/{FIRST_FLOW_PROTOCOL,FIRST_FLOW_RUNBOOK}.md`: exact contract, install/rollback and lab gates.
- `.github/workflows/manager-first-flow.yml`: separate Manager and Windows agent gates without inflating the core wheel.

## Task 1: Manager approval, identity and durable job protocol

**Files:** Manager runtime and `control` files above except collection/worker; tests in `manager/control/tests/test_jobs.py` and `test_api.py`.

**Interfaces:** Produces `Device`, `RunnerRelease`, `Job`, `AuditEntry` models; `approve_job(job_id, actor)` and `claim_job(device)`; protocol endpoints and read-only job result metadata. `Job` owns `execution_state`, `collection_state`, nullable `report`, `error_code`, `payload_sha256`, `receipt`, `collection_start`, `collection_end` and a UUID primary key. `RunnerRelease` pins local Manager scenario/profile files, runner/kit/payload hashes and timeout. No job input supplies filesystem paths.

- [ ] Write failing Django tests: anonymous/admin approval, unsigned draft not dispatched, revoked/wrong certificate denied, expired job denied, duplicate poll not new lease, duplicate exact receipt accepted, conflicting receipt rejected, unexpected fields rejected, single-flight blocks next job until collection/reconciliation.
- [ ] Run `python manager/manage.py test control.tests.test_jobs control.tests.test_api`; confirm assertions fail due to absent implementation.
- [ ] Implement migrations, authenticated admin approval and append-only audit; RSA-PSS/SHA256 signs exact UTF-8 payload bytes. Strict certificate authentication only behind verified local nginx; direct headers from untrusted peers denied. Pin proxy deployment boundary in documentation.
- [ ] Run the tests again and Django `check`; expect all pass. Create a focused commit containing only this task's files and its test report.

## Task 2: Foreground Windows agent

**Files:** `agent/windows/Aegis.Agent/`, `agent/windows/Aegis.Agent.Tests/`, local configuration example with placeholders.

**Interfaces:** Consumes the exact protocol and RSA public key. `--config <private.json> --once` polls at most one job; no job exits 0. It validates the fixed runner catalog, obtains start authorization, persists launch intent, runs the unchanged SCN-001 runner and submits the terminal receipt. A separate test executable exercises real validation/journal/process behavior.

- [ ] Write failing tests for valid/tampered signature, target/generation/hash mismatch, expiry/schema/parameter violations, journal duplicate/crash recovery, HTTPS restrictions and owned child-tree cleanup using inert test children.
- [ ] Run `dotnet run --project agent/windows/Aegis.Agent.Tests`; observe the intended missing-behavior failures.
- [ ] Implement strict schema, mTLS HttpClient without redirects/proxy, durable exclusive journal, locally pinned catalog and suspended creation into a kill-on-close Windows Job Object. Persist terminal receipt before sending it; replay receipt only, never the runner. Bound output and local deadline. Ctrl+C closes the owned Job Object.
- [ ] Run agent tests, `dotnet build` and existing safe-runner preflight tests. No actual SCN-001 execution on the user's host. Commit only agent files.

## Task 3: Wazuh collection and canonical evaluation worker

**Files:** `manager/control/{worker,collection}.py`, `management/commands/manager_worker.py`, collection/integration tests.

**Interfaces:** Consumes completed execution plus signed approval, the local release's immutable scenario/profile files, and separately protected Wazuh config. `process_one()` claims one eligible collection; `collect_and_evaluate(job, config, output_root)` returns the unchanged core report or an explicit empty/error result. Collection start/end are approved bounds, not guessed source event times; receipt start/end must lie within them.

- [ ] Write failing tests using the existing Wazuh Transport fixture pattern and real `evaluate_bundle`: a matching synthetic response produces an EID-linked report; absent alert remains Inconclusive; no input remains empty; source failure/tampering remains collection error; never reuse historical evidence for a new job; interrupted worker does not silently dispatch another job.
- [ ] Run `python manager/manage.py test control.tests.test_collection`; observe intended failures.
- [ ] Implement bounded collection using `collect()` only, fixed private config values, new per-job output, pinned profile/scenario and generated unknown-assurance context. Reject context declarations, preserve raw bytes and scope semantics. Add orchestration metadata explicitly saying execution is caller-reported and run binding is unknown; do not assert full SCN-001 study acceptance.
- [ ] Run all Manager tests and full core pytest suite; expect pass. Commit this task separately.

## Task 4: Deployment, integrated check and pilot handoff

**Files:** deployment templates, first-flow runbook, CI workflow, optional build script and focused docs index link.

**Interfaces:** Consumes tested Manager/agent artifacts. Deploy using PostgreSQL/Gunicorn on loopback behind nginx HTTPS; `/agent/v1/` requires mTLS and nginx overwrites/clears identity headers. Private CA/job-signing keys remain separate and outside source. Owner creates local certificates and installs trust only in selected lab VMs.

- [ ] Add a real cross-language test: Python signs a generated temporary job, the built .NET validator accepts it and rejects tampering. Add a local HTTPS/mTLS transport check where feasible, using temporary synthetic certificates only.
- [ ] Document VM inventory/preflight, owner approval, catalog hashes, agent start, job approval, worker start, EID verification and retained artifacts; include backup/stop/rollback and explicit pending live gates.
- [ ] Add isolated CI jobs for Django/SQLite tests and Windows .NET harness, plus PostgreSQL where available; keep existing core distribution unchanged.
- [ ] Run Manager, agent, core and deployment checks; request fresh code/security review and address important findings with regression tests.
- [ ] Build a reviewable local pilot kit with hash inventory. If the selected VM, Manager Linux role, Wazuh configuration or approved private SCN-001 kit is unavailable, report the exact pending lab gate and provide a runnable runbook; do not label fixture success as live VM acceptance.
- [ ] Commit reviewed code. Open a draft PR if appropriate for human/lab review; do not merge without reviewed lab evidence and owner authorization.

## Plan self-review and milestone boundaries

Tasks 1/2 share only the protocol; implementation can proceed in parallel after that contract is saved. Task 3 consumes Task 1's models and never changes agent protocol without coordination. Task 4 verifies all three and is not full v1 service/pilot acceptance. All five review-focus items have tests assigned above. No ground truth, historical lab verdict or private data changes are needed.

Owner already asked to plan **and implement** this first flow in the same instruction; implementation proceeds without another redundant approval prompt. The complete v1 design remains the roadmap; this plan does not promise the 22–33-run/full-fault campaign in this first slice.
