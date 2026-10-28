# Agent pairing and boot startup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Windows/Linux one-time pairing, persistent authenticated presence and boot autostart with a usable combined installation guide for issue #155.

**Architecture:** A new Manager devices app extends the existing Device identity and isolates a separate enrollment issuer. A separate dependency-free .NET 10 presence client runs under Windows SCM/Linux systemd, preserving legacy v1 execution. The current Manager UI gains device management using existing session/authority guards.

**Tech Stack:** Existing Django 5.2.18, cryptography 50.0.2, PostgreSQL, React/TypeScript, .NET 10 BCL, nginx, PowerShell 5.1, Bash/systemd.

**Spec:** `docs/superpowers/specs/2026-10-24-agent-pairing-autostart-design.md` (approved parent design plus owner's explicit implementation/autostart amendment).

## Global Constraints

- Implement only issue #155, on focused branch stacked on Part1; no merge/live deployment.
- Read PRD/ARCHITECTURE before source changes; no dependencies without justification.
- No hard-coded IP addresses, passwords, tokens, connector URLs, real certificates or unsanitized evidence.
- Never modify scenario ground truth. Preserve legacy v1 signed bytes, Windows --once, CurrentUser identity, pilot009 and evaluation boundaries.
- New `paired_presence` Windows/Linux identities cannot lease jobs. Online never means execution-ready.
- Read the Spec's **Wire contract** section verbatim: closed schemas, protocol `2.0`, RSA3072–4096/SHA256, code600s, cert30days, heartbeat15s, offline60s, request timeout10s/body16384.
- All behavior changes have meaningful RED/GREEN tests; real PostgreSQL/nginx/native-platform CI claims require actual runs.
- No lab/desktop service installation, private configuration or certificate access during implementation; test only isolated temporary resources/CI runners.
- Fresh implementer and fresh spec/quality reviewer per task; no worker-created helpers/reviewers. Preserve reports and exact commands.

## Review Focus

- Lost enrollment response: never automatically consume another code or overwrite a pending/enrolled key; Task2 pins recovery.
- Reboot before login/network ready: low-privilege service must reconnect with the same identity and cancel promptly; Task3 native tests, Task5 lab checklist.
- Demotion/logout racing with a displayed pairing code: no late UI disclosure or unauthorized redemption; Tasks1 and4.
- Conflicting installer state/service paths and symlink/reparse state: fail without replacing a key or executing an attacker-writable binary; Tasks2/3.
- TLS IP SAN/CA and mixed pilot/new identity trust: exact origin and protocol boundaries survive shipped nginx config; Tasks1/5.

## File map

- `manager/devices/`: contracts, models/migration, issuer, services, identity, views/urls/admin, tests and issuer init command.
- `manager/control/`: Device migration and presence-only denial at identity/approval/claim boundaries.
- `agent/connection/Aegis.Connection/`: strict wire DTOs, local state, trusted HTTPS client, heartbeat loop, CLI and native Windows service host.
- `agent/connection/Aegis.Connection.Tests/`: dependency-free executable behavioral harness and TLS test helpers.
- `deploy/agent/{windows,linux}/`: safe installers/uninstallers and systemd unit.
- `frontend/src/manager/`: device UI/API/types + tests; reuse existing root authority boundary.
- `scripts/`, `.github/workflows/`: deterministic public package builder, real endpoint/client/service integration gates.
- `docs/manager/AGENT_CONNECTION_RUNBOOK.md`: single Vietnamese prerequisite/commands/troubleshooting/lab guide.

---

### Task 1: Manager pairing issuer, API and presence boundaries

**Files:** Create `manager/devices/{models,contracts,issuer,services,identity,views,urls,admin}.py`, app/migrations/init files, `management/commands/init_enrollment_ca.py`, `tests/test_{issuer,pairing,api,presence,postgres_concurrency}.py`; modify `manager/control/{models,identity,jobs}.py`, control migration, `manager/aegis_manager/{base,settings,urls}.py`, `deploy/manager/nginx.conf.example`, `manager/control/tests/test_proxy_mtls.py`.

**Interfaces:**
- Consume existing `require_product_permission`, singleton AccountMutationLock and session/CSRF API machinery. Read spec Wire contract verbatim.
- Produce `Device.connection_kind` choices `legacy_v1`/`paired_presence` (default legacy_v1), nullable `os,architecture,agent_version,enrolled_at,certificate_not_before,certificate_expires_at,last_heartbeat_at`; nullable Wazuh mapping. Keep existing fields.
- `create_pairing_code(*,actor,environment_id)` returns the mint DTO. `revoke_pairing_code(*,actor,code_id)`, `revoke_device(*,actor,device_id)`, `enroll_device(data)` and `receive_heartbeat(*,request,data)` implement exact API contract. Human denial uses existing fixed API errors. Enrollment audit is separate append-only.
- Settings `ENROLLMENT_CA_KEY`, `ENROLLMENT_CA_CERT` are private-root paths (production env `AEGIS_MANAGER_ENROLLMENT_CA_KEY`/`..._CERT` optional defaults under private root). Lazy issuer validation makes missing setup return503, never break existing v1 startup.
- `manage.py init_enrollment_ca` idempotently initializes those configured paths with no secret output. Refuse symlink/partial/insecure state and never replace.
- URLs/DTOs/status/body/error codes exactly as Spec; use explicit CSRF exemption only machine endpoints. Runtime cap16KiB still enforced without trustworthy Content-Length. Pairing audit never records code/CSR/private fields.

- [ ] Write tests asserting code digest-only600s/single-use/expiry, rollback/signature/key/cert extension/UUID/public-key match, strict JSON/body/permissions/CSRF, issuer init idempotency and refusal, response secret absence, status boundary and null metadata. Run focused test to observe missing-feature RED before production code.
- [ ] Implement issuer restricted clientAuth certificate and safe explicit init; no server/pilot/job-signing key reuse. `connection_kind` defaults preserve old rows; schema migration introduces no guessed Wazuh IDs.
- [ ] Implement transactional services with lock order AccountMutationLock → PairingCode → Device. Recheck issuer active manage_devices during redemption. Heartbeat/revoke share Device lock. Add PostgreSQL ordered double-redemption, issuer-demotion and revoke/heartbeat race tests, skip only when DB actually isn't PostgreSQL.
- [ ] Implement exact human/machine endpoints and nginx exact bootstrap stripping/rate-limit vs verified heartbeat forwarding. Keep existing v1 trust/route intact; add actual proxy tests for bootstrap without cert, paired heartbeat, spoofed headers, wrong trust and paired/v1 exclusion.
- [ ] Add v1 denial tests at authenticate_device, approve_job and claim_job, even manually mapped paired device. No changes to strict v1 envelope format.
- [ ] Run focused GREEN, all Manager tests (`accounts.tests control.tests devices.tests`, explicit settings) plus migration drift. Local SQLite/Windows skips are explicit; actual PostgreSQL/nginx gate owned Task5. Commit only scoped files; report RED/GREEN, totals and exact limitations.

### Task 2: Cross-platform presence client and durable identity

**Files:** Create `agent/connection/Aegis.Connection/{Aegis.Connection.csproj,Program,Protocol,StateStore,AgentClient,HeartbeatLoop,SecretPrompt}.cs` (csproj filename separate), focused state/transport files if one responsibility each; `agent/connection/Aegis.Connection.Tests/{Aegis.Connection.Tests.csproj,Program,...}.cs`, `agent/connection/README.md`.

**Interfaces:**
- Consume Spec Wire contract exactly; Task1 endpoint DTOs are binding. Do not import legacy Windows classes.
- Dependency-free `net10.0`, self-contained runtime pin10.0.13 aligned existing project; executable assembly `aegis-agent`.
- CLI `connect --manager <https-origin> --server-ca <absolute-public-pem> --state-dir <absolute-path>`; hidden code prompt only, no argv/env secret option. `run --state-dir`, `status --state-dir`, `retire --state-dir --device-id <uuid>`. Task3 adds `service` via `WindowsServiceHost.Run(stateDir)`.
- `HeartbeatLoop.RunAsync(string stateDirectory,CancellationToken)` usable by console and native service; return0 on cancellation, fixed nonzero terminal identity/config failures. Console handles Ctrl+C and Linux SIGTERM.
- `StateStore` owns pending/enrolled state, key and exclusive process lock; `AgentClient` owns strict bounded HTTPS requests. Status JSON contains UUID/environment/generation/cert expiry/origin/local last acknowledged contact/fixed state code, never PEM/key/code. No Manager Online inference from process status.
- Pending state is durable before network send; one attempt per connect, unknown outcome retained. Existing enrolled identity refused; pending reuse accepts new owner code without regenerating key. Explicit retire validates matching UUID, exclusive lock, protects archive, preserves complete identity and enables a fresh connect only after successful archive.

- [ ] Write meaningful harness tests before code: exact protocol roundtrip, key persistence/reload, enrolled no-overwrite, pending unknown-response reuse, malformed/insecure/symlink state denial, atomic failure preservation and exclusive lock. Run RED.
- [ ] Implement split focused state/wire/client/loop/CLI units using BCL. Key RSA3072 PKCS8 stays local; private paths0600/dir0700 Linux; Windows restrict to current owner/SYSTEM/Administrators/installed service SID as applicable and reject broad grants/reparse paths. No private key stdout/package/logs.
- [ ] Verify local key against returned cert/issuer/UUID SAN/clientAuth/nonCA/validity and binding DTO before atomic promotion; client issuer never replaces separately trusted server CA. Reject unknown/duplicate/oversized/malformed responses. Origin rejects userinfo/path/query/fragment/HTTP/redirect/proxy.
- [ ] Exercise real ephemeral TLS (not only mocked HttpClient) with correct IP SAN, wrong name/CA, redirected endpoint, oversized response, 403 and transient error. Certificate trust cannot disable name/time/chain checks. Tests use synthetic in-memory/temp keys only.
- [ ] Test heartbeat immediate/15s, timeout10s, exponential backoff2s..60s with bounded jitter, cancellation while pending request/wait, recovery from network interruption using same identity and no token. Inject time/wait/RNG narrowly for deterministic loop tests; do not put test-only behavior in production.
- [ ] Test retire match/mismatch/archive failure/active lock and identity preservation. Run full new harness and build locally; legacy Windows harness once to prove isolation. Linux native run owned by Task5 CI. Commit scoped files with full TDD report.

### Task 3: Windows SCM, Linux systemd and safe installers

**Files:** Create `agent/connection/Aegis.Connection/WindowsServiceHost.cs`, corresponding harness tests; modify only its `Program.cs` dispatch as needed; create `deploy/agent/windows/{Install-Agent,Uninstall-Agent}.ps1`, `deploy/agent/linux/{install,uninstall}.sh`, `deploy/agent/linux/aegis-agent.service`; native integration test scripts under `scripts/tests/agent/`.

**Interfaces:**
- Consume Task2 `HeartbeatLoop.RunAsync(string,CancellationToken)` and CLI. `WindowsServiceHost.Run(string stateDirectory)` registers real SCM service lifetime, not a console executable registered with sc.exe alone. Service name AegisAgent, account NT SERVICE\AegisAgent.
- Installer command Windows `Install-Agent.ps1 -Manager <https-origin> -ServerCa <absolute-pem>` from validated self-contained package; Linux `sudo ./install.sh --manager <https-origin> --server-ca <absolute-pem>`. On existing enrolled state reuse without code, optional Manager/CA must equal persisted config or refuse; do not silently repoint.
- Windows binary `%ProgramFiles%\AEGIS Agent`, state `%ProgramData%\AEGIS\Agent`; Linux binary `/opt/aegis-agent`, state `/var/lib/aegis-agent`, systemuser aegis-agent. Only Admin/root installers; no target SDK requirement.
- Package layout expected `bin/` plus platform install/uninstall files/unit and `SHA256SUMS.txt` with relative paths; Task5 builder supplies it. No embedded identity/token/real CA. Read every manifest entry, verify safe paths/hash and required executable before mutations; refuse reparse/symlink ancestors and attacker-writable binary/state/service.
- Uninstall stops/removes service+binary but preserves identity/config by default; no purge action in this slice. Installer validates existing account/path config, is idempotent, stages upgrades/backup and preserves identity on partial failure. Failed enrollment leaves service disabled and pending key intact.

- [ ] Before production code add behavioral native host lifecycle tests and installer contract tests with wrong account/path/manifest/insecure state/failure preservation. Observe focused RED; no installing on host desktop.
- [ ] Implement narrow native SCM start dispatcher/control handler/status transitions; STOP/SHUTDOWN cancels work and finishes within20s, startup failures report real failed state. Keep delegate lifetimes rooted; no unnecessary NuGet dependency.
- [ ] Implement restricted Windows virtual-service account, quoted absolute paths, delayed-auto/recovery; service gets binary read/execute and state modify only. Create fresh disabled service before SID ACL then pair; enable/start only on valid enrolled state. Verify real SCM operations in disposable Windows CI, test stop while network request pending.
- [ ] Implement Linux root-owned binaries, serviceuser connect, protected state, system unit Type=simple/network-online/Restart/on-failure/UMask0077/read-write state only/multi-user enable. Honor stop/cancellation; validate existing unit/account/paths before overwrite.
- [ ] Add native integration scripts asserting install/start/stop/status/reinstall/account/permissions/conflict/uninstall state preservation, no code consumed after restart and log secret absence using synthetic endpoint. Guard exact dedicated CI paths/service name and cleanup only resources created by test.
- [ ] Run harness/build and platform-available syntax/contract checks. Record actual SCM/systemd checks pending CI separately; commit scoped source/scripts/tests with report.

### Task 4: Manager devices and one-time pairing UI

**Files:** Create `frontend/src/manager/DevicesPage.tsx`, component/API tests; modify `frontend/src/manager/{ManagerApp,api,types}.ts[x]`, focused CSS and tests.

**Interfaces:**
- Consume Task1 human APIs/DTOs exactly; extend existing ManagerApi with optional trailing AbortSignal on every method. Read existing root session generation/authority/write queue before editing.
- Enable Máy route for view; controls Thêm máy / revoke only with manage_devices. Never add readiness/job-run affordance for paired_presence.
- Table host/OS/environment/status/last contact/expiry + bounded pagination/search, manual refresh and15s nonoverlapping refresh, abort on page/session/authority change. Legacy unknown clearly distinguished from paired Offline.
- Pair dialog requests environment, shows code once/deadline and configurable-IP command template using placeholder and trusted public CA, states no endpoint web login. Clear code on close/logout/authority loss/expiry; no URL/localStorage/console/automatic clipboard persistence. Explicit revoke pending-code action while dialog active; device revoke confirmed and server enforced. Session expiry/logout/401/403 reuse Part1 semantics.

- [ ] Write RED tests for viewer read-only, manager mint/revoke, real error/expiry flows, strict result handling, secret clearing on deadline/close/logout/demotion and late response after navigation/logout. No assertions only on mock call counts.
- [ ] Implement typed API and guarded root facade, focused DevicesPage components using established visual language/accessibility and text rendering. Keep accounts protections and auth serialization intact.
- [ ] Add tests for no overlapping refresh, aborts, stale success/failure, pagination/search reset, terminal status/legacy unknown and Online-not-ready copy. No silent permission refresh loop.
- [ ] Run full frontend tests, typecheck and both builds. Report RED/GREEN and component/behavior limitations. Commit scoped files.

### Task 5: End-to-end gates, release packages and combined runbook

**Files:** Modify `.github/workflows/manager-first-flow.yml` (or add focused workflow for new connection jobs), `scripts/stage_agent_connection.py`, builder tests under `backend/tests/test_agent_connection_packaging.py`, real TLS/Django client integration helper under `manager/devices/tests/` and `scripts/tests/agent/`, `docs/manager/AGENT_CONNECTION_RUNBOOK.md`; update `agent/connection/README.md`, `docs/manager/FIRST_FLOW_RUNBOOK.md` links only.

**Interfaces:**
- Consume Tasks1–4. Packages named `AEGIS-Agent-Connection-<version>-win-x64.zip` / `...-linux-x64.tar.gz`; self-contained binaries runtime10.0.13 plus reviewed scripts/unit, public guide, version/source metadata, per-file SHA256SUMS and external archive.sha256. No real deployment config/key/certificate/token/evidence.
- Builder takes explicit source/build/output directories/version/commit, rejects symlinks/traversal/private extras and refuses overwrite. Allowlisted public payload only; stable path/hash manifests. Tests exercise malicious inputs/missing binary/unknown file/no leaked temp config.
- CI includes `agent/connection/**`, `deploy/agent/**`, relevant scripts/docs; Manager suites include devices.tests and real PostgreSQL redemption/authority/revoke races. Keep existing v1 windows/signing checks.
- Real fixture TLS integration must use production Django issuer/views and actual published .NET CLI/loop on Windows/Linux with ephemeral synthetic CA/serverIP-SAN/client identity, then reconnect and revoke. No fabricated production events or mocked proof of integration.
- Windows CI executes real service installer/SCM tests; Ubuntu host with systemd PID1 runs unit/start/stop/account/state checks, else fail intended systemd gate instead of pretending static verify is runtime. Reboot-before-login remains explicit owner lab gate, no local host reboot.

- [ ] Add RED builder/integration tests proving missing packages/contracts before implementing; implement deterministic allowlist builder and focused E2E helpers. Test codes supplied through child stdin only, never process args/env/logs or captured unredacted outputs.
- [ ] Extend workflows to exercise real PostgreSQL/nginx, native client TLS and service installers on isolated runners, upload public packages and bounded synthetic verification outputs. No bypass/skipping required gates on unsupported runner; report environmental failures truthfully.
- [ ] Write Vietnamese guide: supported Windows/Ubuntu versions+x64; Manager Linux setup/migration and separate issuer; exact configurable IP-SAN/trust/ALLOWED_HOSTS/nginx inputs; Windows Administrator/PS5.1 and Ubuntu native dependency prerequisites; package hash verification; UI mint600s; hidden prompt; install/connect/start/stop/restart/status/logs/autostart commands; reconnect after boot/network delay; upgrades/uninstall preserving identity; explicit retire/revoke/replace; pending response unknown; no SDK; Online is not scenario-ready; legacy009 coexistence.
- [ ] Add quick command tables using placeholders (no lab IP/password). Include owner lab checklist for actual reboot without login and same UUID, network outage recovery, revoke/expiry and permission boundaries. Never claim those reboot gates executed from start-configuration tests.
- [ ] Run full relevant local Manager/frontend/new+legacyagent/builder checks and required core pytest once with fresh short external basetemp; migration drift/pip check/build. Record all skips/failures. Commit source/docs/CI and report evidence.
- [ ] Controller requests fresh whole-branch review, fixes findings through workers, pushes focused branch and creates draft stacked PR for #155, attaches PR, waits actual CI and fixes concrete failures. Publish reviewable Downloads package with source commit, actual CI report, public agent artifacts/hash/guide; no merge/live install.
