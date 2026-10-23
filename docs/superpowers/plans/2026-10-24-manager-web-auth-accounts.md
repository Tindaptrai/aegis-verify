# Manager Web Authentication and Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first real Manager web application: login/logout, account creation, role/custom permission grants and durable session revocation, using the approved AEGIS visual direction.

**Architecture:** Add an isolated Django `accounts` app for human identity policy, sessions and APIs; retain the existing agent mTLS and job execution/evaluation boundaries. Build a separate React Manager entry/output with the existing frontend toolchain, keeping the CLI dashboard and core wheel unchanged. Product permissions are enforced in server services and technical Admin paths as well as the UI.

**Tech Stack:** Existing Django/PostgreSQL/React/TypeScript/Vite/Vitest and Python test tooling; no new application dependency.

**Spec:** `docs/superpowers/specs/2026-10-23-manager-ui-agents-catalog-design.md`, especially sections 1–4, 8–10. The accepted v3 mockup fixes appearance, not authentication implementation.

## Global Constraints

- Manager runs on Linux; the initial installer target remains Ubuntu Server 24.04 x64.
- Fresh-install account `aegis/aegis` is explicitly requested by the owner; never reset existing users, passwords, DB, keys, certificates, mappings, catalog, journals or evidence.
- Eight product capability keys: `view`, `run_jobs`, `import_scenarios`, `publish_scenarios`, `manage_devices`, `manage_connections`, `export_evidence`, `manage_users`.
- Presets: Admin has all eight; Operator has `view/run_jobs/export_evidence`; Viewer has `view`; action grants require `view`.
- Product account management cannot mutate `is_staff`/`is_superuser` targets or grant Django technical flags. Own password change remains available with current-password confirmation.
- Session expiry is absolute: eight hours from login. Polling and own-password changes do not extend the deadline. Lock/unlock must never revive an old cookie.
- Preserve canonical events, evidence IDs, assurance, original reports, scenario ground truth, agent v1 signed bytes, dispatch/readiness rules and collection behavior.
- No credentials, real certificates, private configuration, raw evidence or synthetic production events enter Git. Test fixtures are clearly synthetic.
- Tests accompany each behavior change. Review and lab validation precede merge; this plan does not authorize a live upgrade or merge.

## Review Focus

1. A user is locked and unlocked without using an old cookie in between: that cookie must still be rejected (Task 3).
2. Two different technical/product administration requests remove the last usable administrator: only one may succeed; no false audit survives rollback (Task 2).
3. Permission changes affect an actor object already cached in memory: service authorization must reload authority instead of trusting Django permission caches (Tasks 1/4).
4. A slow authenticated response arrives after logout or after another user logs in: it must not repopulate the previous workspace (Task 5).
5. A Manager UI build is absent, contains a symlink, or accidentally enters the core dashboard distribution: fail explicitly without serving another app or a private directory (Task 7).

---

## Delivery boundary and issue scope

This is **part 1**, independently usable and testable. Follow-up plans cover agent pairing/presence, versioned ZIP catalog/runners, multi-device dispatch/collection, and the complete installer. They retain the full spec; nothing in this plan claims those subsystems are already implemented.

**Tóm tắt để chủ lab duyệt:** bản đầu dùng đăng nhập thật, tạo/lưu user trong DB,
cấp ba vai trò hoặc từng quyền, khóa/mở khóa và đăng xuất. UI dùng logo/bố cục đã
chốt; backend kiểm quyền trên mỗi thao tác. Sau khi kiểm thử và review, bàn giao
gói cùng hướng dẫn kiểm tra trên Manager hiện có. Các phần agent, ZIP kịch bản,
chạy nhiều máy và bộ cài được triển khai thành các phần tiếp theo của cùng thiết kế.

Before implementation, create a focused GitHub issue from this scope and acceptance criteria, then create `codex/manager-web-auth-accounts` from the current reviewed design branch. Existing open issues #126/#130 do not cover this work. The current baseline descends from first-flow commit `2df59c2`; PR #152 is still a separate draft dependency, not assumed merged. Preserve this stack explicitly in any future PR.

Acceptance: real session login/logout; real account CRUD without hard deletion; all three presets/custom grants enforced at API/service level; technical-account and last-admin invariants; no revival after lock/unlock; a real branded web shell; standalone Manager build; full existing first-flow and dashboard regression gates. Scope excludes new job endpoints, multi-device execution, ZIP upload, agent heartbeat, PKI changes and automatic deployment.

The first Manager navigation exposes working Overview, My Account, Accounts & Permissions and theme settings. Remaining product sections are marked unavailable until their follow-up is shipped. Overview uses database registration/job counts only; it must not label devices Online or show a synthetic detection/progress value.

## File structure and shared contracts

| Files | Responsibility |
| --- | --- |
| `manager/accounts/{apps,models,permissions,errors}.py`, `migrations/0001_initial.py` | Security generation, mutation lock, auth audit, exact capability policy and seed data. |
| `manager/accounts/{services,admin}.py` | Transactional account mutations and guarded Django User/Group Admin. |
| `manager/accounts/{sessions,middleware,signals}.py` | Absolute session deadline and generation checks for human sessions. |
| `manager/accounts/{contracts,views,urls}.py` | Bounded JSON DTOs and same-origin human APIs. |
| `manager/accounts/{shell,overview}.py` | Read-only Manager HTML entry and real registration/count summary. |
| `manager/accounts/management/commands/bootstrap_manager_owner.py` | Explicit, idempotent fresh-install bootstrap; never startup/migration password resets. |
| `manager/accounts/tests/` | Permission, account, session, API, Admin, concurrency and shell tests. |
| `manager/aegis_manager/{base,settings,urls}.py`, `manager/control/jobs.py` | Register the new app/middleware/routes and replace only human job authorization calls. |
| `frontend/manager.html`, `frontend/vite.manager.config.ts`, `frontend/src/manager/` | Independent Manager React entry, API/contracts, components, styles and tests. |
| `scripts/stage_manager_ui.py`, deploy examples, CI and runbook | Stage only public Manager assets; retain core resource allowlist and agent mTLS location. |

Use a new `manager/accounts/__init__.py` and migration/test package markers where needed. Do not move existing control models or rewrite the dashboard.

### Python interfaces

`accounts.errors.AccountError(ValueError)` takes `(code: str, status: int)` with fixed codes only; no request body/password in diagnostics. Permission helpers raise `PermissionError` to preserve existing job-service callers/tests; human views map it to fixed 403. Lifecycle/input failures use AccountError's explicit status.

`accounts.permissions` exports `CAPABILITIES: tuple[str, ...]`, `PRESETS: dict[str, frozenset[str]]`, `effective_product_permissions(actor) -> frozenset[str]`, `external_group_capabilities(user) -> frozenset[str]`, `require_product_permission(actor, codename: str) -> User`, `require_product_admin(actor) -> User`. Load current User/group/direct permission state from the DB each time. External-group capabilities exclude the three managed preset groups, so those presets remain editable. Active technical superusers retain their existing authority; ordinary users need the relevant product capability plus `view`.

`AccountSecurity` has a OneToOne User, `generation` default 1 and `display_name` max 150. `AccountMutationLock` has seeded PK 1. `AuthAudit` uses nullable positive actor/target integer ID snapshots, username snapshots max 150, a fixed action, allowlisted JSON before/after metadata and timestamp; it is append-only. No cascading user deletion changes an audit snapshot. Do not store request bodies, passwords, hashes, cookies or pairing/reader secrets.

`accounts.services` exports `authority_mutation(*, actor)` as the atomic, singleton-lock context; `create_product_user(*, actor, username: str, display_name: str, password: str, capabilities: tuple[str, ...], active: bool) -> User`; `update_product_user(*, actor, user_id: int, display_name: str, capabilities: tuple[str, ...], active: bool) -> User`; `reset_product_password(*, actor, user_id: int, new_password: str) -> None`; `change_own_password(*, request, current_password: str, new_password: str) -> None`.

`accounts.sessions` exports `stamp_login(request, user) -> None`, `validate_human_session(request) -> bool`, `refresh_own_password_session(request, user, *, original_deadline: int) -> None`. Session keys are `aegis_generation` and `aegis_deadline` (integer UTC epoch seconds). Never accept these values from API input.

### HTTP contracts

All human JSON responses are `Cache-Control: no-store`; GET does not mutate account permissions or claim work. Request JSON is capped at 16 KiB, rejects duplicate/unknown keys and wrong types; CSRF applies to every human POST/PUT. `400` malformed, `401` unauthenticated/invalid login, `403` insufficient authority/technical target, `409` duplicate username or account-policy conflict. Return `{error: {code: string}}`, without echoing source values. No API delete method.

| Route | Contract |
| --- | --- |
| `GET /api/v1/auth/session` | Anonymous-safe `{authenticated, csrf_token, user, expires_at}`; `user/expires_at` null when signed out. Calls Django `get_token()`; fresh token returned after login. |
| `POST /api/v1/auth/login` | `{username,password}`; generic 401 for unknown/locked/wrong password; success returns session DTO. No arbitrary redirect input. |
| `POST /api/v1/auth/logout` | Empty object; flush current session, 204. |
| `POST /api/v1/auth/password` | `{current_password,new_password}`; active user; 204, preserve current session only. |
| `GET /api/v1/users` | `view+manage_users`; query `page` integer >=1 (default 1), optional `q` string <=100; page size fixed 50, stable order username/PK. Response `{results:UserDTO[],count,page,page_size:50}`. Invalid query is 400; no unbounded query. |
| `POST /api/v1/users` | `{username,display_name,password,capabilities,is_active}`; manage-users authority; 201 with UserDTO. |
| `PUT /api/v1/users/<int:user_id>` | `{display_name,capabilities,is_active}`; username immutable; 200 UserDTO. |
| `POST /api/v1/users/<int:user_id>/reset-password` | `{new_password}`; 204; reject technical targets. |
| `GET /api/v1/users/permissions` | `view+manage_users`; fixed friendly labels, preset sets and inheritance explanation. |
| `GET /api/v1/overview` | `view`; `{registered_devices,recorded_jobs,recorded_releases}` real DB counts, no presence/detection inference. |

`UserDTO`: `id:number`, `username:string`, `display_name:string`, `is_active:boolean`, `role:admin|operator|viewer|custom|technical`, `capabilities:Capability[]`, `inherited_capabilities:Capability[]`, `editable:boolean`. Session DTO also applies to an active legacy user with no product `view`, so that user can log out/change their own password and see access-denied instead of a login loop.

## Execution preparation (after plan review)

- [ ] Create the focused issue and branch above; reuse the attached isolated worktree. Record the exact base SHA and confirm no unrelated changes.
- [ ] Use a private virtual environment with core editable install plus existing `manager/requirements.txt`; use existing Node/npm lockfile. Verify baseline control, backend and frontend tests before feature edits. No live credentials or lab dependency in fixtures.
- [ ] Preserve the complete v3 mockup as a visual reference only. Do not import its demo accounts, role switcher, fake progress, ZIP sample or JavaScript auth into production.

### Task 1: Permission, audit and bootstrap foundations

**Files:** Create `manager/accounts/{__init__,apps,models,permissions,errors,signals}.py`, migrations package/`0001_initial.py`, `management/commands/bootstrap_manager_owner.py`, tests `helpers.py`, `test_permissions.py`, `test_bootstrap.py`; modify `manager/aegis_manager/base.py`.

**Interfaces:** Produces the models, permission functions and AccountError above. Custom Django permissions use `accounts.<capability>` on AccountSecurity with `default_permissions=()`. Managed Groups are `AEGIS Administrators`, `AEGIS Operators`, `AEGIS Viewers`.

`tests.helpers.AccountsCase(TestCase)` supplies real fixture users `owner` (technical superuser), `admin` (all eight), `operator` (three) and `viewer` (view), using the literal test-only password `synthetic-test-password`. Fixture grants may use the ORM; production mutations must use policy services. Later tasks extend helpers only when their endpoint exists.

- [ ] **Write failing tests** asserting exact eight permissions/preset membership; anonymous/inactive/removed actors denied; technical active superuser allowed; a previously loaded User observes a new DB grant/revoke; `AuthAudit` update/delete rejected; seed migration does not alter existing hashes, flags or memberships. A pre-existing reserved role-group name on first install must abort seed atomically instead of granting new rights to its existing members.

```python
def test_viewer_cannot_run(self):
    self.assertEqual(effective_product_permissions(self.viewer), frozenset({'view'}))
    with self.assertRaises(PermissionError):
        require_product_permission(self.viewer, 'run_jobs')
```
- [ ] **Run:** `python manager/manage.py test accounts.tests.test_permissions accounts.tests.test_bootstrap --settings=aegis_manager.test_settings --verbosity 2`. Expect missing app/interfaces before implementation.
- [ ] **Implement** models and policy. Data migration explicitly creates content type/custom permissions before assigning new groups (not relying on post_migrate), lock row 1 and security rows for existing users. A User post_save receiver registered by Apps.ready creates AccountSecurity for newly created users; GET serializers never create account state. A reserved-name collision fails before changing existing groups. Fresh actors are fetched by PK; clear/refetch permission caches rather than trust the caller object.
- [ ] **Implement** `bootstrap_manager_owner --new-install`: require explicit flag and migrated preset groups; inside the account lock create only when **no auth users exist**, hash the user-requested published default, grant product Admin without staff/superuser flags. Existing-user case is a no-op with a fixed status; repeated bootstrap is idempotent and never rewrites groups. Never invoke automatically at routine startup/migration.
- [ ] **Verify** the two test modules pass plus `python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings` reports no changes.
- [ ] **Commit:** `feat(manager): add product authority and safe owner bootstrap`.

### Task 2: Account mutations and technical Admin invariants

**Files:** Create `manager/accounts/{services,admin}.py`; tests `test_services.py`, `test_admin.py`, `test_postgres_concurrency.py`.

**Interfaces:** Consumes Task 1 policy/models; produces create/update/reset and `authority_mutation` above. Own-password session handling is implemented in Task 3. `authority_mutation` serializes the complete mutation plus final validation, revocation and audit in one DB transaction. Session generation increments are persisted here; request stamping comes in Task 3.

- [ ] **Write failing service tests** for create/update, immutable username, duplicate/unknown grants, `view` prerequisite, three presets/custom effective union, external inherited grants retained, self-lock 409, technical target 403 and no hard deletion. Test that permissions take effect with an already loaded actor and that no password/hash reaches audit/DTO/error.

```python
def test_product_admin_cannot_reset_technical_password(self):
    before = self.owner.password
    with self.assertRaises(AccountError) as error:
        reset_product_password(actor=self.admin, user_id=self.owner.pk,
                               new_password='synthetic-new-password')
    self.assertEqual(error.exception.status, 403)
    self.owner.refresh_from_db()
    self.assertEqual(self.owner.password, before)
```
- [ ] **Write failing Admin tests** for User/Group changeform including M2M changes, `UserAdmin.user_change_password`, last Admin password disabled, inherited Group removal, technical target reset allowed only through technical Admin, and denied single/bulk user deletion. Group deletion is disabled in this first slice; group edits remain guarded.
- [ ] **Run:** `python manager/manage.py test accounts.tests.test_services accounts.tests.test_admin --settings=aegis_manager.test_settings --verbosity 2`. Expect failures for missing service/guard behavior.
- [ ] **Implement** services with Django hashing and MinimumLengthValidator(8) for new/reset/changed product passwords (max 1024); the explicit fresh-install default is the requested bootstrap exception. Existing passwords are neither revalidated nor rewritten during login/upgrade. Reject privilege fields and technical target mutations at the boundary. Store display name in AccountSecurity; preserve usernames using Django's existing username normalization/validation. Determine role from exact effective set.
- [ ] **Implement** capability-set changes: requested capabilities describe the desired effective product set and must include immutable external-group grants. Remove only managed preset memberships/product direct grants; assign a matching preset Group when the set matches, otherwise persist only desired capabilities minus external-group grants as direct permissions. Keep all unrelated groups/permissions. DTO inherited_capabilities includes only external-group grants, so Operator preset rights can be customized without being falsely locked or copied into permanent direct grants.
- [ ] **Implement** last-usable-Admin policy after actual changes: active, usable password, and technical superuser or all eight capabilities. Lock increments generation; unlock never decrements. Rejected changes roll back authority, generation and audit.
- [ ] **Implement** guarded UserAdmin/GroupAdmin subclasses covering outer POST changeform and M2M, plus the separate password-change route. Disable user/group delete views and bulk deletion before default deletion logging. Keep existing technical account editing available; catch fixed policy errors outside atomic and discard rolled-back success messages.
- [ ] **Write/run PostgreSQL concurrency tests** using separate connections and barrier-controlled transactions: simultaneous self-demotions of two full Admins, product/Admin mixed lock/demotion, and Admin password-disable/group change. Assert exactly one mutation commits, one usable Admin remains, and rejected state/audit is absent. SQLite skips are explicit and do not satisfy this gate.
- [ ] **Verify** service/Admin modules pass; retain PostgreSQL verification for Task 7 CI.
- [ ] **Commit:** `feat(manager): enforce account mutation and administrator invariants`.

### Task 3: Real human session authentication and revocation

**Files:** Create `manager/accounts/{sessions,middleware,contracts,views,urls}.py`; tests `test_sessions.py`, `test_auth_api.py`; extend `signals.py`/`apps.py`, `manager/aegis_manager/{base,urls}.py`.

**Interfaces:** Consumes Tasks 1–2; produces session interfaces/auth HTTP contracts above and `accounts.contracts.parse_json(request) -> dict`, `user_dto(user, actor) -> dict`, `session_dto(request) -> dict`. `accounts.views.csrf_failure(request, reason: str = '') -> HttpResponse` returns fixed human API errors and delegates normal Admin HTML errors. Install middleware immediately after Django AuthenticationMiddleware; apply human markers to `/api/v1/` and `/admin/`, not `/agent/v1/` certificate operations.

- [ ] **Write failing tests with `Client(enforce_csrf_checks=True)`**: anonymous session bootstrap, missing/invalid CSRF rejected, generic unknown/locked/wrong password failures, successful session-key rotation, POST-only logout, unauthenticated read 401 and no-store headers. The custom CSRF failure view returns fixed JSON for human APIs and preserves normal Admin HTML errors.
- [ ] **Write regression tests** named `test_old_cookie_rejected_after_lock_then_unlock_without_intermediate_request`, `test_polling_does_not_extend_eight_hour_deadline`, `test_admin_login_has_security_markers`, `test_legacy_cookie_without_markers_requires_relogin`, `test_own_password_retains_current_session_original_deadline_only`. Also assert another session is rejected after reset/password change and a role change is reflected at the next request.

```python
def test_polling_does_not_extend_eight_hour_deadline(self):
    client = self.login_human(self.viewer)  # helper uses real CSRF + login API
    deadline = client.session['aegis_deadline']
    client.get('/api/v1/auth/session')
    self.assertEqual(client.session['aegis_deadline'], deadline)
    self.assertEqual(deadline - self.login_epoch, 8 * 60 * 60)
```

Extend `AccountsCase.login_human(user) -> Client` here; freeze the server login clock in tests as `self.login_epoch` and use `Client(enforce_csrf_checks=True)`.
- [ ] **Run:** `python manager/manage.py test accounts.tests.test_sessions accounts.tests.test_auth_api --settings=aegis_manager.test_settings --verbosity 2`. Expect missing endpoints/middleware behavior.
- [ ] **Implement** login through Django authenticate/login and user_logged_in signals for both UI/Admin; stamp server generation and deadline=login UTC+8h, set cookie expiry and enforce deadline on the server. Reject missing/mismatched/expired markers by flushing the session. Existing users keep passwords/authority but old unstamped cookies require one new login.
- [ ] **Implement** current-session logout and own-password change. Keep the original deadline after update_session_auth_hash and restamp only the new generation; never call login again to extend it. Reject external redirect input rather than forwarding it. Keep CSRF/certificate exemptions unchanged for agent v1.
- [ ] **Verify** auth/session tests plus `control.tests.test_api` pass; agent CSRF/cert protocol tests must behave as before.
- [ ] **Commit:** `feat(manager): add real login logout and revocable sessions`.

### Task 4: Account APIs and business authorization

**Files:** Create `manager/accounts/overview.py`; extend `contracts.py`/`views.py`/`urls.py`; tests `test_account_api.py`, `test_overview.py`; modify `manager/control/jobs.py`, relevant `control/tests/test_jobs.py`/`test_api.py`.

**Interfaces:** Implements the account/overview routes above, consuming Task 2 services and Task 3 contracts exclusively. Reuse shared `parse_json/user_dto/session_dto`; do not introduce alternate serializers or privilege semantics. Use closed request fields and fixed error codes.

- [ ] **Write failing API tests** for the full role/action matrix; forged username/privilege/generation fields; duplicate JSON keys; wrong types/unknown capabilities; technical targets; safe DTO/no secret leakage; bounded pagination; read no-op. Include locked/password-reset session effects via real client requests, not force_login only.
- [ ] **Write direct service tests** that Operator may approve/cancel an otherwise valid bounded job but cannot reconcile; Viewer cannot approve; revoked actor with cached permissions is denied. Existing signature/pin/state/single-flight assertions remain unchanged.

```python
def test_viewer_users_endpoint_is_forbidden(self):
    self.client.force_login(self.viewer)  # real login signal stamps this session
    self.assertEqual(self.client.get('/api/v1/users').status_code, 403)
```

Add the job integration case to existing `control.tests.test_api.ProtocolTests`: create an Operator in the seeded group, use existing `self.job()` to approve once and assert queued; reconcile that job with existing `self.owner`, remove the Operator grants, then approve another `self.job()` using the same cached User object and assert PermissionError and unchanged draft state. Before this task, the first Operator approval fails under the old owner-only check.
- [ ] **Run:** `python manager/manage.py test accounts.tests.test_account_api accounts.tests.test_overview control.tests.test_jobs control.tests.test_api --settings=aegis_manager.test_settings --verbosity 2`.
- [ ] **Implement** account serializers/views. Use Task 2 services for every mutation, map AccountError to the agreed statuses and paginate by validated positive page and max 50 rows. An authenticated user lacking `view` still gets their own session/password/logout paths but no workspace data. Overview counts registered DB rows only.
- [ ] **Replace only** `owner(actor)` call sites: approve/cancel require `run_jobs`; reconcile requires full product Admin or active technical owner. Leave OwnerAdmin technical-only and do not change signing bytes, readiness/pins, global dispatch lock, state transitions or mTLS identity.
- [ ] **Verify** account/overview tests and complete `control.tests` pass. Audit that no new jobs can be created by a GET or account mutation.
- [ ] **Commit:** `feat(manager): expose account APIs and enforce action permissions`.

### Task 5: Separate real Manager frontend and authenticated shell

**Files:** Create `frontend/manager.html`, `vite.manager.config.ts`, `src/manager/{main,ManagerApp,LoginPage,AccountMenu,MyAccount}.tsx`, `api.ts`, `contracts.ts`, `styles.css`, `api.test.ts`, `ManagerApp.test.tsx`; modify `frontend/package.json`, `tsconfig.json`, root `.gitignore` for `frontend/dist-manager/`.

**Interfaces:** `Capability` is the eight-key union; `UserDTO`/`SessionDTO` match Task 3/4 contracts. `createManagerApi(fetcher?: typeof fetch)` exposes `session/login/logout/changePassword/listUsers/createUser/updateUser/resetPassword/permissions/overview`; argument/result types follow the exact HTTP table. `ManagerApi = ReturnType<typeof createManagerApi>`; `ManagerApp({api}: {api: ManagerApi})` is the injectable root. Methods use only `/api/v1/`, same-origin cookies and the current in-memory CSRF token. No Operations token/client reuse.

- [ ] **Write failing UI/API tests** for login success/generic error, CSRF refresh after login, account menu/logout, expiry/401, denied 403 without a login loop, and `test_late_response_after_logout_cannot_restore_previous_workspace`. Add `pageshow` restoration with an expired cookie: protected data remains masked until server session revalidation. Assert no demo role switcher, synthetic devices/progress, embedded default password or browser auth persistence exists in product UI.

```tsx
it('clears workspace on logout', async () => {
  const api = signedInApiFixture('admin'); // local synthetic test responses
  render(<ManagerApp api={api} />);
  fireEvent.click(await screen.findByRole('button', { name: /Menu tài khoản/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Đăng xuất' }));
  expect(await screen.findByRole('heading', { name: 'Đăng nhập Manager' })).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Tạo tài khoản' })).not.toBeInTheDocument();
});
```

Keep synthetic API fixtures in `frontend/src/manager/test-fixtures.ts` imported only by tests; no runtime fallback to them. Its `signedInApiFixture(role: 'admin'|'operator'|'viewer', options?: {technicalTarget?: boolean}) -> ManagerApi` supports the examples and deferred-response tests.
- [ ] **Run:** `npm test -- src/manager/api.test.ts src/manager/ManagerApp.test.tsx` from `frontend`; expect missing modules/components.
- [ ] **Implement** the separate entry/output `dist-manager`, base `/static/manager/`, `build:manager` script and typechecking for the new config. Keep existing Vite `build`, dashboard `/api` proxy, `dist` output and core resource staging unchanged. Manager development must use its own explicitly configured proxy to Django, never silently target dashboard port 8765.
- [ ] **Implement** the v3 visual language; import the existing `packaging/windows/demo-launcher/assets/aegis-demo-logo.png` unchanged into the Manager bundle. Start signed out, bootstrap session from server; capabilities control navigation/actions. Use a request-generation counter plus AbortController so logout/user changes discard late responses and clear protected state. Revalidate restored pages before revealing protected state. No account demo switcher/sample data. Theme can be local UI state; password/auth state cannot persist.
- [ ] **Implement** working Overview/My Account/theme screens; show remaining future sections unavailable. Use real count DTOs, no invented Online status. `/manager/` is the sole SPA shell; local navigation does not require unprotected data-bearing HTML routes. Account menu stays visible below the old 760px breakpoint.
- [ ] **Verify** focused tests, `npm run typecheck`, `npm run build:manager` and the existing frontend suite pass.
- [ ] **Commit:** `feat(manager-ui): add branded session-backed Manager shell`.

### Task 6: Real account and permission management UI

**Files:** Create `frontend/src/manager/{UsersPage,UserEditor,PermissionEditor}.tsx` and `UsersPage.test.tsx`; extend `api.ts`/`ManagerApp.tsx`/styles.

**Interfaces:** Consumes Task 5 API and Task 4 DTO/choices. `UsersPage({api,onAuthorityChanged}: {api: ManagerApi,onAuthorityChanged?: () => Promise<void>})` notifies the root to reload session authority after writes; the callback is optional for isolated component tests. UserEditor submits exact closed create/update bodies; role presets select capability sets, modified sets render Custom. Effective inherited rights are visibly locked, not false unchecked deny controls.

- [ ] **Write failing tests** for create with preset; custom grant; immutable username on edit; active/locked state; password reset without ever echoing existing password; technical account read-only; inherited grants; duplicate/self-lock/last-admin errors; and old-user data discarded after logout/account switch. Viewer has no account administration; Operator can use only their permitted actions.

```tsx
it('renders technical users read-only', async () => {
  const api = signedInApiFixture('admin', { technicalTarget: true });
  render(<UsersPage api={api} />);
  const row = await screen.findByRole('row', { name: /synthetic-owner/ });
  expect(within(row).queryByRole('button', { name: 'Chỉnh sửa' })).not.toBeInTheDocument();
  expect(within(row).queryByRole('button', { name: /Đặt lại mật khẩu/ })).not.toBeInTheDocument();
});
```
- [ ] **Run:** `npm test -- src/manager/UsersPage.test.tsx`; expect missing account UI.
- [ ] **Implement** real API-backed paginated/searchable list, create/edit drawer, friendly permission descriptions, three presets/custom state, lock/unlock, reset-password and fixed error presentation. New-user password is cleared on success/cancel; password reset is a separate action. No username or technical flag editing. Own-password form uses the dedicated endpoint.
- [ ] **Implement** server-refreshed current permissions following an account update; if a user loses `manage_users`, leave the account screen and drop cached list data. A server 403 always wins over previously visible controls. No mutation request can be triggered by rendering or a read-only navigation.
- [ ] **Verify** new tests, all Manager UI tests, `npm run typecheck` and `npm run build:manager` pass. Integrated browser checks follow in Task 7 after the shell and public assets exist.
- [ ] **Commit:** `feat(manager-ui): add real account and permission administration`.

### Task 7: Serving, CI, reviewable package and acceptance

**Files:** Create `manager/accounts/shell.py`, tests `test_shell.py`, `scripts/stage_manager_ui.py`, `backend/tests/test_manager_ui_staging.py`, `docs/manager/WEB_AUTH_RUNBOOK.md`; update `manager/aegis_manager/{settings,urls}.py`, `deploy/manager/{manager.env.example,nginx.conf.example}`, `.github/workflows/manager-first-flow.yml`, `manager/README.md`.

**Interfaces:** Setting `MANAGER_UI_ROOT` comes from optional `AEGIS_MANAGER_UI_ROOT`, a trusted read-only public build directory. `GET /manager/` reads only `manager.html`; `/` redirects there. Missing build returns fixed 503 `manager_ui_unavailable`, not a private path or a fallback to another app. `/admin/` and `/agent/v1/` retain their routes.

- [ ] **Write failing serving/staging tests** for valid shell refs under `/static/manager/`, missing/invalid build 503, symlink/path traversal rejection, and no private-directory alias. `stage_manager_ui.py --build-root <dist-manager> --static-root <public-static>` copies only validated public assets into `manager/assets`, leaves dashboard/core resources untouched and emits a hash manifest. It never exports private config/evidence or executes build content.

```python
@override_settings(MANAGER_UI_ROOT=None)
def test_missing_manager_build_is_explicit(self):
    response = self.client.get('/manager/')
    self.assertEqual(response.status_code, 503)
    self.assertEqual(response.json()['error']['code'], 'manager_ui_unavailable')
```
- [ ] **Run:** `python manager/manage.py test accounts.tests.test_shell --settings=aegis_manager.test_settings`; `python -m pytest backend/tests/test_manager_ui_staging.py -q`.
- [ ] **Implement** the shell, separate public asset staging, env/example/runbook. Preserve the existing nginx optional-browser/required-agent-mTLS split; do not raise upload limits or expose Indexer/private folders in this slice. Document new-user bootstrap separately from upgrade; upgrade backs up, migrates and retains identities/passwords, with one human relogin for new session markers.
- [ ] **Update CI** paths for `manager/accounts/**`, `frontend/src/manager/**`, Manager config/entry, staging tests and deploy/docs. Add Manager Node build; run `accounts.tests control.tests`, migration drift and actual PostgreSQL auth/control concurrency tests in isolated CI. Do not label SQLite skips as concurrent-policy coverage.
- [ ] **Run complete gates:** `python manager/manage.py test accounts.tests control.tests --settings=aegis_manager.test_settings --verbosity 2`; `python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings`; `python -m pytest -q -rs -p no:cacheprovider`; `npm test`; `npm run build`; `npm run build:manager`. PostgreSQL CI command: `python manager/manage.py test accounts.tests.test_postgres_concurrency control.tests.test_postgres_concurrency --settings=aegis_manager.ci_settings --verbosity 2` with isolated CI settings. Retain existing agent/nginx/cross-language gates in the Manager workflow.
- [ ] **Self-check spec coverage and request fresh whole-branch review.** Resolve findings; create a draft PR against the correct first-flow dependency branch, attach it to this chat and report local/CI results separately. Do not merge or deploy just because tests pass.
- [ ] **Deliver** the reviewed version/hash/runbook and a concrete lab validation checklist: existing-account login unchanged, new product-user creation/grant/revoke, Viewer forbidden direct API, lock→unlock cookie rejection, clean logout, and legacy Windows first-flow compatibility. Include normal-width/634px account-menu and create/custom grant/logout checks against the actual API-backed app, restoring temporary viewport overrides. Owner performs any password entry and reviews lab evidence before merge/upgrade.
- [ ] **Commit:** `build(manager): package and verify authenticated web UI`.

## Plan self-review record

- Full-spec sections outside this first subsystem are explicitly follow-up plans; this deliverable is useful without claiming agent presence, ZIP intake or parallel runs.
- Exact public/service interfaces are shared above; task references use those names consistently. Job helper is `owner`, not `_owner`.
- Every Review Focus item has a named owning test/gate, including stale browser responses and mixed technical/product account changes.
- No production source, dependency installation, account mutation or live deployment was performed while writing this plan.
- Execution method and plan review remain the next handoff; implementation starts after that review.
