# Catalog ZIP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Owners upload, review and publish immutable scenario ZIP versions in Manager.

**Architecture:** A bounded no-extraction package validator feeds a new Django catalog
app with private storage and audited lifecycle APIs. React uses existing session,
CSRF, permissions and visual design. Catalog never invokes the execution pipeline.

**Tech Stack:** Existing Python/Django/Pydantic/PyYAML, PostgreSQL, React/TypeScript;
standard-library ZIP/hash/storage only, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-25-catalog-zip-design.md`

## Global Constraints

- Preserve existing SCN-001 ground truth, PKI, devices, auth and legacy jobs.
- No script execution, new connector or agent runtime in this issue.
- 20 MiB ZIP, 100 MiB expanded, 200 files, ratio 100, text 1 MiB, YAML 256 KiB.
- Only `aegis-scenario-package/1` + `windows-powershell-script@1` contract from spec.
- Session/CSRF and fresh view/import_scenarios/publish_scenarios permissions.
- Immutable ID/version/digest; publication never changes YAML draft status.
- Private packages; no submitted text in logs/errors; inert preview.
- Tests for behavior changes, human review/lab validation before merge.

## Review Focus

1. A hostile ZIP path/header must not allocate beyond budgets or write arbitrary paths.
2. Upload parsing must obey actual stream limits before Django multipart spooling.
3. Same-version concurrent imports/publish must not clobber another package or audit.
4. Permission/session changes during in-flight reads/writes must not leak old UI data.
5. Private bytes modified after import must prevent content preview/publication.

---

### Task 1: Bounded package contract, validator and authoring sample

**Files:** Create `manager/catalog/{__init__,package,errors}.py`,
`manager/catalog/tests/{__init__,test_package,helpers}.py`,
`scripts/create_catalog_sample.py`, `docs/manager/CATALOG_PACKAGE.md`.

**Interfaces:** Produces `validate_package(stream: BinaryIO) -> ValidatedPackage`;
result attributes `sha256,metadata,files,contents` (metadata JSON-compatible closed
package metadata plus scenario name; files list path/size/sha256; contents map of
relative paths to bytes). `CatalogError(code,status=400,codes=None)` is bounded.
`read_package_file(path: Path, expected_sha256: str, member: str)` may be provided
by task 2 using task 1 validation. No DB/auth in validator.

- [ ] Write test ZIP helpers and red tests: valid separate SCN-900 package accepted;
  identity/version/profile mismatch, duplicate JSON keys, unlisted/missing/hash,
  traversal/drive/backslash/casefold/duplicates/link/encryption/nested archive,
  actual/member/expanded/count/ratio budgets rejected with fixed error codes.
- [ ] Run new tests and record expected missing-feature failures.
- [ ] Implement no-extraction bounded validator reusing existing YAML/profile loaders.
  Avoid detailed parser exceptions. Validate all text and manifest relationships.
- [ ] Add deterministic sample generator with harmless output-only `.ps1`, distinct
  SCN-900 manifest/profile and SHA sidecar; document complete format.
- [ ] Run package tests, record evidence and commit only task-owned files.

### Task 2: Private catalog lifecycle, human APIs and upload boundary

**Files:** Create `manager/catalog/{models,storage,services,contracts,views,urls}.py`,
`manager/catalog/migrations/0001_initial.py`, catalog lifecycle/API/concurrency
tests. Modify `manager/aegis_manager/{base,urls}.py`,
`.github/workflows/manager-first-flow.yml`. Create upload handler/middleware if needed.

**Interfaces:** Consumes task 1 validator/result/errors; produces all API paths,
DTOs and statuses exactly as spec. Internal services
`import_package(*,actor,stream)`, `publish_package(*,actor,package_id,sha256)`,
`unpublish_package(*,actor,package_id,sha256)` use fresh permission checks.

- [ ] Write red tests: private valid import201/exact replay200/conflict409;
  view/import/publish/locked user/session/CSRF boundaries; list/detail/file;
  exact digest publish/unpublish retries and immutable history; tampered storage;
  route-scoped actual upload budget; fault rollback and same-version races.
- [ ] Run missing-feature tests; implement models/migration/private storage/services.
  Unique ID/version plus transaction locks, verified bytes before reads/publish,
  append-only audit. No hard delete/edit/download/execute API.
- [ ] Implement authenticated API and route-scoped pre-parser upload handler.
  Preserve general API64KiB limit. Bind DTOs/error codes to spec and coordinate UI.
- [ ] Add catalog tests to Manager CI, including PostgreSQL import/lifecycle races.
- [ ] Run catalog suite, migration drift and existing Manager suites; commit.

### Task 3: Manager Catalog UI and browser contracts

**Files:** Create `frontend/src/manager/{catalogTypes,CatalogPage}.tsx` (types may .ts),
catalog tests/CSS. Modify `api.ts`, `ManagerApp.tsx`, existing API/shell tests
as needed. No backend files owned by this task.

**Interfaces:** Consumes exact spec DTOs/routes. API methods:
`listCatalog(query?,signal?)`, `importCatalog(file:File,signal?)`,
`catalogPackage(id,signal?)`, `catalogFile(id,path,signal?)`,
`publishCatalog(id,sha256,signal?)`, `unpublishCatalog(id,sha256,signal?)`.
FormData upload must leave Content-Type boundary to browser and send CSRF.

- [ ] Write red tests for real navigation/list/filters/pagination, import permission,
  validation error, preview escaped text, exact hash confirmation and unpublish.
- [ ] Run tests to record feature failures. Implement small responsive components
  using existing Manager design; no fabricated catalog rows or Run action.
- [ ] Add strict runtime DTO guards and bounded mapped error handling. Guard shell
  methods by session generation, 401 logout/403 refresh; abort/ignore stale reads
  and duplicate writes on context change. Test these and denied direct API paths.
- [ ] Run frontend tests, typecheck, both builds; commit.

### Task 4: Integration, deployment guidance and review artifact

**Files:** Create `docs/manager/CATALOG_RUNBOOK.md`, path-scoped nginx upload
example and meaningful config regression tests in existing deployment tests.
Update `manager/README.md` and release notes; no live host configuration changes.

**Interfaces:** Consumes tasks1–3; produces documented backup/migrate/build/static/
nginx verification with existing CA/CRL/listener preservation and rollback limits.

- [ ] Test nginx upload location preserves trusted header/session routing and keeps
  agent/auth limits unchanged; document app20MiB vs request21m allowance.
- [ ] Generate sample ZIP and verify against live validator; stage public UI through
  existing staging tool. Record actual commands/results, no secrets/lab evidence.
- [ ] Run relevant full Manager/frontend/canonical regression suites and migration
  checks once after integration. Use actual PostgreSQL/nginx CI for native gates.
- [ ] Request independent broad review; fix one scoped wave and reverify changes.
- [ ] Produce source/UI/sample/checksum review package + draft PR; attach PR, do not
  merge or live-upgrade automatically. Tell owner exact lab validation remaining.
