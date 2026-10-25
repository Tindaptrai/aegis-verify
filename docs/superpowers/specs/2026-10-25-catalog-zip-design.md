# Catalog ZIP — implementation design

## Intent and authorization

Owners need to add a versioned scenario from the Manager web UI without editing
server files. The owner selected Catalog ZIP before execution/batch work and
explicitly asked to implement the roadmap on 2026-10-25. This slice refines the
approved `2026-10-23-manager-ui-agents-catalog-design.md`; the owner requested
execution now rather than another design-question cycle.

## Goals, non-goals and alternatives

Deliver upload → bounded validation → private immutable draft → content review →
publish/unpublish, with real permissions and audit. Compare exact version hashes;
preserve all existing pilot data, profiles, accounts, PKI and legacy releases.

Catalog-first was selected over adding a fixed SCN-001 Run button first: it gives
subsequent execution a stable package identity. A script editor was rejected in
favor of ZIP packages. This release does not execute uploads, dispatch jobs,
install Wazuh rules, add connectors or a Linux runner, certify script safety,
modify scenario ground truth, or enable batch execution.

## Package contract (builder choices)

ZIP root contains `package.json`, `scenario.yaml`, `profile.json`, `README.md`,
and at least one UTF-8 `.ps1` file below `payload/`. No wrapping directory.
`package.json` is closed JSON:

```json
{
  "format": "aegis-scenario-package/1",
  "scenario_id": "SCN-900",
  "version": "0.1.0",
  "platform": "windows",
  "runner": "windows-powershell-script@1",
  "entrypoint": "payload/demo.ps1",
  "cleanup": null,
  "timeout_seconds": 120,
  "profile_fingerprint": "<existing profile fingerprint>",
  "files": {"scenario.yaml": "<sha256>", "profile.json": "<sha256>", "README.md": "<sha256>", "payload/demo.ps1": "<sha256>"}
}
```

All members except package.json must be inventoried, and nothing else is accepted.
README is text; payload files may be `.ps1`, `.json`, `.txt`, `.yaml`, `.yml`.
Entrypoint/optional cleanup must be inventoried payload `.ps1` files. Timeout is
an integer 1–600 seconds. Only the above Windows runner contract is admitted in
this first slice; it is metadata, not an installed execution capability.
Scenario identity/version match the existing scenario manifest. YAML remains
`status: draft`; DB publication never rewrites it. Profile validation reuses the
existing engine's manifest/profile/fingerprint checks. A separate SCN-900 sample
is illustrative authoring material, not production evidence or an installed pilot.

## Intake boundary

ZIP bytes ≤20 MiB, expanded bytes ≤100 MiB, ≤200 members, compression ratio ≤100,
each text file ≤1 MiB, scenario YAML ≤256 KiB. Check actual streamed bytes as well
as declared metadata. Reject encrypted/unsupported compression, links/special
members, nested archives, absolute/drive/UNC/backslash/traversal/ambiguous paths,
case-insensitive collisions, duplicate members, invalid UTF-8, unlisted/missing
files, duplicate JSON keys, schema/hash/profile mismatches. No extraction of
untrusted paths to the filesystem. Validation errors use bounded fixed codes,
not submitted script content, parser dumps or private paths.

Only valid packages are stored as drafts. Invalid upload returns a bounded
validation report and is discarded. A 20 MiB limit is enforced before multipart
parsing using a route-specific streaming upload handler; request overhead is
bounded separately. Keep the general 64 KiB API limit and the machine listener
limits. Nginx gets an exact upload-location example with 21m request allowance,
while application file enforcement stays 20 MiB. Do not globally loosen nginx.

## Storage, lifecycle and concurrency

New Django `catalog` app; `ScenarioPackageVersion` has UUID, ID, version, ZIP
digest, immutable validated metadata/report, private storage reference, status,
created/reviewed actor and timestamps. Unique (scenario_id, version). File stored
below PRIVATE_ROOT/catalog, outside public static/checkouts. Persist ZIP by
server-selected UUID with restrictive mode and atomic replace. Roll back failed
DB inserts and remove only staging owned by this request. No upload filename is
used as a storage path. No public download or delete endpoint in this slice.

Reimport same identity/version/digest returns existing row (HTTP 200), different
digest gives 409 version_conflict. Successful first import is 201. Serialize
mutations with DB transactions/row locks; only fresh effective permissions
authorize them. Publish requires the submitted exact SHA-256 and verified stored
bytes; publish from draft/unpublished, unpublish from published. Retry same action
is idempotent. No content edits; history and bytes survive unpublish. Catalog
audit is append-only through services with action, actor, version, digest, time;
no credentials or uploaded content. Publication means reviewed for availability,
not proven detection, runtime readiness or trusted code execution.

## Human API contract

Same-origin session/CSRF, existing `human_api`, fresh `view` for reads,
`import_scenarios` for intake, `publish_scenarios` for lifecycle. No-store.

- GET `/api/v1/catalog?page=1&q=&status=` → `{results,count,page,page_size:50}`.
- POST `/api/v1/catalog/import` multipart field `package` → package detail.
- GET `/api/v1/catalog/<uuid>` → package detail including files and audit.
- GET `/api/v1/catalog/<uuid>/file?path=...` → `{path,text}` inert text.
- POST `/api/v1/catalog/<uuid>/publish` or `/unpublish` JSON `{sha256}` → detail.

List item fields: `id,scenario_id,name,version,platform,runner,timeout_seconds,
sha256,status,created_at,created_by,published_at,published_by` (actor is username
or null). Detail additionally `validation:{valid:true,codes:[]},files:[{path,
size,sha256}],audit:[{action,actor,at}],execution_supported:false`.
Error `{error:{code}}`; failed validation may add `validation:{valid:false,codes}`.
Unknown UUID 404; invalid request/package 400; oversized 413; permission 403;
unauthenticated 401; version/content conflict 409; private storage unavailable 503.

## Web UX

Enable Kịch bản navigation. Real paginated searchable list with draft/published/
unpublished filter, name/ID/version/platform/hash, honest empty/loading/error
states. Import button only for import permission; preview drawer includes the
inventory, inert escaped README/script text, assessment disclaimer and full hash.
Publish confirmation states exact version/hash and is available only with publish
permission. Unpublish stops catalog availability for future work, retains history.
No Run button yet. Abort stale reads, isolate settled writes/session generations,
refresh permissions on 403 using the existing shell pattern. Responsive styling
uses the existing Manager design system, account menu and theme.

## Verification and rollout

Fixture ZIP tests cover every budget/path/relationship boundary; real service/API
tests cover CSRF/permissions/lifecycle/idempotence/storage tampering and concurrency.
Frontend tests cover import, validation failures, preview text/XSS, publish,
permission change and stale responses. CI adds catalog to real PostgreSQL coverage.
Build both frontends, migration drift check, existing canonical/Manager regressions.
Release is a reviewable source/UI/sample package with hashes and an upgrade runbook.
No live upgrade/merge is done as part of local implementation; operator backs up
DB/private storage/config, applies migrations and path-scoped upload configuration,
then validates a separate sample in lab before merge.
