# Manager web authentication: build, upgrade and lab validation

This release adds the independent branded Manager web UI, real Django sessions,
product account creation, permission updates, lock/unlock and password changes.
The first navigation exposes Overview, My Account, Accounts & Permissions and
theme settings. Counts are database registrations/jobs/releases, not online
presence or detection results. Other product sections remain unavailable.

Use this with [FIRST_FLOW_RUNBOOK.md](FIRST_FLOW_RUNBOOK.md) for the existing Linux
Manager/Windows foreground-agent flow. Agent pairing/presence, ZIP intake,
multi-device execution, Windows service/MSI and a complete installer remain future
work. Code review and owner-reviewed lab evidence are required before merge or
upgrade. A passing synthetic test is not lab acceptance.

## Build and review the public artifact

Use the reviewed source commit and locked dependencies in a build environment:

```sh
cd frontend
npm ci
npm test
npm run build
npm run build:manager
cd ..
python scripts/stage_manager_ui.py --build-root frontend/dist-manager --static-root /REPLACE_REVIEWED_PUBLIC_STATIC_ROOT
```

The dashboard remains in `frontend/dist`; the Manager build is exclusively
`frontend/dist-manager/manager.html` plus flat `assets/`. Do not combine them or
add the Manager to the core wheel public-resource allowlist. No build content is
executed by the stager. Only reviewed public JS, CSS, images and fonts are allowed;
private config, source maps, JSON, logs, nested directories, unknown root files,
symlinks, redirected ancestors and Windows junctions fail validation. Keep the
original logo: the bounds are 64 KiB HTML, 128 assets, 4 MiB per asset and 8 MiB
total. The original approximately 1.49 MB logo fits without alteration.

The command writes only `<public-static>/manager/assets/*` and
`<public-static>/manager/manifest.json`. The SHA-256 map includes `manager.html`
and `assets/<filename>` relative to the build; HTML is hashed but never exported
under `/static/`. An existing `manager/` directory must have a valid staging
manifest before replacement. Unrelated Django/core public resources are left
alone. Review the manifest against the delivered build, record the source commit,
artifact version and manifest hash in the private change record, and retain the
previous reviewed build and manifest for rollback. The manifest detects accidental
byte changes; it is not a signature or proof of publisher identity.

Copy the reviewed source/build to the root-owned release directory, then use the
stager against `/srv/aegis-manager-static` under the deployment administrator.
Keep directories `0755`, files `0644`, no writable access for nginx or the service
account, and no symlinks. Never stage config, evidence, keys, certificates, catalog
or Indexer files. Django `collectstatic` remains separate; publish only its
reviewed public output into the same static root as in the first-flow runbook.

Set optional `AEGIS_MANAGER_UI_ROOT=/opt/aegis/current/frontend/dist-manager` in
the private systemd EnvironmentFile. It becomes `MANAGER_UI_ROOT` (a path string;
tests may also supply a `Path`), trusted and read-only while serving. `/manager/`
reads only `manager.html` after validating the build paths and asset references;
every asset reference must be `/static/manager/assets/<filename>`. `/` redirects
to `/manager/`. Unset/missing/invalid/symlink builds return the fixed
`503 {"error":{"code":"manager_ui_unavailable"}}`, without a filesystem path or
another application fallback. Publish the matching assets before service restart.

Use the existing nginx template: client certificates stay optional for browser
routes and mandatory, chain-verified for `/agent/v1/`. Preserve `64k` upload limit,
cleared proxy headers and `disable_symlinks on` for static files. The sole static
alias is `/srv/aegis-manager-static/`; `/manager/` is proxied to Django, `/admin/`
retains technical administration. Do not add an Indexer/private-directory alias.
Run `nginx -t` before reload and verify the existing mTLS negative cases.

## Fresh install only: explicit initial product owner

Follow first-flow provisioning for private environment, DB, PKI and signing keys.
After `migrate`, and only on a new database with no users, the owner may run:

```sh
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py bootstrap_manager_owner --new-install
```

The explicitly requested published initial product account is `aegis/aegis`.
It has the eight product capabilities and no Django staff/superuser flags. The
owner enters this initial password and replaces it through My Account before
allowing access beyond the isolated setup session. The command prints
`owner_created`, or `existing_users_unchanged` if any user exists; it never resets
an existing identity/password. It is never run by startup or migrations. Creating
a separate technical superuser is an explicit owner operation, not a product-user
grant. Never put private passwords in shell history, logs, screenshots or Git.

## Upgrade an existing Manager

1. Record the current reviewed commit/build/manifest, live schema state and account
   inventory in the private change record. Arrange a maintenance window and finish
   or reconcile first-flow jobs under the existing runbook; stop worker/web before
   backup and mutation. Keep nginx maintenance behavior explicit.
2. Back up PostgreSQL, private env, DB identities/password hashes, PKI/signing keys,
   catalog/mappings, journals and evidence with their permissions. Verify backup
   hashes and a restore in isolation. Keep these private; do not export them with
   the UI package. Never replace the database or regenerate PKI to install a UI.
3. Install the reviewed source/build and matching staged public assets, retaining
   rollback artifacts. Preserve the existing private env, secret key, DB settings
   and keys; add only the optional UI-root setting. Do not run the fresh bootstrap,
   flush, reset users/passwords, reseed live evidence or delete existing sessions.
4. With the existing service identity/environment run `manage.py migrate`,
   `manage.py check --deploy`, and the reviewed collectstatic/publication procedure
   from the first-flow runbook. Migrations add account security/audit/preset data;
   existing user identities, passwords and technical flags are retained. Existing
   legacy accounts are not automatically assigned new product capabilities.
5. Review `nginx -t`, restart web, then complete the acceptance checks below before
   restoring worker operation. Legacy browser cookies lack the new generation and
   absolute deadline markers: their first human request signs them out once. The
   same existing username/password can then log in; authorize product access
   explicitly if needed. Human sessions expire eight hours after login; polling
   and own-password changes never extend the deadline.
6. If acceptance fails, stop services, preserve new audit/evidence and consult the
   first-flow rollback procedure. Do not blindly reverse migrations or restore an
   old active identity/journal. Reconcile schema/DB/evidence with the owner before
   resuming. This document does not authorize deployment or a live rollback.

Product Admin has all eight capabilities. Operator has `view`, `run_jobs` and
`export_evidence`; Viewer has `view`. Custom action grants require `view`. Product
administration cannot modify a technical staff/superuser target or grant technical
flags. Group-inherited grants are displayed and cannot be silently removed through
product editing. The final usable product administrator is protected across both
product and technical administration. Locked users lose current sessions;
unlocking never revives an old cookie. Account management uses lock/unlock, not
hard deletion. A legacy user without `view` can still log out/change own password.

## Local and CI gates

```sh
python manager/manage.py test accounts.tests control.tests --settings=aegis_manager.test_settings --verbosity 2
python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings
python -m pytest -q -rs -p no:cacheprovider
# frontend: npm test; npm run build; npm run build:manager
```

The Manager workflow also builds both frontends and stages the real Manager build.
Its isolated Linux PostgreSQL 17 job runs the full accounts/control suite and the
explicit concurrency command:

```sh
python manager/manage.py test accounts.tests.test_postgres_concurrency control.tests.test_postgres_concurrency --settings=aegis_manager.ci_settings --verbosity 2
```

That gate runs eight actual PostgreSQL account/bootstrap races and the control
dispatch race. SQLite skips do not verify row locking. CI settings require the
ephemeral CI environment and never target a lab DB. Existing Linux nginx/mTLS,
Windows agent, Python/.NET cross-language and published-agent gates remain.
Record actual local, CI, browser and lab results separately with test counts/skips
and commit/manifest hashes; never pre-fill a pass for a pending environment.

## Owner-reviewed lab checklist

- Existing account: same username/password works after the single legacy-cookie
  relogin; stored identity, password hash, technical flags and private PKI persist.
- Product admin: create a clearly labeled test Viewer, reload to confirm DB
  persistence, grant Operator/custom capabilities, revoke actions and verify each
  changed action through its API. Preserve at least one usable administrator.
- Viewer: Accounts & Permissions is unavailable and direct `GET /api/v1/users`
  returns the fixed `403` capability error. CSRF-less human writes are rejected.
- Lock then unlock a second test identity without using its old cookie between
  mutations; the old cookie must still fail. Newly authenticated access succeeds.
- Logout clears protected content; reload stays signed out; a late request cannot
  restore the prior workspace. Eight-hour absolute expiry is covered by tests.
- Native technical Admin: the owner changes their own password at
  `/admin/password_change/`, confirms the success page and continued access in
  that browser, and verifies another browser's prior cookie is rejected. Compare
  the session API's `expires_at` before and after: the original absolute deadline
  must remain unchanged. Review the `password_changed` audit; the owner enters
  the current and replacement passwords privately.
- Actual API-backed browser at normal width and 634px: inspect the real logo,
  account name/role/menu/My Account, create-user editor, custom grants and logout;
  include a long synthetic display name, reachable permission/save/cancel controls,
  contained table scrolling and supported themes. Capture sanitized screenshots,
  restore viewport overrides and remove only disposable test artifacts.
- Owner enters all live/private passwords. Review sanitized auth audit entries,
  account IDs and HTTP outcomes without passwords/cookies/CSRF tokens. Browser
  screenshots do not establish simultaneous PostgreSQL transaction behavior.
- Legacy Windows first flow: existing foreground agent trust, registration,
  signed-job bytes, bounded dispatch/execution/cleanup and evidence collection
  remain compatible. Check missing/foreign/spoofed client-cert rejection and an
  approved one-device lab job using the existing runbook. Security conclusions
  link actual report evidence IDs and raw hashes; registration/job counts do not
  claim detection coverage or online presence.
- Human reviewers approve code, tests, real PostgreSQL CI and lab evidence before
  merge/upgrade. Record unresolved checks and owner decision in the private change
  record; never infer acceptance from a UI build alone.
