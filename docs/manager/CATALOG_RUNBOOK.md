# Catalog ZIP: build, upgrade and lab acceptance

This slice adds scenario package intake and reviewed publication to Manager.
Publication does not execute a script, enable an agent runner, attest detection,
or install Wazuh rules. Existing pilot profiles, evidence and RunnerRelease pins
remain unchanged. See [package format](CATALOG_PACKAGE.md) and
[design](../superpowers/specs/2026-10-25-catalog-zip-design.md).

## Build the reviewed release

Use the reviewed source commit in a build environment and existing locked deps:

```sh
python -m pip install -e . -r manager/requirements.txt
python manager/manage.py test accounts.tests control.tests devices.tests catalog.tests --settings=aegis_manager.test_settings
python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings
cd frontend
npm ci
npm test
npm run build
npm run build:manager
cd ..
python scripts/create_catalog_sample.py /REPLACE_REVIEW_OUTPUT/AEGIS-SCN900-Sample-0.1.0.zip
```

Generate the separate SCN-900 authoring sample with that command's output
argument. Keep the ZIP and its SHA sidecar with the review artifact. The
sample only contains harmless output; it is not telemetry or pilot ground truth.
Never commit real scripts containing passwords, private certificates or evidence.

The local SQLite suite explicitly skips real PostgreSQL concurrency and nginx
checks. Require the Manager CI workflow's actual PostgreSQL/nginx job to pass for
the reviewed commit. A skip is not proof of those boundaries.

## Upgrade an existing Linux Manager

Perform this during a maintenance window with no active execution/collection.
Preserve the current release path, private EnvironmentFile and unit definitions.
Back up the PostgreSQL database, roles, private root (including catalog), nginx,
static build and current source/venv. Verify hashes and an archive listing before
any migration. Do not export the private-root backup to a public review package.

Stage the reviewed source and matching `frontend/dist-manager` under a new
root-owned release directory. Use the existing UI staging tool to stage only
public assets; do not alias or copy private catalog contents to `/static/`:

```sh
python scripts/stage_manager_ui.py --build-root frontend/dist-manager --static-root /REPLACE_PUBLIC_STATIC_ROOT
```

Use your service's existing user, working directory and EnvironmentFile to run
`manage.py migrate --plan`, then `manage.py migrate --noinput` against the reviewed
new release while the old service is stopped. Existing installations commonly use
`systemd-run --wait --pipe --collect` with `--uid`, `--gid`, `WorkingDirectory` and
`EnvironmentFile`; derive those values from `systemctl show`, not this example.
Do not bootstrap/reset users or regenerate enrollment/server CA, CRL or signing
keys. Retain existing TLS identity checks on both browser and agent listeners.

Point the release symlink and `AEGIS_MANAGER_UI_ROOT` at the matching reviewed
build, then restart the existing Manager service. Check `systemctl is-active`,
the verified HTTPS `/manager/` page and authenticated API before dispatch resumes.
This release requires no agent upgrade and no Wazuh restart/rule change.

## Add only the browser upload exception

On the existing **browser** HTTPS server, copy the exact
`location = /api/v1/catalog/import` block from
`deploy/manager/nginx.conf.example`. Retain the deployment's own upstream and
header policy. Its request limit is `21m` for multipart overhead; application file
limit remains **20 MiB** and the bounded request stream is **21 MiB**. All other
browser API requests keep `64k`; agent endpoints keep their existing limits.
Do not replace the whole live nginx config with the example: existing CA/CRL,
separate agent listener and trust policies belong to the deployment.

Run `nginx -t` before reloading nginx. Verify missing/spoofed client certificates
still fail on legacy and paired agent heartbeat endpoints, and anonymous Catalog
requests fail. Do not use `curl -k` or disable certificate verification to pass.

Storage is private under `PRIVATE_ROOT/catalog`; only the service user and backup
administrator should access it. On Linux both `PRIVATE_ROOT` and its `catalog`
directory must be owned by the Manager service user with mode `0700`; ZIP files
are `0600`. Verify those exact directories before import and fix only their
ownership/modes as needed; do not recursively rewrite private-root permissions.
Catalog must be outside the checkout and public static root. The default sibling
layout `PRIVATE_ROOT/static` and `PRIVATE_ROOT/catalog` is supported.
Account for up to 20 MiB ZIP per version plus DB
metadata and backups; there is no automatic retention deletion in this slice.
Validation rejects bad packages before publishing. Valid structure and hashes
do not establish that a script is safe; inspect scripts and intended impact.

## Owner lab checklist

1. Login using an existing owner; verify devices/accounts/history are preserved.
2. Open **Kịch bản**, import the separate SCN-900 ZIP, inspect inventory/full SHA,
   README and script as inert text. Confirm draft has no Run action.
3. Reimport identical bytes: same UUID, no duplicate version. Change bytes without
   changing version: conflict, original bytes/history preserved.
4. Confirm Viewer cannot import/publish and Operator has no implied publish grant.
   A granted importer without publisher permission can only import/read.
5. Publish the inspected exact hash, then unpublish. Confirm recorded actor/time
   and retained preview/history. No scenario has executed.
6. Import a malformed ZIP: bounded useful error, no script execution or row created.
7. Confirm valid upload larger than 64 KiB is accepted while other endpoint limits
   and agent identity rejection still hold. Store selected sanitized acceptance
   results separately from code; do not put raw private evidence in the repository.

## Recovery

Do not downgrade schema by switching only the symlink after new data has been
written. Stop writes, preserve the failed release logs and current private data,
then restore the matched database/private files/config/static/source backup under
the operator's restore procedure. Validate its hashes, TLS, users and history
before restarting. Never recursively delete a catalog to clear an import error.

Publication and unpublication are reversible availability changes. History and
bytes are intentionally retained. The detail UI returns the most recent 100 audit
entries; older history remains in the database. Review and lab acceptance precede merge.
