# Managed Wazuh connections: operator handoff

Issue #163 adds Linux-only private onboarding and a separate registry waiter.
It ends at an **inactive candidate**. `waiting_configuration` is not source
health, a healthy collection lease, execution readiness, least-privilege proof
or native Wazuh acceptance. The legacy collection service keeps its existing
configuration. No binding migration or activation API exists in this slice.

All steps below are an operator-reviewed handoff, not an installer or actions
performed by Manager. This change does not enable, start or mutate live services.
Use the [4.14.4 integration guide](wazuh-4.14.4-integration.md) for the vendor-side
account, CA, role review and explicit acceptance limits.

## Backup and upgrade preparation

1. Record the reviewed release commit, native CI artifact/run URL and current
   service/configuration versions. Schedule a maintenance window and stop new
   onboarding requests while taking a consistent backup.
2. Back up the PostgreSQL database together with PRIVATE_ROOT, Manager environment,
   root policy, nginx configuration and existing unit definitions. Preserve file
   ownership and modes. Private backups contain credentials and certificates:
   encrypt/restrict them outside the checkout, artifacts and public static roots.
   Verify restoration in an isolated environment before upgrading.
3. Stage the reviewed release in the normal installation layout. Verify the
   interpreter, project, environment file and unit paths exist and are trusted.
   The templates use `/opt/aegis/venv/bin/python`,
   `/opt/aegis/current/manager/manage.py`, `/etc/aegis-manager/manager.env`,
   `/var/lib/aegis-manager` and the existing unprivileged `aegis-manager` identity.
   Replace paths/identity only during operator provisioning; never accept paths,
   executable names or service arguments from the browser. Protect code/runtime
   and their parent directories from service-user writes.
4. Using the production environment through the existing trusted service runner,
   run `manage.py check --deploy`, `manage.py makemigrations --check --dry-run`
   and `manage.py migrate --plan`. Review `connections.0001_initial` and any
   unapplied prerequisites. Only after backup/review run `manage.py migrate` as
   the established migration identity. This adds registry tables; it does not
   rewrite existing registrations, jobs, bindings or scenario truth.

## One-time root policy provisioning

Copy `deploy/manager/connection-policy.json.example` to a private administrator
staging location and replace every `REPLACE_*` field. The example deliberately
contains no usable address or credential and fails policy validation as shipped.
Supply the exact reviewed HTTPS origin (including port), pinned addresses and
allowed index strings. Index matching is exact; a reviewed wildcard pattern is
one exact configured string, not permission to submit arbitrary patterns.

A root administrator installs the finished JSON at, for example,
`/etc/aegis-manager/connection-policy.json`, outside both PRIVATE_ROOT and checkout.
Use `root:aegis-manager` mode `0640` for the regular, single-link policy file;
use root-owned parents with no group/other write permissions (for example
`0750` with the service group for `/etc/aegis-manager`). Every ancestor must be
root-owned and traversable by the service identity, with no writable group/other
bits or symlinks. The service must be able to read, but never replace, the policy.
Do not put policy under a temporary world-writable directory or symlinked parent.
Verify each ancestor and final file with `namei -l` and `stat` before installation.

Set `AEGIS_MANAGER_CONNECTION_POLICY` in the root-protected Manager environment
file. Set PRIVATE_ROOT outside the checkout, owned by the service identity with
mode `0700`, no symlinks and no group/other access; onboarding creates exclusive
`0600` credential/CA files in `0700` directories. Never expose it through nginx.
The root policy is metadata; it contains no usernames, passwords or CA contents.

In the service environment, validate policy locally without network access using
`manage.py shell` and `connections.policy.load_target(reviewed_origin,
reviewed_index)`, with the administrator's actual reviewed values. Verify success
as the unprivileged Manager identity. Do not print credentials or file contents.
Missing, untrusted, malformed or non-matching policy fails new onboarding closed.
The waiter itself only reads candidate metadata and **does not validate policy**;
its successful `--once` output cannot replace this provisioning check.

Only explicitly pinned private/global IPv4 and globally routable IPv6 pass this
slice's address policy. Shared IPv4 space, IPv6 ULA, loopback, link-local,
unspecified and multicast addresses fail closed. DNS results must all be approved;
TLS connects to the approved address while verifying the original hostname/SAN.
There is no proxy, redirect or insecure mode.

## Exact nginx upload route

Merge `deploy/manager/nginx-connections.conf.example` into the existing browser TLS
server after replacing its upstream placeholder with the reviewed local Manager
upstream. Keep `client_max_body_size 64k` at server level and existing agent mTLS
routes unchanged. Only exact `/api/v1/connections/wazuh/test` receives `96k` for
JSON including a public CA up to 64 KiB. Save/prepare and neighboring paths do not
inherit that increase. Django independently enforces the 96 KiB test request cap.

Review request buffering/logging: the example disables proxy request buffering
and sets a 96 KiB body buffer. Never enable request-body, Authorization or debug
logging, request capture, or middleware instrumentation that records credentials.
Run `nginx -t` on the completed configuration, then perform the approved reload.
Check oversized requests and exact-route scope in isolated native validation.

## Waiting service dry run and optional installation

Run the following command as the existing Manager service identity with its
trusted environment loaded by the established operator runner (systemd
EnvironmentFile syntax is not a shell script; do not `source` it):

```text
/opt/aegis/venv/bin/python /opt/aegis/current/manager/manage.py managed_connection_worker --once
```

Exit zero emits exactly `waiting_configuration:no_candidate` or
`waiting_configuration:candidate_selected`. A saved unselected version is never
implicitly chosen. Invalid metadata/registration revision gives `registry_invalid`;
unavailable registry gives `registry_unavailable`, both nonzero with no raw error
values. There are no config, endpoint, activation or execution flags.

If the owner requests a persistent waiter, review and install
`deploy/manager/managed-connections-worker.service` under its own unit name,
verify the final unit with `systemd-analyze verify`, and use the normal root
operator procedure to daemon-reload/start/enable it. Keep the legacy worker unit
separate. The web application never runs sudo or systemctl.

The unit uses the same unprivileged identity, fixed paths, `Restart=on-failure`,
five-second restart delay and a read-only filesystem view. The process polls
candidate metadata at five-second intervals, emits only changed fixed states,
and exits gracefully on SIGTERM/SIGINT with handlers restored. It creates no
collection lease and never calls collection, resolves credentials, queries Wazuh,
or mutates jobs/bindings. Inspect unit status and its journal for waiting state;
restart with a candidate selected and verify it still waits. A running unit is
only waiter process liveness, never collection health or Ready.

## Cleanup, rollback and recovery

Run `manage.py cleanup_connection_drafts` manually as the Manager service identity
with the same trusted environment. It has no custom flags. It serializes with
publication, retains registered sources and live drafts, and cleans only known
files in expired unreferenced directories (including eligible partial orphans).
Unknown files, links and suspicious storage fail closed; investigate privately.
This change adds no host scheduler or recurring automation.

To roll back, first stop new onboarding requests and the separate waiting service
through the approved operator process. Restore the previous application/nginx/
environment configuration as a reviewed unit. Prefer retaining the additive
connections tables and all private history; never run `migrate connections zero`
or delete credential directories as an automatic rollback. If a database restore
is necessary, restore its corresponding private files from the same consistent
backup in the maintenance window and reconcile any post-backup writes with the
owner. Preserve previous registrations and active legacy collection settings.
Credential/CA rotation creates a newly tested immutable source version and new
registration UUID/revision 1; it never overwrites prior files or registrations.

## Native review and lab acceptance checklist

- Require the exact-commit `Manager PostgreSQL and mTLS proxy` CI artifact. The
  `postgres_connections` group requires all publication/candidate/version races
  and three separate-session PostgreSQL authority regressions (generation,
  session-key rotation, permission revocation while probe I/O is paused). The
  authority tests mock only the network/storage fixture boundaries; they do not
  certify real Wazuh or private persistence.
- Require `native_connections_policy` (4 concrete tests),
  `native_connections_storage` (4) and `native_connections_tls` (5, including
  approved-IP dial/hostname pinning). Policy root fixtures run only in isolated
  CI under `/var/lib/aegis-synthetic-policy-*`; production Manager stays unprivileged.
  Missing or skipped required tests fail the gate. Windows-specific optional
  skips are reported separately, never treated as native success.
- Native operator validation remains separate: policy readability/ownership,
  installed unit paths and SIGTERM/restart behavior, no new healthy lease or
  binding/job mutation, exact nginx body limit, and rollback restoration drill.
- Owner/lab review must confirm Wazuh 4.14.4 effective grants, public HTTP CA/SAN,
  approved routing, query/scroll/clear-scroll and credential rotation. Record
  sanitized evidence IDs and the exact release; no write/delete probing of real
  evidence. A zero-hit onboarding test alone proves neither least privilege nor
  full collection compatibility. Genuine sanitized screenshots remain unavailable.

Linux/systemd/PostgreSQL and live Wazuh lab acceptance were not run on the Windows
implementation host. No lab switch, agent/VM change, scenario run or merge follows
from this handoff; human review and separate lab authorization remain required.
