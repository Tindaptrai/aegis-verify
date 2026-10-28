# AEGIS Manager first flow

Separate experimental Manager runtime; the existing core wheel stays at 0.4.0.
This milestone implements one owner-approved job for one foreground Windows agent,
followed by bounded Wazuh collection and the existing canonical evaluation engine.
It does not establish live lab acceptance or enterprise readiness.

- [Approved design](../docs/superpowers/specs/2026-10-21-manager-v1-agent-pilot-design.md)
- [Implementation plan](../docs/superpowers/plans/2026-10-21-manager-first-flow.md)
- [Protocol](../docs/manager/FIRST_FLOW_PROTOCOL.md)
- [Vietnamese deployment and recovery runbook](../docs/manager/FIRST_FLOW_RUNBOOK.md)
- [Windows foreground agent](../agent/windows/README.md)
- [Authenticated web UI build, fresh bootstrap, upgrade and lab checklist](../docs/manager/WEB_AUTH_RUNBOOK.md)
- [Catalog ZIP package format](../docs/manager/CATALOG_PACKAGE.md)
- [Catalog ZIP upgrade and lab checklist](../docs/manager/CATALOG_RUNBOOK.md)

The independently built `/manager/` UI adds real sessions, product accounts and
per-action capabilities. `/` redirects there; `/admin/` remains technical
administration and `/agent/v1/` retains its certificate boundary. An absent or
invalid `AEGIS_MANAGER_UI_ROOT` returns `503 manager_ui_unavailable`. Build with
`npm run build:manager` in `frontend`, then stage public assets with
`python scripts/stage_manager_ui.py --build-root frontend/dist-manager --static-root <public-static>`.
Do not point the setting or nginx at private configuration or the dashboard build.

## Development checks

Install the core and `manager/requirements.txt` in a separate virtual environment.
Do not change the user's core installation or expose development settings on a LAN.

```sh
dotnet run --project agent/windows/Aegis.Agent.Tests
python manager/manage.py test accounts.tests control.tests --settings=aegis_manager.test_settings --verbosity 2
python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings
python -m pytest backend/tests/test_manager_ui_staging.py -q
# In frontend (locked dependencies):
npm test
npm run build
npm run build:manager
```

On Windows, building the agent first is required for the Python/.NET contract
tests. nginx tests skip explicitly when nginx is absent; PostgreSQL concurrency
tests skip on SQLite. The separate CI workflow exercises both on Linux, including
five auth authority/bootstrap races and one control dispatch race with actual
PostgreSQL row locks. Its dedicated gate is:

```sh
python manager/manage.py test accounts.tests.test_postgres_concurrency control.tests.test_postgres_concurrency devices.tests.test_postgres_concurrency catalog.tests.test_postgres_concurrency control.tests.test_execution_postgres --settings=aegis_manager.ci_settings --verbosity 2
```

CI settings require the isolated CI environment and must not target a lab DB. Neither
CI nor synthetic fixtures count as evidence of a live Windows/Wazuh run.

New dependencies are isolated here: Django supplies auth/CSRF/ORM/admin;
cryptography supplies RSA-PSS signatures and certificate parsing; psycopg supplies
PostgreSQL; Gunicorn supplies the Linux WSGI server. No new core wheel or agent
NuGet dependency is introduced.

## Paired Windows execution 0.3

Presence remains the installation default; Linux is presence-only. Windows opt-in
requires explicit protected profile/grant/separate exact RSA3072 execution public
pin and fresh service-local readiness. Old 0.1/0.2 state creation versions,
identity keys/certificates and durable journal entries are preserved. Follow
[the reviewed setup/recovery guide](../docs/manager/windows-web-execution.md).
Execution receipts and health do not establish detection or collection completeness.
