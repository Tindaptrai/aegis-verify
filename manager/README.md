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

## Development checks

Install the core and `manager/requirements.txt` in a separate virtual environment.
Do not change the user's core installation or expose development settings on a LAN.

```sh
dotnet run --project agent/windows/Aegis.Agent.Tests
python manager/manage.py test control.tests --settings=aegis_manager.test_settings
python manager/manage.py makemigrations --check --dry-run --settings=aegis_manager.test_settings
```

On Windows, building the agent first is required for the Python/.NET contract
tests. nginx tests skip explicitly when nginx is absent; PostgreSQL concurrency
tests skip on SQLite. The separate CI workflow exercises both on Linux. Neither
CI nor synthetic fixtures count as evidence of a live Windows/Wazuh run.

New dependencies are isolated here: Django supplies auth/CSRF/ORM/admin;
cryptography supplies RSA-PSS signatures and certificate parsing; psycopg supplies
PostgreSQL; Gunicorn supplies the Linux WSGI server. No new core wheel or agent
NuGet dependency is introduced.
