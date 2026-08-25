# AEGIS Verify

Continuous detection validation and evidence-driven SOC readiness platform.

AEGIS Verify replays safe security scenarios, normalizes telemetry from open-source
security controls, and verifies every security conclusion against raw evidence. Its
core workflow is **Gap → Rule Fix → Re-test → Pass**.

> Status: repository foundation. The first 14-day milestone is a fixture-driven CLI;
> the dashboard and GitHub Pages are intentionally deferred until the validation core
> works end to end.

## MVP

- 3 repeatable security scenarios
- 4 fixture connectors: Wazuh, Suricata, pfSense, and Cowrie
- One canonical event model
- Evidence-linked validation results
- Detection/prevention/missing-telemetry classification
- Regression comparison between test runs
- CLI-first workflow, followed by a small results dashboard

## Repository map

```text
docs/          Product, architecture, threat model, and demo documentation
backend/       Future validation engine, CLI, API, and unit tests
frontend/      Deferred MVP results dashboard
connectors/    Fixture-first adapters for four telemetry sources
scenarios/     Safe, repeatable scenario manifests
detections/    Detection content owned by each source integration
tests/fixtures Sanitized evidence used by tests and CI
```

Start with [the MVP PRD](docs/PRD.md), then read
[the architecture](docs/ARCHITECTURE.md). Contributors and coding agents must also
follow [AGENTS.md](AGENTS.md).

## First technical milestone

The target interface is:

```bash
aegis validate \
  --scenario scenarios/SCN-002-attempted-exfiltration.yaml \
  --fixture tests/fixtures/inc002/
```

A result is valid only when it references evidence IDs. Missing evidence is never
inferred, and fields absent from source telemetry remain `null`.

## Security and data handling

- Never commit credentials, tokens, webhooks, certificates, `.env` files, or raw
  production exports.
- Put unreviewed exports under a local `tests/fixtures/raw/` directory; it is ignored
  by Git.
- Sanitize hostnames, usernames, public IPs, secrets, and organization identifiers
  before adding fixtures.
- Keep timestamps and correlation fields internally consistent so timelines remain
  testable.

See [the fixture policy](tests/fixtures/README.md) and
[the threat model](docs/THREAT_MODEL.md) before committing evidence.

## Scope

AEGIS Verify is not a SIEM, full SOAR platform, autonomous response agent, or
multi-tenant SaaS product. Scope changes are deferred until the CLI milestone is
complete.

## License

No license has been selected. All rights are reserved unless the repository owner
adds a license.
