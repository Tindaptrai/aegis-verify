# AEGIS Verify

Continuous detection validation and evidence-driven SOC readiness platform.

AEGIS Verify replays safe security scenarios, normalizes telemetry from open-source
security controls, and verifies every security conclusion against raw evidence. Its
core workflow is **Gap → Rule Fix → Re-test → Pass**.

> Status: Canonical Event v1.0 and read-only Scenario YAML validation are merged.
> Canonical Event v2.0 lossless timestamps are merged via PR #16.
> A fixture-only Wazuh Windows 4688 parser is implemented on this branch,
> pending human mapping/lab review before Issue #3 integration.
> The first 14-day milestone is a fixture-driven CLI;
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

## Current implementation: event contract

[Canonical Event v1.0](docs/CANONICAL_EVENT.md) provides validation, UTC timestamps,
JSON serialization, and exact-byte SHA-256 hashing. No live lab is required:

[Canonical Event v2.0](docs/CANONICAL_EVENT_V2.md) adds exact 0..9-digit timestamps,
an explicit versioned reader and v1 migration, without changing the v1 alias.
The v2 guide includes Vietnamese explanations and runnable Python examples.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

Requires Python >=3.11. Contract tests use artificial data; Wazuh parser tests also
use one reviewed, sanitized user sample, not proof of an incident.
The full validation CLI described below is still planned.

## Current implementation: Wazuh fixture parser

[Wazuh Windows 4688 guide](docs/WAZUH_FIXTURE_PARSER.md) explains the first JSON-only
profile, exact timestamp mapping, evidence identity, explicit collection topology,
safe errors and runnable local comparison. No live SIEM or scenario execution.

## Current implementation: scenario contract

[Scenario YAML v0.1](docs/SCENARIO_SCHEMA.md) validates the three unchanged draft
manifests, their safety metadata, source declarations and assertion identities.
`aegis_verify.scenario_loader.load_scenario(path)` reads one local UTF-8 YAML file
without rewriting it. Malformed or ambiguous YAML raises a contextual error.

This checks the manifest contract only: it does not execute a scenario, authorize
a lab action, evaluate log evidence or return detection/prevention results.

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
