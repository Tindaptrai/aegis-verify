# AEGIS Verify

Continuous detection validation and evidence-driven SOC readiness platform.

AEGIS Verify replays safe security scenarios, normalizes telemetry from open-source
security controls, and verifies every security conclusion against raw evidence. Its
core workflow is **Gap → Rule Fix → Re-test → Pass**.

> Status (2026-09-19): controlled demo/lab V1 is integrated through PRs #28–#30.
> The fixture-driven CLI, regression comparison, read-only dashboard, optional
> native-review input and bounded live Wazuh Indexer collector are available.
> This is not production certification or live fleet monitoring. Historical run
> binding remains unknown; successful reads do not prove least-privilege access.
> Start with the [V1 handoff/runbook](docs/V1_HANDOFF.md) and
> [draft release notes](docs/V1_RELEASE_NOTES.md). No release tag is declared here.

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
backend/       Validation engine, CLI, read-only dashboard server, and tests
frontend/      Read-only results dashboard (Vite + React), see docs/DASHBOARD.md
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
The offline validation CLI is available on this branch; see the runnable example below.

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

## Current implementation: Suricata fixture parsers

[Suricata A](docs/SURICATA_WAZUH_ALERT.md) handles Wazuh-exported alerts.
[Suricata B](docs/SURICATA_EVE_JSONL.md) handles direct EVE JSONL alert/flow,
including skip outcomes, exact line evidence and explicit sensor context.
The B guide documents the four initial lab exports and the additional real MGMT flow sample.

## Current implementation: Cowrie fixture parsers

[Cowrie directions A and B](docs/COWRIE_FIXTURE_PARSER.md) parse either one
offline Wazuh-exported Cowrie search-hit or bounded native Cowrie JSONL. Both emit
canonical v2 events plus immutable source provenance; B also returns explicit
per-line skip outcomes. The [native intake record](docs/COWRIE_NATIVE_INTAKE.md)
documents the audited real derivative, safe aggregates and remaining human/lab
gate. Live access is not implemented.

## First technical milestone

The offline CLI evaluates explicit bundles through the real parsers and engine.
Start with this synthetic test-only example:

```bash
aegis validate \
  --scenario tests/fixtures/cli/synthetic-detected/scenario.yaml \
  --fixture tests/fixtures/cli/synthetic-detected \
  --format json
```

A result is valid only when it references evidence IDs. Missing evidence is never
inferred, and fields absent from source telemetry remain `null`.

See [the Vietnamese CLI guide](docs/CLI_VALIDATE.md) for installation, bundle
contracts, explicit profile/context selection, exit codes and privacy. The sample
returns `Detected` with two distinct evidence IDs; it proves the offline software
path only, not lab coverage. Human review and local/lab validation remain pending.

## Current implementation: results dashboard

Windows: after preparing the venv and frontend build, use
`./Start-Aegis.ps1 -Reports '<reviewed-report-directory>' -Port 8766`.
See [the one-command launcher guide](docs/START_AEGIS.md) for prerequisites and errors.

[The results dashboard](docs/DASHBOARD.md) is a read-only React page over the
CLI's JSON reports, served by `aegis dashboard --reports <dir>` (standard-library
HTTP on loopback, no new Python dependency). It shows scenario, run ID, final
result, per-assertion outcomes with evidence IDs, the report's ordered evidence
timeline and before/after comparisons, and renders loading, empty, malformed and
backend-error states without reimplementing validation. Try it on the synthetic
fixtures:

```powershell
cd frontend; npm install; npm run build; cd ..
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports tests\fixtures\dashboard --static frontend\dist
```

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
