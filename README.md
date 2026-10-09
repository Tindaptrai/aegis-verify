# AEGIS Verify

Continuous detection validation and evidence-driven SOC readiness platform.

AEGIS Verify evaluates exported evidence from approved security tests, normalizes
telemetry from security controls, and links each validation result to raw evidence.
Its core workflow is **Gap → Rule Fix → Re-test → Pass**. Scenario execution and
rule changes remain separate, operator-controlled steps.

> Status (2026-10-09, package version **0.3.0**, Apache-2.0): lab MVP with four
> scenarios and the merged Lab C expansion. Results use real lab evidence evaluated
> offline through the engine:
>
> - SCN-001 `Regression Passed` ([v3 result](docs/SCN001_V3_RESULT_2026-09-27.md));
> - SCN-002 `Prevented` ([result](docs/SCN002_RESULT_2026-09-22.md));
> - SCN-003 `Detected` ([result](docs/SCN003_RESULT_2026-09-26.md));
> - SCN-004 / Lab C: owner-accepted scenario/profile **0.2.0**, including the SIEM
>   alert assertion A04. The normal → sensor-agent outage → recovery sequence reports
>   `Prevented` → `Inconclusive` → `Prevented`
>   ([evidence and acceptance](docs/SCN004_LAB_C_ACCEPTANCE.md),
>   [approval and pins](docs/SCN004_A04_APPROVAL_AND_PINS.md)).
>
> Read-only collectors exist for the Wazuh Indexer (Python 3.11–3.13) and for
> SCN-002/SCN-003 lab rounds (`aegis collect`). This is a single-operator lab tool,
> not production certification or live fleet monitoring. Collection assurance is
> attested by the operator, and all four manifests still declare `status: draft`.
> Elastic support for Lab B is pending; delivering Elastic logs is separate from
> accepting an AEGIS connector or verdict.
>
> **New to the project or running it in another lab?** Start with the
> [lab onboarding guide](docs/LAB_ONBOARDING.md), then the
> [offline demo](docs/DEMO_WALKTHROUGH.md). Release notes:
> [0.3.0](docs/RELEASE_NOTES_0.3.0.md).

## Implemented lab scope

- 4 security scenario manifests: SCN-001 through SCN-004
- 6 source families: Wazuh, Suricata, pfSense, Cowrie, Snort 3, and OPNsense
- 14 registered bundle parser keys; fixture tests require no live lab
- One canonical event model
- Evidence-linked validation results
- Detection/prevention/missing-telemetry classification
- Regression comparison between test runs
- CLI-first workflow, followed by a small results dashboard

## Repository map

```text
docs/          Product, architecture, threat model, guides and run records
backend/app/   Canonical model, bundle intake, validation engine, CLI, compare,
               read-only dashboard server with optional Operations mode
backend/tests/ Unit, integration and CLI subprocess tests
frontend/      Read-only results dashboard (Vite + React), see docs/DASHBOARD.md
connectors/    Parsers for six source families; bounded read-only Wazuh reader
scenarios/     Reviewed ground-truth manifests and public evaluation profiles
detections/    Detection content templates (Wazuh SCN-001, Suricata SCN-002 marker)
tests/fixtures Sanitized or synthetic evidence used by tests and CI
raw-evidence/ Local private archive, ignored by Git; not included in a clone
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

Requires Python >=3.11. Runtime dependencies are `pydantic` and `PyYAML` only.
Tests use synthetic data and reviewed, sanitized samples, not proof of an incident.
CI runs the backend suite on Ubuntu with Python 3.11–3.13 and on Windows with 3.11
and 3.13, plus the frontend tests and build. Pull requests run Linux, and also
Windows/3.13 when they touch Windows-specific code ([CI notes](docs/CI.md)).

## Current implementation: bundle parsers

A bundle's `inputs.json` names one parser key per file. The registry currently
accepts fourteen keys; the [CLI guide](docs/CLI_VALIDATE.md) lists each key's input
and required context.

| Source | Keys | Guide |
| --- | --- | --- |
| Wazuh, Windows | `wazuh-win4688-v2`, `wazuh-sysmon1-v1`, `wazuh-powershell4104-v1` | [4688](docs/WAZUH_FIXTURE_PARSER.md), [Sysmon 1 and PowerShell 4104](docs/WINDOWS_TELEMETRY_PARSERS.md) |
| Wazuh, network | `wazuh-sysmon3-archive-v1` (manager archive, UDP), `wazuh-suricata-alert-v1` (Wazuh alert raised from a Suricata alert), `wazuh-snort-alert-v1` (Wazuh alert raised from a Snort 3 alert) | [Wazuh from Suricata](docs/WAZUH_SURICATA_ALERT.md), [Wazuh from Snort](docs/WAZUH_SNORT_ALERT.md) |
| Wazuh, deception | `wazuh-cowrie-alert-v1` (Wazuh manager alert raised from Cowrie) | [Wazuh from Cowrie](docs/WAZUH_COWRIE_ALERT.md) |
| Suricata | `suricata-wazuh-alert-v1` (search hit), `suricata-eve-jsonl-v1` (direct EVE) | [A](docs/SURICATA_WAZUH_ALERT.md), [B](docs/SURICATA_EVE_JSONL.md) |
| pfSense | `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | [filterlog](docs/PFSENSE_FIXTURE_PARSER.md) |
| OPNsense | `opnsense-filterlog-bsd-v1` (BSD syslog as received; IPv4 TCP/UDP/ICMP, IPv6 UDP/ICMPv6) | [filterlog](docs/OPNSENSE_FILTERLOG_PARSER.md) |
| Snort 3 | `snort3-alert-json-v1` (raw `alert_json`, pinned field list) | [alert_json](docs/SNORT3_ALERT_JSON_PARSER.md) |
| Cowrie | `cowrie-wazuh-v1`, `cowrie-jsonl-v1` | [Cowrie](docs/COWRIE_FIXTURE_PARSER.md) |

Every parser emits Canonical Event v2 with an exact `raw_event_ref` and SHA-256.
No parser opens a network connection or executes a scenario.

## Current implementation: scenario contract

[Scenario YAML v0.1](docs/SCENARIO_SCHEMA.md) validates the four draft manifests,
their safety metadata, source declarations and assertion identities. Approved
ground-truth changes include the SCN-002-A04 rewording (PR #65) and the addition
of SCN-004-A04 in scenario 0.2.0
([Lab C approval record](docs/SCN004_A04_APPROVAL_AND_PINS.md)).
`aegis_verify.scenario_loader.load_scenario(path)` reads one local UTF-8 YAML file
without rewriting it. Malformed or ambiguous YAML raises a contextual error.

This checks the manifest contract only: it does not execute a scenario, authorize
a lab action, evaluate log evidence or return detection/prevention results.

## Scenarios

| Scenario | Expected outcome | Where it stands |
| --- | --- | --- |
| [SCN-001](scenarios/SCN-001-powershell-execution.yaml) PowerShell execution | `detected` | Gap → Fix → Re-test on real lab evidence: B→C `Regression Passed` in the [v2 set](docs/SCN001_V2_APPROVAL_AND_PINS.md) and again in the [v3 set](docs/SCN001_V3_RESULT_2026-09-27.md) (2026-09-27, runner no longer fires the demo rule); see also [Operations acceptance](docs/OPERATIONS_ACCEPTANCE.md) |
| [SCN-002](scenarios/SCN-002-attempted-exfiltration.yaml) attempted exfiltration | `prevented` | `Prevented` on real lab evidence, 2026-09-22; [public profile](docs/SCN002_EVALUATION_PROFILE.md), [block-round runbook](docs/SCN002_BLOCK_RUN_RUNBOOK.md), [`aegis collect scn002`](docs/SCN002_COLLECT.md), [result](docs/SCN002_RESULT_2026-09-22.md), [lab-derived sanitized bundles](tests/fixtures/cli/scn002-lab-sanitized/README.md) |
| [SCN-003](scenarios/SCN-003-internal-deception.yaml) internal deception | `detected` | `Detected` on real lab evidence, 2026-09-26/27; [public profile](scenarios/profiles/scn-003/README.md), [control-run runbook](docs/SCN003_CONTROL_RUN_RUNBOOK.md), [`aegis collect scn003`](docs/SCN003_COLLECT.md), [result](docs/SCN003_RESULT_2026-09-26.md), [lab-derived sanitized bundle](tests/fixtures/cli/scn003-lab-sanitized/README.md) |
| [SCN-004](scenarios/SCN-004-attempted-exfiltration-lab-c.yaml) attempted exfiltration, Lab C (Snort 3, OPNsense, Wazuh) | `prevented` | Technical acceptance and photos/dashboard accepted by the owner on 2026-10-09; scenario/profile 0.2.0 covers A01–A04. Historical 0.1.0 results, five live 0.2.0 runs, and two historical re-evaluations are recorded separately. [Configuration](docs/SCN004_LAB_C.md), [acceptance and evidence](docs/SCN004_LAB_C_ACCEPTANCE.md), [approval/pins](docs/SCN004_A04_APPROVAL_AND_PINS.md), [runbook](docs/LABC_RUNBOOK.md), [sanitized bundles](tests/fixtures/cli/scn004-lab-c-sanitized/README.md) |

Ground truth changes need explicit owner approval; every manifest still says
`status: draft`.

For a 25-minute offline walkthrough of the original three scenarios and the dashboard,
see [the customer demo guide](docs/DEMO_WALKTHROUGH.md). PRD-by-PRD acceptance with
evidence links: [MVP_ACCEPTANCE.md](docs/MVP_ACCEPTANCE.md).

## Partner labs and handoff

| Lab | Stack and current status | Start here |
| --- | --- | --- |
| Lab A | Wazuh, pfSense, Suricata, Cowrie and Windows; original SCN-001/002/003 lab evidence | [Onboarding](docs/LAB_ONBOARDING.md), scenario result links above |
| Lab B | Elastic Security, pfSense, Suricata and Windows. Direct EVE/filterlog parsers exist; Elastic source-event and detection-alert parsers, `SourceType.elastic`, and EVTX ingestion are not implemented at the status date above | [Lab B onboarding](docs/LAB_ONBOARDING.md#lab-b-elastic-security) |
| Lab C | OPNsense, Snort 3, Wazuh and Windows. The reviewed code, runbook and acceptance chain is merged into main | [Runbook](docs/LABC_RUNBOOK.md), [acceptance](docs/SCN004_LAB_C_ACCEPTANCE.md), [approval and pins](docs/SCN004_A04_APPROVAL_AND_PINS.md) |

### Lab C integration verification — 2026-10-09

The 13-PR Lab C chain, including the reviewed documentation update
([PR #142](https://github.com/Tindaptrai/aegis-verify/pull/142)), was merged into
main at `5e8b2f6baf1e8e1a18c2256b03631796955b6864`:

- [Fixture CI on that commit](https://github.com/Tindaptrai/aegis-verify/actions/runs/37829840701):
  all six jobs passed across Ubuntu, Windows and the frontend.
- Local Windows backend checks: **3,655 passed / 3 platform skips**; frontend:
  **108 passed**, build passed; dependency and wheel checks passed.
- Replay on the final main commit: **23/23 full JSON reports and exit codes
  matched**, plus **2/2 comparison JSON matches**. These are replays of saved
  evidence, including historical re-evaluations, not 23 new live runs.

The independent operator's live run is recorded from the owner's confirmation;
its separate raw/report was not supplied for direct audit. That distinction and
the collection-assurance limits remain in the acceptance record. Integration
closure does not certify production readiness or verify VM backup recovery.

### Private files in the owner's local workspace

The following paths are relative to the repository root and are **local-only**.
They are ignored by Git and will not be downloaded by cloning the repository:

| Path | Contents |
| --- | --- |
| `raw-evidence/lab-c/nghiem-thu-2026-10-09/` | Three source handoff/photo archives, the merged-main handoff ZIP and SHA-256 sidecar, audit reports, final integration receipt, `README.txt` and `SHA256SUMS.txt` |
| `raw-evidence/lab-b/YEU-CAU-BAN-GIAO-LAB-B.md` | Operator handoff checklist: native EVTX, Elastic source events and separate alerts, queries/count reconciliation, run provenance, hashes, checks, screenshots, runbook and backup |

Collect and assemble evidence into a private directory **outside a Git working
tree**, even if a subdirectory is ignored. Reviewed archive copies can be stored
locally afterward. Keep an independent backup of raw evidence, VM disks and
configuration, and check recovery before removing lab VMs.

Lab B can deliver its raw data before an Elastic connector exists. AEGIS verdicts
require reviewed connectors and a suitable approved scenario/profile contract;
the current Wazuh SCN-001 cannot be converted to Elastic by changing its profile
alone. Do not relabel Elastic records as Wazuh or modify existing ground truth
to make them pass.

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
path only, not lab coverage.

`aegis compare --before <report> --after <report>` compares two runs of the same
scenario, profile and bindings ([compare guide](docs/CLI_COMPARE.md)). It is
built for Gap → Fix: `Regression Passed` needs a `false_negative` assertion to
become `satisfied`. A control round followed by a block round therefore reports
`Inconclusive` by design; the block round's own verdict is the conclusion.

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

## Opt-in local operations workspace

The owner-approved Operations milestone is **SCN-001 local lab MVP**, including
the SCN-001 workflow and Reports/Agents/Collections. SCN-002 was validated
separately through exported evidence bundles, not through Operations.
This is not full-PRD live acceptance or a production-readiness claim.

Reports remain read-only by default. The optional Operations mode adds manual
Wazuh agent inventory and bounded historical collection; it does not run
scenarios, change rules, or automatically evaluate collected evidence.

Start with the [Vietnamese operator guide](docs/OPERATIONS.md) and
[private configuration requirements](docs/OPERATIONS_BACKEND.md). Server API
and Indexer credentials are separate and must stay outside Git and browser UI.
See the [acceptance record and remaining release gates](docs/OPERATIONS_ACCEPTANCE.md)
for tested revisions, live proof references and original PRD limitations.

## Security and data handling

- Never commit credentials, tokens, webhooks, certificates, `.env` files, or raw
  production exports.
- Collect raw exports and private configurations outside a Git working tree.
  The local `raw-evidence/` archive is ignored by Git; it is for reviewed archive
  copies, not a live collector destination or a substitute for independent backup.
- Sanitize hostnames, usernames, public IPs, secrets, and organization identifiers
  before adding fixtures.
- Keep timestamps and correlation fields internally consistent so timelines remain
  testable.

See [the fixture policy](tests/fixtures/README.md) and
[the threat model](docs/THREAT_MODEL.md) before committing evidence.

## Scope

AEGIS Verify is not a SIEM, full SOAR platform, autonomous response agent, or
multi-tenant SaaS product. Further integrations and production features require
separate reviewed scope and acceptance criteria.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
Lab evidence and private configurations are not part of the repository and are not
covered by this license.
