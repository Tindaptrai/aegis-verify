# AEGIS Verify

Continuous detection validation and evidence-driven SOC readiness platform.

AEGIS Verify evaluates exported evidence from approved security tests, normalizes
telemetry from security controls, and links each validation result to raw evidence.
Its core workflow is **Gap → Rule Fix → Re-test → Pass**. Scenario execution and
rule changes remain separate, operator-controlled steps.

> Status (2026-10-21, package version **0.3.0**, Apache-2.0): lab MVP with six
> scenarios and the merged Lab B and Lab C integrations. Results use real lab
> evidence evaluated offline through the engine:
>
> - SCN-001 `Regression Passed` ([v3 result](docs/SCN001_V3_RESULT_2026-09-27.md));
> - SCN-002 `Prevented` ([result](docs/SCN002_RESULT_2026-09-22.md));
> - SCN-003 `Detected` ([result](docs/SCN003_RESULT_2026-09-26.md));
> - SCN-004 / Lab C: owner-accepted scenario/profile **0.2.0**, including the SIEM
>   alert assertion A04. The normal → sensor-agent outage → recovery sequence reports
>   `Prevented` → `Inconclusive` → `Prevented`
>   ([evidence and acceptance](docs/SCN004_LAB_C_ACCEPTANCE.md),
>   [approval and pins](docs/SCN004_A04_APPROVAL_AND_PINS.md)).
> - SCN-005/006 / Lab B: offline Elastic integration is merged in
>   [PR #144](https://github.com/Tindaptrai/aegis-verify/pull/144). Technical
>   evidence was **accepted within the reviewed lab scope on 2026-10-21**:
>   DK-01 human review and DK-03 backup/recovery are closed; DK-02 retains its
>   run-specific software-operation exception
>   ([acceptance and scope](#lab-b-conditional-technical-acceptance)).
>
> Read-only collectors exist for the Wazuh Indexer (Python 3.11–3.13) and for
> SCN-002/SCN-003 lab rounds (`aegis collect`). This is a single-operator lab tool,
> not production certification or live fleet monitoring. Collection assurance is
> attested by the operator, and all six manifests still declare `status: draft`.
> Lab B uses exported Elastic files and separate SCN-005/006 profiles; it has no
> live Elastic collector. See [Lab B integration](docs/LABB_ELASTIC.md);
> historical results remain scoped to their original commits and labs.
>
> **New to the project or running it in another lab?** Start with the
> [lab onboarding guide](docs/LAB_ONBOARDING.md), then the
> [offline demo](docs/DEMO_WALKTHROUGH.md). Release notes:
> [0.3.0](docs/RELEASE_NOTES_0.3.0.md).

## Standalone distribution preview

The wheel includes the built dashboard, six unchanged scenario manifests and
reviewed public demo inputs. After installing the wheel in a fresh environment,
run outside the checkout (the output directory must be new and its parent must exist):

```powershell
aegis demo --out "$env:TEMP\aegis-demo-new"
aegis dashboard --bundled --reports "$env:TEMP\aegis-demo-new\reports"
```

The replay evaluates eight cases and writes twelve reports. SCN-002/003/004 use
sanitized derivatives; SCN-005/006 and the separate Gap/Fix comparison are
synthetic examples. It does not run live scenarios or certify enterprise coverage.
Without `--bundled`, the dashboard retains its explicit static/scenario options.

For Windows EXE builds and the fresh-machine acceptance checklist, see
[Windows distribution](docs/WINDOWS_DISTRIBUTION.md). The offline EXE includes
Python and the UI; it is a local CLI preview. MSI rollout and authenticated shared
server deployment have separate gates in [enterprise deployment](docs/ENTERPRISE_DEPLOYMENT.md).
Source wheel builds require a fresh `npm ci` / `npm run build` in `frontend/` first.

## Implemented lab scope

- 6 security scenario manifests: SCN-001 through SCN-006
- 7 source families: Wazuh, Elastic, Suricata, pfSense, Cowrie, Snort 3, and OPNsense
- 18 registered bundle parser keys; fixture tests require no live lab
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
connectors/    Parsers for seven source families; bounded read-only Wazuh reader
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
accepts eighteen keys; inputs and required context are documented in the
[CLI guide](docs/CLI_VALIDATE.md) and the [Elastic parser contract](docs/ELASTIC_PARSER.md).

| Source | Keys | Guide |
| --- | --- | --- |
| Elastic, offline exports | `elastic-sysmon1-v1`, `elastic-sysmon3-v1`, `elastic-powershell4104-v1`, `elastic-security-alert-v1` | [Parser contract](docs/ELASTIC_PARSER.md), [Lab B integration](docs/LABB_ELASTIC.md) |
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

[Scenario YAML v0.1](docs/SCENARIO_SCHEMA.md) validates the six draft manifests,
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
| [SCN-005](scenarios/SCN-005-powershell-elastic-lab-b.yaml) PowerShell telemetry and Elastic alert, Lab B | `detected` | `Detected` with 3/3 assertions and byte-identical replay for the reviewed run; [technical acceptance and scope](#lab-b-conditional-technical-acceptance), [profile](scenarios/profiles/scn-005/README.md). Full prepared timing contract remains unmet. |
| [SCN-006](scenarios/SCN-006-http-visibility-lab-b.yaml) HTTP visibility, Lab B | `detected` | Endpoint telemetry, Suricata IDS and pfSense allow for the tested flow; accepted Elastic network alerts = 0. [Technical acceptance and scope](#lab-b-conditional-technical-acceptance), [profile](scenarios/profiles/scn-006/README.md). No prevention claim. |

Ground truth changes need explicit owner approval; every manifest still says
`status: draft`.

For a 25-minute offline walkthrough of the original three scenarios and the dashboard,
see [the customer demo guide](docs/DEMO_WALKTHROUGH.md). PRD-by-PRD acceptance with
evidence links: [MVP_ACCEPTANCE.md](docs/MVP_ACCEPTANCE.md).

## Partner labs and handoff

| Lab | Stack and current status | Start here |
| --- | --- | --- |
| Lab A | Wazuh, pfSense, Suricata, Cowrie and Windows; original SCN-001/002/003 lab evidence | [Onboarding](docs/LAB_ONBOARDING.md), scenario result links above |
| Lab B | **Technical acceptance completed within the reviewed lab scope on 2026-10-21.** Offline Elastic Sysmon1/3, PowerShell4104 and Security alerts; SCN-005/006 draft profiles, direct EVE/filterlog and native EVTX comparison. DK-01 and DK-03 are closed; DK-02 retains its exception for the reviewed software-operated run only. | [Acceptance and scope](#lab-b-conditional-technical-acceptance), [integration](docs/LABB_ELASTIC.md) |
| Lab C | OPNsense, Snort 3, Wazuh and Windows. The reviewed code, runbook and acceptance chain is merged into main | [Runbook](docs/LABC_RUNBOOK.md), [acceptance](docs/SCN004_LAB_C_ACCEPTANCE.md), [approval and pins](docs/SCN004_A04_APPROVAL_AND_PINS.md) |

<a id="lab-b-conditional-technical-acceptance"></a>

### Lab B technical acceptance

**Lab B đã hoàn tất nghiệm thu kỹ thuật trong phạm vi bằng chứng đã kiểm ngày
21/10/2026: DK-01 và DK-03 đã đóng; DK-02 giữ ngoại lệ có phạm vi.** The original
conditional acceptance dated 2026-10-20 is retained as a historical record.
On 2026-10-21 the user accepted the reviewed backup/recovery evidence, and
Nguyễn Lê Trọng Tín directly confirmed in this chat that he had reviewed the
dossier and accepted the two disclosed timing variances and the replica change
within the lab scope. The private confirmation and closing appendix record these
decisions.

- Code integration: [PR #144](https://github.com/Tindaptrai/aegis-verify/pull/144)
  was merged on 2026-10-19 at `a8c894f8ad4e1ddecace4a9d73b2e35c9fbe4b22`.
- Reviewed SCN-005 run `LABB-OP-PS-20261019-01`: native → Elastic **28/28**,
  engine **`Detected`, 3/3 assertions**, and byte-identical offline replay.
  Codex software performed that run; independent human operation remains unproven.
- The two new Kibana photos are accepted. V2's **10/10** previously missing
  references and the appendix's **60/60** index entries and **58/58** technical
  references were checked. Neither new photos nor another V2 delivery is required.
- SCN-006 evidence is scoped to endpoint telemetry, Suricata IDS and pfSense
  allow for the tested flow. A historical PowerShell alert in the NET export is
  not a new network detection; accepted Elastic network alerts = **0**.

The full prepared timing contract **did not pass**: two ancillary Sysmon3 records
have absolute time differences of **3.5660511 s** and **3.5847297 s**, exceeding
the prepared **3 s** threshold. Neither is a child-process assertion witness;
the engine's 3/3 result retains its narrower scope. Preflight also changed
replicas from 1 to 0 on exactly two Security UI lists/items indices; the recorded
requests and readbacks were checked. Tín accepted these disclosed limits within
the lab scope; this does not turn the timing contract into a pass or provide
node-loss redundancy for the two indices.

| Condition | Recorded resolution |
| --- | --- |
| DK-01 — actual human review | **Closed, 2026-10-21.** Nguyễn Lê Trọng Tín directly confirmed that he reviewed the dossier and accepted both timing variances and the replica 1→0 change within the lab scope. His actual confirmation is retained with the completed review record. |
| DK-02 — independent operation | **Resolved by scoped exception, 2026-10-20.** Applies only to the reviewed evidence from `LABB-OP-PS-20261019-01`; independent human operation is not proven. |
| DK-03 — VM backup/recovery | **Closed, 2026-10-21.** The user accepted the inventory, disk/config hash catalogs and isolated boot/data/local-service recovery evidence for pfSense, Elastic, Windows, Sensor and DMZ. Full VM disks remain private; no disk upload or new recovery run is required. |

DK-03 closure covers the documented recovery checks. Source application
consistency and full-topology recovery were not established; four restored copies
needed disk repair before successful boot. Elastic and Windows source/copy pairs
share a drive, so this evidence does not establish independent protection against
loss of that physical drive.

**DK-02 — resolved by scoped exception on 2026-10-20:** the user accepted only
the reviewed evidence from software-operated run `LABB-OP-PS-20261019-01`.
This does not demonstrate that another human can independently operate the
runbook, or waive independent-operation requirements for other runs.

These decisions close the acceptance conditions within their recorded scope and
do not authorize VM cleanup. Manifests remain `draft` and collection assurance remains `unknown`;
there is no claim of sustained stability, prevention, gap→fix/regression or
detection outage→recovery for Lab B.

The reviewed SCN-005 witnesses are retained in the private report under these EIDs:

- Child Sysmon1: `elastic:evidence-v1:f2337755b8c2a2d8671232677c3c7d0473443a4647aa8e8db66ef84829b8f60b`.
- PowerShell marker: `elastic:evidence-v1:bb74454425768bef7e27600b1323131921c772a378684e10d4c6eaba56edc023`.
- Linked alert: `elastic:evidence-v1:52cac63fbf7e0f12d7fc4c88d82bdbf01d5076cfe19248f297558f342abaccc3`.

The local-only minutes and review archives are listed below. Lab B's public
fixture examples are synthetic; its raw lab evidence is not published here.

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
| `raw-evidence/lab-b/BIEN-BAN-NGHIEM-THU-KY-THUAT-LAB-B-CO-DIEU-KIEN-20261020.md` | Original conditional technical acceptance minutes; subsequent decisions are recorded separately below |
| `raw-evidence/lab-b/PHU-LUC-QUYET-DINH-DK02-DK03-LAB-B-20261020.md` | Historical decisions dated 2026-10-20: DK-02 run-specific exception and the retained backup/restore requirement. Later DK-01/DK-03 closure is recorded separately below |
| `raw-evidence/lab-b/nghiem-thu-2026-10-19/`, `raw-evidence/lab-b/nghiem-thu-2026-10-20/`, `raw-evidence/lab-b/nghiem-thu-2026-10-20-phu-luc/` | Frozen FINAL/live evidence and the V2/appendix archives, hash inventories, independent checks and review reports |
| `raw-evidence/lab-b/nghiem-thu-2026-10-21-dk01-dk03/` | Final documentary handoff, original ZIP, extracted members, hash verification and independent review of five-VM recovery proof |
| `raw-evidence/lab-b/nghiem-thu-2026-10-21-quyet-dinh/` | Historical DK-03 closure appendix and the unfilled DK-01 template prepared before Tín's confirmation |
| `raw-evidence/lab-b/nghiem-thu-2026-10-21-dong-dk01/` | Tín's exact direct confirmation, completed DK-01 review record and final scoped technical acceptance appendix |
| `raw-evidence/lab-b/LAB-B-CURRENT-STATUS.json` | Current acceptance state: DK-01 and DK-03 closed; DK-02 retains the run-specific exception |

Collect and assemble evidence into a private directory **outside a Git working
tree**, even if a subdirectory is ignored. Reviewed archive copies can be stored
locally afterward. Keep an independent backup of raw evidence, VM disks and
configuration, and check recovery before removing lab VMs.

Lab B evaluates exported Elastic evidence through its own offline parsers and
SCN-005/006 contracts. Native EVTX remains comparison evidence. Use the matching
profile and reviewed context bindings; do not relabel Elastic records as Wazuh
or change existing ground truth to make them pass.

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
