# SCN-003 Offline Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fixture-first SCN-003 path that evaluates one bounded Cowrie login-failure interaction across Suricata, pfSense, Cowrie, and Wazuh without creating lab traffic or changing scenario ground truth.

**Architecture:** Keep pre-NAT and post-NAT evidence as separate telemetry roots. Suricata detection correlates to the pfSense pre-NAT event; Wazuh detection correlates to the Cowrie post-NAT login event. Promote Cowrie's existing privacy-safe session hash into an optional canonical `session_key`, add one strict Wazuh manager-alert parser for Cowrie-derived alerts, reuse the existing three source parsers, and prove the complete contract through a synthetic four-source CLI bundle.

**Tech Stack:** Python 3.11+, Pydantic 2, pytest, YAML/JSON fixtures, Suricata rule syntax, Wazuh XML rules.

**Spec:** `docs/superpowers/specs/2026-09-23-scn003-safe-cowrie-design.md`

## Global Constraints

- Work only on GitHub issue #76 and branch `codex/scn003-safe-cowrie-design`.
- Do not modify `scenarios/SCN-003-internal-deception.yaml`; its draft status and ground truth remain unchanged.
- Do not access the lab, install detection content, start VMs, create network traffic, or use real credentials in this plan.
- Keep lab IP addresses, ports, firewall trackers, usernames, passwords, certificates, and connector URLs out of Git.
- Use only canonical fields in evaluation rules. Absent values remain `null`; never infer NAT translations or source fields.
- Treat every committed fixture as synthetic. A green test proves software behavior only, not live detection coverage.
- Pin the reviewed IDs `1000012` (Suricata SID) and `120003` (Wazuh rule ID). Before implementation, fail if either ID appears outside this plan/spec.
- Never serialize a password into canonical events, provenance, fixtures, reports, diagnostics, or test failure output.
- Use LF endings and one trailing newline for committed rule templates and fixtures.

## Review Focus

- The two NAT domains must never be collapsed: A01/A02 use `decoy_ip` and `decoy_port`; A03/A04 use `cowrie_ip` and `cowrie_port`.
- A01 and A04 are detections with literal reviewed IDs; A02 and A03 are telemetry roots.
- Correlation must include source IP, source port, destination IP, destination port, protocol, and bounded time. A04 also joins the privacy-safe Cowrie `session_key` and pins the run-scoped username.
- The Wazuh parser must reject search-hit envelopes, non-Cowrie groups, non-login-failure data, malformed rule IDs, and missing source timestamps.
- Synthetic tests must cover missing sources, wrong IDs, wrong NAT bindings, source-port rewrite, wrong username, out-of-window evidence, and cross-run evidence.
- The offline PR must not claim the live run is complete. A separate reviewed live-acceptance plan is required.

## Implementation Environment

Before Task 1, create an isolated interpreter in this worktree and use it for every command below:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scenario_loader.py -q
```

Expected: the scenario-loader tests pass. Dependency installation is limited to the versions already pinned in `pyproject.toml`; this plan adds no dependency.

---

## Task 1: Add reviewed SCN-003 detection content

**Files:**

- Create: `detections/suricata/scn-003/decoy-connect.rules.template`
- Create: `detections/wazuh/scn-003/login-failed.xml.template`
- Create: `backend/tests/test_scn003_detection_content.py`
- Create: `docs/SCN003_DETECTION_CONTENT.md`

- [ ] **Step 1: Prove the IDs are unclaimed**

Run:

```powershell
rg -n --glob '!docs/superpowers/plans/2026-09-24-scn003-offline-foundation.md' --glob '!docs/superpowers/specs/2026-09-23-scn003-safe-cowrie-design.md' '1000012|120003' .
```

Expected: no output. If either ID is present, stop and amend the spec with a reviewed replacement before writing rules.

- [ ] **Step 2: Write failing content-contract tests**

Create tests that require:

```python
SURICATA_SID = "1000012"
WAZUH_RULE_ID = "120003"
SURICATA_VARIABLES = {"src_net", "decoy_ip", "decoy_port"}
WAZUH_VARIABLES = {"parent_group"}

def test_suricata_rule_is_one_tcp_syn_alert_with_fixed_sid():
    text = SURICATA.read_text("utf-8")
    assert text.count("alert tcp ") == 1
    assert "flags:S;" in text
    assert "sid:1000012;" in text
    assert 'msg:"AEGIS SCN-003 decoy connection"' in text

def test_wazuh_rule_is_one_cowrie_login_failure_detection():
    root = ElementTree.fromstring(WAZUH.read_text("utf-8"))
    rule = root.find("rule")
    assert rule is not None and rule.attrib == {"id": "120003", "level": "5"}
    fields = {node.attrib["name"]: node.text for node in rule.findall("field")}
    assert fields["data.eventid"] == r"\Acowrie\.login\.failed\z"
    assert fields["data.username"] == r"\AAEGIS-SCN003-[0-9a-f]{8}\z"
```

Also test exact template variables, valid XML after substituting `parent_group=cowrie`, no IPv4 literal, no password field/value, LF endings, one trailing newline, and exactly one rule per file.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_detection_content.py -q
```

Expected: FAIL because the templates do not exist.

- [ ] **Step 3: Add the Suricata template**

Use this single reviewed rule, with deployment values left as explicit template variables:

```text
alert tcp $src_net any -> $decoy_ip $decoy_port (msg:"AEGIS SCN-003 decoy connection"; flow:to_server; flags:S; classtype:policy-violation; metadata:aegis_scenario SCN-003, confidence High; sid:1000012; rev:1;)
```

The rule observes only a TCP SYN to the approved decoy endpoint. It does not scan and does not claim compromise.

- [ ] **Step 4: Add the Wazuh template**

Use one child rule tied to a reviewed Cowrie parent group:

```xml
<!-- AEGIS SCN-003 LAB ONLY: one reviewed login-failure marker. -->
<group name="aegis_scn003,cowrie,">
  <rule id="120003" level="5">
    <if_group>$parent_group</if_group>
    <field name="data.eventid" type="pcre2">\Acowrie\.login\.failed\z</field>
    <field name="data.username" type="pcre2">\AAEGIS-SCN003-[0-9a-f]{8}\z</field>
    <description>AEGIS SCN-003 lab marker: one Cowrie login failure; not a compromise verdict.</description>
    <options>no_email_alert</options>
  </rule>
</group>
```

The only variable is the parent group verified later with `wazuh-logtest`. Rule ID and marker grammar are fixed in Git.

- [ ] **Step 5: Document rendering and offline limitations**

`docs/SCN003_DETECTION_CONTENT.md` must state:

- the two fixed IDs and their meanings;
- exact accepted username grammar `AEGIS-SCN003-[0-9a-f]{8}`;
- the three Suricata deployment variables and one Wazuh parent-group variable;
- synthetic/XML tests do not prove either engine loads or fires the rule;
- rendered files and lab values stay outside Git;
- live installation is deferred to a separate approved plan.

- [ ] **Step 6: Run tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_detection_content.py -q
git diff --check
git add detections/suricata/scn-003 detections/wazuh/scn-003 backend/tests/test_scn003_detection_content.py docs/SCN003_DETECTION_CONTENT.md
git commit -m "feat(scn-003): add reviewed deception detections (#76)"
```

Expected: all tests pass and commit contains no rendered lab values.

## Task 2: Promote the Cowrie session key and add the strict Wazuh alert parser

**Files:**

- Modify: `backend/app/models/_canonical_fields.py`
- Modify: `backend/app/validation/contracts.py`
- Modify: `connectors/cowrie/parser.py`
- Modify: `connectors/cowrie/native.py`
- Create: `connectors/wazuh/cowrie_alert.py`
- Modify: `connectors/wazuh/__init__.py`
- Modify: `backend/app/intake/contracts.py`
- Modify: `backend/app/intake/registry.py`
- Modify: `docs/CANONICAL_EVENT.md`
- Modify: `docs/CANONICAL_EVENT_V2.md`
- Create: `tests/fixtures/wazuh/cowrie-alert/wazuh-cowrie-alert.synthetic.json`
- Create: `tests/fixtures/wazuh/cowrie-alert/README.md`
- Modify: `backend/tests/test_canonical_event.py`
- Modify: `backend/tests/test_canonical_event_v2.py`
- Modify: `backend/tests/test_validation_contracts.py`
- Modify: `backend/tests/test_cowrie_parser.py`
- Modify: `backend/tests/test_cowrie_native_parser.py`
- Create: `backend/tests/test_wazuh_cowrie_alert.py`
- Modify: `backend/tests/test_intake_bundle.py`

- [ ] **Step 1: Write failing canonical session-key tests**

Add optional `session_key` coverage to both canonical versions. Accept only the existing opaque namespace and digest shape:

```python
SESSION_KEY_PATTERN = r"^cowrie:session-v1:[0-9a-f]{64}$"

event = event_factory(session_key="cowrie:session-v1:" + "a" * 64)
assert event.session_key == "cowrie:session-v1:" + "a" * 64
```

Reject raw Cowrie session IDs, blank strings, uppercase hex, wrong namespaces, and wrong digest lengths without echoing the rejected value. Add `session_key` to validation `FILTER_FIELDS` and `JOIN_FIELDS`, but not `TARGET_FIELDS`: an assertion must still carry an independently scoped IP/username binding.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_canonical_event.py backend/tests/test_canonical_event_v2.py backend/tests/test_validation_contracts.py -q
```

Expected: FAIL because `session_key` is not a canonical field.

- [ ] **Step 2: Implement and document the optional privacy-safe field**

Add to `CanonicalFields`:

```python
SessionKey = Annotated[
    StrictStr,
    Field(pattern=r"^cowrie:session-v1:[0-9a-f]{64}$"),
]

session_key: SessionKey | None = None
```

Map the already-computed `provenance.session_key` into native and Wazuh-wrapped Cowrie canonical events. Do not expose the raw source session. Update both canonical documents: the field is an opaque correlation identifier, optional for every source, and never a replacement for evidence identity.

Run the same focused tests plus existing Cowrie tests. Expected: PASS.

- [ ] **Step 3: Create a synthetic manager-alert fixture with explicit lineage**

The fixture is one Wazuh manager alert, not an Indexer search hit. Its supported envelope is:

```json
{
  "timestamp": "2026-01-01T00:00:11.250+0000",
  "rule": {
    "level": 5,
    "description": "AEGIS SCN-003 lab marker",
    "id": "120003",
    "groups": ["cowrie", "aegis_scn003"]
  },
  "agent": {"id": "013", "name": "synthetic-cowrie"},
  "manager": {"name": "synthetic-manager"},
  "id": "1767225611.250",
  "data": {
    "eventid": "cowrie.login.failed",
    "username": "AEGIS-SCN003-1a2b3c4d",
    "timestamp": "2026-01-01T00:00:10.800000+0000",
    "src_ip": "192.0.2.10",
    "src_port": 51003,
    "dst_ip": "198.51.100.20",
    "dst_port": 2222,
    "protocol": "ssh",
    "session": "synthetic-session-003"
  }
}
```

The README must label every value synthetic, state that no password is present, and record that a real sanitized sample must be reviewed before live acceptance.

- [ ] **Step 4: Write failing parser tests**

Require this public API:

```python
def parse_wazuh_cowrie_alert_record(
    raw: bytes,
    *,
    source_ref: str,
    environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
    collection_mode: str,
) -> CowrieAlertResult: ...
```

Happy-path assertions:

```python
event = parse(sample).event
assert event.source_type == "wazuh"
assert event.event_provider == "cowrie"
assert event.rule_id == "120003"
assert event.event_action == "login"
assert event.username == "AEGIS-SCN003-1a2b3c4d"
assert (str(event.src_ip), event.src_port) == ("192.0.2.10", 51003)
assert (str(event.dst_ip), event.dst_port) == ("198.51.100.20", 2222)
assert event.protocol == "ssh"
assert event.session_key.startswith("cowrie:session-v1:")
assert event.timestamp.isoformat() == "2026-01-01T00:00:10.800000Z"
```

Compare tuple, username, action, protocol, session key, and source timestamp with `parse_cowrie_jsonl()` over the same `data` object using the same `environment_id` and `sensor_id`. Assert only `source_type`, Wazuh rule identity, and evidence identity differ.

Negative cases must reject `_source`, missing/non-list groups, missing `cowrie` group, wrong event type, success login, command event, missing source session, missing source timestamp, non-decimal Wazuh rule ID, malformed canonical fields, and any input containing a `password` member. Assert diagnostics expose field paths only and never rejected values.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_wazuh_cowrie_alert.py -q
```

Expected: FAIL because the parser is absent.

- [ ] **Step 5: Implement the parser by reusing Cowrie mapping**

Implement `CowrieAlertProvenance` and `CowrieAlertResult` as frozen, closed Pydantic models. Parse the manager envelope with `connectors/wazuh/_json.py` helpers, then call:

```python
fields, metadata = map_cowrie_event(data, prefix="data.")
if metadata["source_event_type"] != "cowrie.login.failed":
    raise WazuhParseError("unsupported_profile", "data.eventid") from None
if metadata["session"] is None:
    raise WazuhParseError("invalid_field", "data.session") from None
if "password" in data:
    raise WazuhParseError("unsupported_profile", "data.password") from None
fields.update(
    source_type="wazuh",
    event_provider="cowrie",
    rule_id=rule_id,
    source_record_id=source_id,
    asset_id=agent_id if collection_mode == "direct" else None,
    session_key=session_key(environment_id, sensor_id, metadata["session"]),
)
```

Use Cowrie source time as canonical `timestamp`; retain Wazuh receipt time only in provenance. Construct event ID and raw reference with the same `wazuh:evidence-v1` identity policy as `suricata_alert.py`.

- [ ] **Step 6: Wire the closed intake registry**

Add parser key `wazuh-cowrie-alert-v1` and a closed `WazuhCowrieAlertContext` containing `ingested_at`, `collection_mode`, and `sensor_id`. The `sensor_id` must match the direct Cowrie parser context so both views derive the same session key. Set canonical source type to `wazuh`, dispatch to the new parser, and include the key in the single-record branch of `parse_entry()`.

Extend `test_intake_bundle.py` with the synthetic fixture and assert exactly one Wazuh event and one ledger entry.

- [ ] **Step 7: Run focused and regression tests, then commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_canonical_event.py backend/tests/test_canonical_event_v2.py backend/tests/test_validation_contracts.py backend/tests/test_wazuh_cowrie_alert.py backend/tests/test_intake_bundle.py backend/tests/test_cowrie_parser.py backend/tests/test_cowrie_native_parser.py backend/tests/test_wazuh_suricata_alert.py -q
git diff --check
git add backend/app/models/_canonical_fields.py backend/app/validation/contracts.py connectors/cowrie/parser.py connectors/cowrie/native.py connectors/wazuh backend/app/intake docs/CANONICAL_EVENT.md docs/CANONICAL_EVENT_V2.md backend/tests/test_canonical_event.py backend/tests/test_canonical_event_v2.py backend/tests/test_validation_contracts.py backend/tests/test_cowrie_parser.py backend/tests/test_cowrie_native_parser.py backend/tests/test_wazuh_cowrie_alert.py backend/tests/test_intake_bundle.py tests/fixtures/wazuh/cowrie-alert
git commit -m "feat(wazuh): parse Cowrie-derived manager alerts (#76)"
```

Expected: all focused tests pass; no fixture contains a password key or value.

## Task 3: Add the SCN-003 evaluation profile and contract tests

**Files:**

- Create: `scenarios/profiles/scn-003/profile.json`
- Create: `scenarios/profiles/scn-003/context.example.json`
- Create: `scenarios/profiles/scn-003/README.md`
- Create: `backend/tests/test_scn003_profile.py`

- [ ] **Step 1: Write failing profile tests with synthetic canonical events**

Pin scenario fingerprint:

```text
d84ec3dbd59081ac6e275ef62393f2eff6cdcac207c3b28332737274184d1550
```

The example context must define exactly these non-lab bindings:

```text
initiator_ip, initiator_port, decoy_ip, decoy_port,
cowrie_ip, cowrie_port, firewall_rule_tracker, username_marker
```

Build four synthetic canonical events:

- A02 root: `pfsense`, pre-NAT tuple, `event_action=allowed`, reviewed firewall tracker.
- A01 witness: `suricata`, pre-NAT tuple, `signature_id=1000012`.
- A03 root: `cowrie`, post-NAT tuple, `event_action=login`, run username.
- A04 witness: `wazuh`, `event_provider=cowrie`, post-NAT tuple, `rule_id=120003`, same username.

Tests must prove:

1. all four witnesses produce final status `Detected`;
2. A01 anchors only on A02 and A04 anchors only on A03;
3. removing each source produces no `Detected` verdict;
4. wrong SID/rule ID produces `False negative` when its telemetry root remains;
5. wrong decoy or Cowrie destination never correlates;
6. rewritten source port never correlates across NAT;
7. wrong username never satisfies A03/A04;
8. a witness 1 ns beyond the five-second synthetic contract window fails;
9. events from another run tuple/username cannot be mixed into a green verdict;
10. empty evidence returns `Missing telemetry`.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_profile.py -q
```

Expected: FAIL because the profile and context do not exist.

- [ ] **Step 2: Implement the profile with two telemetry roots**

Use profile ID `scn003-single-cowrie-session-detected`, version `0.1.0`.

A02 is the pre-NAT telemetry root:

```json
{
  "assertion_id": "SCN-003-A02",
  "role": "telemetry",
  "capability": "supported",
  "source_type": "pfsense",
  "scope": [
    {"field": "src_ip", "op": "eq", "binding": "initiator_ip"},
    {"field": "src_port", "op": "eq", "binding": "initiator_port"},
    {"field": "dst_ip", "op": "eq", "binding": "decoy_ip"},
    {"field": "dst_port", "op": "eq", "binding": "decoy_port"},
    {"field": "protocol", "op": "eq", "value": "tcp"}
  ],
  "match": [
    {"field": "event_action", "op": "eq", "value": "allowed"},
    {"field": "rule_id", "op": "eq", "binding": "firewall_rule_tracker"}
  ]
}
```

A01 is a Suricata detection scoped to the same pre-NAT bindings with `protocol=TCP`, `signature_id=1000012`, and correlation to A02 on the full four-field tuple over `[-5s,+5s]`. Protocol is pinned separately because the source parsers preserve different case.

A03 is the post-NAT telemetry root scoped to initiator IP/port, Cowrie IP/port, `protocol=ssh`, username binding, `session_key` existence, and `event_action=login`. The login event is the primary assertion witness. A same-session `session.connect` event remains supporting timeline evidence, verified by the bundle contract test without teaching the validation engine to read source provenance.

A04 is a Wazuh detection scoped to the same post-NAT bindings with `event_provider=cowrie`, `rule_id=120003`, username binding, and correlation to A03 on source IP/port, destination IP/port, protocol, username, and `session_key` over `[-5s,+5s]`.

- [ ] **Step 3: Document what the profile does not prove**

The README must state:

- the five-second window is a conservative synthetic contract, not a measured lab allowance;
- live acceptance must replace it only through reviewed readiness evidence if clocks require a different window;
- source IP and source port preservation is a hard gate;
- the example context uses documentation-only addresses and no credential;
- collection declarations remain `unknown` until a reviewer signs complete coverage.

- [ ] **Step 4: Run tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_profile.py backend/tests/test_validation_engine.py -q
git diff --check
git add scenarios/profiles/scn-003 backend/tests/test_scn003_profile.py
git commit -m "feat(scn-003): add two-domain evaluation profile (#76)"
```

Expected: all profile and engine tests pass without changing the scenario manifest.

## Task 4: Prove the complete offline path through the real CLI

**Files:**

- Create: `tests/fixtures/cli/scn003-synthetic-detected/inputs.json`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/context.json`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/filterlog-pass.log`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/eve-alert.jsonl`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/cowrie-session.jsonl`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/wazuh-cowrie-alert.json`
- Create: `tests/fixtures/cli/scn003-synthetic-detected/README.md`
- Create: `backend/tests/test_scn003_cli_bundle.py`

- [ ] **Step 1: Write the failing CLI integration test**

Run the production CLI:

```python
result = subprocess.run(
    [sys.executable, "-m", "aegis_verify", "validate",
     "--scenario", str(SCENARIO), "--fixture", str(BUNDLE),
     "--profile", str(PROFILE), "--format=json"],
    capture_output=True, text=True, check=False, cwd=str(ROOT),
)
```

Assert return code 0, final status `Detected`, exactly five parsed/referenced events, four satisfied assertions, A01 witness anchored on the pfSense evidence ID, A04 witness anchored on the Cowrie login evidence ID, and timeline source types exactly `{pfsense, suricata, cowrie, wazuh}`.

Parse `cowrie-session.jsonl` directly in a fixture-contract test and assert it contains exactly one `cowrie.session.connect` followed by one `cowrie.login.failed`, both with the same non-null canonical `session_key`. This is the supporting proof for the two Cowrie records; the validation engine still uses only canonical fields.

Add portable-copy mutation tests for:

- filterlog source port changed by one;
- Suricata SID changed;
- Cowrie username changed without changing Wazuh;
- Cowrie connection session changed without changing the login session;
- Wazuh session changed while tuple and username remain equal;
- Wazuh rule ID changed;
- Wazuh timestamp moved beyond the window;
- one evidence file removed from `inputs.json`;
- bytes changed without updating SHA-256.

Every mutation except hash tampering must emit a report whose final status is not `Detected`; hash tampering must stop intake without a report.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_cli_bundle.py -q
```

Expected: FAIL because the bundle does not exist.

- [ ] **Step 2: Create internally consistent synthetic evidence**

Use documentation ranges only:

- initiator `192.0.2.10:51003`;
- decoy `203.0.113.30:22`;
- Cowrie `198.51.100.20:2222`;
- username `AEGIS-SCN003-1a2b3c4d`;
- firewall tracker `1700000003`;
- source times within one second of `2026-01-01T00:00:10Z`.

The Cowrie JSONL must contain exactly `session.connect` and `login.failed` with one shared synthetic source session; the parser exposes only their derived session key. The Cowrie events and Wazuh alert must contain no password field. `inputs.json` must list exact byte SHA-256 values and explicit parser contexts, using the same Cowrie `sensor_id` for direct and Wazuh-derived evidence. The README must state that all records are invented and are not lab evidence.

- [ ] **Step 3: Run the complete offline suite and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_scn003_detection_content.py backend/tests/test_wazuh_cowrie_alert.py backend/tests/test_scn003_profile.py backend/tests/test_scn003_cli_bundle.py backend/tests/test_intake_bundle.py -q
.\.venv\Scripts\python.exe -m pytest backend/tests -q
git diff --check
git status --short
git add tests/fixtures/cli/scn003-synthetic-detected backend/tests/test_scn003_cli_bundle.py
git commit -m "test(scn-003): prove synthetic four-source CLI path (#76)"
```

Expected: full backend suite passes; only intentionally committed files exist; no lab values or credentials are present.

## Task 5: Close the offline milestone and prepare the separate live gate

**Files:**

- Modify: `docs/SCN003_DETECTION_CONTENT.md`
- Create: `docs/SCN003_OFFLINE_ACCEPTANCE.md`
- Create later in a separate reviewed change: `docs/superpowers/plans/2026-09-24-scn003-live-single-session.md`

- [ ] **Step 1: Record offline acceptance evidence**

`docs/SCN003_OFFLINE_ACCEPTANCE.md` must include:

- issue and commit IDs;
- exact test commands and results;
- scenario/profile fingerprints;
- detection IDs `1000012` and `120003`;
- synthetic bundle inventory and SHA-256 verification result;
- explicit statement: no VM was started, no lab config changed, and no live traffic was generated;
- explicit remaining gates: real manager-alert shape, `suricata -T`, `wazuh-logtest`, NAT source preservation, clock measurements, one-session owner approval, evidence review, rollback.

- [ ] **Step 2: Run secret and lab-value review**

Run:

```powershell
rg -n -i 'password|passwd|token|secret|api[_-]?key|192\.168\.|10\.0\.' detections/suricata/scn-003 detections/wazuh/scn-003 scenarios/profiles/scn-003 tests/fixtures/cli/scn003-synthetic-detected tests/fixtures/wazuh/cowrie-alert docs/SCN003_*.md
git diff origin/main...HEAD --check
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

Expected: only explanatory statements about forbidden credentials match; no secret value or lab IP appears; all tests pass.

- [ ] **Step 3: Request human review; do not merge automatically**

Reviewers must confirm:

1. rule semantics and fixed IDs;
2. parser envelope and password exclusion;
3. pre/post NAT separation and correlation joins;
4. negative-test matrix and evidence IDs;
5. absence of live claims and ground-truth changes.

Commit the acceptance document:

```powershell
git add docs/SCN003_DETECTION_CONTENT.md docs/SCN003_OFFLINE_ACCEPTANCE.md
git commit -m "docs(scn-003): record offline acceptance gates (#76)"
```

- [ ] **Step 4: Write the live plan only after review**

The separate live plan must use the accepted offline commit and define exact owner-filled local configuration, preflight, engine validation, one connection, one login failure, bounded collection, sanitization, CLI evaluation, rollback, and stop conditions. It must stop before traffic if source IP/port preservation, clock health, rule loading, or real Wazuh alert shape is not proven.

Do not include live execution in the offline pull request.
