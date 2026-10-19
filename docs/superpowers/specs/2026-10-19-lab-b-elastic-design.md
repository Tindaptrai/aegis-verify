# Lab B offline Elastic integration

User request: implement the missing Lab B adapter/profile, verify the integration,
and deliver a new private handoff. This extends the existing connector → canonical
event → profile → CLI report path. Existing scenario ground truth stays unchanged.

## Scope and decisions

Add the distinct `elastic` source to canonical/scenario/profile closed sets. Add
four explicit byte parsers: `elastic-sysmon1-v1`, `elastic-sysmon3-v1`,
`elastic-powershell4104-v1`, `elastic-security-alert-v1`. They consume one complete
exported Elasticsearch search hit, including `_index`, `_id`, and `_source`.
Bundle assembly extracts exact individual JSONL line slices; no live dependency
or binary EVTX dependency is introduced. Original EVTX remains native comparison
evidence, not an input silently converted to a different source type.

Parse native Windows `event.original` XML as the authority for provider/channel,
record ID, process/PID, network tuple, and single-part 4104 facts. Canonical source
timestamp is **XML System.TimeCreated**, at its original precision, for all three
Windows profiles. Preserve Sysmon UtcTime and normalized @timestamp separately in
provenance; never repair clocks or substitute collection time. Validate exported
identity aliases against the XML when present. Reject DTD/entities, duplicate
JSON/XML fields, invalid namespace, contradictory identities, boolean integers,
invalid ports, missing required identity/time and incomplete/multipart script
blocks. Diagnostics use fixed vocabulary and never echo source values.

Telemetry has no rule ID inferred from copied ECS fields and cannot accept an
Elastic alert shape. Alert shape is explicitly the reviewed flat dotted
`event.kind=signal` / `kibana.alert.*` representation; no arbitrary flattening.
Alert canonical time is `kibana.alert.start`, its first detection time, while
copied Windows time stays provenance. Alert `event_provider=elastic-security`
distinguishes the producing system from the copied Windows provider. Rule ID is
`kibana.alert.rule.rule_id`, not the alert UUID. Textual severity/risk score is not
invented into canonical integer severity. Preserve alert ancestors, rule revision,
native identity, source and alert document identities.

Every event uses the `elastic:evidence-v1:` identity namespace, exact raw bytes,
source_ref and environment in stable evidence identity. Provenance is immutable
and retains source-specific fields; absent optional canonical facts remain null.
Environment labels supplied in the hit must agree with caller context.

## Separate Lab B scenarios

SCN-005: safe PowerShell execution through Elastic. A01 requires Sysmon1 process
creation facts (provider, exact bound executable/PID/host, command line present).
A02 requires a complete single-part PowerShell4104 for that child PID/host. A03
requires the reviewed custom Elastic rule `aegis-labb-safe-powershell-v1`, joined
to A02 on hostname/process_id within **0–120 seconds**. This window is the planned
operational alert observation budget, pinned before new runs; it is not a change
to SCN-001. Expected outcome is detected. Alert-only and Sysmon3-only data cannot
satisfy source telemetry. Missing alerts remain Inconclusive without an independently
justified complete-collection declaration.

SCN-006: safe HTTP visibility. A01 is Elastic Sysmon3 for the bound 5-tuple;
A02 is Suricata IDS SID9900201/rev1 for that tuple, joined to A01 within ±3 seconds;
A03 is pfSense **allowed** telemetry for that exact bound 5-tuple/tracker. Expected
outcome is detected, not prevented; HTTP body/status and bidirectional packet
counts remain independently verified raw operational facts.

All lab addresses, hosts, PIDs, ports and tracker assignments enter context bindings.
Synthetic fixtures use documentation addresses and artificial identities. Production
code never fabricates events. Existing SCN-001–004 bytes and profiles remain intact.

## Verification and delivery

Write failing tests before each behavior change. Cover parser robustness/precision,
source isolation, intake/packaging, positive and negative profile contracts,
deterministic reports, and unchanged existing scenario tests. Use no new runtime
dependency. Run relevant tests, full backend suite, wheel build/install smoke and
frontend checks if its source presentation is affected.

Evaluate frozen historical evidence with explicit retrospective labels. After
contract/profile/code pins, run fresh approved benign PowerShell and HTTP tests,
collect native/Elastic/raw sources, reconcile exact identities and ancestor
references, then generate actual CLI reports/ledger/EIDs and replay the frozen
bundles deterministically. Canonical PID/time joins do not prove an exact Elastic
ancestor join: verify exact index/document lineage in a separate provenance audit.

Keep raw evidence, credentials, TLS material, native artifacts and full private
reports outside Git. Deliver source changes, test/build logs, real reports,
provenance, native inputs, replay instructions and ZIP SHA256 in a new handoff.
Do not overwrite earlier archives, make full VM backups, modify VM networking, or
merge code without the repository's human review. New manifests are reviewable
drafts authorized for implementation by this request, not claims of upstream
owner approval or production stability.
