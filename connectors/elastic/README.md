# Offline Elastic export profiles

These four explicit adapters consume **one complete Elasticsearch search hit**
as UTF-8 JSON bytes containing `_index`, `_id`, and `_source`. They do not read
EVTX, connect to Elasticsearch, execute a scenario, or infer prevention.

| Registry key / mapping version | Exported record |
| --- | --- |
| `elastic-sysmon1-v1` | Microsoft-Windows-Sysmon/Operational, event 1 |
| `elastic-sysmon3-v1` | Microsoft-Windows-Sysmon/Operational, event 3, TCP or UDP |
| `elastic-powershell4104-v1` | Microsoft-Windows-PowerShell/Operational, complete single-part event 4104 |
| `elastic-security-alert-v1` | Elastic Security dotted-key `event.kind=signal` alert carrying a copied event 4104 |

Public functions are `parse_elastic_sysmon1_document`,
`parse_elastic_sysmon3_document`, `parse_elastic_powershell4104_document`, and
`parse_elastic_security_alert_document`. Each accepts `raw: bytes` and the
keyword-only context `source_ref`, `environment_id`, `ingested_at`. Each returns
an immutable `ElasticParseResult(event, provenance)` or raises
`ElasticParseError` with a fixed-vocabulary diagnostic. No runtime dependency was
added.

## Authority and clocks

Windows `event.original` XML is the authority for provider, channel, event and
record IDs, computer, process/PID, network tuple and script-block facts. Canonical
time is XML `System.TimeCreated` at its original precision for all three Windows
profiles. Sysmon `UtcTime`, the exported normalized `@timestamp`, source
`event.ingested`, collector identity and Sysmon clock delta are kept separately
in provenance. They never replace missing source time. `ingested_at` is the
caller-declared evidence intake time.

The alert profile uses `kibana.alert.start` for canonical time and the fixed
provider `elastic-security`; copied Windows time stays in provenance. The rule
identifier is `kibana.alert.rule.rule_id`. Textual alert severity and risk score
remain source metadata, not an invented canonical severity integer. Ancestors
retain exact source index/document identities. Parsing an ancestor does not
prove that the referenced source document exists; verify that separately.

## Identity, scope and optional facts

Canonical `asset_id` is the source's explicit `host.id`; `agent.id` is retained
as collector provenance. Windows process names are full native Image paths.
Script block text remains in hashed raw evidence and is never mislabeled as a
command line. Absent optional Windows facts remain null, even when ECS aliases
contain values. Present aliases are type checked and compared when a native
value is known. Windows computer aliases compare case insensitively while the
native spelling is preserved. IP aliases compare address values.

One explicit comparison transform is allowed for the noncanonical
`powershell.file.script_block_text` alias: XML line-ending normalization and
ASCII edge-whitespace trimming. The pinned Winlogbeat 8.19.23
`module/powershell/ingest/powershell_operational.yml` contains the `trim`
processor for that field (same processor in the [upstream pipeline](https://github.com/elastic/beats/blob/v8.19.0/x-pack/winlogbeat/module/powershell/ingest/powershell_operational.yml)).
A transformed match emits provenance warning
`powershell_script_text_xml_newlines_ascii_trim`; other content differences are
rejected. This never changes raw bytes, native script completeness or any
canonical field. Unicode whitespace beyond the reviewed ASCII set is not
silently stripped.

The context environment must agree with `fields.environment_id` when provided.
No lab addresses, credentials, endpoint identities or connector URLs are built
into production code.

The evidence ID is `elastic:evidence-v1:` plus SHA-256 of compact ASCII JSON
`["elastic-evidence-v1", environment_id, source_ref, 1, sha256(raw)]`.
`raw_event_ref` is `source_ref + "#record=1"`; the raw hash includes all exact
input bytes, including BOM, whitespace and final newline. Source document ID
does not replace evidence identity. Source index/document ID and native record
identity remain in provenance. Unknown source fields remain in the raw evidence.

## Rejected shapes

The decoder bounds bytes (256 KiB), JSON depth/nodes and numeric token length;
it rejects invalid Unicode, nonfinite numbers and duplicate keys. XML has
bounded depth/nodes and requires the Windows Event namespace. DTD/entities,
duplicate XML sections/System fields/EventData names, contradictory identities,
boolean integer aliases, invalid IP/port facts and incomplete/multipart 4104
records are rejected. These adapters do not assemble script fragments.

Telemetry profiles reject every alert shape, even when the alert copies valid
Windows XML. The reviewed alert representation uses **literal dotted keys**
such as `_source["event.kind"]` and `_source["kibana.alert.start"]`, beside a
nested `_source["event"]` object. Nested/dotted ambiguous aliases are rejected;
the adapter does not generically flatten vendor data.

Only clearly synthetic test fixtures belong in the repository. Private exports,
native EVTX, credentials and certificates remain outside Git.
