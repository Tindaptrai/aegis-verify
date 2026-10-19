# Elastic exported-evidence parser contract

The implementation contract and field tables are in
[`connectors/elastic/README.md`](../connectors/elastic/README.md). This adapter
consumes exported files offline; it is not an Elastic collector or an EVTX decoder.

| Key | Native source | Canonical timestamp |
| --- | --- | --- |
| `elastic-sysmon1-v1` | Sysmon1 in one exported search hit | XML System.TimeCreated |
| `elastic-sysmon3-v1` | Sysmon3 in one exported search hit | XML System.TimeCreated |
| `elastic-powershell4104-v1` | Complete single-part PowerShell4104 | XML System.TimeCreated |
| `elastic-security-alert-v1` | Reviewed flat dotted Elastic Security alert hit | kibana.alert.start |

All four produce the distinct `elastic` canonical source. Source-specific fields
are retained in immutable provenance and exact hashed raw bytes. Alert-producing
provider is `elastic-security`; copied Windows provider/time/record facts are
provenance, not a second source event. The source parsers reject alert inputs.

Normalized aliases cannot repair missing native facts. The connector documents
the narrowly accepted Winlogbeat script-text whitespace transformation and emits
a warning; it does not rewrite the native XML, accept different content, or move
script text into canonical command_line. Reject malformed/contradictory identities,
DTD/entity XML, duplicate fields and unsupported multipart scripts with safe errors.

Public CLI examples are explicitly synthetic:
`tests/fixtures/cli/scn005-elastic-synthetic` and
`tests/fixtures/cli/scn006-elastic-synthetic`. Private runs must retain original
native EVTX, complete exports, query/pagination/count metadata and exact byte-slice
provenance outside Git. Exact alert ancestor linkage is an additional provenance
audit; the engine currently correlates the reviewed canonical hostname/PID/time
fields and does not claim to join on Elastic document IDs.

See [Lab B usage and limitations](LABB_ELASTIC.md). Vendor context:
[Winlogbeat PowerShell module](https://www.elastic.co/guide/en/beats/winlogbeat/8.19/winlogbeat-module-powershell.html)
and [exported PowerShell fields](https://www.elastic.co/guide/en/beats/winlogbeat/8.19/exported-fields-powershell.html).
The checked-in parser contract and tests, not a floating vendor page, define the
supported input shapes.
