# Suricata fixtures

## Reviewed direction A sample

`suricata-wazuh-alert-001.sanitized.json` is one Wazuh search-hit containing a
Suricata alert, not a direct EVE record and not verified INC-002 evidence.
SHA256: `9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c`.
It is 2137 bytes / 92 physical lines. `.gitattributes` disables newline conversion.

Prepared from the user's lab export: 14 leaf substitutions (document/source IDs,
collector identity, network addresses, flow ID, interface labels and location).
Packet, payload and payload_printable were removed from this derivative because
they can embed identifying packet bytes. Network substitutions remain consistent
between packet and flow fields. All other values/types were retained. Original
evidence is not committed; its hash and mapping remain with the lab owner.

This fixture proves parsing of this representation only. Hashing the sanitized
file does not authenticate the original event or establish a security verdict.
Test-generated variants are artificial validation inputs, not production evidence.

## Future direct EVE coverage

Direction B adds four one-line `eve-*.sanitized.jsonl` derivatives from user-supplied
direct EVE exports. `eve-fixture-manifest.json` records original file hashes, source
line numbers, original line hashes and derivative hashes plus each sanitization
operation. Original export/line hashes identify a source without embedding its contents.

WAN line 1 is ICMP alert; LAN line 15 is TCP alert; MGMT line 7 is UDP alert; DMZ
line 1 is DNS (skip coverage). Each becomes derivative line 1; JSON was compactly
reserialized with LF. Global deterministic IP aliases preserve equality and endpoint
direction, including LAN's reversed packet/flow endpoints. Flow IDs and interfaces
are aliased; packet/payload fields and metadata/DNS content are removed where present.
All other retained values/types, including timestamps, SID, ports, counters and rule
descriptions, are unchanged. Do not interpret aliases as real network topology.

The four original exports contain 1651 alerts and ZERO standalone flow records.
Flow examples in `test_suricata_eve.py` are artificial unit data based on the EVE
contract, not captured lab evidence. Direct flow lab validation remains pending.
No incident or ground-truth association is established by these samples.

Add the reviewed INC-002 EVE export as `inc002-eve.json`. Preserve SID, timestamp,
flow, protocol, address/port, and action correlations while sanitizing identifiers.
