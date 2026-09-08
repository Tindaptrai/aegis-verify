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

Add the reviewed INC-002 EVE export as `inc002-eve.json`. Preserve SID, timestamp,
flow, protocol, address/port, and action correlations while sanitizing identifiers.
