# SCN-006: benign HTTP visibility in Lab B

This separate draft verifies a controlled, allowed TCP flow. It does not change
SCN-002's prevention/Wazuh requirements and does not report `Prevented`.

| Assertion | Required witness |
| --- | --- |
| A01 | Elastic Sysmon 3, observed action, Windows Sysmon provider and the bound TCP tuple. |
| A02 | Direct Suricata IDS alert SID `9900201`, matching the complete tuple and within ±3 seconds of A01. |
| A03 | Direct pfSense allowed telemetry for the same bound tuple and the bound pass-rule tracker. |

The five tuple components are sender IP/port, receiver IP/port and TCP protocol.
The four variable address/port components and `pass_rule_tracker` enter through
the context. The profile preserves the source-specific protocol literals:
Sysmon/pfSense `tcp`, Suricata `TCP`. It joins all four variable components between
the IDS target and the Windows anchor; protocol is fixed explicitly on each.

The Sysmon canonical timestamp is original XML `System.TimeCreated`, not Sysmon
`UtcTime` or Elastic receipt time. Check clocks independently before executing
the request; do not alter source times to make the ±3 second join pass. A03 is
bounded tuple/tracker telemetry within the run's context interval; it does not
claim a separate engine correlation join to A01.

Pin SID revision/rule-file hash and the approved destination before a new run.
Canonical `signature_id` represents the SID; signature revision remains in raw
provenance and must be audited separately. A passive sensor's `allowed` alert
does not prove a firewall decision. HTTP status/body, packet counts in each
direction, routing and isolation require their own native operational proof.

Examples use only documentation addresses and artificial values. Keep real
contexts and raw exports outside Git. Missing detection is `Inconclusive` when
collection has not been independently confirmed complete for that scope.

See [Lab B integration](../../../docs/LABB_ELASTIC.md) for the bundle procedure.
