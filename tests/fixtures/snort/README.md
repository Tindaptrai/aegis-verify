# Snort 3 alert_json fixtures

`lab-c-probe-20261006.sanitized.jsonl` holds nine consecutive lines (source lines 10-18)
of one `alert_json` file written by Snort 3.12.2.0 on the Lab C sensor during a harmless
probe run on 2026-10-06. The rules only matched marker strings the operator sent
(sid 1000001 ICMP echo to the gateway, 1000002 DNS over UDP, 1000003 DNS over TCP).
The original file stays outside Git; `manifest.json` records its whole-file SHA-256,
size and line count, each original line hash and each derivative line hash.

The logger used the pinned field list, `process.utc = true` and
`output.show_year = true` (see `docs/SNORT3_ALERT_JSON_PARSER.md`).

Sanitization replaced exactly two values, consistently on every line:

| Role | Replacement |
| --- | --- |
| Lab C endpoint in the user segment | `192.0.2.10` |
| Lab C user-segment gateway | `192.0.2.1` |

No reverse alias map or original network identifier is stored here. Every other byte
is preserved: Snort's own spacing, `seconds`, `timestamp`, packet numbers, ports,
messages and rule identifiers. The rule messages are the lab's own marker names.

The file keeps LF bytes only. The local `.gitattributes` prevents newline conversion;
the line hashes include the newline byte. A changed file needs an updated manifest
hash, source label and review.
