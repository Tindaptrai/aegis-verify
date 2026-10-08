# OPNsense filterlog fixtures

Two sanitized derivatives of one Lab C file, `filterlog-raw.log`, which rsyslog wrote
with the template `%rawmsg%` while OPNsense 26.7 sent `filterlog` over BSD syslog/UDP
(2026-10-06, 03:21:28 to 13:26:20 UTC). The original stays outside Git;
`manifest.json` records its whole-file SHA-256, size, line count, every source line
used with its hash, and each derivative line hash.

| File | Source lines | Expected outcome |
| --- | --- | --- |
| `lab-c-20261006.sanitized.log` | 2, 4, 43, 44, 72, 418, 986, 988, 2055, 2069, 11390, 11396, 11498, 11499, 11500, 11557 | 16 parsed |
| `concatenated-l1707.sanitized.log` | 1707 | error `invalid_field` (`label`) |

The 16 lines cover every layout the source holds: IPv4 TCP, UDP and ICMP, IPv6 UDP
and ICMPv6, pass and block, `in` and `out`, all four interfaces, user-rule UUID
labels and automatic-rule MD5 labels. Lines 11498 and 11557 are the ICMP blocks of
the Lab C probe run (pings at 11:11:08 and 11:11:52 UTC from the endpoint). Lines
43/44 and 11499/11500 are the same packet logged on entry and on exit; the exit line
shows the TTL already decremented.

Line 1707 is a real collector defect: a message cut off at 04:28:11 when the
collector stopped, followed on the same line by the next message at 08:21:13.
A strict whole-file parse of the original fails at that line.

Sanitization:

- the syslog hostname became `fixture-fw` (twice in line 1707);
- each address cell became the alias listed in `manifest.json` under
  `substitutions`, the same alias on every line. IPv4 aliases use RFC 5737. The
  endpoint and the user-segment firewall address use the same aliases as the Snort
  fixture (`192.0.2.10`, `192.0.2.1`). The two IPv6 link-local addresses became
  `fe80::1` and `fe80::2`, which removes the MAC-derived interface ID;
- `0.0.0.0`, `255.255.255.255` and the multicast groups `ff02::1`, `ff02::2`,
  `ff02::1:2` are protocol constants and stay as they are.

No reverse alias map or original address is stored here. Every other byte is kept:
PRI, timestamp, PID, rule number, rule label, interface, TTL, IP ID, ports, sequence,
TCP options and `datalength`.

Parser context: year 2026 and offset `+00:00`. OPNsense runs in UTC, and the probe
pings above fall inside the UTC windows the endpoint recorded for them.
`ingested_at` is the collection time of the original file.

The files keep LF bytes only; the local `.gitattributes` prevents newline
conversion, and the line hashes include the newline byte. A changed file needs an
updated manifest hash, source label and review.
