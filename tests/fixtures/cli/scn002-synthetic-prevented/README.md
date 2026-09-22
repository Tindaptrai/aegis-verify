# Synthetic SCN-002 block-round bundle (test-only)

Created 2026-09-22 to prove the whole `aegis validate` path for SCN-002: four
parsers, the public profile and the engine, ending in `Prevented`. Every record
is invented. Addresses are RFC 5737, hosts and identifiers are synthetic, and
no lab byte, hash, hostname or topology is included. This bundle is **not**
evidence that the lab prevented anything; that requires the private block-round
bundle described in `docs/SCN002_EVALUATION_PROFILE.md`.

| File | Parser | Models |
| --- | --- | --- |
| `sysmon3-archive.json` | `wazuh-sysmon3-archive-v1` | A01: the sender's Sysmon Event 3 for the UDP datagram, source time `utcTime` |
| `eve-alert.jsonl` | `suricata-eve-jsonl-v1` | A02: Suricata LAN alert, SID 1000010, action `allowed` (IDS) |
| `filterlog-block.log` | `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | A03: pfSense LAN `block` with tracker `1700000001`, replayed with year 2026 and offset +07:00 |
| `wazuh-suricata-alert.json` | `wazuh-suricata-alert-v1` | A04: Wazuh rule 86601 raised from the Suricata alert |

All four share the tuple `192.0.2.11:51000 -> 198.51.100.10:40000/udp`. Source
times sit within 0.4 s of the Sysmon anchor; Wazuh receipt times are later on
purpose and must not be used as event time.

The scenario is the committed `scenarios/SCN-002-attempted-exfiltration.yaml`
and the profile is `scenarios/profiles/scn-002/profile.json`; neither is copied
here, so the fixture cannot drift from ground truth. `context.json` binds the
synthetic tuple and tracker. `declarations: []` is intentional: witnesses
support the result without claiming collection completeness.

Exact-byte SHA-256 (UTF-8, LF, including final newline):

| File | SHA-256 |
| --- | --- |
| `sysmon3-archive.json` | `a15268aac81fa3f172d7e3dc2187707b59d1d207a7e047c2ffae1fc60a4862ac` |
| `eve-alert.jsonl` | `4a3e9863b3e0f10933ef994897398225d38cd0df0a3879c211cbc592772fb5ce` |
| `filterlog-block.log` | `dbb5a233f22817fe3b77c7730f4a83e7649768b7be0c682da6b8b13a3f24b545` |
| `wazuh-suricata-alert.json` | `95937f663826f30d332f20198653bd065929d153f2124f92fad9141b32eae0eb` |

Run:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-002-attempted-exfiltration.yaml --fixture tests\fixtures\cli\scn002-synthetic-prevented --profile scenarios\profiles\scn-002\profile.json --format json
```

Test: `backend/tests/test_scn002_cli_bundle.py`. The nested `.gitattributes`
keeps every file LF so the hashes survive Windows checkout. Recompute hashes
from bytes for an intentional change; never repair a mismatch blindly.
