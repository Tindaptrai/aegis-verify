# Synthetic SCN-003 single-session bundle (test-only)

Created 2026-09-26 (#76, plan Task 4) to prove the whole `aegis validate` path
for SCN-003: four parsers, the public two-root profile and the engine, ending in
`Detected`. Every record is invented. Addresses are RFC 5737, hosts, session,
username marker and identifiers are synthetic. No lab byte, hash, hostname or
topology is included, and no password appears anywhere. This bundle is **not**
evidence that the lab detected anything.

| File | Parser | Models |
| --- | --- | --- |
| `filterlog-pass.log` | `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | A02 root: pfSense LAN `pass` for the TCP SYN, pre-NAT tuple, tracker `1700000003`, replayed with year 2026 and offset +07:00 |
| `eve-alert.jsonl` | `suricata-eve-jsonl-v1` | A01: Suricata alert SID 1000012 on the same pre-NAT tuple |
| `cowrie-session.jsonl` | `cowrie-jsonl-v1` | A03 root: `cowrie.session.connect` with the post-NAT tuple; plus one `cowrie.login.failed` of the same session as supporting evidence (no ports, like a real record) |
| `wazuh-cowrie-alert.json` | `wazuh-cowrie-alert-v1` | A04: Wazuh rule 120003 raised from that login failure |

Pre-NAT tuple `192.0.2.10:51003 -> 203.0.113.30:2223/tcp`; post-NAT tuple
`192.0.2.10:51003 -> 198.51.100.20:2223/telnet`. The initiator port is the
only bridge between the two domains, as the profile README explains. Source
times sit within 1 s of each other; the Wazuh receipt time is later on purpose.

The scenario is the committed `scenarios/SCN-003-internal-deception.yaml` and
the profile is `scenarios/profiles/scn-003/profile.json`; neither is copied
here. `context.json` binds the synthetic tuples, protocol, tracker and username
marker. `declarations: []` is intentional.

Exact-byte SHA-256 (UTF-8, LF, including final newline):

| File | SHA-256 |
| --- | --- |
| `filterlog-pass.log` | `ec364ce85d6e45a8865d91197857a2624e9ca497acaa67c0457a8901e8cd6cc0` |
| `eve-alert.jsonl` | `40629e3529c7ecf50bde27f3b55cb90e1acc1d1f3f67e3bd0f434181d704d4c6` |
| `cowrie-session.jsonl` | `c21bdcd924837636cea1c4c40bd77b01f8a2d92ae216723b10ad4b2693905abd` |
| `wazuh-cowrie-alert.json` | `59b04006434b268674ab538a1ed048fecd547abddf871c188a22a33ac393c142` |

Run:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-003-internal-deception.yaml --fixture tests\fixtures\cli\scn003-synthetic-detected --profile scenarios\profiles\scn-003\profile.json --format json
```

Expected: `Detected`, exit 0, parsed 5, referenced 4 (the direct login record
is timeline evidence only). Test: `backend/tests/test_scn003_cli_bundle.py`.
The nested `.gitattributes` keeps every file LF so the hashes survive Windows
checkout. Recompute hashes from bytes for an intentional change; never repair
a mismatch blindly.
