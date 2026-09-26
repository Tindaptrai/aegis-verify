# SCN-003 lab-derived, sanitized bundle

Derived from the **real** SCN-003 control round of 2026-09-26 (run
`cac43623545449cb8d0544522941666d`), whose verdict is recorded in
`docs/SCN003_RESULT_2026-09-26.md`: `Detected`, four assertions satisfied. The
originals stay outside Git; their SHA-256 below match that document, so
anyone holding the private evidence can verify the lineage.

This bundle lets the real source shapes be replayed through the parsers, the
public two-root profile and the engine without a lab. A green test says the
derivative still produces the recorded verdict; it is not itself proof about
the lab. Sanitized on 2026-09-26 by Claude, reviewed by the project owner in
the pull request that added it.

## Substitutions (byte-level, consistent across files)

| Original | Replacement | Why |
| --- | --- | --- |
| initiator address (Kali) | `192.0.2.10` | RFC 5737 |
| decoy VIP (pre-NAT) | `203.0.113.30` | RFC 5737 |
| Cowrie address (post-NAT) | `198.51.100.20` | RFC 5737 |
| pfSense filterlog syslog hostname | `lab-fw` | alias |
| Cowrie/Wazuh agent name `corwrie` | `lab-cowrie` | alias |
| Wazuh manager name | `lab-manager` | alias |
| the real random password | `synthetic-marker-password`, everywhere it appeared (`data.password`, `data.message`, `full_log`) | the parser never reads this field, but a real secret must not sit in Git regardless |
| `packet` (base64 frame) | removed | embeds addresses and MACs |

Everything else is preserved byte for byte: timestamps, ports, the firewall
rule tracker `1790410513`, Suricata SID `1000012`, Wazuh rule `120003`, the
Cowrie session id, the run's username marker, flow and record ids.

## Lineage

| File | Original SHA-256 (outside Git) | Derivative SHA-256 | Bytes |
| --- | --- | --- | --- |
| `filterlog.log` | `b7f6b92e02cee84e38f5490b2398644c076f7b153d75422ae28ee50119a2b957` | `dd35d21770268a2128561bfb081321f0c76cce53c6ab0aeeb7b9a2206a5e4930` | 189 → 189 |
| `eve-alert.json` | `22266bc2f5503bfc5cabb6280bf2cea9cf4723c9c7244ac753e541ffdb823bfa` | `81fcb8982d0637ecdd7827459842c8adbed47078b6b352f791a28efcbd76818c` | 832 → 730 |
| `cowrie-session.jsonl` | `28ae96da77465007d764fe184c944f15740205cbd122210f63656f0aa509422e` | `8cfad3c24cd9d83d36f7dcca9c8595efaaca6ed81d53ff33ad5142c79343fc75` | 711 → 738 |
| `wazuh-alert.json` | `411ad9540bfa9e26c9bdf314471425b2c1aeccb82076d4b2a196eff63e23a629` | `d9ec0bd9c5d500ae60c69d5463f2a89cfdf23b5fad817fee574d82b05e89629e` | 1328 → 1381 |

`inputs.json` carries the derivative hashes; `context.json` binds both NAT
domains, the protocol, the tracker and the username marker. The scenario and
profile are the committed ones under `scenarios/`, not copied here.
`declarations: []` is intentional.

Run:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-003-internal-deception.yaml --fixture tests\fixtures\cli\scn003-lab-sanitized --profile scenarios\profiles\scn-003\profile.json --format json
```

Test: `backend/tests/test_scn003_lab_sanitized.py`. The nested
`.gitattributes` keeps LF so hashes survive Windows checkout. A changed
derivative needs a new hash here and in `inputs.json`, plus review; never
repair a mismatch blindly.
