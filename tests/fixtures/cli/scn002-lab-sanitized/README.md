# SCN-002 lab-derived, sanitized bundles

Two bundles derived from the **real** SCN-002 rounds of 2026-09-22, whose
verdicts are recorded in `docs/SCN002_RESULT_2026-09-22.md`: `block/` (four
sources, `Prevented`) and `control/` (three sources, `Inconclusive`). The
originals stay outside Git; their SHA-256 below match that document, so anyone
holding the private evidence can verify the lineage.

These bundles let the real source shapes be replayed through the parsers,
the public profile and the engine without a lab. A green test says the
derivatives still produce the recorded verdicts; it is not itself proof about
the lab. Sanitized on 2026-09-22 by Claude, reviewed by the project owner
in the pull request that added them.

## Substitutions (byte-level, consistent across files)

| Original | Replacement | Why |
| --- | --- | --- |
| sender address | `192.0.2.11` | RFC 5737 |
| receiver address | `198.51.100.10` | RFC 5737 |
| firewall agent address | `192.0.2.1` | RFC 5737 |
| sender host, FQDN, receiver hostname, firewall agent name | `LAB-SENDER`, `lab-sender.lab.example`, `lab-receiver.lab.example`, `lab-firewall.lab.example` | aliases |
| Windows account | `operator` | identity omitted |
| manager name | `lab-manager` | alias |
| filterlog syslog hostname | `lab-fw` | alias |
| `packet` (base64 frame) | removed | embeds addresses and MACs |

Everything else is preserved byte for byte: timestamps, ports, tracker
`1790087102`, SID `1000010`, Wazuh rule `86601`, payload marker with run UUID,
flow ids, record ids, `full_log` text (with the same substitutions applied
inside it). Ports and the receiver port `45002` are kept because the profile
binds them.

## Lineage

| Round | File | Original SHA-256 (outside Git) | Derivative SHA-256 | Bytes |
| --- | --- | --- | --- | --- |
| block | `sysmon3-archive.json` | `78cdd2e9b218c517d7cea6705d71d8c879fbc704f977d48206682bc11a31bdbb` | `99d2f89f48e8be0675da758aad395f8ab19941f5470fcf9e02991ba3b5a70c67` | 3604 → 3623 |
| block | `eve-alert.json` | `4f5f708592c3024395a1349d11d0e894ba54246ebd9414898e8adb09090f2e03` | `289c730d3a48568e18239e12086974e14f35194eaec2a8d64d31c926d92ac938` | 1074 → 920 |
| block | `filterlog.log` | `da0448a12b066c58ef93f96407ee5dc42b92999a24cea6f562a9740332d99c0e` | `7ae763d0fbd5cd957ed6dd86654811c4719e2901c2c06e03d7962b59e4694689` | 150 → 150 |
| block | `wazuh-alert.json` | `3f632fbc2b3199c1701b75305309081fb5f93424bd6e54f33a467e03e7e9ab5b` | `4cf0a542c0000874b711d2b1eb1ca1db7015d28fa6a70c7b3f8da53ebb54952b` | 1572 → 1422 |
| control | `sysmon3-archive.json` | `352dbd275c8f7a41f54f7287c4fbb50efb05725d0299ab9e783a68ddcbff81ea` | `300155fafb11211852df9b6931053e1492611b7b2314545086223660848bf82e` | 3603 → 3622 |
| control | `eve-alert.json` | `f97d854cb6cc72afcd2f4369ba0da0be52b9f2b5d1bd2639745fce80192c25dd` | `00ed154a31362f7f0f47196947ce5c42cfb33a1eafa691367f74119aff0652f3` | 1084 → 926 |
| control | `wazuh-alert.json` | `2be5218a259a8575143867af81d7ca91e8985bda6c5f0247e656af6d2b6a4540` | `aec66d2cef15ca531cdab8c2a1ae03b09773313713f556dc3ac7e4cb662a5541` | 1581 → 1427 |

`inputs.json` in each bundle carries the derivative hashes; `context.json`
binds the RFC 5737 tuple, port `45002` and tracker `1790087102`. The scenario
and profile are the committed ones under `scenarios/`, not copied here.
`declarations: []` is intentional.

Run either bundle:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-002-attempted-exfiltration.yaml --fixture tests\fixtures\cli\scn002-lab-sanitized\block --profile scenarios\profiles\scn-002\profile.json --format json
```

Test: `backend/tests/test_scn002_lab_sanitized.py`. The nested
`.gitattributes` keeps LF so hashes survive Windows checkout. A changed
derivative needs a new hash here and in `inputs.json`, plus review; never
repair a mismatch blindly.
