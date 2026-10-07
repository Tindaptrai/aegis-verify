# SCN-004 lab-derived, sanitized bundles (Lab C)

Two bundles derived from the **real** SCN-004 rounds on Lab C of 2026-10-07, whose
verdicts are recorded in `docs/SCN004_LAB_C.md` (section 9):

- `block/` — run `8541573e`, three sources, `Prevented`;
- `sensor-down/` — run `509edcce`, sent while Snort had stopped capturing, two
  sources, `Inconclusive` (A02 `collection_not_confirmed`).

The originals stay outside Git; their SHA-256 below let anyone holding the private
evidence verify the lineage. These bundles replay the real source shapes through the
parsers, the public profile and the engine without a lab. A green test says the
derivatives still produce the recorded verdicts; it is not itself proof about the lab.

## Substitutions (byte-level, applied in this order, consistent across files)

| Original | Replacement | Why |
| --- | --- | --- |
| Wazuh agent name of the sender | `lab-sender` | alias |
| sender computer name (upper case, then mixed case) | `LAB-SENDER`, `Lab-Sender` | alias |
| Windows account | `operator` | identity omitted |
| manager name | `lab-manager` | alias |
| sender address | `192.0.2.10` | RFC 5737; same alias as the Snort and OPNsense parser fixtures |
| filterlog syslog hostname | `fixture-fw` | alias, as in the OPNsense parser fixture |

The receiver `203.0.113.10` is a documentation address in the lab too and is kept.
Everything else is preserved byte for byte: timestamps, ports, the OPNsense rule
label, Snort SID `1000010`, record IDs, process GUID and the `full_log` text (with the
same substitutions applied inside it). `inputs.json` and `context.json` were rewritten
with the derivative hashes, `environment_id: lab-c-sanitized` and the aliased sender.

## Lineage

| Round | File | Original SHA-256 (outside Git) | Derivative SHA-256 | Bytes |
| --- | --- | --- | --- | --- |
| block | `sysmon3-archive.json` | `41adce6b4c04355280a2d9d10301b5bf27e8c8e82d66097c9fa011c09594d3a7` | `e314f984b3654e402fd78a5081e341ab2f644b01f826e22384a4837f8b87e416` | 3377 → 3432 |
| block | `snort-alert.jsonl` | `861ffe4a2148ef7b5865a0fd24264548fea3cabc825e5aca6e2ce02fe91d29a7` | `8ac860774a3bf998c7faf5ae5fbd09bcd6df6fc273686dd11cf74ff3a12e12b6` | 388 → 387 |
| block | `filterlog.log` | `743a8ee646c4a919b26315fb109a41cdac78c8f5c7fd30ea164245fb112ba77e` | `b2e31b408850d919ae73831b314268f2fe1551525e9d171ac204f527d98f7683` | 191 → 183 |
| sensor-down | `sysmon3-archive.json` | `e4aa27ce10b5ae0db800202f39361a1ef808559314a897abcbd258ca26d10e7a` | `1261dfbef8cc68873e4c0f9606e7a551dfeeaf00337a7a428d176cd780d6a0a0` | 3377 → 3432 |
| sensor-down | `filterlog.log` | `79386375dbae682f5d9cf55b903ea283ec6529357e00af37f1aa4a47777d3e88` | `961d89cf6c3845ed663017bc7b21e404b84855d7821c99746c2c1e922bb9a0b6` | 191 → 183 |

Each original is one exact line taken from a source file, recorded with its line
number and the file's SHA-256 at collection:

| Round | Source file | SHA-256 at collection | Line |
| --- | --- | --- | --- |
| block | Snort `alert_json.txt` (19 lines) | `99f0f69a1cc2e527884aea619f5dfa227562a35768eaad8e0974d41e0da2a76e` | 19 |
| block | OPNsense `filterlog-raw.log` (26,261 lines) | `7d3447dd65833565a03ef90f36809cbdc6a56d56cb8e86a10f8e16a13c9ed2ab` | 25,920 |
| block | Wazuh `archives.json` | `ed597fdc3f3bf2ab2a48c6766337762c599b82967e5b672c2b2e1cc5d6a7f777` | 3,704 |
| sensor-down | Snort `alert_json.txt` (18 lines, no new alert) | `6573e8539dde3846a107b389e39d40c3fcd35536887fb078f1cef78ce2f7b46a` | — |
| sensor-down | OPNsense `filterlog-raw.log` (25,424 lines) | `43c4a7c81013e1186035360cf8aee867c7f5924dd17ba78cc6d351535eb05018` | 25,098 |
| sensor-down | Wazuh `archives.json` | `706640941328377bbae7d390db6c05995b0ff58051b9fa436844da2d0ad1b788` | 2,327 |

Run either bundle:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-004-attempted-exfiltration-lab-c.yaml --fixture tests\fixtures\cli\scn004-lab-c-sanitized\block --profile scenarios\profiles\scn-004\profile.json --format json
```

Test: `backend/tests/test_scn004_lab_sanitized.py`. The nested `.gitattributes`
keeps LF so hashes survive a Windows checkout. A changed derivative needs a new hash
here and in `inputs.json`, plus review; never repair a mismatch blindly.
