# Suricata A Verification — 2026-09-09

## Scope outcome

Implemented only direction A: one sanitized Wazuh search-hit containing a Suricata
alert maps to CanonicalEventV2 plus immutable provenance. No direct EVE/flow, CSV,
live connector, canonical schema, scenario ground truth, push, merge or issue closure.

## Test-driven evidence

- Baseline before changes: 650 tests passed.
- RED: focused `test_exact_source_time` failed because the public parser did not exist.
- GREEN after implementation: 802 full-suite tests passed.
- Reviewer independently passed 152 focused and 802 full-suite tests; no blocking or
  important finding. Their 24 extra boundary probes passed.
- Reviewer suggested committing boundary coverage for absent/null metadata,
  128-digit numeric fields and flow fraction/length limits. Those tests were added.
- Final editable run after that hardening: 826 tests passed; `pip check` clean.
- Wheel `aegis_verify-0.1.0-py3-none-any.whl` installed into a fresh venv; imports
  resolved from its `site-packages`; all 826 tests passed with importlib mode and
  dependency check clean.
- The documented sample command ran successfully and asserted source timestamp,
  SID, Wazuh rule, flow identity, evidence hash and literal evidence ID.

Pytest initially hit the Windows 32,767-character environment-variable limit because
two parameter IDs embedded 256 KiB test bytes. Root cause was pytest's current-test
environment variable, not parser behavior. Tests now use short deterministic SHA-256
labels; data and assertions are unchanged.

## Fixture / deterministic values

- Committed file and working file compared byte-for-byte.
- SHA-256: `9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c`.
- Size: 2137 bytes; 92 physical lines; Git newline conversion disabled for JSON.
- Expected event ID with environment `unit-lab` and fixture filename:
  `suricata:evidence-v1:559e130f8ef34149bad4588114937637a06784d9e14361d30fcda44c426593e0`.
- Original user export remains outside Git and unchanged; recorded local SHA-256:
  `094cc37e8cbe1ff07c1fa636e5d9dd4bd15729519b99dfdf75ef0698607c87c4`.

## Enforced limits

One bytes JSON object; 256 KiB, depth 20, 10,000 nodes and 128-character numeric
tokens. Source timestamp preserves 0–9 fractional digits. Ports are 0–65535. Caller
supplies an explicit safe source label, bounded environment label, ingestion time
and deployment mode. Errors use fixed diagnostic vocabulary and suppress source /
filesystem content. Optional canonical fields remain null; malformed present fields
fail instead of being guessed.

## Review limits and human gate

The independent technical review covered production commit `403b29c` against base
`4869b52`; documentation and the subsequently added hardening tests were checked by
the implementing agent. Automated checks do not validate the user's live Suricata
version, collector topology, clock accuracy, alert authenticity or firewall result.
The lab owner must compare the documented fields and IDS meaning before integration.
Direction A is ready for that human review; Issue #4 is not complete.

## B handoff

The exact user checklist, sanitization warnings and implementation sequence for B
are in `docs/SURICATA_WAZUH_ALERT.md`, section 5. B starts with direct EVE alert and
flow samples if available, then an explicit flow-identity decision. It must preserve
A compatibility and may not claim cross-export deduplication without a new design.
