# Synthetic test-only CLI bundle

Created 2026-09-11 for Issue #8 software acceptance. Every record, detector ID,
host/manager label and timestamp is artificial. There is no source incident,
credential material or claim of lab detection coverage. SCN-999 is test-only;
the reviewed ground truth under `scenarios/` is unchanged.

`activity.json` models Windows 4688 activity with synthetic rule ID `900001`;
`alert.json` is a distinct record one second later with synthetic rule ID `900002`.
The profile joins on `synthetic-host` within two seconds, with separate activity
and alert matches. These IDs are example literals, not installed Wazuh rules.
Both inputs pass the existing Wazuh parser and unchanged validation engine.
Unknown collection assurance (`declarations: []`) is intentional: positive
witnesses support this synthetic result without asserting collection completeness.

Manually inspected fields: synthetic source IDs, agent ID/name, manager name,
rule IDs/levels, standard Windows provider/channel/event ID, artificial UTC
timestamps, synthetic hostname, process ID and inert process label. No payload
is executed. Human review and lab validation are still pending.

Exact-byte SHA-256 (UTF-8, LF, including final newline):

| File | SHA-256 |
| --- | --- |
| activity.json | `ea047cbd66426cbcea520654e075a1d33e8aefbe44bb6c8a0ff9f0f0d29707f2` |
| alert.json | `f42363eef779bd818fbada18825f90c8f6c5ce36e71d0a792f33f1780cff113f` |

The nested `.gitattributes` fixes JSON/YAML to LF across checkout platforms.
Recompute hashes from bytes for an intentional fixture change and review both
the raw diff and profile; never repair mismatches blindly. No production fixture
generator or automatic attestation is provided. Run the example using
[the CLI guide](../../../../docs/CLI_VALIDATE.md).
