# Synthetic Windows telemetry — NOT lab evidence

Every event, identifier, path, rule ID, timestamp and script in this folder was
constructed for offline tests. Nothing here was executed or copied from a raw
lab export. The placeholder image hash is deliberately not a real hash.

This bundle exercises the unchanged SCN-001 manifest and the new parser registry.
It contains two telemetry records and NO expected detection. Collection assurance
is unknown, so the expected final status is **Inconclusive**, exit code **3**.
This is NOT the approved lab evaluation profile and NOT a completed Issue #12 demo.
The example's filename conditions must not be copied into the production demo
as a substitute for a reviewed behavior-preserving profile.

`inputs.json` hashes the exact fixture bytes. Do not rewrite line endings without
reviewing and updating these hashes. Read `docs/WINDOWS_TELEMETRY_PARSERS.md` for
PowerShell commands, field semantics, limitations and future extension boundaries.
