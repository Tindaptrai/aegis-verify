# Gap → Fix → Re-test Demo

## Goal

Demonstrate that AEGIS Verify can distinguish missing telemetry from a detection gap
and can prove a rule regression was fixed.

## Scenario

Use `SCN-001` with an approved, safe PowerShell test script. The payload behavior is
kept equivalent across runs; only the filename changes.

## Run A — Baseline

```text
Filename: lab_update.ps1
Telemetry: Found
Filename-based detection: Found
Expected result: PASSED
```

## Run B — Safe variant

```text
Filename: maintenance_check.ps1
Equivalent approved behavior: Preserved
Sysmon/PowerShell telemetry: Found
Filename-based detection: Missing
Expected classification: FALSE NEGATIVE
Expected result: FAILED — Detection Gap
```

The failed assertion must link to telemetry proving that the activity occurred while
the expected Wazuh detection did not.

## Rule fix

Replace the fragile filename match with reviewed behavioral conditions such as the
PowerShell process, relevant command-line characteristics, and correlated process and
network evidence. Exact conditions belong in version-controlled detection content and
must be tested against benign cases.

## Run C — Re-test

```text
Telemetry: Found
Behavior-based detection: Found
Regression comparison: Passed
Expected result: PASSED
```

## Demo evidence

- The three run IDs and scenario version
- Assertion results with supporting evidence IDs
- Raw-event links for each evidence ID
- Before/after rule revisions
- A comparison showing the detection changed while scenario behavior remained stable

Do not publish screenshots or fixtures until secrets and identifying data have been
reviewed.
