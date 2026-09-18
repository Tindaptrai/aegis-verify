# Gap → Fix → Re-test Demo

## Trạng thái triển khai Issue #12

[Kit SCN-001 và hướng dẫn tiếng Việt](../demos/scn-001/README.md) hiện triển khai
phần chuẩn bị offline/preflight/rehearsal và, từ kit 0.2.0, revision
`behavioral`. Hai payload cùng bytes; `baseline` theo filename; `fixed` theo toàn
bộ nội dung đã review (chịu được đổi tên, **không phải** detector hành vi);
`behavioral` theo hai hành vi quan sát được trong một script block, chịu được cả
đổi tên lẫn viết lại. Checklist vận hành lặp lại được:
[SCN001_OPERATOR_CHECKLIST.md](SCN001_OPERATOR_CHECKLIST.md).

Các mục A/B/C bên dưới mô tả mục tiêu/kỳ vọng, **không phải kết quả lab đã đạt**.
Export/attestation và evaluation profile còn cần kế hoạch riêng. Manifest
execution và synthetic logtest không thay canonical evidence hay kết luận CLI.

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

Replace the fragile filename match with reviewed behavioral conditions. The shipped
`behavioral` revision (`detections/wazuh/scn-001/behavioral.xml.template`) keys on the
two behaviors the payload actually performs in one script block — an environment or
machine-identity read and a process-identity read — in any wording, and is tested
against benign cases (env-only, pid-only, marker-only) plus a reworded equivalent.
Its known limit is stated in the kit catalog: commented-out code still matches.

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
