# Gap → Fix → Re-test Demo

## Trạng thái triển khai Issue #12

[Kit SCN-001 và hướng dẫn tiếng Việt](../demos/scn-001/README.md) hiện triển khai
phần chuẩn bị offline/preflight/rehearsal và, từ kit 0.2.0, revision
`behavioral`. Hai payload cùng bytes; `baseline` theo filename; `fixed` theo toàn
bộ nội dung đã review (chịu được đổi tên, **không phải** detector hành vi);
`behavioral` theo hai hành vi quan sát được trong một script block, chịu được cả
đổi tên lẫn viết lại. Checklist vận hành lặp lại được:
[SCN001_OPERATOR_CHECKLIST.md](SCN001_OPERATOR_CHECKLIST.md).

Các mục A/B/C bên dưới mô tả mục tiêu/kỳ vọng. Kết quả lab đã đạt của bộ v2
(2026-09-18: A Detected, B False negative caller-attested, C Detected, B→C
Regression Passed), evidence ID, pins và bản ghi duyệt payload nằm ở
[SCN001_V2_APPROVAL_AND_PINS.md](SCN001_V2_APPROVAL_AND_PINS.md). Manifest
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
Its known limits are stated, not hidden: commented-out code still matches (kit
catalog), and the demo runner's own preflight function reads the machine name and
`$PID` in one script block, so on the real engine it also fires 118001 (Run C,
Windows record 12921). That record is excluded from the verdict only by the A03
path scope; on baseline the same block already fires stock rule 91815. The rule is
a lab demo artifact under group `aegis_safe_demo` and must not be deployed outside
the lab until an explicit tooling exception is added and re-tested (assessment and
recommendation in SCN001_V2_APPROVAL_AND_PINS.md, section 5).

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
