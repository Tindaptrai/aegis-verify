# Issue #12 — Checkpoint demo vô hại

Ngày ghi nhận: 2026-09-12. Giao tiếp/lab commands trong task này dùng tiếng Việt.

## Repository

- Worktree: `I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo`.
- Branch: `codex/issue-12-safe-demo`.
- Base PR #25: `bf4852979293a998e169b06d214486465678360e`.
- Design commit: `273fab6`.
- [Thiết kế](superpowers/specs/2026-09-12-safe-demo-design.md).
- [Kế hoạch phần 1 — kit lab](superpowers/plans/2026-09-12-safe-demo-lab-kit.md).
- Chưa có implementation kit, chưa push/merge/đóng Issue #12.
- Root checkout và dữ liệu chưa commit của người dùng không được reset/clean.

## Việc lab người dùng đã thực hiện và báo kết quả

Đây là **kết quả người dùng cung cấp**, không phải agent SSH vào manager hoặc
tự chạy kiểm chứng trên lab. Không có raw log/credential được lưu trong file này.

Wazuh manager: 4.14.4. Config test ban đầu exit 0 nhưng cảnh báo duplicate
IDs 120850, 120860, 120861 trong local_rules.xml. Người dùng đã duyệt:

1. Giữ ba định nghĩa đầu dùng if_group=suricata, bỏ ba bản sau cùng ID dùng
   if_sid=86601 và MITRE. Không sửa các rule khác.
2. Sau test phát hiện lệch field, người dùng duyệt đổi đúng ba field từ
   data.alert.signature_id sang alert.signature_id, PCRE2 exact anchors.

Mapping cuối đã được logtest synthetic kiểm tra:

| Input signature | Expected rule | Level | Kết quả người dùng |
| --- | --- | --- | --- |
| 1008502 | 120850 | 12 | PASS |
| 1008601 | 120860 | 10 | PASS |
| 1008602 | 120861 | 11 | PASS |
| 10085020 | 86601 | 3 | PASS |
| 10086010 | 86601 | 3 | PASS |
| 10086020 | 86601 | 3 | PASS |
| 2231000 | 86601 | 3 | PASS |

Lệnh kiểm tra dùng wazuh-logtest -q -U expected_id:level:json và đầy đủ timestamp.
Mẫu synthetic đầu tiên agent đưa thiếu timestamp nên không khớp parent 86600;
đã sửa mẫu và không dùng kết quả lỗi đó để kết luận lỗi production.

## Backup trên manager — không nhầm các phiên bản

- `/root/aegis-rule-review.y1PaZ5/original.xml`: bản **còn duplicate** ban đầu.
- `/root/aegis-rule-review.y1PaZ5/candidate.xml`: bản bỏ duplicate, **chưa sửa field**.
- `/root/aegis-field-review.yHRWke/before.xml`: bản bỏ duplicate, **chưa sửa field**.
- `/root/aegis-field-review.yHRWke/candidate.xml`: bản bỏ duplicate và **đã sửa ba field**.

Không tự rollback chỉ để đồng bộ tên file; mọi restore phải xác minh hash/diff
và trạng thái hiện tại, chỉ thực hiện theo yêu cầu người dùng.

## Sau restart

Active Response block người dùng gửi là placeholder bên trong XML comment;
không bật/tắt AR trong lượt sửa này. Không suy ra tất cả tích hợp tự động khác
đã được audit. Phải kiểm tra lại điều kiện liên quan khi thêm rule demo mới.

Người dùng chạy config test, systemctl restart wazuh-manager và kiểm tra status:
active (running), startup SUCCESS, từ 2026-09-12 20:21:16 +07 = 13:21:16 UTC.

Metadata alert sau restart do người dùng cung cấp:

| Wazuh record ID | Timestamp UTC | Rule | Decoder |
| --- | --- | --- | --- |
| 1789219285.6149942 | 2026-09-12T13:21:25.685+0000 | 5502 | pam |
| 1789219288.6150303 | 2026-09-12T13:21:28.973+0000 | 60642 | windows_eventchannel |
| 1789219291.6151883 | 2026-09-12T13:21:31.168+0000 | 19003 | sca |

Các ID trên là source record IDs do Wazuh cấp, **không phải canonical evidence
IDs của một AEGIS evaluation run**. Chúng hỗ trợ nhận định manager tiếp tục ghi
alert, không chứng minh custom Suricata detection, Sysmon/4104 của demo, hoặc
firewall blocked. Chưa có A/B/C evaluation reports hay Regression Passed.

## Bước tiếp theo

1. Chọn cách thực thi kế hoạch kit lab; không mở subagent nếu chưa được chọn.
2. TDD cho payload/generator/rule templates, sau đó runner preflight/manifest.
3. Xác minh parent rule thực tế cho PS4104, custom ID trống, alert threshold
   và tác động tích hợp trước cài demo. Không dùng Suricata rule IDs cho demo PS.
4. Review kit rồi rehearsal trên Windows lab; không sửa policy/ground truth.
5. Lập kế hoạch export/attestation và evaluation A/B/C, tái sử dụng CLI hiện có.
6. Chỉ đóng Issue #12 sau human review và evidence lab hợp lệ.
