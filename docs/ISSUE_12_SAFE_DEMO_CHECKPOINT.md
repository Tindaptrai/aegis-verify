# Issue #12 — Checkpoint demo vô hại

Ngày ghi nhận: 2026-09-12. Giao tiếp/lab commands trong task này dùng tiếng Việt.

## Repository

- Worktree: `I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo`.
- Branch: `codex/issue-12-safe-demo`.
- Base PR #25: `bf4852979293a998e169b06d214486465678360e`.
- Design commit: `273fab6`.
- [Thiết kế](superpowers/specs/2026-09-12-safe-demo-design.md).
- [Kế hoạch phần 1 — kit lab](superpowers/plans/2026-09-12-safe-demo-lab-kit.md).
- Implementation phần 1: commit `92b412f` (generator, runner, 85 tests mới).
- [Hướng dẫn kit tiếng Việt](../demos/scn-001/README.md).
- Đã làm inline/tuần tự, không mở subagent. Chưa push/merge/đóng Issue #12.
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

1. Human/reviewer độc lập xem kit trước khi cài rule hoặc chạy lab.
2. Người dùng chạy đối chiếu tests theo README; không cần raw lab export để test kit.
3. Xác minh parent rule thực tế cho PS4104, custom ID trống, alert threshold
   và tác động tích hợp trước cài demo. Không dùng Suricata rule IDs cho demo PS.
4. Review kit rồi rehearsal trên Windows lab; không sửa policy/ground truth.
5. Lập kế hoạch export/attestation và evaluation A/B/C, tái sử dụng CLI hiện có.
6. Chỉ đóng Issue #12 sau human review và evidence lab hợp lệ.

## Implementation đã làm trong lượt tiếp tục

- Generator Python stdlib tạo hai tên cùng bytes/hash, hai revision cùng rule
  ID và level 5, manifest hash artifacts và 12 synthetic logtest cases.
- Không nhận arbitrary payload; bản chuẩn chỉ Write-Output marker và own PID.
- Validation chặt ID/host/path, từ chối overwrite/reparse/UNC và output trong
  Git checkout (ngoại lệ build của worktree này cho test). Đọc lại bytes đã ghi
  trước publish `kit.json`; output dang dở không được tự xóa hay dùng lại.
- Runner Windows PowerShell 5.1 x64 mặc định preflight không ghi run files hoặc
  launch. Kiểm tra host, bytes chuẩn độc lập với hash trong manifest, rule hash,
  services/log access và run selection. Chỉ `-Execute` mới tạo child.
- Execute path có window danh nghĩa 120 giây bằng Stopwatch, launch khoảng +10s,
  timeout child 30s, chỉ dừng child do runner tạo; kiểm tra stdout/PID/exit/stderr.
  Start/launched/final manifests tách biệt, không gán verdict hoặc assurance.
- README tiếng Việt phân máy/trách nhiệm, lệnh preflight, review/logtest/cài
  một revision, rollback guard hash, rehearsal và điểm dừng trước evaluation.
- Không thay scenario ground truth, canonical, connectors, engine, comparison
  hoặc dependencies. Không đọc/commit credential hoặc raw lab exports.

## Kiểm chứng mới đã chạy trên máy phát triển

Venv riêng của worktree: `.venv`, Python 3.13.14. Editable import đã kiểm tra
trỏ tới `issue-12-safe-demo/backend/app/__init__.py`, không phải root checkout.
Không sửa venv cũ/root của người dùng.

Baseline chạy lại trước thay đổi: **2009 passed, 1 skipped** (60.66s).
Targeted kit/runner trước guard cuối: **84 passed** (44.25s). Sau thêm guard
Git checkout khác, generator suite: **47 passed** (5.28s).

Full suite cuối trên implementation commit `92b412f`:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-handoff-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
git diff --cached --check
```

- **2094 passed, 1 skipped in 126.25s**; 85 test mới so với baseline.
- Skip: `backend/tests/test_intake_io.py:452`, FIFO không có trên Windows.
- `pip check`: `No broken requirements found.`
- Diff whitespace checks: exit 0. Git có thông báo chuyển LF/CRLF cho text
  thông thường; payload/runner/templates có `.gitattributes` giữ LF.
- Các relative file links trong README/DEMO đã được kiểm tra tồn tại.
- Cú pháp hashtable splatting tới PowerShell native exe trong README đã có test.

Đây là kết quả mới của agent trên máy phát triển, không phải test do người
dùng chạy trên endpoint lab. Không chạy `-Execute`, Wazuh config/logtest demo
mới hoặc cài rule trong lượt này.

## Tự rà soát và giới hạn cần review độc lập

Tự rà soát đã bổ sung regression tests cho scalar fields bị thay bằng arrays
(PowerShell comparison có thể im lặng cho qua), generator output ở checkout
khác và readback mismatch. Không thay semantics engine để làm demo đạt.

Chưa có review độc lập cho `92b412f`. Reviewer cần đọc AGENTS, design/plan,
README và review `cac892f..92b412f` ở worktree trên, đặc biệt:

1. Safety của payload/runner, no-overwrite/reparse, path/argument quoting,
   timeout/child lifecycle và partial manifests.
2. Hai payload cùng bytes, rule anchors/escaping, parent chain, host/counters,
   negative controls; fixed không được quảng bá là detector malware.
3. Manifest/hash chỉ là metadata/kết quả operator đối chiếu; không chứng thực
   remote, không là canonical evidence hoặc completeness attestation.
4. Hướng dẫn cài/rollback không đụng rule khác, Active Response/integrations
   cần được kiểm tra riêng trước lab.

Các giới hạn còn lại:

- Chưa kiểm chứng PCRE2, decoder và parent SID trên Wazuh 4.14.4 của lab.
  Python chỉ kiểm tra XML/pattern subset; `not_demo` không có nghĩa no alert.
- Runtime thành công/timeout, service/log access thực tế xuyên window, clock
  và thu log đầy đủ chưa được lab xác minh. Unit doubles không thay thế việc đó.
- Runner không phải sandbox chống operator độc hại hoặc concurrent writers;
  kit/output phải nằm trong thư mục riêng tin cậy, không sửa JSON/hash thủ công.
- Chưa có export packaging/attestation, frozen evaluation profile, reports A/B/C
  hoặc `Regression Passed`. Issue #12 chưa hoàn tất và chưa được đóng.
