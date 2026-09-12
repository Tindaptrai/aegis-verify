# Bàn giao hướng A — telemetry chuẩn bị Issue #12

Ngày: 2026-09-12. Người dùng đã chạy đối chiếu: **2009 passed, 1 skipped in
43.10s**, `pip check` sạch, và duyệt commit/push/tạo PR riêng cho prerequisite.
Merge vẫn cần review/duyệt riêng. **Không đóng Issue #12.**

## Checkout và phạm vi

- Worktree: `I:\AEGIS-VERIFY\.worktrees\issue-12-windows-telemetry`.
- Branch: `codex/issue-12-windows-telemetry`.
- Base: `d5f977980a9850225f67f94967939348738e1ec9` từ `origin/main` đã fetch.
- Root checkout `I:\AEGIS-VERIFY` vẫn ở nhánh Issue #9; giữ nguyên các file người
  dùng chưa commit. Không reset/clean hay chuyển branch root.
- Python riêng: `.venv\Scripts\python.exe`, Python 3.13.14 trên Windows, editable
  package đã xác nhận trỏ đúng `backend/app` của worktree mới.
- Không thêm dependency vào dự án; venv cài từ `.[test]` hiện có.

## Đã làm

1. Hai byte API và registry keys mới: Sysmon 1, PowerShell 4104 một đoạn qua Wazuh.
2. Giữ source timestamp không mất chữ số, fields thiếu/null, exact-byte evidence ID,
   hash và raw ref/line ledger; không tự đoán nguồn từ collector.
3. Giữ script raw-only, metadata/GUID trong provenance; từ chối multipart hoặc
   thiếu metadata/script text trước khi đưa vào engine.
4. Nối vào CLI intake; không sửa 4688 mapping, canonical, validation, comparison
   hoặc ground truth của scenario.
5. Thêm 151 test và bộ fixture synthetic có mẫu CLI chạy được. Cố định LF cho các
   JSON trong thư mục fixture mới bằng `.gitattributes` để hash ổn định khi checkout.
6. Kiểm tra tại chỗ hai mẫu JSON do người dùng chọn: cả hai parse thành công.
   Không copy chúng vào repo, không in script, không gửi đi dịch vụ ngoài.

Chi tiết mapping, giới hạn, nơi chạy và lệnh CLI:
[WINDOWS_TELEMETRY_PARSERS.md](WINDOWS_TELEMETRY_PARSERS.md).

## Kiểm chứng đã chạy trong lượt triển khai này

Tất cả lệnh dưới chạy tại worktree mới, dùng đúng venv của worktree.

```powershell
New-Item -ItemType Directory -Path 'build' -Force | Out-Null
$aegisTestTemp = 'build/pytest-final-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

- Baseline trước sửa: **1858 passed, 1 skipped in 55.95s**.
- Sau triển khai: **2009 passed, 1 skipped in 48.82s**.
- Skip: `backend/tests/test_intake_io.py:452`, FIFO unavailable on this platform.
- `pip check`: **No broken requirements found.**
- `git diff --check`: không có lỗi whitespace; Git có cảnh báo LF→CRLF cho một
  số source/docs cũ theo thiết lập checkout. Fixture mới có `eol=lf` riêng.
- CLI synthetic: A01/A02 satisfied, A03 inconclusive/collection_not_confirmed;
  final Inconclusive, parsed=2 referenced=2 skipped=0; exit code 3 đúng hợp đồng.
- Test-first đã quan sát lỗi API mới chưa tồn tại, khóa parser chưa được registry
  nhận và bundle mẫu chưa tồn tại, rồi xác nhận các ca tương ứng pass sau bổ sung.
- Lỗi setup ban đầu: chạy test trước khi pip hoàn tất; sau đó thư mục cha `build`
  chưa tồn tại khiến pytest không tạo được basetemp. Đã hoàn tất setup/tạo parent
  rồi chạy lại toàn bộ thành công; không sửa quyền hay xóa dữ liệu người dùng.

## Review và giới hạn

Reviewer AI riêng đã đọc code theo phạm vi A, không mở raw lab/credentials, không
sửa code: không có finding actionable. Reviewer chạy 150 test mới trước lúc thêm
static smoke test, 250 test Wazuh/intake cũ (1 skipped), cùng 6 probe PID/null;
sau đó static smoke test đã pass. Reviewer chưa review toàn bộ tài liệu cuối lượt.
Đây không thay thế human review hoặc xác nhận thực nghiệm lab.

Những điểm người review độc lập nên tập trung:

- Sysmon PID mới khác PID provider; PowerShell PID emitter không phải GUID.
- 4104 `1/1` không đồng nghĩa đã thu toàn bộ activity của run; không suy luận thành
  executed-success hay collection complete.
- CLI không có script/GUID predicates; provenance metadata không đi vào engine.
- Bất kỳ partial/malformed input phải dừng, không thành báo cáo success một phần.
- Evidence phải truy được exact bytes; không lấy Wazuh rule-level telemetry làm
  bằng chứng detection mong đợi chỉ vì có rule ID.
- Bộ profile synthetic chỉ thử plumbing, chưa là profile lab được review.

## Phạm vi còn lại

Commit/push/PR của phần prerequisite không đồng nghĩa merge hoặc đóng issue.
Không đổi lab hoặc rule Wazuh trong lượt triển khai này. Chưa chạy payload A/B/C,
chưa xác nhận detection gap/regression pass.
Chưa hỗ trợ multipart, schema script/GUID, live connector, dashboard, Linux runtime.

## Người dùng làm tiếp

1. Test đối chiếu trên máy chứa repo đã hoàn tất, **không chạy trên WIN-USER01**.
2. Review PR trước khi duyệt merge phần prerequisite này.
3. Chốt thiết kế demo #12 riêng: safe payload, target, rule revisions, profile cố
   định, collection scope, đồng hồ, quy trình export và làm sạch cho A/B/C.
4. Chỉ chạy lab sau khi duyệt. Không lấy vài mẫu đã export để tự khai
   `complete_for_scope`; thiếu alert khi collection chưa xác nhận vẫn Inconclusive.
