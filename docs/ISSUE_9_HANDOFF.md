# Bàn giao Issue #9 — 2026-09-11

Branch: `codex/issue-9-compare-runs`, repo `I:\AEGIS-VERIFY`.
Commit chức năng đã push: `9cef982`; baseline main: `ef61d36`.

## Trạng thái chốt

Đã hoàn tất triển khai và self-review local của Issue #9, gồm bản sửa cuối cho
metadata profile/context. Chưa tạo PR, merge hoặc đóng issue trên GitHub. Người
dùng đã cho phép commit/push; merge vẫn cần duyệt rõ. Xem `git log -3 --oneline`
để biết commit review cuối chứa file này (sau commit chức năng `9cef982`).

## Đã làm

- Thêm library `compare_reports` (dictionary, không I/O) và adapter
  `compare_runs` (hai report JSON local), tích hợp CLI text/JSON.
- Kiểm tra scenario/profile identity, version và fingerprints; môi trường,
  target bindings và độ dài cửa sổ bằng nhau. Run ID, thời điểm, evidence và
  collection declarations có thể khác theo contract.
- Phân biệt 16 chuyển trạng thái assertion, không gộp unknown/missing thành fail.
- `Regression Passed` chỉ áp dụng khi gap đã xác nhận được khắc phục hoàn toàn;
  sửa một phần trả `Improved with remaining gaps`.
- Giữ evidence IDs, refs/hashes, witness pairs và unevaluable IDs hai phía;
  hiển thị evidence added/removed/retained, sửa lỗi text tách ID thành ký tự.
- Từ chối assertion trùng ID, witness/ref đứt, counts/verdict/assurance mâu thuẫn,
  JSON hỏng, metadata thiếu hoặc không khớp hash.
- Review cuối phát hiện và sửa thêm: metadata dù được tính lại hash vẫn phải
  có binding đúng kiểu, nguồn rule khớp scenario và role phù hợp expected outcome.
  Tái sử dụng `validate_rule_source` và `resolve_operand` hiện có của engine.
  Bốn regression tests xác nhận engine từ chối input này và comparison cũng vậy.
- Bổ sung tài liệu tiếng Việt, lệnh PowerShell chạy nguyên khối và lưu checkpoint này.

## Kiểm chứng mới nhất

Ngày 2026-09-11, Python `I:\AEGIS-VERIFY\.venv\Scripts\python.exe`, phiên bản
3.13.14, Windows:

| Kiểm tra | Kết quả |
| --- | --- |
| `backend/tests/test_compare_contract.py` và `test_cli_compare.py` | 77 passed |
| Toàn bộ `backend/tests` | 1858 passed, 1 skipped, 35.61 giây |
| Test skipped | `test_intake_io.py:452`: FIFO không có trên Windows |
| `python -m pip check` | No broken requirements found |
| `git diff --check` | Không có lỗi whitespace |
| Wheel build với build isolation | Thành công, không thêm runtime dependency |
| Import comparison trực tiếp từ wheel, không dùng source checkout | Thành công |
| Wheel smoke với synthetic report | Unchanged pass |

Lệnh full test đã dùng:

```powershell
$finalReviewTemp = 'build/pytest-issue9-final-review-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp $finalReviewTemp --tb=short
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Các con số 1781/1786/1854 trong lịch sử không phải kết quả cuối của bản này.
Test trước fix metadata: 4 ca mới đều fail đúng vì comparison chưa từ chối;
sau fix, 77 test comparison và toàn bộ backend đều pass như trên.

## Phạm vi và giới hạn review

Đã đối chiếu acceptance criteria Issue #9 do user cung cấp, đọc diff/engine
contracts và kiểm chứng các ca synthetic. Chưa đọc được issue bằng GitHub web
trong lượt khảo sát trước; không giả định đã xác minh nội dung online mới nhất.
Không phát hiện thêm blocker trong phạm vi self-review sau bản sửa cuối.
Đây không phải review độc lập; cần người review khác trước merge.

- Không có lab retest thật trong lượt này. Synthetic chứng minh logic phần mềm,
  không chứng minh detection rule của lab đang hoạt động.
- Fingerprints không phải chữ ký. Không xác minh raw bytes hoặc attestation
  ngoài đời, không re-evaluate predicates từ raw logs.
- Adapter file giới hạn 1 MiB/report; từ chối thay vì cắt evidence.
- Report cũ thiếu `comparison_inputs` phải chạy `validate` lại.
- JSON mới có snapshot scenario/profile/context, có thể chứa dữ liệu cấu hình
  nhạy cảm; sanitize trước chia sẻ. Chưa có live connector, dashboard hoặc execution.
- Không sửa engine/canonical semantics, scenario ground truth hay dependency runtime.

## Tiếp tục từ đây

1. Đọc `docs/CLI_COMPARE.md` và file này; kiểm tra `git status`, branch, remote
   trước thao tác. Không reset/clean các file của user.
2. Reviewer độc lập xem diff `ef61d36..HEAD`, ưu tiên compatibility policy,
   unknown states, Regression Passed và evidence traceability. Có thể dùng
   lệnh smoke PowerShell trong tài liệu; không cần lab để chạy bộ test phần mềm.
3. Sau khi user duyệt tạo PR/merge, kiểm tra CI và head mới nhất, rồi mới tích hợp.
   Không đánh dấu issue đã đóng trước khi GitHub xác nhận.
4. Lab validation là bước demo tiếp theo: hai snapshot trước/sau cùng scenario,
   profile và target scope; baseline có telemetry và attestation đủ để xác nhận
   gap, sau sửa rule có detection witness. Không tự tạo attestation cho lab thật.

Các tài liệu tổng kết cũ và `tests/fixtures/cli/synthetic-detected-after/` đang
untracked là dữ liệu có trước, không thuộc commit Issue #9. Giữ nguyên chúng.
Không mở raw lab exports hoặc credentials để tiếp tục task này.

## Prompt chuyển giao ngắn

> Tiếp quản Issue #9 AEGIS Verify tại I:\AEGIS-VERIFY, branch
> codex/issue-9-compare-runs. Đọc AGENTS.md, docs/ISSUE_9_HANDOFF.md và
> docs/CLI_COMPARE.md trước. Code đã triển khai, kiểm chứng và push; chưa merge.
> Baseline main ef61d36; kết quả local cuối 1858 passed, 1 skipped (Windows FIFO).
> Không coi kết quả lịch sử là test mới chạy. Review diff, giữ nguyên file untracked
> của user, không sửa ground truth hoặc làm issue khác. Chỉ tạo PR/merge khi user
> duyệt rõ. Nếu có finding, nêu file/dòng, tác động và cách tái hiện.
