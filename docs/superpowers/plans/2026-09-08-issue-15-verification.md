# Issue #15 — báo cáo triển khai và kiểm chứng

Ngày: 2026-09-08. Nhánh: `codex/issue-15-lossless-timestamps`.
Worktree: `I:\AEGIS-VERIFY\.worktrees\issue-15-lossless-timestamps`.
Code đã kiểm chứng tại commit `85347f1`; tài liệu được commit tiếp sau.
**Chưa push, chưa merge, chưa đóng Issue #15.**

## Kết quả

- Baseline trước thay đổi: **365 passed**.
- Toàn bộ backend sau sửa và review: **507 passed** — thêm 142 test cases.
- Bản wheel cài vào môi trường mới: **507 passed**, import từ `site-packages`.
- `pip check` ở cả hai môi trường: **No broken requirements found.**
- Hai đoạn Python trong hướng dẫn v2: **2 passed**.
- `git diff --check`: không lỗi whitespace (Git có cảnh báo LF -> CRLF thông thường).
- Không sửa dependencies, connector, scenario/ground truth, hash helper hoặc test v1 cũ.
- Không thêm log thật, fixture chưa ẩn danh, credentials hoặc secrets.

Môi trường đã chạy: Windows, Python 3.13.14, Pydantic 2.13.5, pytest 9.1.1.
Không dùng `.venv` của root đang editable-install từ worktree Issue #1.

## Đã triển khai

1. `PreciseTimestamp`: immutable, UTC, 0..9 chữ số, integer arithmetic, epoch âm,
   giữ trailing zeros, so sánh/hash theo instant, chênh lệch 1 ns chính xác.
2. Chỉ chuyển về datetime khi biểu diễn chính xác; không cắt hoặc làm tròn.
3. `CanonicalEventV2` dùng kiểu mới cho cả hai trường thời gian; giữ v1 riêng,
   dùng chung non-time validation để tránh lệch hợp đồng.
4. Reader có version rõ ràng, JSON UTF-8 strict, giới hạn dung lượng/depth/number,
   chống duplicate key, cycle, NaN/Infinity và thông báo lỗi lộ input.
5. Nâng cấp v1 -> v2 có revalidation, giữ IDs/hash/reference/fields, không mutate.
6. [Hướng dẫn tiếng Việt](../../CANONICAL_EVENT_V2.md), có ví dụ chạy được.

## TDD và review

- Trước code, test từng phần ghi nhận module/API chưa tồn tại.
- Timestamp: sửa lỗi forward annotation khi import; test tiếp theo phát hiện
  dataclass bị Pydantic xuất dict nội bộ trong Python mode. Chuyển sang immutable
  slotted value object, kiểm tra lại cả Python và JSON serialization.
- Test bổ sung phát hiện `copy`/`model_copy(deep=True)` không tương thích với
  immutable slots. Thêm copy/deepcopy trả cùng value bất biến; RED -> GREEN.
- Review độc lập chỉ đọc code: không tìm thấy lỗi mất precision; reviewer chạy
  thêm 10.000 phép thử timestamp/offset/width xác định và 312 focused tests.
- Finding P2: migration dùng nhầm reader nên từ chối v1 hợp lệ có field vượt
  reader budget. Tái hiện bằng hai test (text > 1 MiB, integer 129 chữ số), cả hai
  fail trước sửa. Đổi sang validate v2 trực tiếp sau revalidate/serialize v1.
- Review lại: 53 reader/migration tests passed, P2 resolved, không finding mới.
- Full suite cuối và wheel đều 507 passed. Đây là review hỗ trợ, không thay
  thế người dùng review/lab validation khi tới phần parser nguồn.

Sai sót setup đã xử lý: lượt baseline đầu dùng `--basetemp=build/...` khi chưa có
parent `build`, dẫn đến 360 passed + 5 setup errors. Sau tạo parent và dùng đường
dẫn temp mới, baseline đạt 365 passed. Đây không phải lỗi code sản phẩm.

Lượt thử thêm với lệnh pytest mặc định sau đó chạy tới 100% nhưng thất bại ở
session cleanup: Windows từ chối quyền truy cập `Temp/pytest-of-kuroh/pytest-current`.
Không tính lượt đó là pass; không sửa ACL hoặc xóa thư mục Temp của người dùng.
Lệnh đối chiếu dưới đây chọn basetemp mới trong worktree như các lượt đã xanh.

## Lệnh đối chiếu dành cho người dùng

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-15-lossless-timestamps'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
```

Kỳ vọng: `507 passed` và `No broken requirements found.` Dùng đúng `.venv`
của worktree này, không chạy `python <đường-dẫn-python.exe>`.

## Lệnh kiểm chứng đã chạy

Từ worktree:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp=build/pytest-review-fix
# 507 passed in 1.66s
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -m pip wheel . --no-deps --wheel-dir build/reviewed-wheel
& '.\.venv\Scripts\python.exe' -m venv build/package-check
```

Từ thư mục `build`:

```powershell
& '.\package-check\Scripts\python.exe' -m pip install '.\reviewed-wheel\aegis_verify-0.1.0-py3-none-any.whl[test]'
& '.\package-check\Scripts\python.exe' -c 'import aegis_verify; print(aegis_verify.__file__)'
& '.\package-check\Scripts\python.exe' -m pytest ../backend/tests -q --import-mode=importlib --basetemp=pytest-wheel-final
# 507 passed in 2.19s
& '.\package-check\Scripts\python.exe' -m pip check
```

Import được xác nhận tại `build/package-check/Lib/site-packages/aegis_verify/__init__.py`.
Wheel đã test: `build/reviewed-wheel/aegis_verify-0.1.0-py3-none-any.whl`.
SHA-256: `21fcef94360d17765440559209057fac6aa46d09ebd8791a43a0eb416234b43b`.
Bản wheel thử trước review ở `dist/` đã lỗi thời; không dùng nó để cài/phát hành.
Các artifact build/venv không được commit. Không tái sử dụng các basetemp trên
nếu cần giữ output cũ, vì pytest tự dọn thư mục đó khi chạy lại.

## Giới hạn và bước tiếp theo

- Chưa chạy CI GitHub hoặc Python 3.11/3.12/Linux; wheel được test trên Windows 3.13.
- Chưa chứng minh thời gian đồng hồ lab chính xác; nanosecond là độ rộng dữ liệu.
- Chưa triển khai Wazuh parser, CSV import, live SIEM hay engine trong Issue #15.
- Reader giới hạn resource; gọi trực tiếp model constructor không có các budget đó.
- Revalidation xử lý API bypass thông thường; Python reflection không được sandbox.
- Người dùng đọc hướng dẫn, chạy đối chiếu, review trước khi cho phép push/PR/merge.
- Sau duyệt Issue #15 mới cập nhật thiết kế Issue #3 và triển khai fixture parser
  Wazuh dùng timestamp v2, kiểm tra log đã ẩn danh và hash evidence.
