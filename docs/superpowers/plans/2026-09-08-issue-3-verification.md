# Issue #3 — mốc Wazuh Windows 4688 và kết quả kiểm chứng

Ngày: 2026-09-08 (UTC+7). Worktree:
`I:\AEGIS-VERIFY\.worktrees\issue-3-wazuh-fixture-parser`.
Nhánh: `codex/issue-3-wazuh-fixture-parser`.
Code đã kiểm chứng: `2e2176d`; tài liệu commit tiếp sau.
**Chưa push/PR/merge Issue #3, chưa đóng issue. Cần người dùng đối chiếu mapping.**

## Trạng thái nền tảng

- Issue #15 đã được người dùng chạy đối chiếu: 507 passed, pip check sạch.
- Đã push và merge [PR #16](https://github.com/Tindaptrai/aegis-verify/pull/16),
  commit main `cf55f9d23fbe78ed664afea37a8eca51cb9caffa`; Issue #15 đã đóng.
- GitHub có GitGuardian successful, không phải pytest CI. Chưa có test CI được
  thiết lập/chạy cho lượt này. Báo cáo Issue #15 cũ là snapshot trước merge.
- Worktree Issue #3 được cập nhật main, dùng venv riêng. Không sửa `.venv` root
  đang editable-install từ worktree Issue #1; không xóa các worktree cũ.

## Đã triển khai trong Issue #3

1. Decoder JSON bounded: strict UTF-8, duplicate-key rejection, finite numbers,
   depth/node/numeric/byte limits và diagnostic không lộ raw input.
2. Profile Windows Security-Auditing/Security/4688 → `CanonicalEventV2`.
3. Event time chỉ từ Windows `systemTime`, giữ nguyên 0..9 chữ số, chuẩn hóa UTC.
4. Topology do caller khai báo; collector khác event origin; không suy IP kết nối
   từ agent IP. Optional missing/null giữ null, sai kiểu phải báo lỗi.
5. Hash đúng byte, evidence ID có namespace và context rõ ràng, raw ref record 1.
6. Loader chỉ đọc file; package import qua `aegis_verify.connectors.wazuh`.
7. Mẫu người dùng đã ẩn danh, `.gitattributes -text` giữ nguyên byte fixture;
   hướng dẫn tiếng Việt có ví dụ chạy được và giới hạn profile.

Không thêm dependency, không sửa canonical schema/ground truth, không chạy live
SIEM hoặc scenario, không đưa log gốc chưa ẩn danh vào Git. Mẫu này không được gán
cho INC-002 hay kết luận tấn công.

## Kiểm thử và review

| Check | Kết quả |
|---|---|
| Baseline sau cập nhật v2 | 507 passed |
| Decoder mới | 29 passed; full suite 536 passed |
| Mapper đầu tiên | 109 passed; full suite 645 passed |
| Sau sửa finding PID | **650 passed in 2.53s** |
| Wheel cài riêng, import từ site-packages | **650 passed in 2.95s** |
| pip check cả hai môi trường | No broken requirements found |
| Ví dụ Python trong hướng dẫn | Chạy được, 3 assertion pass |
| Independent reviewer lần đầu | 138 connector tests passed |
| Independent reviewer sau sửa | 143 connector tests passed |

TDD: decoder và mapper đều có lượt RED vì API chưa tồn tại trước implementation.
Review độc lập không thấy critical/important finding. Một finding nhỏ: PID có
107 hex digits chuyển thành 129 decimal digits, qua canonical model nhưng bị
canonical JSON reader từ chối. Thêm 2 test RED (DID NOT RAISE), giới hạn giá trị
sau chuyển đổi <=128 decimal digits; thêm 3 test reader round-trip, kể cả boundary
và leading zeros. Tổng 5 test GREEN; không thay đổi hợp đồng canonical.
Review lại xác nhận finding resolved, không có finding code mới. Lỗi định dạng
bảng trong design cũng đã được sửa.

Môi trường: Windows, Python 3.13.14, Pydantic 2.13.5, pytest 9.1.1.
Chưa kiểm chứng Python 3.11/3.12 hoặc Linux, chưa fuzz exhaustive.
Lượt review hỗ trợ không thay thế human lab validation hoặc chứng minh độ phủ
toàn bộ Wazuh. Byte hash không chứng minh đồng hồ/source authenticity.

## Lệnh đã chạy

Từ worktree:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp=build/pytest-review-fix-3
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -m pip wheel . --no-deps -w build/wheels-issue3-reviewed
& '.\build\package-check-issue3\Scripts\python.exe' -m pip install --force-reinstall --no-deps build/wheels-issue3-reviewed/aegis_verify-0.1.0-py3-none-any.whl
```

`build/package-check-issue3` đã được tạo mới bằng `python -m venv`, cài wheel
và `[test]` trước review; sau sửa chỉ reinstall wheel code mới, không editable.
Từ thư mục `build`:

```powershell
& '.\package-check-issue3\Scripts\python.exe' -c 'import aegis_verify, aegis_verify.connectors.wazuh as w; print(aegis_verify.__file__); print(w.__file__)'
& '.\package-check-issue3\Scripts\python.exe' -m pytest ../backend/tests -q --import-mode=importlib --basetemp=pytest-wheel-3-reviewed
& '.\package-check-issue3\Scripts\python.exe' -m pip check
```

Cả hai import được xác nhận trong `build/package-check-issue3/Lib/site-packages`.
Wheel đã test: `build/wheels-issue3-reviewed/aegis_verify-0.1.0-py3-none-any.whl`.
SHA-256: `08c340afb37e508ba4397204425e5d1cbc2398d1a56068c882503cb99253f135`.
Wheel cũ ở `build/wheels-issue3` có trước sửa PID, không dùng để phát hành.

Fixture SHA-256:
`27813eae73a3276ab9bc61aeccf8572d0ba5309692ae4a888f7b8f7e55527571`.
`git hash-object --no-filters` và index blob đều là
`b39bcaa22d10ca2e3a7e68463c0e7c4413d84cd7`: byte được stage không đổi.
Fixture đã đọc/scan toàn bộ; bản gốc chưa ẩn danh nằm ngoài Git.

Không tái dùng basetemp nếu muốn giữ output cũ: pytest tự dọn target khi chạy lại.
Windows có thể lỗi cleanup trong Temp mặc định, nên dùng đường dẫn fresh ở `build`
như hướng dẫn, không sửa ACL/xóa Temp người dùng.

## Cần người dùng làm tiếp

Đọc [hướng dẫn](../../WAZUH_FIXTURE_PARSER.md), chạy lệnh đối chiếu ở đúng worktree,
gửi tổng kết test/pip check và kiểm tra các trường với log gốc. Chọn thêm profile
theo scenario thực tế nếu cần, chuẩn bị mẫu đã ẩn danh trước khi mở rộng.
Chỉ tạo PR/merge sau khi người dùng review evidence và quyết định độ phủ Issue #3.
