# Results dashboard (Issue #10)

Dashboard đơn giản hiển thị kết quả validation do backend tạo. Nó là lớp trình
bày: đọc report JSON của `aegis validate` và `aegis compare`, không đánh giá
lại, không suy luận, không viết lại validation rules.

## Kiến trúc

```text
aegis validate --format json  ─┐
aegis compare  --format json  ─┼─► thư mục report (*.json)
                               │
        aegis dashboard --reports <dir> [--static frontend/dist]
                               │  (http.server stdlib, 127.0.0.1, chỉ GET)
                               ▼
        GET /api/reports  ·  GET /api/reports/<name>  ·  static dist/
                               │
                               ▼
        frontend (React) — loading / empty / malformed / backend-error
```

- Server không thêm dependency Python. Nó dùng đúng giới hạn intake hiện có
  (`read_local`, `decode_config`, 1 MiB mỗi report) và trả `422` với mã lỗi
  intake khi file không decode được; không bao giờ trả report một phần.
- Tên file phải khớp `[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json`; không có
  traversal; chỉ liệt kê tối đa 200 file.
- Report `evaluation` nay có thêm mục `timeline` (version `0.1.0`): các event
  được `evidence_index` tham chiếu, sắp theo `timestamp` rồi `event_id`, với các
  trường canonical sao chép nguyên (`null` giữ `null`). `EvaluationResult`,
  fingerprints và `compare` không đổi. Report cũ không có mục này vẫn được
  dashboard hiển thị, kèm thông báo không có thời điểm.

## Chạy nhanh với fixture synthetic

```powershell
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports tests\fixtures\dashboard --static frontend\dist
```

Nếu `frontend/dist` chưa có: `cd frontend; npm install; npm run build`.
Mở `http://127.0.0.1:8765/`. Fixture gồm run trước (False negative, attestation
synthetic), run sau (Detected), comparison (Regression Passed), một file JSON
cụt và một file `kind` không hỗ trợ để thấy trạng thái malformed.

## Acceptance criteria → nơi kiểm

Màn hình run có hai biểu đồ từ số đếm backend: vòng phân bố bốn outcome
assertion và thanh ngang cho parsed/referenced/skipped. Các thanh dùng cùng
thang đo và là số đếm độc lập (referenced không phải nhóm tách biệt khỏi parsed).
Biểu đồ không suy luận coverage toàn hệ thống hay tạo kết luận detection mới.
Số liệu có nhãn văn bản, hỗ trợ screen reader và trạng thái không có dữ liệu.
Không thêm thư viện biểu đồ hoặc dependency.

| AC | Nơi kiểm |
| --- | --- |
| Scenario, run ID, final result, classification, evidence count | `RunView` mục "Tổng quan"; test `renders scenario, run ID, final result…` |
| Assertion pass/fail với evidence IDs liên kết | bảng Assertions, link `#evidence-<id>` tới timeline; cùng test |
| Timeline có thứ tự, không bịa giá trị thiếu | backend `evidence_timeline` (`test_cli_timeline.py`); frontend giữ thứ tự backend, hiển thị `null`; test "explains a report without a timeline" |
| So sánh trước/sau Gap → Fix → Re-test | `ComparisonView`; fixture `comparison-regression-passed.json`; test "Comparison view" |
| Loading, empty, malformed, backend-error | `App.test.tsx` mục "App states" và các test 422/500/network |
| Không tái hiện validation rules | `contracts.ts` chỉ kiểm cấu trúc; không có logic outcome/status trong frontend |
| Tests tập trung | `frontend/src/*.test.ts(x)`, `backend/tests/test_dashboard_server.py`, `backend/tests/test_cli_timeline.py` |
| Tests hiện có xanh | `pytest backend/tests`; `npm test` |

## Run binding (bổ sung hiển thị)

Màn hình run và comparison hiển thị `run_binding.status`, `reasons`, run ID và
`both_sides_caller_declared` từ report. Hai phía comparison được trình bày riêng.
Report cũ thiếu attachment được ghi "chưa có dữ liệu", không suy ra đã review.
Attachment có status không hỗ trợ, reasons sai kiểu hoặc run ID khác report
bị từ chối bởi structural reader. Không thay verdict detection/comparison,
collection assurance hoặc tự suy ra `lab_verified` từ `caller_reviewed`.

Phần này không nhập native review và không sửa cơ chế companion/backend.
Các findings native thu riêng không tự cập nhật report lịch sử; reason cũ như
`native_review_missing` vẫn phản ánh chính input của report đó.
Tests: `frontend/src/binding.test.tsx`; toàn frontend 59 tests và build đã qua
ngày 2026-09-19. Chỉ dùng synthetic fixtures trong tests, không đưa log lab vào Git.

## Ngoài phạm vi (theo issue)

Không auth, không multi-tenant, không billing, không production hosting, không
live connector (#11). Server chỉ dành cho máy của người vận hành với report đã
review; không expose ra mạng.

## Review hardening (2026-09-19)

- Các số đếm phải là số nguyên không âm trong miền safe integer của JavaScript;
  report sai cấu trúc bị từ chối trước khi vẽ biểu đồ. Đây không phải tính lại
  kết quả validation.
- Bảng mô tả assertion dùng map không có prototype; ID như `__proto__` không
  làm React lỗi hoặc hiển thị một mô tả chưa có trong dữ liệu.
- Nhãn so sánh dùng “Trước”, không tự gọi mọi run trước là detection gap.
- Bảng giữ cuộn ngang bên trong wrapper; nhãn ẩn cho screen reader không làm
  tràn toàn trang trên mobile. Kiểm tra browser 390px: lỗi tràn 636px trước sửa,
  sau sửa document 375px khi bảng đã tải; desktop 1440px không tràn ngang.
- 45 test frontend đạt; TypeScript/build production đạt. Có regression test cho
  malformed counts, prototype-named IDs, và nhãn so sánh trung lập.
- Backend toàn bộ: **2595 passed, 1 skipped** (FIFO không hỗ trợ Windows).
  Lượt đầu lỗi setup do thiếu thư mục cha của pytest basetemp; đã tạo thư mục
  build/verification và chạy lại toàn bộ đạt. Review độc lập sau sửa không còn
  phát hiện Critical/Important.

Giao diện kiểm tra bằng fixture synthetic, không phải báo cáo detection của lab
live. Human review vẫn cần trước merge; không tự đóng Issue #10.
PR #27 đã merge; các bổ sung charts/hardening/run binding được bàn giao qua
nhánh follow-up `codex/issue-10-dashboard-polish`, không cập nhật PR đã merge.
