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

## Ngoài phạm vi (theo issue)

Không auth, không multi-tenant, không billing, không production hosting, không
live connector (#11). Server chỉ dành cho máy của người vận hành với report đã
review; không expose ra mạng.
