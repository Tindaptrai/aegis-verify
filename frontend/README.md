# Frontend — results dashboard (Issue #10)

Dashboard chỉ đọc cho report của CLI: `aegis validate --format json` (một run)
và `aegis compare --format json` (trước/sau). Nó **không** đánh giá lại
assertion, không sắp xếp lại evidence, không điền giá trị backend để `null`.
Mọi trạng thái (`Detected`, `False negative`, `unknown`, …) hiển thị nguyên
văn như backend trả.

Stack: Vite + React + TypeScript; test bằng Vitest + Testing Library (jsdom).
Chỉ có `react`/`react-dom` là dependency runtime; phần còn lại là dev-only.
Lý do chọn: ARCHITECTURE.md đã đặt React cho interface sau CLI; Vite/Vitest là
bộ tối thiểu có test component mà không cần cấu hình riêng.

## Chạy

Backend (không thêm dependency Python; server stdlib chỉ bind loopback, chỉ GET):

```powershell
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports tests\fixtures\dashboard --static frontend\dist
```

Mở `http://127.0.0.1:8765/`. `--reports` là thư mục chứa file `*.json` do CLI
tạo; `--static` (tùy chọn) phục vụ bản build của frontend từ cùng cổng.
Đổi cổng bằng `--port`; `--host` mặc định `127.0.0.1`.

Phát triển frontend với hot reload (proxy `/api` sang cổng 8765):

```powershell
cd frontend
npm install
npm run dev
```

Build tĩnh vào `frontend/dist` (đã gitignore):

```powershell
npm run build
```

## Kiểm tra

```powershell
cd frontend
npm run typecheck
npm test
```

Test dùng fixture synthetic ở `tests/fixtures/dashboard/` (sinh bằng
`scripts/prepare_dashboard_fixtures.py` qua engine thật) và fetch giả lập cho
các trạng thái loading, rỗng, malformed (422 hoặc body sai contract) và
backend-error (mạng lỗi, HTTP 5xx). Backend server có test riêng trong
`backend/tests/test_dashboard_server.py`.

## Contract phía backend mà dashboard đọc

| Nguồn | Nội dung hiển thị |
| --- | --- |
| `GET /api/reports` | danh sách file, tóm tắt (`kind`, `scenario_id`, `run_id`, `final_status`, `comparison_status`) hoặc `error` nếu file không decode được |
| `GET /api/reports/<name>` | report nguyên bản; 422 nếu malformed, 404 nếu không có |
| report `evaluation` | scenario, run ID, `final_status`, `counts` theo outcome, số evidence, từng assertion với evidence IDs / unevaluable IDs / witness pairs / assurance, mục `timeline` (thứ tự do backend cung cấp) |
| report `comparison` | run trước/sau, `comparison.status`, số lượng theo state, từng assertion trước/sau với evidence thêm/bỏ/giữ |

Report tạo trước khi CLI có mục `timeline` vẫn hiển thị được: phần timeline
báo rõ "không có thời điểm trong report" và liệt kê evidence index theo ID.
