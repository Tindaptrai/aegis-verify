# Dashboard overview fixtures

Output thật của `backend/app/dashboard/overview.py` (`/api/scenarios`,
`/api/scenarios/<id>`, `/api/system/status`), sinh bằng
`scripts/prepare_dashboard_overview_fixtures.py`. Không có tệp nào viết tay.

Đầu vào đều đã được review:

- manifest thật trong `scenarios/`;
- các bundle lab đã sanitize trong `tests/fixtures/cli/` (SCN-002 lượt đối chứng và lượt Block, SCN-003), được engine thật đánh giá, kèm bản so sánh SCN-002;
- các report SCN-999 synthetic và một file JSON cụt trong `tests/fixtures/dashboard/`.

Thời gian file và đồng hồ trạng thái được cố định, nên chạy lại cho đúng cùng bytes.
`backend/tests/test_dashboard_overview.py` kiểm các file này vẫn khớp với backend;
frontend dùng chúng để test giao diện tổng quan.
