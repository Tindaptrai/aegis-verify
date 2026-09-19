# V1 — bàn giao demo/lab

## Phạm vi đã tích hợp

Baseline: main `a3990089d7a05b6f59a0ef7a35b5eafa7da10944`, sau PR #28, #29, #30.
V1 là mốc demo/lab; không có nghĩa package đã đổi version hoặc đã tạo release.
Dashboard chỉ đọc report: bấm chọn không chạy payload, không kết nối máy đích,
không tự hiển thị trạng thái online của endpoint.

## Chạy ở máy nào?

| Máy | Vai trò | Chạy gì |
| --- | --- | --- |
| Máy thật / máy vận hành chứa repo | Chạy AEGIS và xem kết quả | Python, build frontend, dashboard, collector, SSH tunnel nếu dùng |
| VM MGMT | Máy quản trị lab riêng | Chỉ thao tác quản trị; không mặc định là máy chạy scenario |
| VM USER | Endpoint được chọn cho scenario | Chỉ chạy safe-demo đã được duyệt; Sysmon/PowerShell logging |
| Máy Wazuh | Lưu/thu thập telemetry | Manager/Indexer; không chạy lệnh Python của repo ở đây |

Tên/IP/agent ID thật nằm trong hồ sơ riêng, không hard-code vào hướng dẫn chung.
PowerShell mở mới không thừa hưởng biến từ cửa sổ khác. Không suy ra tên máy từ
prompt `C:\Windows\system32`; dùng `$env:COMPUTERNAME` để kiểm tra.

## Khởi động từ checkout đã duyệt trên máy vận hành

Trong thư mục gốc repo, Python >=3.11 và Node/npm đã được cài:

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -e '.[test]'
Push-Location frontend
npm ci
npm run build
Pop-Location
$reports = Read-Host 'Duong dan thu muc report da review'
./.venv/Scripts/python.exe -m aegis_verify dashboard --reports $reports --static frontend/dist --port 8766
```

Mở `http://127.0.0.1:8766/`. Giữ cửa sổ lệnh này mở; Ctrl+C dừng server.
Đây là loopback không có authentication: không expose ra mạng hoặc đổi sang
`0.0.0.0`. Xem report đã có không cần VM, tunnel hay mật khẩu Wazuh.
Không chạy `git pull` vào checkout đang có thay đổi chưa lưu; dùng worktree riêng.

## Kiểm tra giao diện

1. Chọn từng run, kiểm tra run ID, assertion và evidence IDs.
2. Mở Timeline, bật ID đầy đủ; đối chiếu raw ref với hồ sơ riêng.
3. Chọn comparison, kiểm tra đúng cặp run và trạng thái từng assertion.
4. Đọc collection assurance/run binding riêng với detection verdict.
5. Bấm Tải lại: chỉ đọc lại report, không chạy scenario.

Đối chiếu demo lịch sử bằng [pins và evidence IDs](evidence/scn001-v2-pins.json)
và [bản ghi duyệt](SCN001_V2_APPROVAL_AND_PINS.md). Không tạo dữ liệu hoặc đổi
ground truth để làm đẹp kết quả. Native corroboration chưa được nhập vào report
lịch sử không tự xóa lý do `native_review_missing`.

## Collector và tài khoản

Theo [hướng dẫn live collector](WAZUH_LIVE_CONNECTOR.md). Chạy trên máy vận hành,
trong đúng phiên đã nạp credential và CA. Không gửi mật khẩu vào chat.
URL phải là chuỗi HTTPS thuần, không phải cú pháp liên kết Markdown.
Chọn agent/window đã duyệt; collector không thực thi scenario.

Kiểm tra quyền thực tế ở Indexer bằng tài khoản quản trị do người vận hành giữ:
review user mapping, tất cả mapped roles, index patterns, cluster/index actions,
backend roles và role inheritance/action groups. Chỉ cho phép phạm vi đọc/search/
scroll/clear-scroll cần thiết trên index được duyệt. Không tự cấp all_access,
quyền ghi hoặc wildcard mọi index để chữa lỗi 403. Đăng nhập dashboard thành công
hay search thành công không chứng minh tài khoản không có quyền dư.

## Lỗi thường gặp

| Hiện tượng | Cần kiểm tra |
| --- | --- |
| `& $python` báo BadExpression | Biến chưa có ở cửa sổ hiện tại; dùng đường dẫn Python venv đầy đủ |
| `invalid_config` | Có username/password trong đúng process, URL thuần, CA hợp lệ, khoảng UTC hợp lệ |
| `permission_denied` | Review role mapping; không cấp admin để bỏ qua |
| Lỗi TLS | CA/hostname/tunnel đúng; không tắt certificate verification |
| Record overflow | Khoảng nhỏ hơn hoặc `--adaptive`; không evaluate thư mục INCOMPLETE |
| Count mismatch khác overflow | Dừng và điều tra; adaptive không chữa mọi lỗi count |
| Report rỗng | Chưa đủ cơ sở kết luận false negative |
| Port đang dùng | Kiểm tra đúng server hiện có trước khi dừng; không kill mọi tiến trình Python |

## Bàn giao và các gate còn mở

- Source trên Git; bằng chứng gốc, báo cáo thật, CA và credential ở ngoài Git.
- Lập manifest SHA-256, kiểm lại hash trước khi sao lưu. Hash chỉ kiểm toàn vẹn,
  không chứng minh tính xác thực hay collection đầy đủ.
- Sao lưu mã nguồn và dữ liệu riêng thành hai phần; chỉ chia sẻ evidence qua
  kênh được chủ dự án duyệt. Bản lưu cùng ổ không thay thế backup độc lập.
- Review quyền: operator đã xác nhận qua giao diện rằng tài khoản collector chỉ
  được map vào role đọc đã review, không có role khác. Ảnh được cung cấp hiển thị
  read trên index alerts, scroll/clear-scroll, không tenant permissions và backend
  roles trống. Đây là operator-reviewed, không phải kiểm chứng tự động toàn bộ
  quyền hiệu lực hoặc định nghĩa action groups; ảnh gốc giữ ngoài Git.
- Historical run binding: unknown; không tự ký approval hoặc đổi thành lab_verified.
- Behavioral demo rule có thể khớp runner lành tính; không triển khai production.
- Chờ chủ dự án duyệt ghi chú/tên tag trước khi tạo tag hoặc GitHub Release.
- Không tự xóa staging, rule backup, evidence hay worktree.
