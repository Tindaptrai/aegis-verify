# Khởi động dashboard bằng một lệnh (Issue #33)

Chạy trên máy vận hành có repo, không phải VM USER hay Wazuh.
Sau khi chuẩn bị Python venv/package và build frontend theo
[runbook](V1_HANDOFF.md), tại gốc checkout:

```powershell
./Start-Aegis.ps1 -Reports 'D:/private/reports' -Port 8766
```

Thay đường dẫn ví dụ bằng thư mục report đã review. Từ thư mục khác, gọi script
bằng đường dẫn đầy đủ; đường dẫn reports tương đối được tính từ thư mục hiện tại.
Đường dẫn có dấu cách phải đặt trong dấu nháy. Không dùng wildcard hoặc ký tự
`*?[]`: quy tắc intake hiện có vẫn được giữ nguyên.

- Mặc định dùng `.venv/Scripts/python.exe` bên cạnh script, không đoán Python từ PATH.
- Nếu dùng môi trường khác đã cài AEGIS, truyền `-PythonPath 'D:/env/Scripts/python.exe'`.
- Kiểm tra thư mục report, Python >=3.11/import AEGIS, `frontend/dist/index.html`
  và khả năng bind port. Không kiểm chứng độ mới/toàn vẹn của toàn bộ asset build;
  hãy build lại khi đổi frontend.
- Script in URL; mở URL đó trong trình duyệt. Server chạy foreground trên
  `127.0.0.1`, Ctrl+C để dừng. Không cài background service hay tự mở trình duyệt.
- Không cài dependency/build tự động; không sửa execution policy, kết nối lab,
  đổi report, kill tiến trình hoặc chạy scenario.
- Mặc định không hỏi credential. Chỉ khi dùng Operations và truyền cả
  `-OperationsConfig` lẫn `-PromptCredentials Inventory|Collections|Both`,
  launcher mới hỏi username và mật khẩu ẩn ngay trong terminal (thêm ở PR #45).
  Credential chỉ nằm trong môi trường tiến trình khi server chạy và được khôi
  phục khi thoát; không truyền qua tham số, không lưu file. Chi tiết và mã lỗi
  `credential_input_failed`, `launcher_start_failed`: xem
  [Nhập credential trong terminal](OPERATIONS.md#nhập-credential-trong-terminal-windows-powershell).
- Hỗ trợ Windows PowerShell 5.1 và PowerShell 7 trên Windows. Nếu chính sách tổ
  chức chặn script, dừng và nhờ người quản trị review; không tắt policy toàn máy.

| Mã/thông báo | Cách xử lý |
| --- | --- |
| `reports_missing` | Chọn thư mục report tồn tại |
| `python_missing` | Chuẩn bị venv hoặc cung cấp PythonPath đúng |
| `python_unsupported` | Dùng Python >=3.11 |
| `package_missing` / `python_environment_invalid` | Kiểm tra môi trường Python và cài project theo runbook |
| `build_missing` | Trong frontend: npm ci, sau đó npm run build |
| `port_unavailable` | Chọn port khác hoặc tự dừng đúng server cũ |
| `invalid_path` | Chọn đường dẫn local không mơ hồ theo quy tắc intake |
| `local_path_required` | Không dùng UNC/network share, URL hay đường dẫn provider |

Port có thể bị tiến trình khác chiếm sau preflight; server vẫn bind độc quyền và
báo lỗi qua CLI, không chiếm lại port bằng cách dừng tiến trình đó. Không thể
kết luận endpoint online hoặc detection thành công từ việc dashboard mở được.

Tests chạy launcher thật trên cả hai shell khi có sẵn, dùng fixture và port
loopback tạm; kiểm tra lỗi, đường dẫn có dấu cách, read-only HTTP và giữ report
nguyên byte. Tests không dùng bằng chứng hay credential lab.
