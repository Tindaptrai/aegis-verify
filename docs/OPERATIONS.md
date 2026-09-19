# Local operations workspace

## Hướng dẫn nhanh cho người vận hành

### Phân biệt nơi thực hiện

| Nơi | Công việc |
| --- | --- |
| Máy Windows cài AEGIS | Mở PowerShell thường, giữ SSH tunnel, khởi động AEGIS và mở dashboard loopback. |
| Máy quản trị (MGMT) | Quản trị lab qua trình duyệt/SSH; không mặc định là máy cần kiểm thử. Nếu AEGIS cài ở đây thì chạy launcher tại đây. |
| Máy endpoint/user | Máy được theo dõi; chọn đúng agent ID trong allowlist. Không chạy launcher AEGIS ở đây trừ khi chủ động cài AEGIS trên máy đó. |
| Wazuh server | Kiểm tra dịch vụ/chứng chỉ trong terminal Linux. Quản trị API qua **Server management → Dev Tools** trên Wazuh Dashboard. |

### Trình tự sử dụng

1. Người quản trị chuẩn bị hai tài khoản riêng: Indexer đọc alerts và Server API
   có `agent:read` giới hạn theo agent ID đã duyệt. Không đưa tài khoản admin vào
   AEGIS. Không nhầm Server API users với Indexer Internal users. Quyền
   `agent:read` rộng hơn chỉ xem trạng thái, nên vẫn phải bảo vệ mật khẩu.
2. Kiểm tra CA/chứng chỉ của **từng nguồn**, đối chiếu fingerprint qua kênh tin
   cậy. Host trong URL phải khớp SAN của chứng chỉ. Nếu dùng SSH tunnel, giữ cửa
   sổ tunnel mở; không dùng tùy chọn bỏ kiểm tra TLS để xử lý lỗi.
3. Chuẩn bị cấu hình JSON riêng và evidence root chỉ người vận hành được truy
   cập theo tài liệu backend bên dưới. Không đặt chúng vào Git hoặc thư mục
   reports. Endpoint, agent ID và đường dẫn phải lấy từ lab thực tế, không sao
   chép nguyên ví dụ.
4. Trong **cùng cửa sổ PowerShell thường** khởi động launcher, nạp credential
   bằng lời nhắc nhập ẩn trong terminal. Mật khẩu không được ghi vào JSON, lịch sử lệnh, log hay
   chat. Biến môi trường của cửa sổ khác không tự truyền sang tiến trình AEGIS.
5. Chạy `Start-Aegis.ps1` với `-Reports`, cổng còn trống và `-OperationsConfig`.
   Không truyền `-OperationsConfig` thì chỉ có Reports. Giữ cửa sổ server mở.
6. Mở **Agents**, bấm **Làm mới từ Wazuh** một lần, đối chiếu agent ID, trạng thái
   nguồn và thời gian. Mở trang hoặc đọc snapshot không tự gọi nguồn Wazuh.
7. Mở **Collections**, chọn agent và khoảng UTC ngắn đã qua. Bấm **Xem lại yêu
   cầu**, kiểm tra rồi xác nhận. Đây là thu thập log, **không chạy kịch bản trên
   endpoint**, không tự sửa rule và không tự tạo verdict.
8. Chờ job kết thúc. `0 records` không đồng nghĩa false negative; assurance
   `unknown` không chứng minh telemetry đầy đủ. Kiểm tra cảnh báo cleanup, giữ
   evidence riêng và thực hiện đánh giá/review trước khi đưa report lên Reports.
9. Khi xong, chờ job hoàn tất rồi Ctrl+C tại cửa sổ AEGIS. Đóng cửa sổ credential
   và tunnel sau đó. Không tắt cưỡng bức hoặc xóa evidence để làm mất lỗi.

### Khi có lỗi

| Hiện tượng | Kiểm tra an toàn |
| --- | --- |
| Không có Collections/Agents | Có truyền cấu hình Operations không; bootstrap có lỗi không. Reports vẫn là chế độ mặc định. |
| Nguồn chưa cấu hình | Kiểm tra cặp biến credential đúng nguồn trong tiến trình launcher; không in giá trị mật khẩu. |
| `401` từ nguồn | Kiểm tra đúng tài khoản/nguồn, mật khẩu và phiên xác thực; không cấp thêm quyền để chữa lỗi đăng nhập. |
| `403` từ nguồn | Kiểm tra role/policy và agent allowlist; không chuyển sang admin. |
| TLS lỗi | Kiểm tra tunnel, SAN, hạn chứng chỉ và CA riêng từng nguồn; không tắt xác minh. |
| Cổng đã sử dụng | Chọn cổng trống hoặc xác định đúng tiến trình của mình; không tự dừng dashboard khác. |
| Evidence root bị từ chối | Dùng PowerShell không nâng quyền và root owner-only; không nới quyền để vượt kiểm tra. |
| Snapshot cũ/refresh lỗi | Không suy ra máy disconnected. Kiểm tra nguồn/tunnel; chờ cooldown rồi refresh chủ động. |
| Phiên server đổi/lỗi gửi job | Tải lại và xem lịch sử trước khi gửi lại; lỗi mạng không chứng minh job chưa được tạo. |

Tài liệu này không chứng nhận lab đã nghiệm thu. Chỉ chốt MVP sau khi kiểm thử
trên đúng phiên bản, review evidence và có quyết định của người phụ trách.

Operations is optional. Without `-OperationsConfig`, the launcher retains the
read-only Reports dashboard. Enabling it adds Collections and Agents; it does not
run scenarios, modify detection rules, administer agents, or generate verdicts.

## Prepare and start

Follow [backend configuration and ACL requirements](OPERATIONS_BACKEND.md).
Use an existing private JSON config and owner-only evidence root outside the
checkout, reports and static directories. Windows must use a normal non-elevated
operator session; the backend checks permissions but never changes them.

Supply credential pairs in the **same process environment** as the launcher:

- Indexer collection: `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`.
- Server API inventory: `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`.

Provide HTTPS endpoint and CA file separately per source in the private config.
Never put passwords in the config, command line, browser, Git, or a chat. Missing
credentials disable only that source. Do not use admin to work around a 403.

```powershell
.\Start-Aegis.ps1 -Reports 'C:/AEGIS-reviewed/reports' -Port 8770 -OperationsConfig 'C:/AEGIS-private/operations.json'
```

These paths are illustrative, not automatic setup. Choose your actual private
paths and an unused local port. The launcher installs nothing and stops no
existing service. An invalid config fails startup; it does not silently enable
an insecure fallback. UI bootstrap failure leaves Reports available and hides
the operations navigation.

### Nhập credential trong terminal (Windows PowerShell)

Sau khi chuẩn bị config/root đúng quyền, chạy từ thư mục repo trong một cửa sổ
PowerShell thường dành riêng cho AEGIS. Hai username có thể khác nhau; không nhập
tài khoản admin. Mẫu này không tạo tài khoản, không lưu mật khẩu và không tự thu
thập. Nếu chỉ dùng một nguồn, bỏ phần nạp credential của nguồn còn lại.

```powershell
$reports = Read-Host 'Thu muc report da review'
$config = Read-Host 'Duong dan operations.json rieng'
try {
    $env:WAZUH_API_USERNAME = Read-Host 'Username Server API (inventory)'
    $secret = Read-Host 'Mat khau Server API' -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential($env:WAZUH_API_USERNAME, $secret)
    $env:WAZUH_API_PASSWORD = $credential.GetNetworkCredential().Password
    $secret.Dispose()
    $credential = $null

    $env:WAZUH_INDEXER_USERNAME = Read-Host 'Username Indexer (alerts, khong phai tai khoan API)'
    $secret = Read-Host 'Mat khau Indexer' -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential($env:WAZUH_INDEXER_USERNAME, $secret)
    $env:WAZUH_INDEXER_PASSWORD = $credential.GetNetworkCredential().Password
    $secret.Dispose()
    $credential = $null

    .\Start-Aegis.ps1 -Reports $reports -Port 8770 -OperationsConfig $config
} finally {
    $credential = $null
    Remove-Item Env:WAZUH_API_USERNAME, Env:WAZUH_API_PASSWORD, Env:WAZUH_INDEXER_USERNAME, Env:WAZUH_INDEXER_PASSWORD -ErrorAction SilentlyContinue
}
```

Chọn cổng khác nếu cổng minh họa đang dùng. Đóng cửa sổ PowerShell riêng sau khi
dừng server. `401` sau khi nhập không chứng minh lỗi phân quyền: kiểm tra đúng
nguồn/tài khoản trước; không sửa role hoặc reset password để đoán lỗi.

## Collections

1. Select an allowlisted agent, enter explicit UTC start/end (`Z` or `+00:00`),
   and choose adaptive collection. Window must be at most 24 hours and not future.
2. Select **Xem lại yêu cầu**, review the frozen agent/window, then confirm.
   Escape or **Quay lại** dismisses the confirmation without submitting.
3. Watch the job or select it from history. Running jobs poll metadata every
   two seconds while viewed. Leaving the page stops polling, not the backend job.
4. A completed empty query is **0 records**, not a false negative. Collection
   assurance remains `unknown`; cleanup warnings are displayed separately.
5. Evidence remains private at the backend. Review it and use the existing
   explicit evaluation workflow before publishing a report into Reports.

One job runs at a time, no queue and no cancel button. If a request fails or the
server session changes, it is not automatically retried. Reload the page and
inspect history before intentionally submitting another request; network failure
does not prove the backend did not accept the first one. Session tokens are held
only in client memory, never in a URL or local storage.

## Agents

Opening Agents reads the saved snapshot; only **Làm mới từ Wazuh** queries the
Server API. GET polling while a refresh runs does not start another source query.
Source state, keepalive, and fetch time are distinct. Null remains unknown; an
unrecognized status is displayed as such, never guessed as disconnected.

Snapshots older than 60 seconds, or retained following a refresh failure, are
stale. Refresh errors preserve the previous complete snapshot. Refreshes have a
30-second cooldown. Pagination is not an atomic source snapshot: otherwise valid
pages can contain statuses observed at different moments. Source status is not a
ping result or a security verdict; inactive agents may still have historical logs.

## Stop and recover

Keep the backend alive until collection finishes. Ctrl+C stops admission and
drains in-flight work; a bounded source operation can delay shutdown. A forced
termination can leave incomplete evidence and an `interrupted` job at restart;
no job automatically resumes. Preserve evidence and inspect errors; do not edit
metadata to manufacture success. See backend documentation for disk/job limits,
root ownership, corruption handling and scope binding.

## Acceptance boundary

Xem [hồ sơ nghiệm thu và các gate còn mở](OPERATIONS_ACCEPTANCE.md) để đối chiếu
phiên bản đã kiểm thử, bằng chứng live riêng và giới hạn so với PRD gốc.

Fixture tests and UI previews are not live-lab proof. Human review and a real
read-only inventory refresh plus short historical collection are required before
calling this the final operational MVP. No merge/tag/release is implied by this
guide. Automated scenario execution is outside this delivery.
