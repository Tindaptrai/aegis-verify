# Cowrie connector

Connector offline V0 hỗ trợ hai profile tách biệt:

- **Hướng A — Wazuh:** đọc đúng một Wazuh search-hit JSON chứa
  `_source.data` qua `parse_cowrie_wazuh_document` hoặc
  `load_cowrie_wazuh_document`.
- **Hướng B — native Cowrie:** đọc JSONL `cowrie.json` đã sanitize qua
  `parse_cowrie_jsonl` (atomic tuple) hoặc `iter_cowrie_file` (iterator lazy).

Cả hai profile phát `CanonicalEventV2` và provenance bất biến, dùng chung mapping
cho sáu loại event: `session.params`, `session.connect`, `session.closed`,
`login.success`, `login.failed` và `command.input`. Trường nguồn vắng hoặc null
giữ canonical `null`; parser không suy đoán hoặc bổ sung fact từ record cùng
session. Native event ngoài sáu loại nhưng có `eventid` hợp lệ được trả về dưới
dạng explicit skip.

Fixture B thực tế đã audit chứa tám dòng từ cùng một source session: bảy parsed
records bao phủ đủ sáu loại được hỗ trợ và một `cowrie.client.size` skip rõ ràng.
Đây là coverage của mẫu offline, không phải bằng chứng forensic đầy đủ, kết luận
scenario hoặc lab acceptance. Session và authentication outcome chỉ nằm trong
provenance; validation engine hiện chỉ tiêu thụ canonical event nên chưa thể dùng
hai fact đó làm assertion.

Connector không kết nối live Cowrie/Wazuh, không chạy command hoặc tải URL trong
log, và không tự sanitize input production tùy ý. Credential, command và dữ liệu
định danh trong file đầu vào phải được xem là dữ liệu nhạy cảm bất hoạt; việc
sanitize diễn ra trước parser theo quy trình intake đã review. Live access vẫn
thuộc V1.
