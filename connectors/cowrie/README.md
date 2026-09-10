# Cowrie connector

Profile V0 hiện có là hướng A: đọc offline **một Wazuh search-hit JSON** chứa
`_source.data` Cowrie qua `parse_cowrie_wazuh_document` hoặc
`load_cowrie_wazuh_document`. Parser phát một `CanonicalEventV2` cùng provenance
bất biến; không kết nối Wazuh/Cowrie và không chạy command hay URL trong log.

Profile nhận sáu loại event: `session.params`, `session.connect`,
`session.closed`, `login.success`, `login.failed` và `command.input`. Mapping chỉ
đọc `_source.data`; trường vắng giữ `null`, không fallback từ `full_log`.

Đây không phải reader cho file `cowrie.json` JSONL native. Native JSONL offline
là profile B chưa triển khai; live Cowrie/Wazuh access thuộc V1. Session và kết
quả authentication được giữ trong provenance, chưa có trong canonical contract
mà validation engine hiện tiêu thụ.
