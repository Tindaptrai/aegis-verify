# Wazuh alert sinh từ alert Suricata — parser `wazuh-suricata-alert-v1`

## 1. Dùng cho gì

SCN-002-A04 khai `source: wazuh`: bằng chứng là **Wazuh đã nổ rule** (86601 trong
lab) cho alert Suricata của đúng flow. Parser này đọc **một bản ghi alert của
manager** (một object JSON có `rule`, `agent`, `manager`, `decoder`, `location`
và alert EVE trong `data`, không có `_source`) và cho ra một `CanonicalEventV2`
với `source_type = wazuh`.

Nó khác `suricata-wazuh-alert-v1`: parser đó đọc search-hit của Indexer và cho
`source_type = suricata` để dùng cho A02. Không đếm cả hai như hai sensor độc
lập cho cùng một assertion.

Offline, không thu thập, không đổi cấu hình, không kết luận prevention.

## 2. Trường nào lấy từ đâu

| Nội dung | Nguồn | Vì sao |
| --- | --- | --- |
| `rule_id` | `rule.id` | Rule Wazuh, đây là detection của A04; số nguyên hay chuỗi thập phân đều giữ dạng chuỗi |
| `signature_id` | `data.alert.signature_id` | SID Suricata; profile pin cả hai literal |
| Tuple, `protocol`, `event_action`, `severity`, thời gian | `data.*` qua `map_alert` của connector Suricata | Cùng một hàm với A02, nên cùng giá trị và cùng chính sách thời gian |
| `timestamp` | `data.timestamp` | Giờ Suricata; giờ Wazuh nhận (`timestamp` ngoài cùng) chỉ ở provenance `collector_received_at` |
| `event_provider` | cố định `suricata` | Provider logic của bằng chứng |
| `hostname` | **không** | Agent chạy trên firewall, không phải endpoint của flow |
| `asset_id` | `agent.id` khi `collection_mode = direct` | Giống các profile Wazuh khác |

`protocol` giữ nguyên chữ của EVE (`UDP`). `event_action` giữ nguyên
`allowed`/`blocked` của alert; `allowed` ở chế độ IDS không bao giờ thành bằng
chứng chặn.

## 3. Bị từ chối

| Bản ghi | Mã | Trường |
| --- | --- | --- |
| Có `_source` (search-hit) | `unsupported_profile` | `_source` |
| `rule.groups` không có `suricata`, hoặc thiếu | `unsupported_profile` / `invalid_field` | `rule.groups` |
| Thiếu `rule.id` hoặc không phải số thập phân | `invalid_field` | `rule.id` |
| `data.event_type` khác `alert` | `unsupported_profile` | `data.event_type` |
| Lỗi trong `data` (action lạ, giờ sai, thiếu trường) | mã của connector Suricata, đường dẫn `data.…` | |

Diagnostic chỉ có từ vựng cố định, không chứa giá trị nguồn.

## 4. Context và intake

Context bundle: `ingested_at` có timezone và `collection_mode`
(`direct`/`forwarded`/`unknown`), giống `wazuh-sysmon3-archive-v1`. Một file,
một bản ghi, `raw_event_ref = <source_ref>#record=1`.

Test: `backend/tests/test_wazuh_suricata_alert.py`, fixture synthetic
`tests/fixtures/wazuh/suricata-alert/`.
