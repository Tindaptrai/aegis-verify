# Wazuh alert sinh từ alert Snort 3 — parser `wazuh-snort-alert-v1`

## 1. Dùng cho gì

Bằng chứng là **Wazuh đã nhận alert của Snort và nổ rule của chính nó** (130110
trong Lab C) cho đúng flow. Parser đọc **một bản ghi alert của manager** (một
object JSON có `rule`, `agent`, `manager`, `decoder`, `location`, `full_log` và
bản sao dạng chuỗi của dòng alert trong `data`, không có `_source`) và cho ra một
`CanonicalEventV2` với `source_type = wazuh`.

Nó khác `snort3-alert-json-v1`: parser đó đọc thẳng `alert_json.txt` của sensor
và cho `source_type = snort` để dùng cho SCN-004-A02. Hai parser cho hai bằng
chứng khác nhau của cùng một alert — alert tại nguồn, và alert SIEM đã tạo cho
nó — nên có hai evidence ID khác nhau. Không đếm cả hai như hai sensor độc lập
cho cùng một assertion.

Từ scenario `SCN-004` **0.2.0**, parser này phục vụ assertion **A04** (vai trò
detection, nguồn `wazuh`, rule Wazuh `130110`, SID Snort `1000010`), xem
[SCN004_LAB_C.md](SCN004_LAB_C.md). A02 và A04 là hai assertion riêng trên hai bản
ghi riêng: thiếu A04 trong khi A02 đạt nghĩa là **sensor phát hiện nhưng SIEM không
nhận được**, chứ không phải không phát hiện.

Offline, không thu thập, không đổi cấu hình, không kết luận prevention.

## 2. Hồ sơ được pin (Lab C)

Wazuh đọc `alert_json.txt` bằng decoder `json`, nên bản ghi giữ **nguyên dòng
alert** trong `full_log` và một **bản sao dạng chuỗi** trong `data`.

Parser map dòng trong `full_log` bằng `map_alert` của connector Snort, rồi **đòi
từng trường trong `data` phải khớp đúng dòng đó** (số thành chuỗi). Nhờ vậy câu
"Wazuh đã nhận chính alert này" là một điều được kiểm, không phải giả định; số
trường đã đối chiếu nằm ở provenance `confirmed_data_fields`. Thứ tự khoá trong
`data` không cố định giữa các phiên bản nên chỉ so tập khoá và giá trị; `full_log`
phải đúng thứ tự trường mà logger của Lab C đã pin.

## 3. Trường nào lấy từ đâu

| Nội dung | Nguồn | Vì sao |
| --- | --- | --- |
| `rule_id` | `rule.id` | Rule Wazuh, đây là detection; số nguyên hay chuỗi thập phân đều giữ dạng chuỗi |
| `signature_id` | SID trong `rule` của dòng Snort (`gid:sid:rev`) | Cùng giá trị như parser Snort trực tiếp |
| Tuple, `protocol`, `event_action`, `severity`, thời gian | `full_log` qua `map_alert` của connector Snort | Cùng một hàm với A02, nên cùng giá trị và cùng chính sách thời gian |
| `timestamp` | `timestamp`/`seconds` của dòng Snort | Giờ của sensor; giờ Wazuh nhận (`timestamp` ngoài cùng) chỉ ở provenance `collector_received_at` |
| `event_provider` | cố định `snort` | Provider logic của bằng chứng |
| `severity` | `priority` của Snort, 0 là không có | Level của rule Wazuh ở provenance `wazuh_rule_level`, không trộn vào severity |
| `hostname` | **không** | Agent chạy trên sensor, không phải endpoint của flow |
| `asset_id` | `agent.id` khi `collection_mode = direct` | Giống các profile Wazuh khác |

`protocol` giữ nguyên chữ của Snort (`UDP`). `event_action` giữ nguyên ánh xạ của
connector Snort; `allow` ở chế độ IDS không bao giờ thành bằng chứng chặn.

## 4. Bị từ chối

| Bản ghi | Mã | Trường |
| --- | --- | --- |
| Có `_source` (search-hit) | `unsupported_profile` | `_source` |
| `rule.groups` không có `snort3` hoặc `snort`, hoặc thiếu | `unsupported_profile` / `invalid_field` | `rule.groups` |
| Thiếu `rule.id` hoặc không phải số thập phân | `invalid_field` | `rule.id` |
| `decoder.name` khác `json` | `unsupported_profile` | `decoder.name` |
| Thiếu `full_log`, hoặc nội dung không phải JSON | `invalid_field` / `invalid_json` | `full_log` |
| Dòng trong `full_log` ngoài hồ sơ pin của Snort | mã của connector Snort | `full_log` |
| `data` thiếu/thừa trường so với dòng | `unsupported_profile` | `data` |
| Một trường trong `data` không khớp dòng | `invalid_field` | `data.<trường>` |

Diagnostic chỉ có từ vựng cố định. Lỗi bên trong dòng alert báo ở `full_log`, không
nêu giá trị nào của dòng.

## 5. Context và intake

Context bundle: `ingested_at` có timezone và `collection_mode`
(`direct`/`forwarded`/`unknown`), giống `wazuh-sysmon3-archive-v1`. Một file, một
bản ghi, `raw_event_ref = <source_ref>#record=1`.

Test: `backend/tests/test_wazuh_snort_alert.py`. Fixture là **một bản ghi thật của
Lab C đã sanitize**: `tests/fixtures/wazuh/snort-alert/` (xem README ở đó để biết
các phép thay thế và nguồn gốc). Dòng trong `full_log` của fixture chính là dòng
Snort đã có trong bundle `tests/fixtures/cli/scn004-lab-c-sanitized/block/`.
