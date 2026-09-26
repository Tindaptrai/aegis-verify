# Wazuh alert sinh từ Cowrie login failure — parser `wazuh-cowrie-alert-v1`

Issue #76, plan Task 2. Dùng cho SCN-003-A04 (`source: wazuh`): bằng chứng là
**Wazuh đã nổ rule** cho một `cowrie.login.failed` của đúng phiên. Parser đọc
**một bản ghi alert của manager** (object JSON có `rule`, `agent`, `manager`,
`decoder`, `location` và event Cowrie trong `data`, không có `_source`) và cho
ra một `CanonicalEventV2` với `source_type = wazuh`.

Nó khác `cowrie-wazuh-v1` (search-hit của Indexer, `source_type = cowrie`, dùng
cho A03) và cùng mẫu với `wazuh-suricata-alert-v1` của SCN-002.

## 1. Trường nào lấy từ đâu

| Nội dung | Nguồn | Vì sao |
| --- | --- | --- |
| `rule_id` | `rule.id` | Rule Wazuh, đây là detection của A04 |
| `username`, `src_ip`, `protocol`, `event_action = login`, thời gian | `data.*` qua `map_cowrie_event` của connector Cowrie | Cùng một hàm với hai parser Cowrie trực tiếp, nên cùng giá trị cho cùng record. Bản ghi `login.failed` thật **không có** cổng nguồn, IP và cổng đích; chúng giữ `null`, không lấy từ `session.connect` |
| `session_key` | `session_key(environment_id, sensor_id, data.session)` | Cùng công thức với parser Cowrie trực tiếp; `sensor_id` trong context phải là **cùng nhãn** thì A03 và A04 mới join được |
| `timestamp` | `data.timestamp` | Giờ Cowrie; giờ Wazuh nhận chỉ ở provenance `collector_received_at` |
| `event_provider` | cố định `cowrie` | Provider logic |
| `hostname` | **không** | Máy honeypot là đích của flow, không phải máy khởi tạo |
| `asset_id` | `agent.id` khi `collection_mode = direct` | Giống các profile Wazuh khác |

Định danh phiên gốc (`data.session`) không vào canonical event, không vào
provenance, không vào report. Chỉ khoá mờ được giữ.

## 2. Bị từ chối

| Bản ghi | Mã | Trường |
| --- | --- | --- |
| Có `_source` | `unsupported_profile` | `_source` |
| `rule.groups` thiếu hoặc không có `cowrie` | `invalid_field` / `unsupported_profile` | `rule.groups` |
| Thiếu `rule.id` hoặc không phải số thập phân | `invalid_field` | `rule.id` |
| `data.eventid` khác `cowrie.login.failed` (kể cả login success, command) | `unsupported_profile` | `data.eventid` |
| Thiếu `data.session` | `invalid_field` | `data.session` |
| Lỗi trong `data` (giờ, cổng, giao thức) | mã của connector Cowrie, đường dẫn `data.…` | |

Diagnostic chỉ có từ vựng cố định; không chứa giá trị nguồn, kể cả username.

**Về `data.password`.** Bản ghi `cowrie.login.failed` thật mang mật khẩu người ta
gõ, và Wazuh giữ nguyên nó trong `data` (xác nhận trên lab 2026-09-26). Parser
**không đọc** trường này, giống hai parser Cowrie trực tiếp: không vào canonical
event, không vào provenance, không vào ledger hay report, không xuất hiện trong
diagnostic. Bản đầu (plan Task 2) từ chối cả bản ghi; như vậy A04 không bao giờ
đánh giá được trên dữ liệu thật nên đã đổi. File thô trong hồ sơ riêng vẫn giữ
nguyên byte, hash tính trên đúng byte đó; fixture công khai không được chứa mật
khẩu.

## 3. Vì sao chỉ nhận login failed

Spec SCN-003 chọn một lần đăng nhập thất bại vì nó không mở shell. Parser hẹp
đúng bằng hợp đồng đó để một alert `login.success` hay `command.input` không
bao giờ lọt vào A04 như bằng chứng. Mở rộng là thay đổi có review riêng.

## 4. Context và intake

Context bundle: `ingested_at` có timezone, `collection_mode`
(`direct`/`forwarded`/`unknown`) và `sensor_id`. Một file, một bản ghi,
`raw_event_ref = <source_ref>#record=1`, event ID theo chính sách
`wazuh:evidence-v1`.

Fixture synthetic `tests/fixtures/wazuh/cowrie-alert/`; test
`backend/tests/test_wazuh_cowrie_alert.py`. Số trong `data` là chuỗi vì decoder
JSON của Wazuh stringify chúng, như đã thấy với Suricata trong SCN-002. Mẫu
thật của manager cho rule Cowrie phải được đối chiếu trước khi nghiệm thu live.
