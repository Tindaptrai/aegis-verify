# SCN-002 — parser Sysmon 3 từ Wazuh archives (offline)

Trạng thái: owner đã duyệt hướng archives offline; bản thiết kế này chờ review.
Đây là phần tiếp theo sau source readiness #49, không phải hoàn tất #49 hoặc
phê duyệt thay ground truth. Issue triển khai riêng sẽ chốt theo acceptance dưới.

## Mục tiêu và giới hạn

Đọc một bản ghi manager archive nguyên gốc thành CanonicalEventV2 để có telemetry
UDP cho AEGIS mà không phải nâng level mọi kết nối mạng thành alert. Mẫu thật đã
được lấy read-only, lưu private và kiểm tra hash; không đưa raw vào repository.
Nguồn mới là archive JSON, không giả bọc `_source` để nhận là Indexer search hit.

Không sửa live collector, manager snapshot, dashboard, quyền Indexer, firewall,
Sysmon, SCN-001 hoặc executable ground truth. Không gửi traffic, không thêm
dependency. Không xây JSONL batch runner hoặc SSH collector trong issue này.

Các lựa chọn đã cân nhắc: nâng rule để ép có search hit gây thay đổi lab và noise;
bọc archive thành search hit làm sai provenance; entry point archive tường minh
giữ được nguồn và hash thật nên là hướng owner đã chọn.

## API và nguồn đầu vào

Module mới `connectors/wazuh/network_telemetry.py`, entry point
`parse_wazuh_sysmon3_archive_record(raw: bytes, *, source_ref, environment_id,
ingested_at, collection_mode)`. Trả result bất biến gồm event và provenance.
Context validation, raw hashing và canonical model dùng các thành phần hiện có.
Giữ các entry point cũ nguyên hành vi; không auto-dispatch archive ở parser cũ.

Input đúng một JSON object UTF-8, có thể có newline cuối; không nhận array,
search hit có `_source`, hoặc nhiều JSONL records. Dùng bounded decoder hiện có:
256 KiB, depth 20, nodes 10000, từ chối duplicate keys, NaN/Infinity, invalid
Unicode và số quá dài. Không parse hoặc thực thi `full_log` để bù field thiếu.

Require object `data.win.system`, `data.win.eventdata`; provider/channel/Event ID
phải chính xác Microsoft-Windows-Sysmon, kênh Operational tương ứng và string 3.
Phiên đầu chỉ nhận protocol string `udp` và IP nếu có phải là IPv4 không scope.
TCP/IPv6 là unsupported trong profile này, không tuyên bố hỗ trợ khi chưa review.

## Mapping và thời gian

| Canonical | Archive path / policy |
| --- | --- |
| timestamp | data.win.eventdata.utcTime, UTC của Sysmon; bắt buộc |
| ingested_at | context do caller truyền, không lấy manager timestamp thay thế |
| source_type / event_provider | wazuh / provider đã xác minh |
| source_record_id | id nếu có, string |
| asset_id | agent.id chỉ khi collection_mode=direct, còn lại null |
| hostname / username | system.computer / eventdata.user nếu có |
| src_ip / dst_ip | eventdata.sourceIp / destinationIp nếu có |
| src_port / dst_port | sourcePort / destinationPort: decimal string, 0..65535 |
| protocol | udp đã kiểm tra |
| process_id / process_name | processId decimal string / image string nếu có |
| event_action | observed, không suy allowed hoặc blocked từ Sysmon |
| rule_id / severity | rule.id / rule.level chỉ khi nguồn có giá trị hợp lệ |

Timestamp grammar: `YYYY-MM-DD HH:MM:SS` và tùy chọn 1..9 chữ số thập phân;
gán UTC theo field utcTime của Sysmon, chuẩn hóa dấu phân cách sang PreciseTimestamp
mà không đi qua float. Thiếu/sai thời gian là lỗi, không fallback systemTime hoặc
manager timestamp. Giữ hai thời gian còn lại trong raw reference; provenance ghi
timestamp_basis=`sysmon.utcTime` và số chữ số thập phân nguồn.

Optional thiếu/null giữ null; optional sai kiểu từ chối, không ép bool thành số,
không trim hay đoán giá trị. Port/PID chỉ decimal ASCII với giới hạn độ dài hiện
có. Giữ nguyên image/user sau JSON decode, không unicode_escape, không tự bỏ
backslash kép. initiated và IPv6 flags giữ trong raw, không suy thành kết luận.
Không lấy địa chỉ sau NAT từ receiver để thay tuple endpoint.

## Bằng chứng và diagnostics

Hash toàn bộ bytes đầu vào kể cả newline. raw_event_ref dùng source_ref với
record=1; event identity theo convention evidence hiện có dựa trên environment,
source_ref, record index và raw hash. Provenance ghi mapping version riêng
`wazuh-sysmon3-archive-udp-v1`, envelope manager_archive, agent/manager context,
Windows Record ID, ProcessGuid, collection_mode và raw hash/reference.
Unknown source fields còn nguyên trong raw, không gán vào canonical tùy tiện.

Diagnostics dùng WazuhParseError và whitelist field path archive mới; không lộ
values, payload, username, đường dẫn riêng hay full_log. Không thay whitelist
live profile hoặc các mapping Sysmon 1/PowerShell 4104 hiện có.

## Acceptance và kiểm thử

- Fixture tổng hợp được ghi nhãn rõ, không phải bằng chứng live; IP tài liệu,
  tên máy/user/process giả, không sao chép dữ liệu lab vào Git. Mẫu derivative
  từ raw private chỉ được commit sau sanitization và human review riêng.
- Happy path UDP đủ tuple, optional null/absent, port bounds, timestamp exact
  fractional precision, context direct/forwarded/unknown và raw hash/newline.
- Reject wrong envelope/provider/channel/event code/protocol/IP family,
  malformed timestamp, numeric/bool ports, oversized/deep/duplicate JSON.
- Test error redaction bằng marker giả; strings chứa backslash được giữ nguyên.
- Deterministic identity; input thay bytes thay hash; unknown fields giữ trong
  raw; không chế rule, severity, command line, signature hoặc ATT&CK fields.
- Regression suite cho Wazuh parser/Windows telemetry/manager snapshot/live
  và canonical model vẫn xanh. Một private smoke test không in raw chỉ đối chiếu
  mapping với mẫu đã hash; không gọi đó là full scenario acceptance.

Chỉ sau khi owner review bản này mới viết implementation plan. Không dùng việc
parser chạy được để đóng các gate LAN EVE/filterlog, A04, đồng hồ hoặc Indexer.
