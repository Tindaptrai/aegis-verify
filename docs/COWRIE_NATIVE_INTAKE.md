# Cowrie native JSONL — hồ sơ intake fixture B

## Phạm vi và trạng thái

Hồ sơ này ghi lại intake offline ngày 2026-09-11 cho hướng B của Issue #6. Bốn
native export cục bộ được kiểm read-only; original vẫn nằm ngoài Git. Chỉ hai
derivative đã audit là `tests/fixtures/cowrie/native/manifest.json` và
`session-sequence.sanitized.jsonl` được đóng gói.

Trạng thái manifest là `controller_audited_pending_human_review`. Audit này chứng
minh tính nhất quán byte, sanitize và parser compatibility trên máy local; nó
không phải lab acceptance, forensic certification, security verdict hoặc quyền
merge. Human review và lab validation vẫn bắt buộc.

## Aggregate an toàn của collection

Collection start/end UTC đều là `2026-09-11T04:39:42Z`.

| Native export | JSON objects | Distinct session values | Complete-kind sequences |
| --- | ---: | ---: | ---: |
| `cowrie.json` | 82 | 32 | 0 |
| `cowrie.json.2026-04-16` | 89 | 8 | 7 |
| `cowrie.json.2026-05-01` | 55 | 3 | 3 |
| `cowrie.json.2026-05-05` | 356 | 116 | 2 |

Tổng cộng có 582 JSON objects và 159 session values khác nhau; dòng dài nhất
không tính line ending là 2.364 bytes. “Complete-kind” chỉ nghĩa là session có ít
nhất connect, login, command input và closed trong sample; không nói attack thành
công hoặc evidence đầy đủ. Các kind unsupported quan sát được gồm
`client.version`, `client.kex`, `client.size`, `client.var`, `log.closed`,
`telnet.option`, `session.file_download` và `command.failed`.

## Derivative được chọn và hash

Derivative lấy tám dòng 8, 11, 12, 13, 15, 16, 17 và 19 của
`cowrie.json.2026-04-16`, giữ nguyên thứ tự một source session. Không fabricate,
merge hoặc chèn record. Source file SHA-256 đã đối chiếu trước/sau là
`3e26949ef450518ca66bb492bba34fda0f6991e9b9137f5da90049589464836e`.
Derivative compact UTF-8 JSONL với LF có SHA-256:
`846948ff724363676952c060fa5d63f6da7d5561fefecd951d67d591bf8eb762`.

| Derivative line | Original line | Original exact-line SHA-256 | Event kind | Parser outcome |
| ---: | ---: | --- | --- | --- |
| 1 | 8 | `2247f723ac751a6b0d261b1d3cfdb537c9338592a4aa0782757d16f1fa8829bc` | `cowrie.session.connect` | parsed |
| 2 | 11 | `5f27d3d1efb0ebf80a9b7359917eb367c5169fa028d06838d0cbce100b26d6e5` | `cowrie.login.failed` | parsed |
| 3 | 12 | `d9e94b73007039c394424d2302abcc5cc713200e76366a750bde3931df21465f` | `cowrie.login.success` | parsed |
| 4 | 13 | `95f428e120d9429194a4e268044864fcc85915ab989226b82c578f248076fad5` | `cowrie.client.size` | skipped |
| 5 | 15 | `2bcef35f6676bb27e86298bdba801e6991e078cbbce656d04f5fe21437b528cc` | `cowrie.session.params` | parsed |
| 6 | 16 | `d4ddb739afa6391d81f3c1f0b1b3f0a679ba5958137611cfdc6f4ea1eee5934c` | `cowrie.command.input` | parsed |
| 7 | 17 | `b55ccca8b0e964f82c7b900ef3d988db9b649b06317828c1d0c1f8eff5c1bcf0` | `cowrie.command.input` | parsed |
| 8 | 19 | `3000c5fd76ba0959dcce3e2054f5df4136a0ce03c6dd342083ffdc6d790179fa` | `cowrie.session.closed` | parsed |

Bảy parsed records bao phủ đủ sáu kind được hỗ trợ; dòng 4 là một explicit
`unsupported_event_type` skip. Skip không validate schema riêng của
`cowrie.client.size`. Original-line coordinates/hashes chỉ mô tả source bytes;
runtime `raw_event_ref`, per-line `raw_event_hash` và evidence ID mô tả derivative
bytes thực sự được parser đọc. `.gitattributes` ghim riêng JSONL fixture B về LF
để derivative và per-line hash không đổi trên Windows checkout.

## Quy tắc sanitize đã audit

- Chỉ loại field `message` và `password`; tất cả password fields đều bị loại.
- Alias nhất quán IP, session, sensor, UUID và username trong chính fixture B;
  không xuất bản hoặc commit reverse alias map.
- Alias B dùng namespace riêng với fixture Wazuh A; không có cross-fixture
  identity claim.
- Giữ timestamp, ports/types, missing/null/empty distinctions, event kind và
  lexical numeric token đã review.
- Giữ hai command đã review làm inert sensitive text để kiểm mapping; tuyệt đối
  không execute hoặc dùng chúng làm input shell.

Parser không thực hiện sanitize tùy ý cho production input. Field password/lạ
không được đưa vào canonical/provenance, nhưng raw file vẫn có thể chứa chúng.
Vì vậy mọi export phải được sanitize và review trước khi vào Git; không dựa vào
parser để redaction, không in raw record/credential và không fetch URL trong log.

## Audit parser compatibility tại core `517e5e7`

Controller đã exhaust bốn file local bằng native iterator mà không in sensitive
values: 459 records parsed và 123 records explicitly skipped. Phân bố tương ứng
là 76/6, 48/41, 38/17 và 297/59 theo thứ tự bốn file ở bảng trên. Cả 582 dòng có
evidence ID deterministic duy nhất và exact-line hash khớp bytes; timestamp,
peer fields, login result, command mapping và `source_record_id=null` được đối
chiếu trực tiếp với originals. Cả 159 session values cho session key ổn định; bốn
original file hashes không đổi sau kiểm tra.

Đây chỉ là local fixture/parser compatibility. Validation engine hiện tiêu thụ
canonical event, không đọc `provenance.session_key` hoặc
`authentication_outcome`; vì vậy audit không thể tạo kết luận
Detected/Prevented/Missing telemetry/False negative hay Pass/Fail.

## Việc reviewer còn phải làm

1. Đối chiếu lại source/derivative hashes và mapping original lines với originals
   cục bộ, không đưa originals hoặc reverse aliases vào Git.
2. Review code, fixture fields, sanitize allowlist, exact LF bytes và test evidence.
3. Sau review, chạy lại focused/full pytest cùng `pip check`. Controller đã kiểm
   wheel install/import tách biệt trước review; cần lặp lại nếu review làm đổi tree.
4. Thực hiện lab validation riêng nếu muốn đánh giá collection hoặc detection.
5. Chỉ merge/đóng Issue #6 sau khi evidence và tests được human review; quy trình
   này không push hoặc merge tự động.
