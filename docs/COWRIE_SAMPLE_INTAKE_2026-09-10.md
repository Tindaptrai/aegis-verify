# Cowrie — kiểm tra các file bổ sung ngày 10/09/2026

Kiểm tra chỉ đọc các file người dùng gửi sau khi chọn hướng A (Cowrie JSON
export qua Wazuh). Không sửa nguồn, không thêm raw evidence vào Git, chưa chạy
production Cowrie parser vì parser chưa được triển khai.

## Kết quả

| File | Kích thước | Nội dung | Vai trò |
| --- | ---: | --- | --- |
| 1.json | 1.986 bytes | Một Wazuh search-hit, cowrie.session.connect, telnet | Mẫu mapping địa chỉ/cổng và kết nối, sau sanitize |
| 2.json | 1.963 bytes | Một Wazuh search-hit, cowrie.login.failed, telnet | Mẫu login thất bại, cần loại credentials trước làm fixture |
| events-2026-09-10T16_52_26.472Z.csv | 18.823 bytes | 257 hàng dữ liệu, 5 cột | Danh sách alert tóm tắt; không đủ dữ liệu để làm input profile A |

JSON ngoài và string full_log bên trong của cả hai file đều đọc được như JSON.
Đây là kiểm tra cấu trúc và coverage, không thay thế bộ validation giới hạn
depth/duplicate keys/nodes/type của parser tương lai.

## Các field đáng chú ý

`1.json` có timestamp, src_ip/src_port/dst_ip/dst_port, protocol, session,
sensor và uuid. Không có username, password, input hoặc duration trong data.
`2.json` có timestamp, src_ip, protocol, session, sensor, uuid, username,
password; không có src_port/dst_ip/dst_port/input/duration trong data.
Các field network thiếu phải giữ null, không lấy từ event khác hoặc agent.

Hai JSON **khác session**, dù uuid giống nhau. Session/uuid của từng JSON khớp
full_log tương ứng. Hai session này không bằng session của closed event ngày
06/05 đã dán trước đó. Không tự ghép thành kết nối → login → closed và không
suy uuid là record ID duy nhất.

Timestamp Cowrie giữ sáu chữ số phần giây, offset +0000; thời gian collector
Wazuh khác thời gian event. Không dùng cột thời gian hiển thị hoặc collector
timestamp thay thế source event time.

## Credential review

`2.json` có password không rỗng, không giống placeholder redaction thông dụng.
Giá trị đó xuất hiện ở `_source.data.password`, trong `_source.data.message`,
và trong cả password/message của JSON chứa ở `_source.full_log`.
Không in giá trị trong audit. Chưa xác minh đây là mật khẩu dùng thực tế hay
chuỗi thử trong honeypot; vẫn phải loại khỏi fixture công khai theo chính sách.

Khi tạo derivative: remove/replace nhất quán cả bốn vị trí, rà lại các field
khác, alias username/host/IP/session/uuid nhất quán và ghi phép biến đổi trong
manifest. Hash của derivative phải tính mới, không dùng hash file gốc làm hash
cho dữ liệu đã sửa. Chưa tạo derivative hoặc tuyên bố mẫu đã sanitize.

## CSV

Năm cột chính xác: `timestamp`, `agent.name`, `rule.description`, `rule.id`,
`rule.level`. Cả 257 hàng có rule.id `100300`, nhưng điều này không xác định
Cowrie event type. File không chứa data.eventid, session, full_log hay _source.
Không thể phục hồi những field đó từ tên rule hoặc suy bằng file JSON khác.

Có 246 tổ hợp hàng phân biệt trong 257 hàng hiển thị. Vì không có record ID,
không kết luận các hàng trùng giá trị là cùng một sự kiện và không tự deduplicate.
CSV không phải định dạng không thể hỗ trợ về sau; chính bản export năm cột này
không đủ cho hợp đồng parser A đang thiết kế.

## SHA-256 nguồn

| File | SHA-256 |
| --- | --- |
| 1.json | 407e09c6f02d41e161a981d30b21bae3dd75e41ccf5bf03223636466b0607aca |
| 2.json | f11a1b82c7846c88297606237bb990cf901e53de201b719989ad9010989aedb1 |
| events-2026-09-10T16_52_26.472Z.csv | 52a0ec0a614c6f48bc22d8fe292663fa274855b8dcb7c55db5ab126aaaa7e1dc |

Hash đã đối chiếu trước/sau đọc, không thay đổi. Hash chứng minh bytes được giữ
nguyên trong lượt kiểm tra, không tự xác thực nguồn lab hoặc đồng hồ.

## Việc còn thiếu

- Mẫu params đã có từ lần gửi trước; connect và login.failed đã có file lần này.
- Hai mẫu session.closed có nội dung trong chat nhưng chưa có file gốc riêng.
- Chưa có login.success và command.input. Chỉ lấy nếu lab đã có, không cần tạo
  hoạt động mới để lấp coverage.
- Chưa nhận mô tả/acceptance criteria trực tiếp của Issue #6.
- Chưa có chuỗi session được xác minh từ các artifact trên; thiếu mẫu không
  được diễn giải thành missing telemetry của toàn hệ thống.
