# Cowrie — kiểm tra sáu JSON bổ sung ngày 11/09/2026

Tiếp nối intake ngày 10/09. Người dùng đã chọn hướng A: một JSON search-hit
Cowrie export qua Wazuh. Kiểm tra chỉ đọc; chưa tạo fixture sanitized hoặc
production parser. Không chạy command hoặc truy cập URL trong log.

## Loại event

| File | Bytes | Event | Protocol | Ghi nhận |
| --- | ---: | --- | --- | --- |
| 3.json | 1.752 | cowrie.login.success | telnet | data thiếu username/password; hai giá trị trong full_log đã để rỗng |
| 4.json | 1.817 | cowrie.login.success | ssh | Có credentials trong data và full_log/message |
| 5.json | 1.888 | cowrie.command.input | telnet | Command wget có URL; không thực thi hoặc tải về |
| 6.json | 1.740 | cowrie.command.input | telnet | Cùng sensor/session với 5.json |
| 7.json | 1.790 | cowrie.session.closed | telnet | duration trong data đã làm tròn |
| 8.json | 1.790 | cowrie.session.closed | telnet | Session khác 7.json; duration trong data đã làm tròn |

Cả sáu JSON ngoài và full_log bên trong đọc được, rule.groups có cowrie.
Event type, session và source timestamp giữa data/full_log khớp theo từng file.
Đây là kiểm tra cấu trúc và mapping input, không thay thế test strict decoder
duplicate keys, complexity limits hoặc CanonicalEventV2 validation.

Kết hợp mẫu params cũ, connect 1.json và failed 2.json: **9 file JSON, 6 loại
event dự kiến** đã có mẫu. Đủ để bắt đầu chuẩn bị fixtures cho phạm vi mapping;
không tự suy toàn bộ acceptance Issue #6 đã thỏa hoặc parser đã hoàn thành.

## Session và record identity

Trong 1.json–8.json, 5.json và 6.json có cùng sensor/session. Các file còn lại
có session khác nhau; tổng cộng 7 nhóm sensor/session. Cả tám có cùng uuid.
Không dùng uuid riêng lẻ làm event ID, không gán session của một event sang
event khác và không ghép các file này thành một phiên đầy đủ.

Hai command là telemetry đã quan sát. Chỉ có command.input không chứng minh
command chạy thành công, tải file thành công hoặc hệ thống thật bị xâm nhập.
Login.success cũng chỉ mô tả authentication trong honeypot theo nguồn.

## Timestamp và duration

Timestamp nguồn ở sáu file có sáu chữ số phần giây, offset +0000. Việc khảo sát
giữ raw timestamp dưới dạng chuỗi; không dùng chuyển đổi timezone tự động của
công cụ đọc để thay nội dung source. Canonical sau này chuẩn hóa cú pháp offset
và UTC mà không cắt phần giây, không fallback timestamp collector.

| File | data.duration (string) | full_log.duration (number) |
| --- | --- | --- |
| 7.json | 5.001782 | 5.001781940460205 |
| 8.json | 5.015054 | 5.015053987503052 |

Không xem đây là duration giống hệt về độ chính xác. Profile A đã chọn data làm
nguồn mapping; full_log giữ trong raw evidence. Canonical hiện không có duration
nên không cần thêm field hoặc tính lại timestamp từ duration cho parser này.

## Dữ liệu cần làm sạch

- 3.json: data đã thiếu username/password; full_log còn tên hai trường nhưng
  giá trị là chuỗi rỗng. Message có cặp login rỗng. Không nhầm sự hiện diện của
  tên key với một credential chưa che. Không fallback điền username canonical.
- 4.json: password chưa che có mặt trong data/password, data/message và
  password/message của full_log. 2.json từ lượt trước có vấn đề tương tự.
- 5.json: URL trong input/message cần review và alias nhất quán khi tạo fixture.
  Không truy cập đích. 6.json cũng cần review toàn bộ command trước commit.
- Rà soát IP, hostname, username, session, uuid, collector metadata và mọi bản
  sao nested/serialized khi tạo derivatives. Chỉ kiểm tra tên key không đủ
  để khẳng định hết secrets.

Không in credentials, raw command hay URL vào báo cáo. Chưa xác minh password
có được dùng thực tế bên ngoài honeypot hay không; vẫn loại khỏi fixture công
khai. Không sửa file gốc để tạo vẻ như nguồn ban đầu không có những trường này.

## Hash nguồn

| File | SHA-256 |
| --- | --- |
| 3.json | 6536d7c97ff3c166b93c36acabb2a114ed5bbfbfa722e1dca0dfed46343facab |
| 4.json | 29331461fffc78d87044d898b8cdad9b895ffade7a4fbc94f29a7d828103b7c6 |
| 5.json | 7f7ef58b386c01222171c23179ebcfcfb267883078ec6f4ffa3d51ff50324b77 |
| 6.json | 3d143e2669599c7f4467ab0172ee86bdf904272aa3ed892d2fd1ee4d8dc2443e |
| 7.json | 03157280c9a3ea8a4375d1d6675434d9a6102bd74826b253506246221abce77f |
| 8.json | e67eba22e52df220592bed78e13104d823af6c30b00b4e0efd02fb3347d18c5b |

SHA-256 trước/sau lượt đọc được đối chiếu bằng nhau. Hash xác nhận bytes giữ
nguyên trong lượt đọc, không xác thực đồng hồ hoặc tính xác thực sự kiện nguồn.

## Bước tiếp theo

Người dùng chưa cần lấy thêm loại log để bắt đầu chuẩn bị profile A. Cần đối
chiếu mô tả/acceptance criteria Issue #6, sau đó tạo derivatives/manifest,
viết tests và parser, chạy kiểm thử rồi human review/lab comparison trước merge.
Nếu acceptance đòi native JSONL hoặc correlation phiên đầy đủ, đó vẫn là phần
chưa được các mẫu hiện có chứng minh. Không thay canonical hoặc ground truth
để bỏ qua những giới hạn này.
