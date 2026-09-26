# AEGIS Verify — Tổng kết ngày 20/09/2026

## Chốt trạng thái

SCN-002 đã tiến thêm ở khâu chuẩn bị nguồn và đọc bằng chứng offline, **chưa
hoàn tất kiểm chứng end-to-end**. Không coi việc nhận được gói UDP hoặc có log
Pass là chứng minh detection/prevention thành công. SCN-003 chưa được triển
khai trong phần việc này.

Báo cáo ghi các kết quả đã có bằng chứng trong phiên làm việc, không xác nhận
lại toàn bộ các mốc cũ của dự án. Không chứa credentials, chứng chỉ, địa chỉ lab
hay raw evidence. Bằng chứng thật và hash chi tiết được giữ ngoài Git.

## 1. Kết quả đã làm

### Nguồn lab cho SCN-002

- Xác nhận Sysmon đang chạy nhưng ban đầu chưa bật network logging; người dùng
  đã áp dụng cấu hình hẹp cho lưu lượng kiểm thử và thu được Event ID 3.
- Tìm được sự kiện tương ứng trong Wazuh manager archive. Không thấy trong
  giao diện alerts không đồng nghĩa với mất telemetry: cần phân biệt archive
  và alert/indexed search hit.
- Các probe UDP có giới hạn đã có receipt người gửi/người nhận cùng marker.
  Thu được flow Suricata phía LAN và WAN, cùng filterlog Pass của firewall.
- Phát hiện filterlog đi vào Wazuh qua syslog dưới agent manager, không phải
  agent của firewall. Bản archive này chưa có dữ liệu filterlog được Wazuh
  giải mã hoặc rule alert; không diễn giải thành kết quả correlation.
- Giữ nguyên archive và xác minh SHA-256 khi xuất về vùng bằng chứng riêng.

### Thời gian giữa các nguồn

- Đã điều tra lệch giờ lớn trên pfSense. Người dùng thực hiện thay đổi
  timecounter tạm thời sang HPET và khởi động lại NTP trong phạm vi đã duyệt.
- Các mẫu sau đó có active NTP peer và độ lệch tốt hơn. Đây chỉ là các mẫu tại
  thời điểm đo, không phải bảo đảm đồng bộ liên tục hay chứng minh nguyên nhân
  gốc duy nhất đã được loại bỏ.
- Lần probe thứ ba còn chênh **1,371393 giây** giữa Sysmon `utcTime` và
  Suricata `flow.start`. Chưa xác định đầy đủ nguyên nhân; không sửa offset
  hoặc thay timestamp để làm kết quả đạt.
- HPET mới được xác nhận ở trạng thái chạy; chưa xác nhận cấu hình lưu qua
  reboot. Không cần thay đổi thêm trong lúc chốt phiên hôm nay.

### Mã nguồn

1. [PR #51](https://github.com/Tindaptrai/aegis-verify/pull/51) đã merge:
   parser offline cho Sysmon 3 UDP/IPv4 từ Wazuh manager archive. Merge commit
   `8487050979e234de4d825b47769342112836de7a`. Không mở rộng ngầm collector live.
2. [Issue #52](https://github.com/Tindaptrai/aegis-verify/issues/52): bổ sung
   hỗ trợ BSD filterlog thiếu hostname; commit triển khai `c2b603e` trên nhánh
   `codex/pfsense-hostless-syslog`.
   - Hostname thiếu vẫn là `null`, không chèn tên giả vào bằng chứng.
   - `sensor_id` do cấu hình cung cấp được giữ riêng trong provenance.
   - Hash bytes gốc, timestamp context và cách tạo evidence ID không đổi.
   - Định dạng có hostname tiếp tục được hỗ trợ.

## 2. Kiểm thử và review

- Baseline pfSense: **214 passed**.
- TDD: **8 ca mới thất bại đúng lỗi `malformed_header`** trước khi sửa.
- Sau sửa, nhóm pfSense: **226 passed**.
- Toàn bộ backend: **3060 passed, 2 skipped**, thời gian **329,51 giây**.
- `git diff --check`: không có lỗi whitespace; Git chỉ cảnh báo chính sách
  LF/CRLF trên Windows.
- Review độc lập: không có phát hiện correctness/security cần sửa.
- Smoke offline với filterlog thật lần ba: parse thành công, hostname vẫn
  thiếu, timestamp được đọc với year/offset caller cung cấp; hash archive gốc
  và bytes sau kiểm tra không thay đổi.
- Suricata LAN/WAN: parser EVE hiện có đọc được phần `full_log` nguyên nội dung
  JSON trong archive. Không cần ép kiểu từ phần `data` đã được Wazuh giải mã.
- Không chạy lại frontend trong thay đổi parser này vì không sửa frontend;
  không lấy kết quả kiểm thử cũ làm kết quả mới.

## 3. Việc chưa xong — không được đánh dấu hoàn tất

- **Tên thân thiện trên giao diện:** thống nhất dùng tên từ cấu hình, tách khỏi
  hostname quan sát được. Chưa triển khai. Timeline hiện không mang sensor
  provenance; cần thiết kế đường truyền nhãn nguồn qua report và tương thích
  report cũ, không đơn thuần thay chữ `null` bằng tên thiết bị.
- **Truy vết bản trích xuất:** `full_log` UTF-8 là dữ liệu dẫn xuất từ archive,
  không phải bytes của file native. Cần lưu parent hash và quy tắc trích xuất
  khi đóng gói workflow; smoke hiện chỉ xử lý trong bộ nhớ.
- Chênh lệch timestamp còn cần đánh giá đúng ngữ nghĩa từng trường. Timestamp
  phát hành flow khác `flow.start`; không tự dùng thay thế cho nhau.
- Chưa có bằng chứng đầy đủ cho alert/correlation A04 và lượt Block được
  kiểm chứng. Không kết luận Prevented hoặc toàn bộ SCN-002 Passed.
- Chưa thay đổi ground truth, chưa tạo scenario executor và chưa merge #52.

## 4. Thứ tự tiếp tục

1. Đưa bản sửa #52 qua PR/CI và human review; chỉ merge sau khi được duyệt.
2. Thiết kế phần nhãn cấu hình: liên kết đúng sensor/evidence, hiển thị rõ
   “tên cấu hình”, giữ hostname gốc và report cũ nguyên nghĩa; thêm test
   backend/frontend trước khi phát hành.
3. Đóng gói fixture offline đã làm sạch, kèm truy vết parent/derivative;
   đánh giá timestamp và nguồn thiếu mà không nới ground truth ngầm.
4. Hoàn thành các gate SCN-002 còn lại rồi mới thực hiện lượt lab kế tiếp
   có phê duyệt, giới hạn cụ thể và rollback.
5. Chỉ mở SCN-003 sau khi SCN-002 có kết quả review và bằng chứng ổn định.

Không đưa ngày “hoàn hảo/final” cố định: thời gian phụ thuộc gate bằng chứng,
review và lab. Mốc gần nhất là PR parser và thiết kế nhãn nguồn, không phải
hoàn tất tất cả scenario.

## 5. Bàn giao cuối ngày

- Không cần chạy thêm lệnh trên lab hôm nay.
- Không xóa evidence, thư mục replay, worktree hay thay đổi chưa commit của
  người dùng. `docs/SCN002_SOURCE_READINESS.md` đang untracked được giữ nguyên,
  không đưa kèm bản sửa này.
- Không tự merge, restart dịch vụ, sinh thêm lưu lượng hoặc bật logging rộng.
- Phiên sau kiểm tra trạng thái PR và sức khỏe lab trước khi dùng lại kết quả;
  không mặc định cấu hình tạm thời còn hiệu lực sau reboot.
