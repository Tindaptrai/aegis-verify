# SCN-003 — nội dung detection đã review

Issue #76, plan `docs/superpowers/plans/2026-09-24-scn003-offline-foundation.md`
Task 1, review `docs/superpowers/specs/2026-09-26-scn003-design-review.md`.
Hai template nằm trong Git để được review và tái tạo. Giá trị triển khai của
lab ở ngoài Git. **Chưa cài lên lab, chưa nạp thử, chưa có lưu lượng.**

## 1. Hai ID cố định

| ID | Ở đâu | Nghĩa |
| --- | --- | --- |
| SID `1000012` | Suricata, `detections/suricata/scn-003/decoy-connect.rules.template` | một gói TCP SYN từ dải nguồn được duyệt tới đúng địa chỉ và cổng decoy |
| Rule `120003` | Wazuh, `detections/wazuh/scn-003/login-failed.xml.template` | một `cowrie.login.failed` có `username` đúng ngữ pháp marker của run |

Cả hai chưa bị dùng ở đâu khác trong repo (test
`test_the_two_ids_are_not_claimed_elsewhere_in_the_repository` giữ điều đó).
Khác với rule marker SCN-002, nơi SID để placeholder, ở đây hai ID được pin
trong Git theo plan đã duyệt, để profile SCN-003 có literal cố định.

## 2. Ngữ pháp username của run

`AEGIS-SCN003-[0-9a-f]{8}`: chữ hoa cố định, gạch nối, đúng 8 ký tự hex thường.
Client sinh 8 hex ngẫu nhiên cho mỗi run và ghi vào receipt; username này chỉ có
nghĩa trong lab và không trùng tài khoản nào. Password của lần đăng nhập giả
**không** xuất hiện trong rule, profile, fixture, report hay diagnostic.

## 3. Biến template

| Template | Biến | Điền khi nào |
| --- | --- | --- |
| Suricata | `$src_net`, `$decoy_ip`, `$decoy_port` | lúc render cho instance quan sát đường trước NAT, từ cấu hình riêng |
| Wazuh | `$parent_group` | group của rule cha đã bắt Cowrie trên manager; trong lab hiện tại rule `100300` "Cowrie JSON event detected" thuộc group `cowrie` |

Rule Suricata dùng `flow:to_server; flags:S,12;` để chỉ khớp SYN mở kết nối,
bỏ qua hai bit dự trữ, không có `content` vì SYN không mang payload. Đây là mẫu
quen thuộc của các rule SSH trong bộ ET.

## 4. Tên trường trong rule Wazuh

Plan ngày 24/9 viết `data.eventid` và `data.username`. Template dùng `eventid`
và `username`, vì rule Wazuh tham chiếu trường đã decode **không** có tiền tố
`data.`: các template SCN-001 đã kiểm bằng `wazuh-logtest` trên lab dùng
`win.system.eventID` trong khi alert JSON hiển thị `data.win.system.eventID`.
Điểm này vẫn phải được `wazuh-logtest` xác nhận trên manager trước khi cài.

## 5. Test chứng minh gì và không chứng minh gì

`backend/tests/test_scn003_detection_content.py` kiểm: LF và một newline cuối,
đúng tập biến, một rule mỗi file, SYN tới `$decoy_ip $decoy_port`, hai ID cố
định, XML hợp lệ sau khi thay `parent_group`, ngữ pháp username, không có IPv4
hay từ khoá credential, hai ID không bị dùng nơi khác.

Nó **không** chạy Suricata hay Wazuh. Nạp được và nổ được là hai phép thử riêng
trên lab, chỉ đọc trước (`suricata -T` với config của instance, `wazuh-logtest`
với một dòng Cowrie thật), rồi cài qua giao diện theo runbook có duyệt từng bước.
File đã render và giá trị lab không vào Git.
