# SCN-002 — Suricata marker rule

Rule thử để probe của SCN-002 sinh được một alert Suricata. Không có alert thì
A02 không có bằng chứng và A04 không có gì để phát hiện.

Template: [`detections/suricata/scn-002/marker.rules.template`](../detections/suricata/scn-002/marker.rules.template).

Tài liệu này mô tả cách render, áp dụng, kiểm chứng và gỡ bỏ. Nó **không** là
lệnh chạy: mọi thao tác chạm vào lab cần chủ dự án duyệt riêng từng bước.

## 1. Vì sao cần rule này

Đo trên manager ngày 2026-09-20:

| Mục | Số đo |
| --- | --- |
| Sự kiện Suricata vào Wazuh archive | 8478 |
| Trong đó `event_type: alert` | 316 |
| Alert Suricata thành alert Wazuh | 316 trên 316, qua rule **86601** |
| Signature lab tự viết đã chạy qua đường này | `LAB WAN ICMP TEST` |

Đường ống Suricata → Wazuh hoạt động và đã được một signature lab chứng minh.
Probe của SCN-002 chỉ sinh bản ghi `flow` vì payload không khớp signature nào.
Thiếu sót nằm ở tầng Suricata, không phải ở Wazuh.

## 2. Placeholder

| Tên | Ý nghĩa | Ghi chú |
| --- | --- | --- |
| `$src_net` | mạng nguồn, ví dụ biến `$HOME_NET` của Suricata | không ghi địa chỉ vào Git |
| `$dst_ip` | IP máy nhận trong lab | do chủ lab kiểm soát |
| `$dst_port` | cổng UDP đích đã xác nhận không xung đột | không có giá trị mặc định |
| `$sid` | SID trong dải local, từ 1000000 trở lên | phải kiểm không trùng trước khi dùng |

Render bằng `string.Template`. Bytes sau khi render **không** đưa vào Git, giống
cách kit SCN-001 làm: chỉ template và hash được ghi nhận.

## 3. Chọn SID không xung đột

Chạy trên pfSense, chỉ đọc. Xem SID của signature lab đang có để giữ cùng phong
cách và chọn số liền kề:

```sh
grep -rn 'LAB WAN ICMP TEST' /usr/local/etc/suricata/ /var/db/suricata/ 2>/dev/null | head
```

Kiểm SID định dùng còn trống:

```sh
grep -rn 'sid:<SID>;' /usr/local/etc/suricata/ /var/db/suricata/ 2>/dev/null | head
```

Không dòng nào trả về nghĩa là còn trống. Nếu đường dẫn khác, tìm trong thư mục
custom rules của đúng interface trong giao diện Suricata.

## 4. Áp dụng

Các bước sau **đụng cấu hình lab**. Người vận hành thực hiện sau khi chủ dự án
duyệt; sửa file và khởi động lại dịch vụ là hai lần duyệt riêng.

1. Sao lưu file custom rules của interface LAN kèm SHA-256 trước khi sửa.
2. Thêm đúng một dòng rule đã render. Không đổi chế độ blocking của bất kỳ
   interface nào; LAN hiện không bật blocking và giữ nguyên.
3. Khởi động lại Suricata trên đúng interface đó. Ghi lại thời điểm.
4. Chạy lại probe đối chứng với run UUID mới, đúng hợp đồng một datagram.

## 5. Kiểm chứng

Thu ba thứ, ghi hash và giữ ngoài Git:

- Bản ghi `eve.json` có `event_type: alert` và `alert.signature_id` đúng SID vừa
  tạo.
- Alert Wazuh tương ứng, rule **86601**, cùng tuple năm trường.
- Bản ghi archive tương ứng.

Alert sau khi Wazuh xử lý giữ `src_ip`, `src_port`, `dest_ip`, `dest_port`,
`proto`, và khối `alert` có `signature_id`, `signature`, `action`, `category`,
`severity`. Connector Suricata hiện có ánh xạ `alert.signature_id` sang canonical
`signature_id`, nên profile đánh giá dùng được ngay, không cần parser mới.

## 6. Gỡ bỏ

1. Khôi phục file rules từ bản sao lưu, đối chiếu lại SHA-256.
2. Khởi động lại Suricata trên interface đó.
3. Chạy một probe nữa và xác nhận không còn alert cho SID đã gỡ.

## 7. Rule này chứng minh gì và không chứng minh gì

**Chứng minh được**: Suricata nhìn thấy datagram tại vị trí quan sát, sinh alert,
và Wazuh ghi nhận alert đó cho cùng tuple. Đủ cho A02.

**Không chứng minh được**: gói tin bị chặn. Trong chế độ IDS, `alert.action` báo
`allowed` kể cả khi firewall chặn ở nơi khác, nên không đọc trường đó thành
prevention. Lượt Block cần bằng chứng riêng từ filterlog và là một gate khác.

**Chưa giải quyết**: câu chữ của SCN-002-A04. Scenario ghi "correlated detection",
nhưng rule 86601 chỉ nhận và phân loại alert của Suricata, không tương quan nhiều
nguồn. Kể cả khi SID này nổ, thứ chứng minh được là "Wazuh sinh detection từ alert
của Suricata cho cùng tuple". Sửa mô tả A04 là thay đổi ground truth và cần chủ
dự án duyệt; tài liệu này không đụng tới.

## 8. Test

`backend/tests/test_scn002_marker_rule.py` kiểm nội dung template: đúng tập
placeholder, có marker đã review, `depth` có giới hạn, `classtype` là
`policy-violation`, đúng một rule, kết thúc bằng một newline LF, và **không** có
literal IPv4, cổng hay SID nào lọt vào Git. Test đọc văn bản, không chạy Suricata,
nên test xanh chỉ nói nội dung đúng hình dạng đã review, không nói Suricata nạp
được rule hay signature sẽ nổ.
