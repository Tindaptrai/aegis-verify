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
grep -rn 'LAB WAN ICMP TEST' /usr/local/etc/suricata/ /var/db/suricata/ | head
```

Kiểm SID định dùng còn trống:

```sh
grep -rn 'sid:' /usr/local/etc/suricata/suricata_*/rules/custom.rules
```

Lệnh thứ hai liệt kê mọi SID tự tạo; chọn một số chưa xuất hiện. Shell mặc định
của pfSense là tcsh, nên không dùng `2>/dev/null` như bash.

## 3b. Chọn instance nào

Suricata trên pfSense chạy theo từng interface, mỗi instance chỉ thấy lưu lượng
của interface mình. Rule phải nằm trên instance **quan sát được gói trước khi
firewall quyết định chặn**.

Với SCN-002, probe đi từ máy Windows trong LAN ra máy nhận phía WAN. Ở lượt
Block, firewall chặn ngay khi gói vào LAN nên gói không ra tới WAN. Đặt rule
trên instance WAN thì lượt Block sẽ không có alert, và kết quả sẽ giống hệt một
rule hỏng dù rule vẫn đúng. Vì vậy đặt trên instance **LAN**: cả lượt đối chứng
lẫn lượt Block đều đi qua đó.

Kiểm tra agent Wazuh có đọc eve.json của instance đó không, vì rule nổ mà Wazuh
không đọc thì A04 vẫn không có bằng chứng:

```sh
grep -rn 'eve.json' /var/ossec/etc/ossec.conf
```

Shell mặc định của pfSense là tcsh, nên không dùng được `2>/dev/null` như bash.

## 3c. Vì sao dùng `any any` thay vì ghim địa chỉ

`content` với marker đã đủ đặc trưng, nên không cần ghim IP và cổng. Ghim vào
làm rule giòn: đổi máy nhận hoặc đổi cổng là alert im lặng biến mất, và nhìn từ
report nó giống hệt một detection gap dù không phải. Đó đúng là cái bẫy mà
SCN-001 đã phơi bày với rule theo tên file. Render `$dst_ip` và `$dst_port`
thành `any` là hợp lệ; `$src_net` để `any` hoặc `$HOME_NET` đều được.

## 4. Áp dụng

Các bước sau **đụng cấu hình lab**. Người vận hành thực hiện sau khi chủ dự án
duyệt; lưu rule và khởi động lại dịch vụ là hai lần duyệt riêng.

**Không sửa thẳng file `custom.rules`.** Package Suricata của pfSense sinh lại
file đó từ `config.xml` mỗi lần lưu hoặc khởi động lại interface, nên rule gõ
tay vào file sẽ biến mất mà không báo gì. Đường đúng là qua giao diện web.

1. Ghi lại trạng thái xuất phát của file custom rules trên interface đã chọn:

   ```sh
   ls -l /usr/local/etc/suricata/<instance>/rules/custom.rules
   ```

   ```sh
   sha256 /usr/local/etc/suricata/<instance>/rules/custom.rules
   ```

   File rỗng có SHA-256 là
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Nếu file
   đang rỗng thì hoàn tác nghĩa là đưa nó về rỗng, không phải khôi phục bản sao.
   Nếu đang có nội dung, chép ra ngoài kèm hash trước khi sửa.
2. Giao diện web: Services, Suricata, sửa interface đã chọn, mở tab Rules, chọn
   category `custom.rules`, dán đúng một dòng rule đã render, rồi Save. Không
   đổi chế độ blocking của bất kỳ interface nào.
3. Xác nhận lại blocking của interface đó vẫn tắt trước khi khởi động lại, để
   một lần restart không làm rơi lưu lượng.
4. Khởi động lại Suricata **chỉ trên interface đó** từ danh sách Interfaces. Ghi
   lại thời điểm.
5. Đối chiếu file đã được sinh lại đúng nội dung mong đợi bằng `sha256` như bước 1.
6. Chạy lại probe đối chứng với run UUID mới, đúng hợp đồng một datagram.

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

1. Giao diện web: xoá dòng rule khỏi ô custom rules của đúng interface, Save.
   Nếu trước đó file có nội dung, dán lại nguyên văn bản đã chép ra.
2. Khởi động lại Suricata chỉ trên interface đó.
3. Đối chiếu `sha256` của file custom rules bằng giá trị đã ghi ở bước 1 của mục
   4. Về đúng trạng thái xuất phát mới coi là đã hoàn tác.
4. Chạy một probe nữa và xác nhận không còn alert cho SID đã gỡ.

## 6b. Đã nạp thử được, ngày 2026-09-21

Rule render với `any any` và SID 1000010 đã được nạp thử bằng `suricata -T`,
dùng config của instance LAN, ghi log ra thư mục tạm, **không** sửa cấu hình và
**không** khởi động lại dịch vụ nào:

| Mục | Kết quả |
| --- | --- |
| Suricata | 7.0.8 RELEASE trên pfSense 2.7.2 |
| Rule files processed | 1 |
| Rules successfully loaded | **1**, failed **0** |
| Signatures processed | 1, trong đó **1 inspecting packet payload** |
| Kết luận của Suricata | "Configuration provided was successfully loaded." |

Dòng "inspecting packet payload" xác nhận phần khớp `content` có hiệu lực, không
bị rút thành rule chỉ theo IP. `classtype:policy-violation` được bản này chấp
nhận. SID 1000010 còn trống; SID lab đang dùng là 1000003 cho một rule ICMP trên
WAN.

**Nạp được không phải nổ được.** Kết quả trên chỉ nói Suricata hiểu và chấp nhận
rule. Nó không nói signature sẽ khớp gói thật. Chỉ một alert thu được từ lượt
probe mới chứng minh điều đó, và đó là bước kế tiếp.

## 6c. Alert đầu tiên thu được, ngày 2026-09-21

Sau khi rule được lưu qua giao diện web trên instance LAN và Suricata của
interface đó được khởi động lại, một probe đối chứng theo đúng hợp đồng một
datagram đã sinh ra alert ở cả hai tầng. Địa chỉ lab và các file bằng chứng
được giữ ngoài Git.

| Mục | Giá trị |
| --- | --- |
| Run UUID | `12a20fb5c65c45cf8eb66d6d599a1dcd`, nhãn `control` |
| Payload | 68 byte, marker + run UUID + nhãn |
| Suricata | alert trên instance LAN, `signature_id` 1000010, `action` `allowed` |
| Thời điểm sự kiện | 2026-09-21T19:52:33.411629+07:00 theo Suricata |
| Wazuh | rule 86601, description mang đúng `msg` của rule |
| Tuple | năm trường trong alert khớp receipt phía gửi, giao thức UDP |
| eve.json trích ra | SHA-256 `ab3840e0a413693a63ccef51fe80ee6f4f38721a49a231f4ad7e70c7b873477e` |
| Wazuh alert trích ra | SHA-256 `3554f2fe24934824eba821429c6fc5258c610620a84956af996a72bff1a141bc` |
| Wazuh archive trích ra | SHA-256 `9989e6e9ae913497da5a9e2cb2f16b9f6bce46e6b9f75246010c84a73d136cbc` |

Điểm ràng buộc quan trọng: `payload_printable` trong alert chứa đúng run UUID
của lần gửi, nên alert này thuộc về chính probe đó chứ không phải một gói nào
khác tình cờ mang marker.

Kết quả này cho A02 bằng chứng đầu tiên: Suricata thấy datagram tại LAN, sinh
alert, và Wazuh ghi nhận alert cho cùng tuple. Nó **không** chứng minh chặn, và
**không** thay đổi câu hỏi câu chữ của A04 ở mục 7. Đây là một lượt đối chứng
được phép; lượt Block vẫn chưa thực hiện.

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
nên test xanh chỉ nói nội dung đúng hình dạng đã review. Việc Suricata thật sự nạp
được rule là một phép thử riêng, kết quả ghi ở mục 6b; và nạp được vẫn chưa phải
nổ được.
