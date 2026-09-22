# SCN-002 — Runbook lượt Block (gate D, từng bước có duyệt)

Áp dụng cho lượt Block của SCN-002. Người vận hành là chủ dự án; mỗi bước đánh
dấu **[DUYỆT]** cần một câu đồng ý rõ trong chat trước khi làm. Tài liệu này
không chứa giá trị lab: IP, cổng, tracker, tên máy nằm trong hồ sơ evidence
riêng ngoài Git. Chỗ `<...>` là chỗ điền từ hồ sơ đó.

Quyết định đã có (2026-09-21): nguồn của rule chặn là **một máy gửi**, không
phải cả LAN. Suricata LAN giữ chế độ chỉ alert, không bật blocking.

## 0. Điều kiện vào

| Điều kiện | Cách kiểm | Nếu không đạt |
| --- | --- | --- |
| Lượt đối chứng đã đóng gói và chạy `aegis validate` ra `Inconclusive` với A01, A02, A04 `satisfied` | report của bundle `run4-control` | dừng, hoàn tất Giai đoạn 1 trước |
| Lệch giờ Sysmon và Suricata đã đo, cửa sổ tương quan đã chốt | ghi trong readiness | dừng, đo trước |
| Rule marker SID 1000010 vẫn nạp trên LAN | `suricata -T` hoặc log khởi động, chỉ đọc | dừng, xem lại #59 |
| Rule pass LAN cho UDP tới receiver đang bật log | GUI Firewall › Rules › LAN, chỉ nhìn | ghi nhận, filterlog `pass` sẽ không có ở lượt Block nên không chặn bước |
| Receiver trên Kali đang lắng nghe đúng cổng | như lượt đối chứng | khởi động lại receiver theo cách đã làm ở lượt đối chứng |
| Ổ đĩa máy dev còn đủ chỗ cho bundle và report | `Get-PSDrive C` | dọn trước |

## 1. Sao lưu, chỉ đọc

1. pfSense GUI: Diagnostics › Backup & Restore › Download configuration as XML.
   Lưu vào hồ sơ evidence, ghi sha256 của file.
2. Ghi lại thứ tự rule hiện tại của tab LAN (chụp màn hình hoặc xuất), để đối
   chiếu khi hoàn tác.

Không Apply gì ở bước này.

## 2. Thêm rule chặn — [DUYỆT]

Firewall › Rules › LAN › Add (mũi tên lên, để rule nằm **trên** rule pass):

| Trường | Giá trị |
| --- | --- |
| Action | Block |
| Interface | LAN |
| Address family | IPv4 |
| Protocol | UDP |
| Source | Single host: `<IP máy Windows gửi>` |
| Destination | Single host: `<IP receiver>`, port `<cổng receiver>` |
| Log | **bật** |
| Description | `AEGIS SCN-002 block test` |

Save, rồi Apply Changes. Sau Apply, mở lại rule, ghi **Tracker ID** vào hồ sơ
evidence: đây là binding `block_rule_tracker` của lượt này.

Kiểm rule đã vào bộ nhớ, chỉ đọc, từ shell pfSense:

```sh
pfctl -sr | grep "<cổng receiver>"
```

Kỳ vọng thấy một dòng `block ... log ... udp from <IP gửi> to <IP receiver> port = <cổng>`
và nó đứng trước dòng `pass` tương ứng. Không thấy hoặc sai thứ tự thì dừng và
báo, không gửi probe.

Không đụng state table. Nếu lo state cũ của lượt đối chứng còn sống, chờ hết
UDP timeout mặc định (khoảng 60 s kể từ gói cuối) là đủ, không flush.

## 3. Gửi probe Block — [DUYỆT]

Trên máy Windows, cùng script `Send-Scn002Probe.ps1` của lượt đối chứng, từ
thư mục đã dùng:

```powershell
.\Send-Scn002Probe.ps1 -DestinationIp <IP receiver> -Port <cổng receiver> -Label block
```

Script sinh run UUID mới; ghi UUID, `sent_before_utc`, `sent_after_utc` và cổng
nguồn từ receipt vào hồ sơ. Chỉ gửi **một** lần. Nếu script báo lỗi, không
gửi lại trước khi hiểu lỗi.

Kỳ vọng ở receiver: **không** có receipt cho UUID này. Đây là bằng chứng hỗ
trợ; bằng chứng chính của A03 là dòng filterlog `block`.

## 4. Thu bằng chứng, chỉ đọc

Thứ tự thu và lệnh giống lượt đối chứng, thay UUID mới. Mỗi file ghi sha256
ngay sau khi lưu, cùng giờ máy lúc thu.

| Nguồn | Ở đâu | Tìm | Kỳ vọng |
| --- | --- | --- | --- |
| Suricata LAN eve.json | pfSense, thư mục instance LAN | dòng `alert` có SID 1000010 và cổng nguồn của receipt | có 1 dòng. **Giả định cần kiểm chứng**: sensor thấy gói trước khi pf chặn. Không có thì ghi nhận, không mượn alert lượt đối chứng |
| filterlog | archive manager (qua syslog) hoặc `/var/log/filter.log` trên pfSense | dòng có tracker ở bước 2 và cổng nguồn của receipt | có 1 dòng `block,in` |
| Sysmon 3 | archive manager | UUID không có trong Sysmon; tìm theo tuple và cửa sổ `sent_before/after` | có 1 bản ghi, `protocol udp` |
| Wazuh alert 86601 | alerts.json trên manager | UUID trong payload của alert | có 1 alert nếu Suricata có alert |
| Wazuh archive của alert Suricata | archives.json | như trên | có 1 |
| Receipt receiver | Kali | UUID | **không có** |

Tìm marker trên manager bằng mẫu ngoặc để tránh tự nhiễu: `'AEGIS-SCN00[2]-TEST'`.
Trên pfSense là tcsh: không dùng `2>/dev/null`.

Lưu vào thư mục `run5-block` của hồ sơ evidence, ngoài Git.

## 5. Hoàn tác — [DUYỆT]

1. Firewall › Rules › LAN: Disable rule `AEGIS SCN-002 block test`, Apply.
2. Kiểm chỉ đọc: `pfctl -sr | grep "<cổng receiver>"` không còn dòng `block`.
3. Gửi **một** probe đối chứng nữa (`-Label control`), xác nhận receiver có
   receipt. Ghi UUID vào hồ sơ như bằng chứng hoàn tác.
4. Xoá rule đã disable, Apply. Đối chiếu thứ tự rule với bản ghi ở bước 1.
5. Nếu có gì lệch so với bản sao lưu XML ngoài rule vừa xoá, dừng và báo trước
   khi khôi phục toàn bộ.

Không xoá rule sẵn có, không reset firewall, không tắt IDS, không xoá evidence.

## 6. Đóng gói và đánh giá — tôi làm, offline

Bundle `run5-block` theo cùng khung của lượt đối chứng, thêm binding
`block_rule_tracker`. Chạy `aegis validate`. Kỳ vọng trung thực:

| Bằng chứng có | Kết quả |
| --- | --- |
| Đủ bốn nguồn, cùng tuple, trong cửa sổ | `Prevented`, exit 0 |
| Thiếu alert Suricata (sensor không thấy gói bị chặn) | A02 và A04 `inconclusive`, `final_status` `Inconclusive`; ghi nhận giới hạn quan sát, không nới rule |
| Có filterlog `block` nhưng tuple khác Sysmon | A03 `prevention_not_demonstrated`; kiểm NAT và vị trí quan sát, không gán ngược IP |

`aegis compare` đối chứng → Block sẽ ra `Inconclusive` theo quy tắc hiện có, vì
lượt đối chứng không phải gap. Verdict `Prevented` của lượt Block đứng riêng
là kết luận của SCN-002.

## 7. Dừng khi

- Bất kỳ lệnh chỉ đọc nào cho kết quả khác kỳ vọng ở bước 2.
- Probe gửi lỗi hoặc gửi nhiều hơn một lần.
- Receiver **có** receipt ở lượt Block: rule chặn không hiệu lực, hoàn tác và
  xem lại thứ tự rule trước khi thử lại.
- Bất kỳ file evidence nào không hash được ngay sau khi lưu.
