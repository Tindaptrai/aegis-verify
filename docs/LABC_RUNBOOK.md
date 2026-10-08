# Runbook Lab C — chạy một đợt SCN-004 từ đầu đến dashboard

Dành cho người chạy lại đợt nghiệm thu SCN-004 trên Lab C: từ bật lab, kiểm đồng hồ và
nguồn log, gửi probe, thu bundle, tới `validate`, `compare` và dashboard.

Kịch bản và profile: [SCN004_LAB_C.md](SCN004_LAB_C.md). Cấu hình đã chốt của đợt gần
nhất ở mục 10 của tài liệu đó, kết quả ở [SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md).

Runbook này nói **việc cần làm**, không phụ thuộc script riêng của một lab. Lab C có
sẵn một bộ script (gửi probe, thu bằng chứng, đóng gói, chạy validate) nằm ngoài Git vì
chứa địa chỉ và tên máy thật; ai cũng có thể làm từng bước bằng tay theo mô tả dưới đây.

## 0. Nguyên tắc

- **Một probe một lượt.** Mỗi lượt gửi đúng một datagram UDP, có `run_id` riêng.
- **Hai lượt cách nhau ít nhất 150 giây.** Cửa sổ bundle của một lượt là từ 1 phút
  trước tới 2 phút sau phút gửi; hai lượt gần nhau hơn thì cửa sổ của lượt này chứa gói
  của lượt kia, và bằng chứng không còn thuộc về một lượt nữa.
- **Không nới cửa sổ tương quan, không dùng lại log của lượt trước** để đạt kết quả.
- **Lượt hỏng vì quy trình thì ghi lại là không hợp lệ** kèm lý do, rồi chạy một lượt
  mới cùng loại. Không sửa bằng chứng.
- **Chỉ đọc khi thu bằng chứng.** Chép đúng từng byte của dòng cần lấy, kèm số dòng và
  SHA-256 của file nguồn tại thời điểm thu.

## 1. Bật lab

Bật máy ảo theo thứ tự: firewall, SIEM, sensor, máy gửi, máy nhận.

**Dùng "Restart Guest" hoặc "Shut Down Guest", không dùng Suspend.** Sau suspend/resume
đã gặp: DAQ `afpacket` của Snort hỏng và Snort thoát sạch, mạng Docker của Wazuh hỏng,
và đồng hồ firewall lệch hàng nghìn giây. Nếu lỡ suspend thì khởi động lại cả bốn máy
ảo bằng Restart Guest, firewall trước.

Đợi khoảng 3 phút cho dịch vụ lên.

## 2. Kiểm sức khỏe trước mỗi phiên

| Kiểm | Đạt khi |
| --- | --- |
| Snort | dịch vụ `active`, card bắt gói nhận thêm gói trong 10 s, `analyzed` tăng |
| Máy thu log | rsyslog `active`, file `filterlog-raw.log` có dòng mới trong 10 s |
| Wazuh | manager chạy, `logall_json` bật, mọi agent `Active`, `archives.json` có sự kiện mới của từng agent trong 5 phút |
| Rule | rule Snort sid 1000010 có trong file rule đang nạp; rule Wazuh 130110 có trong thư mục rule của manager |
| Máy nhận (chỉ khi chạy lượt "cho qua") | tiến trình nhận UDP đang nghe đúng cổng |
| Đĩa | còn chỗ trên sensor và máy SIEM |

## 3. Kiểm đồng hồ

Đồng hồ là điều kiện để tương quan ±2 s có nghĩa. Nguồn thời gian duy nhất là NTP của
firewall.

1. **Sensor, SIEM, máy nhận**: đo lệch so với firewall bằng truy vấn SNTP. Đạt khi
   |lệch| ≤ 0,05 s. Chưa đạt thì khởi động lại `systemd-timesyncd`, đo lại, rồi mới
   chỉnh đồng hồ một lần theo giá trị đo được.
   Hỏi NTP **thưa**: mỗi truy vấn cách nhau 3–4 giây và bỏ gói trả lời Kiss-o'-Death
   (stratum 0). Hỏi dày sẽ bị ntpd giới hạn tần suất và gói từ chối có thể bị lấy nhầm
   thành một kết quả vô nghĩa.
2. **Máy gửi (Windows)**: `w32tm /resync`, rồi đo lệch so với firewall. Đạt khi
   |lệch| < 0,5 s. w32time chỉ kéo từ từ khi lệch dưới 1 s, nên nếu còn lệch thì dừng
   `w32time`, chỉnh đồng hồ một bước đúng bằng giá trị đo, chạy lại `w32time`.
3. **Đồng hồ sự kiện mạng của Sysmon**: gửi một gói UDP tới `127.0.0.1` và so giờ gửi
   với `UtcTime` của Event 3 tương ứng. Đạt khi |lệch| < 0,5 s.
   Sysmon giữ độ lệch có từ lúc nó khởi động: nếu đồng hồ máy được chỉnh **sau** khi
   Sysmon chạy thì sự kiện mạng vẫn lệch. Cách sửa là cài lại Sysmon (cùng bản, cùng
   file cấu hình) rồi khởi động lại agent Wazuh, sau đó đo lại.

Ghi ba con số này vào biên nhận của mỗi lượt.

## 4. Chạy một lượt

1. **Trước khi gửi**, kiểm lại trong vòng một phút: lệch đồng hồ máy gửi < 0,5 s, lệch
   Sysmon < 0,5 s, Sysmon có rule bắt kết nối UDP tới cổng đích, agent Wazuh đang
   `connected`. Không đạt thì **không gửi**.
2. **Gửi đúng một datagram UDP** từ máy gửi, payload chứa chuỗi đánh dấu và `run_id`.
   Nhãn của lượt:
   - `block`: đích là địa chỉ tài liệu bên ngoài, firewall phải chặn;
   - `allow`: đích là máy nhận trong lab, firewall cho qua;
   - ca rule hụt: như `block` nhưng payload có 80 byte đệm trước chuỗi đánh dấu.
3. **Ghi biên nhận**: `run_id`, nhãn, tình huống, cổng nguồn, SHA-256 payload, giờ UTC
   trước và sau khi gửi, lệch đồng hồ, lệch Sysmon, và Event 3 của chính gói đó.
4. **Đợi** ít nhất 100 giây kể từ lúc gửi **và** qua hết cửa sổ bundle (phút gửi + 2
   phút) thêm khoảng 15 giây. OPNsense gửi log qua syslog có thể trễ; nếu máy thu log
   vừa khởi động lại thì đợi thêm 70 giây nữa trước khi gửi lượt tiếp theo.
5. **Thu bằng chứng, chỉ đọc**, trên sensor và máy SIEM:
   - mọi dòng `alert_json` của Snort trong 60 phút gần nhất;
   - mọi dòng `filterlog` trong 60 phút gần nhất, gồm cả bản vừa xoay vòng;
   - bản ghi Sysmon 3 và alert Wazuh 130110 của cùng luồng trong log của manager;
   - trạng thái dịch vụ Snort và agent Wazuh, thống kê gói của Snort, độ lệch đồng hồ
     của sensor.
   Mỗi tệp kèm số dòng và SHA-256 tại thời điểm thu.
6. **Đóng gói bundle**: cắt theo cửa sổ của lượt, giữ nguyên byte của từng dòng.
   `inputs.json` khai ba file và parser key, `context.json` khai `run_id`, cửa sổ và bốn
   binding (`sender_ip`, `receiver_ip`, `receiver_port`, `block_rule_label`).
   Giá trị `block_rule_label` lấy từ cấu hình firewall đã biết **trước** lượt chạy,
   không lấy từ dòng log của chính probe.
7. **Chạy validate**:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-004-attempted-exfiltration-lab-c.yaml --fixture <bundle> --profile scenarios\profiles\scn-004\profile.json --format json
```

8. **Đối chiếu**: kết quả và exit code có đúng kỳ vọng của tình huống không (mục 7 của
   [SCN004_LAB_C.md](SCN004_LAB_C.md)); trạng thái dịch vụ lúc thu có khớp tình huống
   đã ghi khi gửi không. Không khớp thì lượt đó là lỗi quy trình, không phải phát hiện.

## 5. Các tình huống của ma trận

| Tình huống | Làm gì trước khi gửi | Kỳ vọng |
| --- | --- | --- |
| Đủ nguồn, firewall chặn | không | `Prevented`, exit 0 |
| Firewall cho qua | bật tiến trình nhận trên máy nhận; rule cho qua đã có | `Inconclusive`, exit 3 |
| Snort ngừng thu | dừng dịch vụ Snort bằng `systemctl stop` (dừng có kiểm soát nên chính sách tự chạy lại không kích hoạt) | `Inconclusive`, exit 3, A02 `collection_not_confirmed` |
| Đường log sang Wazuh gián đoạn | dừng agent Wazuh **trên sensor**, Snort vẫn chạy | `Prevented`, exit 0; có alert Snort tại nguồn, không có alert Wazuh |
| Khôi phục | chạy lại dịch vụ vừa dừng, kiểm nó thật sự hoạt động trở lại | lượt mới đạt lại kết quả kỳ vọng |

## 6. Kiểm chứng rule hụt và `compare`

1. Chạy một lượt với payload có chuỗi đánh dấu nằm ngoài phạm vi tìm của rule.
2. Chứng minh telemetry vẫn đủ trước khi kết luận: Snort chạy liên tục từ **trước** cửa
   sổ, không dòng nào không đọc được, không gói nào bị drop, lúc thu bao trùm hết cửa
   sổ, các đồng hồ lệch dưới 0,5 s, intake không bỏ qua bản ghi nào. Đủ các điều kiện
   này mới kèm khai báo `complete_for_scope` cho A02 trong `context.json`; thiếu một
   điều kiện thì **không khai báo**, và A02 sẽ là `inconclusive` thay vì
   `false_negative`. Giữ cả báo cáo của lần chạy chưa khai báo.
3. Sửa rule, lưu bản trước và bản sau kèm SHA-256, nạp lại và kiểm Snort vẫn bắt gói.
4. Chạy lượt mới **cùng nhãn, cùng dạng payload** để hai lượt có cùng binding và cùng
   độ dài cửa sổ.
5. So sánh:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify compare --before <report-truoc>.json --after <report-sau>.json --format json
```

Kỳ vọng `Regression Passed`: A02 `improvement`, các assertion khác `unchanged_pass`,
không assertion nào ở trạng thái unknown. `compare` từ chối hai lượt khác scenario,
khác profile, khác binding hoặc khác độ dài cửa sổ.

## 7. Dashboard

```powershell
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports <thư mục report> --static frontend\dist --scenarios scenarios
```

- Thư mục report nằm ngoài checkout thì truyền **đường dẫn tuyệt đối**: CLI từ chối mọi
  đường dẫn có thành phần `..` (`invalid_path`).
- Luôn truyền `--scenarios`; thiếu nó thì Scenario registry báo `not_configured` và
  trang Tổng quan không có kịch bản nào.
- Hàng KPI đếm theo **kịch bản**, lấy kết quả gần nhất của mỗi manifest, không đếm theo
  số report. Nhãn của từng lượt nằm ở danh sách report.

## 8. Sự cố đã gặp và cách xử lý

| Hiện tượng | Nguyên nhân | Xử lý |
| --- | --- | --- |
| Snort `inactive` sau khi lab chạy lại | DAQ hỏng sau suspend/resume, Snort thoát sạch nên `Restart=on-failure` không chạy lại | đặt `Restart=always` bằng drop-in; chạy lại dịch vụ và kiểm card bắt gói |
| Agent Wazuh `Disconnected`, ping và SSH tới máy SIEM vẫn được | mạng Docker hỏng sau suspend/resume | khởi động lại dịch vụ Docker |
| Giờ firewall lệch hàng nghìn giây | đồng hồ máy ảo sau suspend/resume | Restart Guest, firewall trước; chờ NTP đồng bộ rồi mới chạy lượt |
| Máy gửi lệch khoảng 0,5 s và không tự hết | w32time chỉ kéo từ từ khi lệch dưới 1 s | chỉnh một bước rồi bật lại w32time |
| Sysmon ghi sự kiện mạng lệch gần 1 s dù đồng hồ máy đúng | Sysmon giữ độ lệch từ lúc khởi động | cài lại Sysmon, khởi động lại agent, đo lại |
| Mất log firewall khoảng một phút sau khi máy thu log khởi động lại | bên gửi syslog thử lại sau 60 s rồi gửi bù các bản tin còn hàng đợi với mốc giờ gốc | đợi ≥ 70 s sau khi máy thu log khởi động lại rồi mới gửi probe |
| Đo lệch đồng hồ ra số vô lý (hàng tỉ giây) | hỏi NTP quá dày, bị giới hạn tần suất, gói Kiss-o'-Death bị lấy nhầm | hỏi thưa, bỏ gói có stratum 0 |
| `collect` báo cửa sổ của lượt chứa gói của lượt khác | hai lượt cách nhau dưới 150 s | ghi lượt đó là không hợp lệ, chạy lượt mới |
