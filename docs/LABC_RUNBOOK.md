# Runbook Lab C — chạy một đợt SCN-004 từ đầu đến dashboard

Dành cho người chạy lại đợt nghiệm thu SCN-004 trên Lab C: từ bật lab, kiểm đồng hồ và
nguồn log, gửi probe, thu bundle, tới `validate`, `compare` và dashboard.

Kịch bản và profile: [SCN004_LAB_C.md](SCN004_LAB_C.md). Cấu hình đã chốt của đợt gần
nhất ở mục 10 của tài liệu đó, kết quả ở [SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md).

**Đợt live mới dùng scenario và profile `0.2.0`, có A01–A04.** Chủ dự án đã duyệt
A04 sau khi review gói bàn giao ngày 2026-10-08; phạm vi và fingerprint được ghi tại
[SCN004_A04_APPROVAL_AND_PINS.md](SCN004_A04_APPROVAL_AND_PINS.md). Phê duyệt này
không thay cho lượt live do người khác chạy hoặc nghiệm thu sau tích hợp main.

Runbook này nói **việc cần làm**, không phụ thuộc script riêng của một lab. Lab C có
sẵn một bộ script (gửi probe, thu bằng chứng, đóng gói, chạy validate) nằm ngoài Git vì
chứa địa chỉ và tên máy thật; ai cũng có thể làm từng bước bằng tay theo mô tả dưới đây.

## 0. Nguyên tắc

- **Chốt phiên bản trước khi gửi.** Ghi commit code, version và fingerprint của
  scenario/profile trong kế hoạch phiên chạy. Với `0.2.0`, đối chiếu pins trong hồ sơ
  duyệt: scenario `8de00c64cfe8…`, profile `b529215d02ea…`. Không sửa manifest,
  profile hoặc cửa sổ tương quan giữa hai lượt để ép kết quả.
- **Giữ kết quả lịch sử theo đúng phiên bản.** 16 lượt ngày 7-10 dùng `0.1.0`
  (A01–A03); năm lượt live ngày 8-10 dùng `0.2.0` (A01–A04), gồm hai lượt đầu và ba lượt bổ sung sau phê duyệt. Khi replay một report
  cũ, chọn đúng manifest/profile đã ghim của report đó. Đánh giá lại log cũ bằng
  `0.2.0` lưu riêng và không tính là lượt live mới.
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
và đồng hồ firewall lệch hàng nghìn giây. Nếu lỡ suspend thì khởi động lại các máy
ảo cần dùng trong phiên bằng Restart Guest, firewall trước.

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
   Ghi người chạy, người review, commit và version/fingerprint đã chốt; giá trị thật
   của địa chỉ, cổng và nhãn rule giữ trong hồ sơ private.
4. **Đợi** ít nhất 100 giây kể từ lúc gửi **và** qua hết cửa sổ bundle (phút gửi + 2
   phút) thêm khoảng 15 giây. OPNsense gửi log qua syslog có thể trễ; nếu máy thu log
   vừa khởi động lại thì đợi thêm 70 giây nữa trước khi gửi lượt tiếp theo.
5. **Thu bằng chứng, chỉ đọc**, trên sensor và máy SIEM:
   - mọi dòng `alert_json` của Snort trong 60 phút gần nhất;
   - mọi dòng `filterlog` trong 60 phút gần nhất, gồm cả bản vừa xoay vòng;
   - bản ghi Sysmon 3 trong `archives.json` và alert Wazuh 130110 trong `alerts.json`
     của cùng luồng; alert SIEM phải giữ cả dòng `full_log` của Snort;
   - trạng thái dịch vụ Snort và agent Wazuh, thống kê gói của Snort, độ lệch đồng hồ
     của sensor.
   Mỗi tệp kèm số dòng và SHA-256 tại thời điểm thu. Giữ giờ nguồn và giờ manager
   nhận riêng; khi chọn alert SIEM theo cửa sổ, dùng giờ nguồn Snort đã được parser
   chuẩn hóa, không thay bằng giờ manager nhận. Capture đọc lỗi phải ghi là không
   đầy đủ, giữ bản gốc và hồ sơ dẫn xuất; không xóa dòng hỏng để báo thu đủ.
6. **Đóng gói bundle**: cắt theo cửa sổ của lượt, giữ nguyên byte của từng dòng.
   `inputs.json` khai từng file thực sự thu được, `source_ref`, SHA-256 và parser key:

   - A01, Sysmon Event 3 từ Wazuh archive: `wazuh-sysmon3-archive-v1`.
   - A02, Snort `alert_json` trực tiếp trên sensor: `snort3-alert-json-v1`.
   - A03, OPNsense filterlog BSD: `opnsense-filterlog-bsd-v1`.
   - A04, alert Wazuh 130110 sinh từ Snort, từ `0.2.0`: `wazuh-snort-alert-v1`.

   Dùng [inputs.json của bundle bốn nguồn đã sanitize](../tests/fixtures/cli/scn004-lab-c-sanitized/block-siem/inputs.json)
   làm mẫu cấu trúc, rồi thay bằng metadata và hash của lượt mới. `environment_id`
   trong `inputs.json` phải khớp `context.json`; không dùng lại giá trị fixture.
   `context` của từng entry phải có đủ trường của parser:

   - Wazuh: `ingested_at`, `collection_mode`.
   - Snort: `ingested_at`, `sensor_id`, `deployment_mode` (`ids` với sensor thụ động).
   - OPNsense: `ingested_at`, `sensor_id`, `source_year`, `source_utc_offset`.

   Lấy các giá trị này từ hồ sơ thu và cấu hình đã chốt. BSD syslog thiếu năm và
   offset nên phải khai rõ, không đoán năm hoặc múi giờ từ đồng hồ máy đánh giá.

   Lượt bình thường đủ nguồn dưới `0.2.0` có cả bốn loại bằng chứng. Nếu không thu
   được alert SIEM, ghi thiếu A04 và không tạo file hoặc log giả để bù. Bản ghi
   Sysmon của A01 không thể dùng thay alert Snort của Wazuh cho A04. Không suy ra
   thu đủ chỉ từ số file hoặc số dòng.

   `context.json` khai `run_id`, `environment_id`, cửa sổ và bốn binding
   (`sender_ip`, `receiver_ip`, `receiver_port`, `block_rule_label`).
   Giá trị `block_rule_label` lấy từ cấu hình firewall đã biết **trước** lượt chạy,
   không lấy từ dòng log của chính probe.
7. **Chạy validate**:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-004-attempted-exfiltration-lab-c.yaml --fixture "<duong-dan-bundle>" --profile scenarios\profiles\scn-004\profile.json --format json
```

   Lưu stdout thành `report.json` UTF-8, stderr riêng và exit code thật của CLI trong
   `exit-code.txt`; so version/fingerprint trong report với kế hoạch đã chốt. Đường
   dẫn bundle ngoài checkout phải là đường dẫn tuyệt đối, không có thành phần `..`.

8. **Đối chiếu**: kết quả và exit code có đúng kỳ vọng của tình huống dưới **phiên bản
   đang chạy** không (mục 5 dưới đây); trạng thái dịch vụ lúc thu có khớp tình huống
   đã ghi khi gửi không. Không khớp thì lượt đó là lỗi quy trình, không phải phát hiện.
   Nếu quy trình hợp lệ nhưng kết quả khác kỳ vọng, giữ lượt đó trong tổng và ghi
   sai lệch; không chạy bù để loại kết quả xấu. `Prevented` chỉ nói về các assertion
   của phiên bản đó, không chứng minh mọi đường bảo vệ hoặc mọi thiết bị đều ổn định.

## 5. Các tình huống của ma trận

| Tình huống | Làm gì trước khi gửi | Kỳ vọng `0.2.0` (A01–A04) |
| --- | --- | --- |
| Đủ nguồn, firewall chặn | xác nhận cả đường alert Snort → Wazuh đang hoạt động | `Prevented`, exit 0; A01–A04 `satisfied` |
| Firewall cho qua | bật tiến trình nhận trên máy nhận; rule cho qua đã có | `Inconclusive`, exit 3; A03 `prevention_not_demonstrated`; giữ log nhận riêng |
| Snort ngừng thu | dừng dịch vụ Snort có kiểm soát; agent trên sensor vẫn chạy | `Inconclusive`, exit 3; A02 `collection_not_confirmed`; nếu thiếu alert SIEM thì A04 cũng chưa kết luận |
| Đường log sang Wazuh gián đoạn | dừng agent Wazuh **trên sensor**, Snort vẫn chạy, agent máy gửi vẫn kết nối | A01–A03 `satisfied`, A04 `inconclusive/collection_not_confirmed`; tổng `Inconclusive`, exit 3 |
| Khôi phục | chạy lại dịch vụ vừa dừng, kiểm hoạt động rồi gửi lượt mới | lượt mới đủ A01–A04 thì `Prevented`, exit 0 |

**Khác biệt lịch sử:** dưới `0.1.0`, ca agent Wazuh trên sensor dừng vẫn có thể
`Prevented`, exit 0 vì chỉ đánh giá A01–A03. Không dùng kỳ vọng đó cho `0.2.0`.
Lượt khôi phục phải có gói và bằng chứng mới; không giả định agent tự đọc bù các
alert cũ. Log tiến trình nhận UDP là bằng chứng của tiến trình, không gọi là PCAP.

## 6. Kiểm chứng rule hụt và `compare`

1. Chạy một lượt với payload có chuỗi đánh dấu nằm ngoài phạm vi tìm của rule.
2. Review điều kiện thu thập trước khi khai báo: Snort chạy từ **trước** cửa sổ,
   capture trọn vẹn, collector không có dòng chưa đọc được, lúc thu bao trùm hết cửa
   sổ, các đồng hồ đạt ngưỡng ở mục 3 và intake không bỏ qua bản ghi nào. Giữ trạng
   thái dịch vụ, counters và từng kết quả kiểm trong `collection-checks.json`.
   Counter tổng `analyzed > 0` không chứng minh probe cụ thể đã được sensor nhìn
   thấy; không có trường drop không có nghĩa là drop bằng 0. Ghi rõ giới hạn của
   phép kiểm, không tự điền giá trị thiếu.

   Chỉ khi người thu xác nhận đầy đủ **trong đúng scope** đã review mới kèm
   `complete_for_scope` cho A02 trong `context.json`, cùng collection reference và
   fingerprint theo hợp đồng engine. Đây là `caller-attested`, không phải chứng
   minh độc lập về thu không mất gói. Thiếu cơ sở thì không khai báo: A02 giữ
   `inconclusive/collection_not_confirmed`. Giữ cả báo cáo chưa khai báo.
3. Sửa rule, lưu bản trước và bản sau kèm SHA-256, nạp lại và kiểm Snort vẫn bắt gói.
4. Chạy lượt mới **cùng nhãn, cùng dạng payload**, cùng environment, binding,
   scenario/profile và độ dài cửa sổ. Mỗi lượt vẫn có `run_id`, thời điểm và log mới.
5. So sánh:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify compare --before "<report-truoc>.json" --after "<report-sau>.json" --format json
```

`Regression Passed` cần A02 chuyển `false_negative` → `satisfied`, các assertion
còn lại `unchanged_pass` và không có trạng thái unknown. `compare` từ chối hai lượt
khác scenario/profile, environment, binding hoặc độ dài cửa sổ.

- **Replay cặp lịch sử `0.1.0`:** `f12e4fa7` → `9099c31e` đã cho `Regression Passed`
  (A02 evidence sau sửa `640286c663c4…`; ID đầy đủ trong report). Chạy lại validate
  bằng đúng manifest/profile `0.1.0`; không chạy hai bundle đó với bộ `0.2.0` rồi
  yêu cầu giữ nguyên kết luận ba assertion.
- **Đợt live `0.2.0`:** ca rule hụt có thể thiếu cả A02 và A04. Khai báo thu đủ cho
  A02 không áp dụng cho A04. Nếu A04 còn unknown trước hoặc sau sửa, tổng đánh giá
  hoặc compare vẫn có thể `Inconclusive`; không hứa `Regression Passed`. Muốn đánh
  giá sự vắng mặt của A04 phải có scope, bằng chứng thu thập và khai báo riêng được
  review cho A04. Không xóa A04 hoặc hạ về `0.1.0` để làm lượt nghiệm thu mới đạt.

## 7. Dashboard

```powershell
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports "<thu-muc-report>" --static frontend\dist --scenarios scenarios
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
| Sysmon ghi sự kiện mạng lệch gần 1 s dù đồng hồ máy đúng — sau khi máy ảo suspend/resume thì lệch tới hàng giờ (đo được −51 963 s) | Sysmon đóng dấu sự kiện theo mốc lúc nó khởi động; đồng hồ máy chỉnh sau đó thì sự kiện mạng không theo | đồng bộ đồng hồ máy trước, rồi cài lại Sysmon đúng bản và đúng file cấu hình, khởi động lại agent Wazuh, đo lại cho tới khi lệch < 0,5 s |
| Mất log firewall khoảng một phút sau khi máy thu log khởi động lại | bên gửi syslog thử lại sau 60 s rồi gửi bù các bản tin còn hàng đợi với mốc giờ gốc | đợi ≥ 70 s sau khi máy thu log khởi động lại rồi mới gửi probe |
| Đo lệch đồng hồ ra số vô lý (hàng tỉ giây) | hỏi NTP quá dày, bị giới hạn tần suất, gói Kiss-o'-Death bị lấy nhầm | hỏi thưa, bỏ gói có stratum 0 |
| `collect` báo cửa sổ của lượt chứa gói của lượt khác | hai lượt cách nhau dưới 150 s | ghi lượt đó là không hợp lệ, chạy lượt mới |
| Parser từ chối một dòng của capture filterlog | quan sát thấy dòng nối/cắt và khoảng byte NUL; mất ký tự xuống dòng hoặc máy dừng không sạch là nguyên nhân nghi ngờ, chưa có log hệ thống để xác nhận | **không** xóa dòng; báo capture không đầy đủ kể từ dòng đó, giữ nguyên bản gốc, ghi lại mọi bản dẫn xuất kèm hash nguồn và hash kết quả; xem [SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md) mục 6 |

## 9. Chạy lại độc lập và bàn giao để đóng nghiệm thu

Đây là quy trình chạy lại tiêu chuẩn. Trạng thái nghiệm thu của đợt đã chốt ngày
2026-10-09 và việc bàn giao cuối được ghi ở mục 10.

Một người khác với người tạo chiến dịch ban đầu chạy theo runbook này, gồm **ít
nhất một lượt live mới** dưới bộ `0.2.0` đã duyệt. Khuyến nghị một cặp normal và
agent-down rồi phục hồi để kiểm đường SIEM. Việc chạy lại CLI trên log cũ không thay
cho bước live này.

Trước phiên, chốt số lượt/tình huống, kỳ vọng và thời gian quan sát. Bàn giao:

- tên người chạy/người review, commit code, version/fingerprint scenario/profile;
- `runs/<run_id>/`: receipt, raw, bundle, provenance, report, stderr và exit code;
- `campaign.csv`: mọi lượt hợp lệ kể cả kết quả khác kỳ vọng; `invalid-runs.txt`
  giữ lượt bị loại và lý do; không cộng smoke hoặc replay vào tổng live;
- hash manifest và mô tả mọi bản dẫn xuất; cấu hình/rule trước–sau khi có thay đổi;
- trạng thái cuối các dịch vụ/rule, lỗi đã gặp và giới hạn còn lại.

Giữ bằng chứng thật và giá trị lab ngoài Git. Sau khi kết quả live và test được
review, tích hợp chuỗi PR theo phụ thuộc, chạy validate/compare trên **commit main
cuối**, rồi ghi commit và kết quả vào hồ sơ nghiệm thu. Chỉ lúc các bước này hoàn
tất mới đóng phần tích hợp Lab C; phê duyệt A04 riêng không thay cho quyết định nghiệm thu kỹ thuật và kết quả kiểm tra main.

## 10. Bàn giao cuối và dọn Lab C

Nghiệm thu kỹ thuật và ảnh/dashboard đã được chủ dự án chốt ngày 2026-10-09;
quyết định và giới hạn bằng chứng ở
[SCN004_A04_APPROVAL_AND_PINS.md](SCN004_A04_APPROVAL_AND_PINS.md).
Trạng thái này là quyết định nghiệm thu của chủ dự án; không tự đổi collection
assurance, run binding hoặc scenario/profile trong các report đã lưu.

1. Giữ bằng chứng gốc, report, provenance, cấu hình và manifest SHA-256 ở nơi
   lưu trữ ổn định ngoài Git. Ba gói bàn giao được ghim trong hồ sơ duyệt.
2. Trước khi xóa VM, export đầy đủ đĩa ảo và cấu hình sang nơi lưu trữ độc lập
   với thư mục VM sẽ xóa; kiểm tra tính toàn vẹn và khả năng phục hồi bản export.
3. Review evidence/tests rồi merge các PR Lab C theo thứ tự phụ thuộc.
4. Trên commit main cuối, chạy checks và replay các bundle đã nghiệm thu đúng
   phiên bản manifest/profile đã ghim. Đối chiếu report và exit code; chạy lại
   cặp hồi quy chính `f12e4fa7` → `9099c31e` với pins `0.1.0`. Report `0.2.0`
   dùng pins `0.2.0`; không so sánh trực tiếp report khác phiên bản.
5. Bàn giao SHA main cuối, log checks, kết quả replay/compare, manifest SHA-256
   và vị trí backup. Khi bản backup đã được kiểm tra, có thể dọn VM; giữ repo
   và bằng chứng để replay và đối chiếu sau này.
