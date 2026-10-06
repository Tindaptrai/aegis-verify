# Hướng dẫn tham gia: chạy và phát triển AEGIS Verify trong lab của bạn

Dành cho thành viên dự án nhận bản **0.3.0**: tự cài, chạy thử, đánh giá, rồi phát
triển trên **nhánh riêng**. Lab A là lab gốc, gồm pfSense, Suricata trên pfSense,
Wazuh, Cowrie và một endpoint Windows. Ba kịch bản đã được kiểm chứng ở đó. Lab B
(Elastic Security) và Lab C (OPNsense + Snort 3 + Wazuh) khác lab A. Mục 4 nói rõ
phần nào dùng được ngay và phần nào phải viết thêm.

## 0. Đọc trước (khoảng 15 phút)

- [AGENTS.md](../AGENTS.md): luật làm việc, bắt buộc.
- [PRD](PRD.md) và [Architecture](ARCHITECTURE.md).
- [MVP acceptance](MVP_ACCEPTANCE.md): những gì đã chứng minh và các giới hạn.

Bốn nguyên tắc không thoả hiệp:

1. Không đoán giá trị. Trường nào nguồn không có thì để `null`.
2. Mọi kết luận phải trỏ tới evidence ID.
3. Không sửa ground truth (`scenarios/SCN-*.yaml`), không nới cửa sổ tương quan và
   không mượn bản ghi của lượt khác để có verdict mong muốn.
4. Không commit IP, tên máy, user hay credential thật, cũng không commit bằng chứng
   thô chưa sanitize.

## 1. Cài đặt và smoke test (khoảng 15 phút, không cần lab)

Cần Git, Python 3.11–3.13 và Node 24 (Node chỉ dùng cho dashboard). Chạy được
trên Windows hoặc Linux.

```powershell
git clone https://github.com/Tindaptrai/aegis-verify.git
cd aegis-verify
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q -rs
```

Trên Linux, thay `.\.venv\Scripts\python.exe` bằng `.venv/bin/python`.

Kết quả kỳ vọng với 0.3.0:

- Windows: khoảng 3300 passed, 2–3 skipped (FIFO, quyền POSIX).
- Linux: khoảng 3200 passed, 89 skipped. Các test bị bỏ qua đều chỉ chạy trên
  Windows (PowerShell 5.1, launcher, ACL).
- Nếu ổ chứa thư mục tạm gần đầy, test Operations báo `disk_space` (HTTP 503). Thêm
  `--basetemp <thư mục trên ổ khác>` là được.

Sau đó chạy [demo offline](DEMO_WALKTHROUGH.md) từ mục 0 tới mục 4. Kết quả đúng:

| Lệnh | Kết quả |
| --- | --- |
| SCN-002 lượt đối chứng | `Inconclusive`, exit 3 |
| SCN-002 lượt Block | `Prevented`, exit 0 |
| So sánh hai lượt | `Inconclusive` |
| SCN-003 | `Detected`, exit 0 |
| Dashboard | 3 run, 1 bản so sánh |

Nếu mọi bước khớp, máy bạn đã sẵn sàng. Ghi lại kết quả trong phần đánh giá ở mục 7.

## 2. Làm việc trên nhánh riêng

- Đặt tên nhánh `lab-b/<chủ-đề>` hoặc `lab-c/<chủ-đề>`, ví dụ
  `lab-c/opnsense-filterlog-parser`. Không push thẳng vào `main`.
- Mỗi nhánh làm một việc nhỏ, gắn với một issue. Muốn hợp nhất thì mở PR vào
  `main`; chủ dự án review rồi merge.
- CI tự chạy trên PR:
  - Linux/Python 3.12 và frontend;
  - thêm Windows/Python 3.13 nếu PR đổi code riêng của Windows ([CI](CI.md));
  - GitGuardian quét secret.
- Fixture dùng địa chỉ tài liệu RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) và tên miền `.example` hoặc `.test`. Sanitize theo
  [chính sách fixture](../tests/fixtures/README.md).
- Config lab, bằng chứng thô, receipt và report đầy đủ phải nằm **ngoài Git**, trong
  một thư mục chỉ bạn đọc được. Ví dụ: `%LOCALAPPDATA%\AEGIS\` trên Windows,
  `~/.local/share/aegis/` (mode 700) trên Linux. `aegis collect` từ chối ghi vào bên
  trong một Git working tree.
- Chỉ những thay đổi dùng chung mới vào `main` qua PR riêng, trước khi các nhánh lab
  dùng tới, để tránh hai nhánh sửa cùng một chỗ. Ví dụ: thêm `SourceType` (mục 5)
  hay sửa engine.

## 3. AEGIS đọc dữ liệu như thế nào

Một lượt chạy là một **bundle**, tức một thư mục gồm:

- các file nguồn, giữ nguyên bytes;
- `inputs.json`: mỗi file có `path`, `parser`, `sha256` và context của nguồn
  (`sensor_id`, năm và múi giờ cho syslog BSD...);
- `context.json`: `run_id`, `environment_id`, khung thời gian và các **binding**
  (IP, cổng, tracker của lượt đó).

Luồng xử lý:

1. Parser trong `connectors/` đọc file và sinh **canonical event**
   ([v2](CANONICAL_EVENT_V2.md)).
2. **Profile** (`scenarios/profiles/<scn>/profile.json`) nói mỗi assertion cần
   `source_type` nào, lọc theo trường và binding nào, ghép với nhau ra sao, trong cửa
   sổ thời gian bao nhiêu.
3. `aegis validate` trả verdict kèm evidence ID.

Bundle mẫu: `tests/fixtures/cli/scn002-lab-sanitized/` và
`tests/fixtures/cli/scn003-lab-sanitized/`.

## 4. Bản đồ nguồn dữ liệu theo lab

### Parser có sẵn trong 0.3.0

| Parser key | Đọc gì | Dùng ở |
| --- | --- | --- |
| `wazuh-sysmon1-v1` | Sysmon 1 (tạo process) qua Wazuh | SCN-001 |
| `wazuh-powershell4104-v1` | PowerShell 4104 qua Wazuh | SCN-001 |
| `wazuh-win4688-v2` | Security 4688 qua Wazuh | bộ thu Indexer |
| `wazuh-sysmon3-archive-v1` | dòng Sysmon 3 trong `archives.json` của manager | SCN-002 A01 |
| `suricata-eve-jsonl-v1` | file `eve.json` của Suricata | SCN-002 A02, SCN-003 A01 |
| `wazuh-suricata-alert-v1` | dòng alert 86601 (Suricata) trong `alerts.json` | SCN-002 A04 |
| `suricata-wazuh-alert-v1` | tài liệu alert Suricata trong Wazuh Indexer | dữ liệu Indexer |
| `snort3-alert-json-v1` | file `alert_json` của Snort 3, danh sách trường đã pin | Lab C (chưa có profile) |
| `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | dòng `filterlog` của pfSense dạng syslog BSD, IPv4 TCP/UDP | SCN-002 A03, SCN-003 A02 |
| `opnsense-filterlog-bsd-v1` | dòng `filterlog` của OPNsense dạng syslog BSD, IPv4 và IPv6 | Lab C (chưa có profile) |
| `cowrie-jsonl-v1` | file JSON của Cowrie | SCN-003 A03 |
| `wazuh-cowrie-alert-v1` | dòng alert Cowrie trong `alerts.json` | SCN-003 A04 |
| `cowrie-wazuh-v1` | tài liệu Cowrie trong Wazuh Indexer | dữ liệu Indexer |

`source_type` hiện là tập đóng: `wazuh`, `suricata`, `pfsense`, `cowrie`, `snort`,
`opnsense` (`snort` và `opnsense` thêm cho Lab C).

### Lab B: Elastic Security

| Nguồn | Dùng ngay? | Việc cần làm |
| --- | --- | --- |
| Suricata `eve.json` trên sensor | **Có**: `suricata-eve-jsonl-v1` đọc file gốc | Thu file gốc, đừng thu bản đã qua Elastic Agent. Context: `sensor_id` là tên sensor của bạn, `deployment_mode` là `ids`. Kiểm `event_type` và timestamp thật; sensor nhận mirror nên thấy cả hai chiều. |
| pfSense syslog thô qua rsyslog | **Có điều kiện**: parser pfSense | pfSense phải gửi log dạng BSD (RFC 3164). Template rsyslog phải giữ nguyên dòng `Mmm dd HH:MM:SS <host> filterlog[pid]: <csv>`. So vài dòng với `tests/fixtures/cli/scn002-lab-sanitized/block/filterlog.log` trước khi tin. Parser chỉ nhận IPv4 TCP/UDP và cần `source_year`, `source_utc_offset` trong context. |
| Windows (Sysmon, PowerShell) qua Elastic | **Chưa có parser** | Viết connector `connectors/elastic/`: parser cho tài liệu Elastic của Sysmon 1, Sysmon 3 và PowerShell 4104 (ECS, `winlog.*`), giữ `winlog.record_id` để đối chiếu với EVTX gốc. |
| Elastic Security detection alerts | **Chưa có parser** | Parser riêng cho alert (`kibana.alert.*`), tách khỏi source event, giữ document ID và rule reference. |
| EVTX gốc | Không có parser EVTX | Chỉ là bằng chứng đối chiếu: số bản ghi và record ID phải khớp với bản Elastic. |

Thứ tự nên làm:

1. PR chung thêm `SourceType` `elastic` (mục 5).
2. Parser Elastic cho Sysmon 1 và PowerShell 4104, có fixture sanitize.
3. Một profile SCN-001 riêng cho Lab B.
4. Một lượt baseline và một lượt SCN-001 được duyệt, rồi mới mở kịch bản khác.

Bảng ánh xạ trường mà kế hoạch Lab B yêu cầu nên theo tên trường canonical trong
[CANONICAL_EVENT_V2](CANONICAL_EVENT_V2.md). Trường nào không có thì ghi là thiếu.

### Lab C: OPNsense, Snort 3 và Wazuh

| Nguồn | Dùng ngay? | Việc cần làm |
| --- | --- | --- |
| Windows qua Wazuh agent | **Có**: các parser `wazuh-*` như lab A | Bật `logall_json` trên manager nếu cần Sysmon 3 từ `archives.json`. Bộ SCN-001 (kit, rule mẫu `detections/wazuh/scn-001/`) dùng lại được; đổi rule ID để không trùng rule đang có. |
| OPNsense filterlog | **Có**: `opnsense-filterlog-bsd-v1` (không dùng parser pfSense) | Gửi log từ xa dạng BSD, bộ thu ghi nguyên bản tin (`%rawmsg%`). Context như pfSense: `sensor_id`, `source_year`, `source_utc_offset`. Interface và chiều nằm trong provenance; NAT không được suy ra, xem [OPNSENSE_FILTERLOG_PARSER.md](OPNSENSE_FILTERLOG_PARSER.md). Profile kịch bản cho Lab C còn phải viết. |
| Snort 3 `alert_json` | **Có**: `snort3-alert-json-v1` đọc file gốc | Cấu hình logger đúng bản pin trong [SNORT3_ALERT_JSON_PARSER.md](SNORT3_ALERT_JSON_PARSER.md) và ghi vào bundle. Context: `sensor_id`, `deployment_mode` là `ids`. Thu file trên sensor, không thu bản đã qua Wazuh. Profile kịch bản cho Lab C còn phải viết. |
| Alert Wazuh sinh từ Snort hoặc OPNsense | **Chưa có parser** | Chỉ viết parser sau khi decoder và rule Wazuh đã được kiểm bằng mẫu thật. Thu được log thô và tạo alert đúng là hai cổng nghiệm thu khác nhau. |

Không chạy Snort cùng lúc với IDS (Suricata) tích hợp của OPNsense rồi cộng alert như
hai bằng chứng độc lập. Snort SID và Suricata SID không tự động tương đương.

### Đầu ra bàn giao ánh xạ vào AEGIS

Mỗi đầu ra trong kế hoạch lab nên kết thúc thành một bundle như mục 3:

- file nguồn gốc kèm SHA-256;
- `inputs.json` ghi đúng parser key;
- `context.json` có binding của lượt chạy.

Bằng chứng thô ở ngoài Git. Vào Git chỉ có: code connector, fixture đã sanitize,
profile mới, tài liệu và hash của bằng chứng.

## 5. Thêm connector, source type và profile

1. **SourceType mới** (`backend/app/models/_canonical_fields.py`): một issue và một PR
   nhỏ vào `main`, có test, được chủ dự án duyệt trước. Đây là thay đổi model lõi
   dùng chung cho mọi nhánh.
2. **Connector** trong `connectors/<nguồn>/`, theo mẫu của `connectors/suricata/` hay
   `connectors/cowrie/`:
   - sinh canonical event và giữ `raw_event_ref` ổn định;
   - trường không có thì để `null`;
   - không log credential hay nội dung nhạy cảm;
   - đăng ký parser key trong `backend/app/intake/registry.py`.
3. **Fixture** trong `tests/fixtures/<nguồn>/`, kèm README ghi nguồn gốc mẫu và cách
   sanitize. Test phủ cả trường hợp đúng và các trường hợp từ chối.
4. **Profile** cho lab mới là một file mới cạnh profile cũ, ví dụ
   `scenarios/profiles/scn-002/lab-c-snort.json`, kèm README. Không sửa
   `profile.json` của lab A, không sửa scenario YAML. Profile phải được review trước
   khi dùng cho verdict.
5. Tài liệu: một trang `docs/<NGUỒN>_PARSER.md` nói parser nhận gì và từ chối gì.

## 6. Đồng hồ và những bẫy đã gặp ở lab A

- Cửa sổ tương quan là **±2 s**. Mọi máy phải bám cùng một nguồn NTP nội bộ.
  - Kiểm firewall, SIEM và endpoint trước mỗi lượt.
  - `aegis collect scn002` in `source_minus_send_s` cho từng nguồn; xem số này trước
    khi đọc verdict.
- **Sysmon và đồng hồ:** sự kiện mạng của Sysmon (event 3) không theo kịp khi đồng hồ
  bị chỉnh nhảy sau lúc Sysmon khởi động, và còn trôi dần theo giờ.
  - Sysmon 15 là protected process nên `Restart-Service` không dừng được; khởi động
    lại cả máy.
  - Không suspend/resume VM endpoint giữa các lượt.
- **Agent SIEM có thể ngừng đẩy log mà không báo lỗi.** Trước mỗi lượt, kiểm SIEM có
  sự kiện mới từ sensor hay firewall. Dòng log ghi trong lúc agent hỏng sẽ không được
  gửi lại.
- **Python 3.13 kiểm chứng chỉ chặt.** CA thiếu Key Usage bị từ chối (verify code 92).
  Cấp lại CA cùng khoá, không nới kiểm tra
  ([#112](INDEXER_CA_ROTATION_ISSUE_112.md)).
- **Windows:** chạy bằng PowerShell thường, không "Run as administrator". Thư mục
  bằng chứng phải chỉ chủ sở hữu đọc được.

## 7. Đánh giá và phản hồi

Sau smoke test và một lượt đầu, mở một issue "Đánh giá Lab B" hoặc "Đánh giá Lab C",
gồm:

- môi trường: OS, phiên bản Python, Node và các thành phần lab;
- kết quả mục 1, kèm chỗ nào trong tài liệu sai hay thiếu;
- bảng nguồn dữ liệu thực tế của lab bạn so với mục 4;
- đề xuất issue cho từng connector hoặc profile cần viết.

## 8. Checklist trước khi push

- [ ] `pytest -q -rs` đạt trên máy bạn; frontend `npm test` nếu đụng tới dashboard.
- [ ] Không có IP, tên máy, user, credential, chứng chỉ hay bằng chứng thô trong diff.
      Fixture dùng RFC 5737.
- [ ] Không sửa scenario YAML hay profile có sẵn. Profile mới có README và chờ review.
- [ ] Thay đổi model, engine hoặc `SourceType` nằm trong PR riêng vào `main`.
- [ ] PR nêu issue liên quan, nói đã kiểm gì và chưa kiểm gì.
