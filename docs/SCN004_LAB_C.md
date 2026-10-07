# SCN-004 — Thử rò rỉ dữ liệu trên Lab C (Snort 3, OPNsense, Wazuh)

Manifest: [`scenarios/SCN-004-attempted-exfiltration-lab-c.yaml`](../scenarios/SCN-004-attempted-exfiltration-lab-c.yaml),
`expected_outcome: prevented`. Profile:
[`scenarios/profiles/scn-004/profile.json`](../scenarios/profiles/scn-004/profile.json).
Test offline: `backend/tests/test_scn004_profile.py`.

Chạy lại một đợt: [LABC_RUNBOOK.md](LABC_RUNBOOK.md). Kết quả đợt nghiệm thu và hồ sơ
truy xuất bằng chứng: [SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md).

## 1. Vì sao cần kịch bản riêng

SCN-004 giữ ý đồ của SCN-002: máy gửi thử đẩy dữ liệu ra một đích kiểm soát được,
và AEGIS phải chứng minh cùng một luồng được ghi ở endpoint, được IDS phát hiện và bị
firewall chặn. Lab C không có Suricata hay pfSense mà có Snort 3 và OPNsense.

Không dùng lại SCN-002 được. Mỗi assertion của manifest ghi nguồn của nó (A02 là
`suricata`, A03 là `pfsense`). Engine chỉ cho rule của profile gắn với đúng nguồn
assertion đã ghi, nên một profile Lab C không thể trỏ A02 sang `snort` hay A03 sang
`opnsense`. Test `test_scn002_profile_cannot_be_rebound_to_lab_c_sources` ghi lại điều
này. Sửa SCN-002 thì đổi ground truth của lab A, nên Lab C có manifest riêng.

SCN-004 chưa có assertion tương ứng A04 của SCN-002 (Wazuh ghi alert sinh từ alert
IDS). Parser cho alert Wazuh 130110 sinh từ Snort đã có
(`wazuh-snort-alert-v1`, [tài liệu](WAZUH_SNORT_ALERT.md)) nhưng **chưa assertion nào
dùng**: thêm assertion là đổi ground truth, phải được chủ dự án duyệt trước. Bản ghi
alert đó vẫn được thu cùng mỗi lượt chạy để bổ sung sau.

## 2. Assertion, nguồn và parser

| Assertion | Vai trò | Nguồn | Parser |
| --- | --- | --- | --- |
| A01 | telemetry | Sysmon Event 3 trong `archives.json` của Wazuh manager | `wazuh-sysmon3-archive-v1` |
| A02 | detection | `alert_json` của Snort 3 trên sensor | `snort3-alert-json-v1` |
| A03 | prevention | `filterlog` của OPNsense qua syslog BSD | `opnsense-filterlog-bsd-v1` |

## 3. Bindings

| Tên | Trường | Ý nghĩa |
| --- | --- | --- |
| `sender_ip` | `src_ip` | máy gửi probe |
| `receiver_ip` | `dst_ip` | đích probe |
| `receiver_port` | `dst_port` | cổng UDP đích |
| `block_rule_label` | `rule_id` của A03 | nhãn (UUID) của rule OPNsense phải chặn luồng |

`src_port` không bind vì mỗi lần gửi là một cổng nguồn mới; nó được join giữa các
nguồn để chứng minh cùng một datagram. Giá trị thật của từng lượt nằm trong
`context.json` ngoài Git.

## 4. Ba rule

| Assertion | Literal cố định | Tương quan |
| --- | --- | --- |
| A01 | `event_provider = Microsoft-Windows-Sysmon`, `protocol = udp`, `event_action = observed`, `src_port` tồn tại | neo |
| A02 | `event_provider = snort`, `protocol = UDP`, `signature_id = 1000010` | join 4 trường với A01 |
| A03 | `event_provider = OPNsense-filterlog`, `protocol = udp`, `event_action = blocked`, `rule_id = block_rule_label` | join 4 trường với A01 |

Join bốn trường `src_ip`, `dst_ip`, `src_port`, `dst_port`, cửa sổ **±2 s** quanh neo,
giống SCN-002. Engine so khớp chuỗi chính xác: Snort in `UDP` chữ hoa, OPNsense và
Sysmon cho `udp`, nên profile pin chữ hoa/thường theo từng parser và không join theo
`protocol`.

Syslog BSD của OPNsense chỉ ghi tới giây, nên giờ firewall của một gói có thể sớm hơn
giờ Sysmon tới gần 1 s. Khi đồng hồ các máy lệch dưới 1 s, độ lệch vẫn nằm trong ±2 s.
Không nới cửa sổ để ép khớp.

## 5. Chuẩn bị Lab C

| Thành phần | Cấu hình |
| --- | --- |
| Sysmon trên máy gửi | Rule `NetworkConnect` tên `AEGIS-UDP-probe`: protocol `udp` và cổng đích 40000; vẫn ghi Event 1 cho mọi tiến trình. Đổi cấu hình xong thì **khởi động lại máy gửi** (sự kiện mạng của Sysmon không theo kịp đồng hồ bị chỉnh sau khi Sysmon chạy). |
| Snort 3 | Rule [`detections/snort/scn-004/marker.rules`](../detections/snort/scn-004/marker.rules), sid 1000010, chỉ khớp chuỗi `AEGIS-SCN004-TEST` trong 64 byte đầu. Rule Wazuh 130110 của Lab C đã bắt sid này. |
| OPNsense | Rule chặn mặc định của vùng người dùng, có bật log. UUID của rule là `block_rule_label`; lấy từ cấu hình đã biết **trước** lượt chạy, không lấy từ dòng log của chính probe. |
| Wazuh manager | `logall_json` bật để có Sysmon 3 trong `archives.json`. |

Cấu hình Sysmon tối thiểu:

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Rule name="AEGIS-UDP-probe" groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">40000</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## 6. Một lượt Block

1. Kiểm trước khi gửi: đồng hồ máy gửi lệch dưới 1 s so với nguồn NTP của lab, Sysmon
   có rule `AEGIS-UDP-probe`, agent Wazuh đang chạy.
2. Gửi **đúng một** datagram UDP từ máy gửi tới `receiver_ip:receiver_port`, payload
   `AEGIS-SCN004-TEST run=<32 hex> label=block`. Ghi biên nhận: run, cổng nguồn, giờ
   UTC trước và sau khi gửi.
3. Thu bằng chứng, chỉ đọc. Mỗi bản ghi được tách đúng bytes, kèm số dòng và SHA-256
   của file gốc lúc thu:
   - dòng `alert_json` sid 1000010 trên sensor;
   - dòng `filterlog` có đúng tuple;
   - bản ghi Sysmon 3 trong `archives.json`;
   - alert Wazuh 130110 của cùng luồng (để dành cho A04 sau này).
4. Đóng gói ngoài Git: `inputs.json` gồm ba file và parser key, `context.json` gồm
   `run_id`, cửa sổ từ 1 phút trước tới 2 phút sau phút gửi, và bốn binding.
5. Chạy:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-004-attempted-exfiltration-lab-c.yaml --fixture <bundle> --profile scenarios\profiles\scn-004\profile.json --format json
```

## 7. Kết quả kỳ vọng

| Bằng chứng | Kết quả |
| --- | --- |
| Đủ ba nguồn, cùng tuple, trong cửa sổ, firewall `block` đúng nhãn | `Prevented`, exit 0 |
| Firewall cho qua | `Inconclusive`, A03 `prevention_not_demonstrated` |
| Thiếu alert Snort, chưa khai `complete_for_scope` | `Inconclusive`, A02 `collection_not_confirmed` |
| Bị chặn bởi rule khác nhãn | `Inconclusive`, A03 `prevention_not_demonstrated` |

## 8. Giới hạn

Phạm vi đã kiểm, không suy rộng ra ngoài:

- **Phiên bản đã kiểm**: đúng những phiên bản ở mục 10. Phiên bản khác của Snort,
  OPNsense, Wazuh hay Sysmon chưa được kiểm với kịch bản này.
- **Định dạng log đã pin**: `alert_json` của Snort theo danh sách trường trong
  [SNORT3_ALERT_JSON_PARSER.md](SNORT3_ALERT_JSON_PARSER.md) (`show_year`, `process.utc`
  bật), `filterlog` của OPNsense ở dạng syslog BSD nguyên bản, Sysmon 3 trong
  `archives.json`. Đổi định dạng logger thì parser từ chối, không tự đoán.
- **Một probe mỗi lượt**: mỗi lượt gửi đúng một datagram UDP và một `run_id`. Kịch bản
  không nói gì về nhiều luồng song song, phiên nhiều gói, hay tải cao.
- **Chưa kiểm**: NAT (đích là địa chỉ tài liệu, không dịch địa chỉ), IPv6 (parser
  OPNsense đọc được IPv6 nhưng chưa có lượt live IPv6), chế độ IPS/inline của Snort
  (sensor chạy thụ động nên `event_action` của Snort luôn là `allow`), nhiều máy gửi,
  nhiều sensor.
- **Đường SIEM chưa hỗ trợ**: alert Wazuh sinh từ Snort có parser nhưng chưa assertion
  nào dùng; alert Wazuh sinh từ log OPNsense thì chưa có parser. Bằng chứng chặn lấy từ
  log OPNsense trực tiếp.
- **Giờ**: OPNsense chỉ ghi tới giây, nên độ lệch so với giờ gửi quan sát được trong
  khoảng −0,6…+0,7 s; cửa sổ tương quan ±2 s là số đo, không nới để ép khớp.
- Đích là địa chỉ tài liệu (RFC 5737) nên lượt Block không gửi gì ra ngoài lab; kịch
  bản không chứng minh dữ liệu tới được đích khi firewall cho qua. Lượt "cho qua" dùng
  một máy nhận trong lab để xác nhận đường truyền.

## 9. Hai lượt thật đầu tiên (2026-10-07 sáng)

Hai lượt này là nguồn của bundle đã sanitize trong repo. Cả đợt nghiệm thu 16 lượt ở
mục 11.

| Run | Gửi lúc (UTC) | Cổng nguồn | Sysmon 3 | Snort sid 1000010 | OPNsense | `final_status` |
| --- | --- | --- | --- | --- | --- | --- |
| `8541573e` | 09:08:45.427 | 65382 | 09:08:45.831 | 09:08:44.864 | 09:08:45 `block`, rule `f18da9d8…` | **`Prevented`**, exit 0 |
| `509edcce` | 08:53:31.118 | 63784 | 08:53:31.373 | không có | 08:53:31 `block`, cùng rule | **`Inconclusive`**, exit 3 |

Lượt `8541573e`: cả ba assertion `satisfied`, witness của A02 và A03 cùng neo vào bản
ghi Sysmon. So với giờ gửi theo đồng hồ máy gửi: Sysmon +0,404 s, Snort −0,563 s,
OPNsense −0,427 s (giờ chặn tới giây). Trước khi gửi, đồng hồ máy gửi lệch −0,59 s so
với firewall (w32tm); sensor lệch dưới 1 ms. Mọi nguồn nằm trong ±2 s quanh neo. Cùng
lượt, Wazuh sinh alert 130110 từ alert Snort; bản ghi được giữ cho assertion SIEM sau
này, chưa nằm trong bundle.

Lượt `509edcce`: Snort đã ngừng bắt gói từ trước đó, nên không có alert. A01 và A03
`satisfied`, A02 `inconclusive` với `collection_not_confirmed`. Engine không kết luận
`Prevented` khi thiếu bằng chứng phát hiện, đúng như mục 7.

Hash của file nguồn lúc thu, số dòng và bundle đã sanitize:
[`tests/fixtures/cli/scn004-lab-c-sanitized/`](../tests/fixtures/cli/scn004-lab-c-sanitized/README.md),
test `backend/tests/test_scn004_lab_sanitized.py`.

### Sự cố hạ tầng trong ngày

| Hiện tượng | Nguyên nhân | Cách xử lý |
| --- | --- | --- |
| Agent Wazuh của sensor và máy gửi `Disconnected` từ 2026-10-06 11:36 UTC; từ máy khác vẫn ping và SSH được máy Wazuh nhưng không vào được cổng 1514/1515 | Mạng Docker trên máy Wazuh hỏng sau khi VM bị tạm dừng rồi chạy lại: ngay trên máy Wazuh cũng không vào được container | Khởi động lại dịch vụ `docker` |
| Snort không ghi alert cho probe | Sau khi VM tạm dừng, DAQ `afpacket` báo lỗi socket; Snort thoát sạch nên `Restart=on-failure` không chạy lại | Khởi động lại `snort3-labc` |

Từ đó: tắt VM bằng "Shut Down Guest", không suspend. Trước mỗi lượt kiểm agent Wazuh
đang `connected` và Snort đang nhận gói trên card bắt gói.

## 10. Cấu hình đã chốt cho đợt nghiệm thu (2026-10-07)

Mọi lượt trong mục 11 chạy trên đúng cấu hình này. Địa chỉ, tên máy và tài khoản của
lab không đưa vào repo; các thành phần được gọi theo vai trò.

| Thành phần | Phiên bản đã kiểm | Ghi chú |
| --- | --- | --- |
| AEGIS Verify | 0.3.0 | chuỗi PR Lab C: source type `snort`, parser Snort, parser OPNsense, SCN-004 |
| Firewall | OPNsense 26.7 (FreeBSD 15.1) | `filterlog` bật log trên rule chặn của vùng người dùng; gửi syslog BSD qua UDP tới sensor |
| IDS | Snort 3.12.2.0, DAQ 3.0.27, libpcap 1.10.1 | `--daq afpacket`, thụ động trên card nhận mirror vùng người dùng, `-A alert_json` |
| Máy thu log | rsyslog 8.2112.0 | ghi `%rawmsg%` vào `filterlog-raw.log`; logrotate hằng ngày, `delaycompress`, giữ 14 bản |
| SIEM | Wazuh manager và agent 4.14.4 (rc2) | single-node trên Docker 29.8.2, `logall_json: yes` để có Sysmon 3 trong `archives.json` |
| Endpoint | Sysmon 15.22 trên Windows 10 Pro 10.0.19045 | cấu hình schema 4.50, rule `NetworkConnect` tên `AEGIS-UDP-probe` |
| Sensor, SIEM, máy nhận | Ubuntu 22.04.5 LTS | kernel 5.15.0 |
| Đồng hồ | NTP của firewall là nguồn duy nhất | sensor, SIEM, máy nhận dùng `systemd-timesyncd`; Windows dùng `w32time` |

Hash cấu hình lúc nghiệm thu (để đối chiếu, không phải bí mật):

| File | SHA-256 |
| --- | --- |
| `snort.lua` | `663119c12ef40cc22eb83f0742f082b406c03dfc92c12cf71382b90a4b6f3d12` |
| `labc.lua` (tweaks) | `82274d4285b29a5983eba1199b18800a8026b99d5c3addc37291bbd2f31a053b` |
| `labc.rules` trước khi sửa rule (sid 1000010 rev 1, `depth 64`) | `0a6d95a3e94c3bbb399e5bdad015fc217869169e5ef4c9958946028fdd9bfb33` |
| `labc.rules` sau khi sửa rule (sid 1000010 rev 2, bỏ `depth`) | `0350e7e0d1ff07103307b08ef144e07970148c8b538636315d598a1c063a54b1` |
| cấu hình rsyslog thu filterlog | `7123d5db9af5654b…` (16 ký tự đầu) |
| cấu hình Sysmon | `a1b4788ec796491ece4a810a585eda4610341541aeadf3a8ec569130fcfd051b` |
| rule Wazuh 130110 (`labc_snort_rules.xml`) | `d452ff6a5627fa7e…` (16 ký tự đầu) |

Đường đi của log:

```
Windows (máy gửi)            sensor (Linux)                         Wazuh (Docker)
  probe: 1 datagram UDP
  Sysmon 15.22 ── agent ──────────────────────────────────────────▶ archives.json ──▶ bundle: A01
       │
       └─ gói đi qua firewall
                  │
  OPNsense filterlog ── syslog BSD/UDP ──▶ rsyslog ──▶ filterlog-raw.log ──────────▶ bundle: A03
                  │
                  └─ mirror vùng người dùng ──▶ Snort ──▶ alert_json.txt ──────────▶ bundle: A02
                                                    │
                                                    └─ agent ──▶ alerts.json (rule 130110)
                                                                  (thu nhưng chưa vào bundle)
```

Kịch bản, profile và fingerprint dùng cho cả đợt:

| Hạng mục | Giá trị |
| --- | --- |
| Scenario | `SCN-004`, version `0.1.0`, fingerprint `778619bc836fc26938ff75749f0ec01aeabd0735276c5f9dadd9c07758932d47` |
| Profile | `scn004-udp-marker-prevention`, version `0.1.0`, fingerprint `f2e83d10…` (đầy đủ trong mỗi report) |
| Engine semantics | `0.1.0` |
| Bundle schema | `0.1.0` |
| Assertion | A01 telemetry, A02 detection, A03 prevention; **không** có A04 |
| Cửa sổ tương quan | ±2 s, join theo bộ 4 trường (IP và cổng nguồn/đích) |
| Cửa sổ bundle | từ 1 phút trước tới 2 phút sau phút gửi |

`scope_fingerprint` và `context_fingerprint` khác nhau giữa các lượt (mỗi lượt có cửa
sổ và binding riêng); ba fingerprint ở trên giống nhau ở mọi lượt, nên mọi kết quả
trong mục 11 so sánh được với nhau.

## 11. Đợt nghiệm thu: 16 lượt live (2026-10-07, 16:03–17:58 UTC)

Số lượt và các tình huống được chốt **trước** khi đo. Mỗi lượt có `run_id` riêng, biên
nhận của probe, bundle riêng, report và exit code; không lượt nào dùng lại log của lượt
khác và không lượt nào nới cửa sổ tương quan.

| Tình huống | Lượt | Kết quả kỳ vọng | Thực tế |
| --- | --- | --- | --- |
| Đủ ba nguồn, firewall chặn | 5 | `Prevented`, exit 0 | 5/5 đúng |
| Firewall cho qua (máy nhận trong lab) | 2 | `Inconclusive`, exit 3, A03 `prevention_not_demonstrated` | 2/2 đúng, máy nhận ghi nhận gói |
| Snort ngừng thu | 2 | `Inconclusive`, exit 3, A02 `collection_not_confirmed` | 2/2 đúng |
| Đường log Snort → Wazuh gián đoạn | 2 | `Prevented`, exit 0 | 2/2 đúng; có alert Snort tại nguồn, **không** có alert Wazuh |
| Khôi phục dịch vụ rồi chạy lượt mới | 2 | `Prevented`, exit 0 | 2/2 đúng, alert Wazuh có lại |
| Rule hụt (chuỗi đánh dấu ngoài `depth 64`) | 1 | `False negative`, exit 1 | đúng, A02 `expected_detection_absent` |
| Sau khi sửa rule | 2 | `Prevented`, exit 0 | 2/2 đúng, A02 `satisfied` |

**16/16 lượt đúng kết quả kỳ vọng.** Một lượt bị loại trước đó vì lỗi quy trình (thu
bằng chứng trước khi gửi probe) và được ghi lại là không hợp lệ, không tính vào 16 lượt.
Bảng từng lượt, evidence ID và hồ sơ truy xuất nguồn gốc nằm ở
[SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md).

Chạy lặp và phục hồi: 11 lượt ở phiên 1, sau đó khởi động lại máy ảo sensor và Wazuh
bằng "Restart Guest" rồi chạy 2 lượt nữa ở phiên 2 — Snort bắt gói lại, hai agent
`Active`, đồng hồ sensor lệch 0,0003 s so với firewall. Trong đợt còn hai lần dừng và
chạy lại Snort và hai lần dừng và chạy lại agent Wazuh trên sensor, mỗi lần đều có lượt
khôi phục đạt lại kết quả kỳ vọng.

Độ lệch so với giờ gửi, trên cả đợt: Sysmon −0,007…+0,010 s; Snort +0,022…+0,036 s;
OPNsense −0,6…+0,7 s (chỉ tới giây). Đồng hồ máy gửi so với firewall +0,011…+0,012 s;
lệch đồng hồ sự kiện mạng của Sysmon −0,009…+0,038 s. Alert Wazuh 130110 đến sau alert
Snort +0,53…+1,86 s (9 lượt có alert).

### Kiểm chứng rule hụt và `aegis compare`

Ca kiểm thử an toàn: cùng một probe nhưng payload có 80 byte đệm trước chuỗi đánh dấu,
nên chuỗi nằm ngoài 64 byte đầu mà rule sid 1000010 rev 1 tìm. Telemetry Sysmon vẫn có
và OPNsense vẫn chặn, chỉ thiếu alert IDS — một phát hiện hụt thật, không phải dàn dựng.

Lượt trước khi sửa rule được validate hai lần: lần đầu không kèm khai báo thu thập, A02
ra `inconclusive/collection_not_confirmed`; sau khi đối chiếu 11 điều kiện thu thập bằng
số liệu của chính lượt đó (Snort chạy liên tục từ trước cửa sổ, không có dòng nào không
đọc được, không drop gói, lúc thu bao trùm hết cửa sổ, các đồng hồ lệch dưới 0,5 s) mới
kèm khai báo `complete_for_scope` cho A02, và A02 thành `false_negative`. Cả hai report
được giữ.

Sau khi sửa rule (bỏ `depth`, lên `rev:2`, lưu cấu hình trước và sau kèm SHA-256), lượt
mới cho A02 `satisfied`. `aegis compare` giữa hai lượt — cùng scenario, cùng profile,
cùng binding, cùng độ dài cửa sổ — cho **`Regression Passed`**: A02 `improvement`
(`false_negative` → `satisfied`), A01 và A03 `unchanged_pass`, không có assertion nào ở
trạng thái unknown.

## 12. Kiểm thử đã chạy

| Môi trường | Kết quả | Bỏ qua |
| --- | --- | --- |
| Windows (máy chạy lab, venv của repo) | 3614 passed | 3: `test_intake_io` (FIFO không có trên nền tảng này), `test_operations_config` và `test_private_fs` (kiểm quyền kiểu POSIX) |
| Linux (container của người phát triển) | 3526 passed, 1 failed | 90: 47 `test_scn001_runner` (cần Windows PowerShell 5.1), 37 `test_dashboard_launcher` (launcher Windows), 6 kiểm ACL Windows |
| Frontend (`npm test`) | 6 file, 108 passed | — |

Lượt Linux có một test thất bại: `test_cli_validate.py::test_console_and_module_entry_points_are_equivalent`
cần console script của bản cài editable, container đó không có. Trên Windows test này
pass. Không liên quan tới thay đổi của Lab C.
