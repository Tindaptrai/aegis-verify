# SCN-004 — Thử rò rỉ dữ liệu trên Lab C (Snort 3, OPNsense, Wazuh)

Manifest: [`scenarios/SCN-004-attempted-exfiltration-lab-c.yaml`](../scenarios/SCN-004-attempted-exfiltration-lab-c.yaml),
`expected_outcome: prevented`. Profile:
[`scenarios/profiles/scn-004/profile.json`](../scenarios/profiles/scn-004/profile.json).
Test offline: `backend/tests/test_scn004_profile.py`.

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
IDS): chưa có parser cho alert Wazuh 130110 sinh từ Snort. Bản ghi alert đó vẫn được
thu cùng lượt chạy để bổ sung sau.

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

- Chưa có assertion cho alert SIEM (Wazuh 130110); cần parser riêng.
- Một máy gửi, một sensor thụ động trên vùng người dùng.
- Đích là địa chỉ tài liệu (RFC 5737) nên lượt Block không gửi gì ra ngoài lab; kịch
  bản không chứng minh dữ liệu tới được đích khi firewall cho qua.
- Giờ OPNsense chỉ tới giây.

## 9. Kết quả lượt thật (2026-10-07)

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
