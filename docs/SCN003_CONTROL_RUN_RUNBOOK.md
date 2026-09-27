# SCN-003 — Runbook một lượt đối chứng

Áp dụng cho một lượt `Detected` của SCN-003: một kết nối telnet tới decoy, một lần
đăng nhập thất bại vào Cowrie. Tài liệu này không chứa giá trị lab: IP, cổng,
tracker, tên máy nằm trong hồ sơ evidence riêng ngoài Git. Chỗ `<...>` là chỗ điền
từ hồ sơ đó. Mọi thay đổi trạng thái lab (rule, NTP, route) nằm **ngoài** runbook
này và cần duyệt riêng; runbook chỉ chạy probe và đọc.

Đã chạy theo quy trình này: lượt 2, 3, 4 ngày 2026-09-26 và lượt 5, 6 ngày
2026-09-27, đều `Detected` ([kết quả](SCN003_RESULT_2026-09-26.md)).

## 0. Kiểm trước khi chạy, chỉ đọc

| Điều kiện | Cách kiểm | Nếu không đạt |
| --- | --- | --- |
| Đồng hồ pfSense bám nguồn NTP nội bộ | pfSense: `ntpq -p` có `*` trước peer, `offset` vài ms | đối chiếu `ntpdate -q <NTP nội bộ>` (ntpq có thể hiện số cũ); lệch thật > 1 s thì khởi động lại ntpd bằng đúng config pfSense sinh (không có `service ntpd`) |
| NTP nội bộ đồng bộ với nguồn ngoài | manager: `chronyc tracking` có `Leap status : Normal` | kiểm internet của lab trước (mục 5) |
| Cowrie chạy, cổng honeypot LISTEN | máy Cowrie: `cowrie status`, `ss -ltnp` | khởi động lại Cowrie |
| Agent Wazuh của máy Cowrie Active | manager: `agent_control -lc` | bật lại agent, chờ Active |
| Không còn state cũ tới cổng honeypot | pfSense: `pfctl -ss \| grep <cổng Cowrie>` | chờ 60 s rồi kiểm lại |
| Rule Suricata SID 1000012 và Wazuh 120003 đang nạp | như [nội dung detection](SCN003_DETECTION_CONTENT.md) | cài theo tài liệu đó, có duyệt |

## 1. Probe, một lần

Trên máy khởi tạo:

```bash
python3 scn003_probe.py --destination <decoy VIP> --port <cổng decoy> --label control
```

Output mẫu:

```text
connected <IP khởi tạo>:<cổng nguồn> -> <decoy VIP>:<cổng decoy>  run=<32 hex>  user=AEGIS-SCN003-<8 hex>  label=control
```

Ghi lại **cổng nguồn**, **user** (marker) và **run**. Chờ 30 s rồi mới thu bằng
chứng. Một lượt ứng với một probe; không tự chạy lại.

## 2. Thu bằng chứng, chỉ đọc

Cách nhanh: `aegis collect scn003` làm toàn bộ mục 2 và 3, kèm kiểm trước khi chạy
([hướng dẫn](SCN003_COLLECT.md)). Các lệnh tay dưới đây dùng khi log đã xoay vòng hoặc
lệnh báo lỗi.

**Gán biến một lần ở mỗi máy**, rồi dùng biến. Không thay tay trong từng lệnh:
lỗi dán nguyên placeholder đã làm một lượt thu rỗng.

pfSense (tcsh, dùng `set`; tcsh không hiểu `2>/dev/null`, dùng `|&`):

```sh
set P=<cổng nguồn>
grep '<tracker>' /var/log/filter.log | grep ",<IP khởi tạo>,<IP Cowrie>,$P,<cổng Cowrie>," | head -1 > /root/scn003-filterlog.log; wc -l /root/scn003-filterlog.log; sha256 /root/scn003-filterlog.log
grep '1000012' <đường dẫn eve.json của instance WAN> | grep "\"src_port\":$P," > /root/scn003-eve-alert.json; wc -l /root/scn003-eve-alert.json; sha256 /root/scn003-eve-alert.json
```

Dòng `pass` của filterlog mang **đích sau NAT** (Cowrie), còn Suricata trên cùng
interface thấy **đích trước NAT** (decoy): pf dịch địa chỉ trước khi lọc. Đường
dẫn `eve.json` có thể đổi tên theo phiên bản gói Suricata; tìm bằng
`find / -name eve.json |& grep -v denied`, chọn instance có tên interface WAN.

Máy Cowrie (bash):

```bash
P=<cổng nguồn>
S=$(grep "\"src_port\":$P," <cowrie.json> | grep -o '"session":"[^"]*"' | head -1 | cut -d'"' -f4); echo "session=$S"
grep "\"session\":\"$S\"" <cowrie.json> | grep -E 'session\.connect|login\.failed' > scn003-cowrie.jsonl; wc -l scn003-cowrie.jsonl; sha256sum scn003-cowrie.jsonl
```

Manager (bash):

```bash
M=AEGIS-SCN003-<8 hex>
grep "$M" /var/ossec/logs/alerts/alerts.json | grep '"id":"120003"' > scn003-wazuh-alert.json; wc -l scn003-wazuh-alert.json; sha256sum scn003-wazuh-alert.json
```

Kỳ vọng: filterlog 1 dòng, eve 1 dòng, Cowrie 2 dòng (`session.connect` và
`login.failed`), Wazuh 1 dòng. Alert Wazuh chứa mật khẩu người gõ; parser
`wazuh-cowrie-alert-v1` không đọc trường đó, nhưng file vẫn chỉ nằm trong hồ sơ riêng.

## 3. Chép về máy đánh giá

**Chỉ chép sau khi mọi `wc -l` đúng.** Chép trước rồi sửa lệnh thu sẽ để lại file
rỗng ở máy đánh giá. Đối chiếu SHA-256 sau khi chép với số đo ở nguồn. Nếu máy đánh
giá không có route tới vùng mạng của Cowrie hoặc của máy khởi tạo, chép vòng qua
một máy có route (ví dụ manager). Receipt của máy khởi tạo không vào engine, có thể
chép bằng cách in nội dung.

## 4. Ráp bundle và đánh giá

Bundle gồm bốn file trên cùng `inputs.json` và `context.json` với các binding của
[profile](../scenarios/profiles/scn-003/README.md): `initiator_ip`,
`initiator_port`, `decoy_ip`, `decoy_port`, `firewall_dst_ip`, `firewall_dst_port`,
`cowrie_ip`, `cowrie_port`, `honeypot_protocol`, `firewall_rule_tracker`,
`username_marker`. Mẫu hình dạng: `tests/fixtures/cli/scn003-lab-sanitized/`.

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-003-internal-deception.yaml --fixture <bundle> --profile scenarios\profiles\scn-003\profile.json --format json
```

Kỳ vọng `Detected`, exit 0. Cửa sổ tương quan là ±2 s (#90).

| Kết quả | Xem trước tiên |
| --- | --- |
| A01, A02 `missing_telemetry` | đồng hồ pfSense (mục 0), tracker, file filterlog hoặc eve rỗng |
| A03 `missing_telemetry` | cổng nguồn phía Cowrie khác receipt (NAT viết lại cổng?) |
| A04 `inconclusive` | marker sai, rule 120003 không nạp, alert lệch quá ±2 s |
| exit khác 0, không có report | hash lệch, file rỗng, parser từ chối |

Không nới cửa sổ, không sửa profile hay ground truth để lấy verdict.

## 5. Khi lab mất internet

Nếu NTP nội bộ không đồng bộ được vì lab mất internet, kiểm tầng host ảo hoá trước
khi sửa firewall: ngày 2026-09-26, nguyên nhân là host có nhiều route mặc định cùng
metric, trong đó hai route trỏ vào chính firewall lab. Xem
[kết quả SCN-003](SCN003_RESULT_2026-09-26.md), mục phát hiện.
