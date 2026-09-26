# SCN-003 evaluation profile

`profile.json` là `EvaluationProfile` cho `scenarios/SCN-003-internal-deception.yaml`
(issue #76, plan Task 3, review 2026-09-26). Mọi giá trị riêng của lab đi qua
bindings trong `context.json` của từng lượt, ngoài Git; `context.example.json`
chỉ minh hoạ tên binding bằng dải địa chỉ tài liệu RFC 5737 và một username
marker giả.

Bằng chứng lab thật đã chạy qua profile này ngày 2026-09-26, ra `Detected`;
hash và fingerprint ở [SCN003_RESULT_2026-09-26.md](../../../docs/SCN003_RESULT_2026-09-26.md).
Test engine dùng event tổng hợp; bundle CLI sanitized từ lượt thật ở
[`tests/fixtures/cli/scn003-lab-sanitized/`](../../../tests/fixtures/cli/scn003-lab-sanitized/README.md)
chứng minh đường `aegis validate` với đúng hình dạng nguồn.

## Hai telemetry root, hai miền NAT

| Assertion | Vai trò | Root/witness | Scope | Join |
| --- | --- | --- | --- | --- |
| A02 | telemetry, root phía firewall | pfSense filterlog `pass` TCP | `initiator_ip`, `initiator_port`, `firewall_dst_ip`, `firewall_dst_port`, `protocol = tcp`; `rule_id` = `firewall_rule_tracker` | |
| A01 | detection, **trước NAT** | Suricata alert SID `1000012` | `initiator_ip`, `decoy_ip`, `decoy_port`, `protocol = TCP` | neo A02: `src_ip`, `src_port` |
| A03 | telemetry, **sau NAT** | Cowrie **`session.connect`** | `initiator_ip`, `initiator_port`, `cowrie_ip`, `cowrie_port`, `protocol` = `honeypot_protocol`; `session_key` tồn tại | |
| A04 | detection | Wazuh alert rule `120003` từ `cowrie.login.failed` | `initiator_ip`, `protocol` = `honeypot_protocol`; `username` = `username_marker` | neo A03: `src_ip`, `protocol`, `session_key` |

**Vì sao A03 là `session.connect` chứ không phải login**: bản ghi
`cowrie.login.failed` thật chỉ có `src_ip`, `session`, `protocol`, `username`,
`timestamp`; không có cổng nguồn, IP và cổng đích. Chỉ `session.connect` có đủ
tuple để bind cổng nguồn. Login failed nối vào connect bằng `session_key`
(khoá mờ do connector Cowrie sinh, cùng `sensor_id` cho parser trực tiếp và
parser alert Wazuh).

**Cầu nối hai miền NAT không phải join.** Engine không join A02 với A03; thứ
buộc hai miền là hai binding `initiator_ip` và `initiator_port` cùng xuất
hiện trong scope của cả hai root. Hệ quả: verdict dựa vào receipt phía client
ghi đúng cổng nguồn, và pfSense **không** viết lại cổng nguồn. Nếu cổng bị
dịch, A03 không có root và kết quả là `Missing telemetry`, không phải
`Detected`. Không có NAT resolver.

**Đích mà filterlog ghi là một binding riêng** (`firewall_dst_ip`,
`firewall_dst_port`), vì pf dịch địa chỉ **trước** khi lọc: với port-forward,
dòng `pass` của filterlog mang đích sau NAT (IP Cowrie), còn Suricata cùng
interface thấy đích trước NAT (VIP decoy). Vì vậy A01 chỉ join A02 theo
`src_ip` và `src_port`; đích của mỗi nguồn được bind riêng theo đúng thứ nguồn
đó quan sát, không sao chép sang miền kia. Với port-forward: `firewall_dst_* =
cowrie_*`. Không có DNAT (kết nối thẳng tới Cowrie): `decoy_* = firewall_dst_* =
cowrie_*`; profile không đổi.

## Literal và cửa sổ

SID `1000012` và rule `120003` từ `detections/*/scn-003/` (Task 1).
`protocol` pin riêng từng parser: Suricata `TCP`, pfSense `tcp`, Cowrie qua
binding (`ssh` hoặc `telnet`). Cửa sổ tương quan là **±2 s**, siết từ ±5 s
sau khi đo trên ba lượt lab `Detected` (2026-09-26): A04 lệch A03 tối đa
0,006 s (cùng đồng hồ Cowrie); A01 lệch A02 tối đa ~0,6 s (cùng đồng hồ
pfSense; filterlog BSD syslog chỉ có độ phân giải giây). ±2 s giữ biên cho độ
phân giải giây đó, giống SCN-002. Không nới để lấy verdict.

## Kết quả kỳ vọng

Đủ bốn witness của cùng một run → `Detected`. Thiếu A02 hoặc A03 →
`Missing telemetry`. Thiếu A01 hoặc A04 khi chưa có declaration
`complete_for_scope` → `Inconclusive` với `collection_not_confirmed`; có
declaration hợp lệ → `False negative`. Sai SID, sai rule, sai username, khác
`session_key`, cổng nguồn bị viết lại, ngoài cửa sổ: không bao giờ `Detected`.

Test: `backend/tests/test_scn003_profile.py`, event tổng hợp dựng trong test.
