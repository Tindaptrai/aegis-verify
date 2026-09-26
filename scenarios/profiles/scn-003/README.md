# SCN-003 evaluation profile

`profile.json` là `EvaluationProfile` cho `scenarios/SCN-003-internal-deception.yaml`
(issue #76, plan Task 3, review 2026-09-26). Mọi giá trị riêng của lab đi qua
bindings trong `context.json` của từng lượt, ngoài Git; `context.example.json`
chỉ minh hoạ tên binding bằng dải địa chỉ tài liệu RFC 5737 và một username
marker giả.

## Hai telemetry root, hai miền NAT

| Assertion | Vai trò | Root/witness | Scope | Join |
| --- | --- | --- | --- | --- |
| A02 | telemetry, **trước NAT** | pfSense filterlog `pass` TCP | `initiator_ip`, `initiator_port`, `decoy_ip`, `decoy_port`, `protocol = tcp`; `rule_id` = `firewall_rule_tracker` | |
| A01 | detection | Suricata alert SID `1000012` | `initiator_ip`, `decoy_ip`, `decoy_port`, `protocol = TCP` | neo A02: 4 trường tuple |
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

Không có DNAT (kết nối thẳng tới Cowrie) thì `decoy_ip = cowrie_ip`,
`decoy_port = cowrie_port`; profile không đổi.

## Literal và cửa sổ

SID `1000012` và rule `120003` từ `detections/*/scn-003/` (Task 1).
`protocol` pin riêng từng parser: Suricata `TCP`, pfSense `tcp`, Cowrie qua
binding (`ssh` hoặc `telnet`). Cửa sổ ±5 s là hợp đồng tổng hợp theo spec,
**chưa** đo trên lab; siết bằng PR riêng sau lượt đối chứng, không nới.

## Kết quả kỳ vọng

Đủ bốn witness của cùng một run → `Detected`. Thiếu A02 hoặc A03 →
`Missing telemetry`. Thiếu A01 hoặc A04 khi chưa có declaration
`complete_for_scope` → `Inconclusive` với `collection_not_confirmed`; có
declaration hợp lệ → `False negative`. Sai SID, sai rule, sai username, khác
`session_key`, cổng nguồn bị viết lại, ngoài cửa sổ: không bao giờ `Detected`.

Test: `backend/tests/test_scn003_profile.py`, event tổng hợp dựng trong test.
