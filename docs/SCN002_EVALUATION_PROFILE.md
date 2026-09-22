# SCN-002 — EvaluationProfile công khai

Profile: [`scenarios/profiles/scn-002/profile.json`](../scenarios/profiles/scn-002/profile.json).
Ground truth: [`scenarios/SCN-002-attempted-exfiltration.yaml`](../scenarios/SCN-002-attempted-exfiltration.yaml),
`expected_outcome: prevented`. Test offline: `backend/tests/test_scn002_profile.py`.

## 1. Nguyên tắc

- Git giữ profile với literal đã review. Mọi giá trị riêng của lab đi qua
  **bindings** trong `context.json` của từng lượt và giữ ngoài Git.
  `context.example.json` chỉ dùng dải địa chỉ tài liệu RFC 5737.
- Không sửa manifest SCN-002. `scenario_fingerprint` trong profile là hash của
  file YAML hiện tại; đổi manifest thì profile phải được review và cập nhật, test
  sẽ báo lệch.
- Không nới cửa sổ tương quan hay literal để ép `Prevented`.

## 2. Bindings

| Tên | Trường áp dụng | Ý nghĩa |
| --- | --- | --- |
| `sender_ip` | `src_ip` | Máy gửi probe |
| `receiver_ip` | `dst_ip` | Máy nhận, tuple trước NAT |
| `receiver_port` | `dst_port` | Cổng UDP của receiver |
| `block_rule_tracker` | `rule_id` của A03 | Tracker của rule chặn pfSense ở lượt Block |

`src_port` không bind vì mỗi lần gửi là một cổng nguồn mới; nó được join giữa
các nguồn để chứng minh cùng một datagram.

## 3. Bốn rule

| Assertion | Vai trò | Nguồn | Literal cố định | Tương quan |
| --- | --- | --- | --- | --- |
| A01 | telemetry | wazuh (Sysmon Event 3) | `event_provider = Microsoft-Windows-Sysmon`, `protocol = udp`, `event_action = observed`, `src_port` tồn tại | neo |
| A02 | detection | suricata | `signature_id = 1000010`, `protocol = UDP` | join 4 trường với A01 |
| A03 | prevention | pfsense | `event_provider = pfSense-filterlog`, `protocol = udp`, `event_action = blocked`, `rule_id = binding` | join 4 trường với A01 |
| A04 | detection | wazuh | `rule_id = 86601` **và** `signature_id = 1000010` | join 4 trường với A01 |

Join bốn trường: `src_ip`, `dst_ip`, `src_port`, `dst_port`. Cửa sổ ±5 s quanh
neo theo spec thiết kế; sẽ siết lại sau khi đo lệch giờ thật trên lượt đối chứng
(bước 0c của kế hoạch), không nới rộng thêm.

A04 pin cả hai literal vì 86601 một mình khớp mọi alert Suricata mà Wazuh nhận.
Nghĩa của A04 là "Wazuh ghi nhận detection sinh từ alert Suricata marker của
cùng flow"; mô tả trong manifest đã được chủ dự án duyệt sửa ngày 2026-09-21
theo đúng thứ chứng minh được: Wazuh rule 86601 nhận và phân loại alert
Suricata, không tương quan nhiều nguồn. Parser cho bản ghi này là issue #61.

## 4. Vì sao không join theo `protocol`

Engine so khớp join và predicate bằng đẳng thức chuỗi chính xác. Parser Suricata
giữ nguyên `proto` của EVE là `UDP`; parser pfSense và Sysmon 3 cho `udp`. Join
theo `protocol` sẽ luôn sai giữa A02 và A01. Profile vì vậy pin `protocol` trong
scope của từng rule đúng chữ hoa/thường của parser đó, và join bốn trường còn
lại. Chuẩn hoá protocol ở tầng parser là việc riêng, cần issue và review, không
đổi trong profile này. Test `test_protocol_literals_are_case_exact_per_source`
ghi lại giới hạn đó.

## 5. Kết quả kỳ vọng theo lượt

| Lượt | Bằng chứng | A03 | `final_status` |
| --- | --- | --- | --- |
| Đối chứng | pfSense `allowed`; A01, A02, A04 đủ | inconclusive, `prevention_not_demonstrated` | `Inconclusive` |
| Block, đủ bốn nguồn | pfSense `blocked` với tracker | satisfied | `Prevented` |
| Block, thiếu một nguồn, chưa khai `complete_for_scope` | | tuỳ nguồn thiếu | `Inconclusive` |

Lượt đối chứng ra `Inconclusive` là kết quả đúng của ground truth `prevented`;
nó chứng minh telemetry và detection hoạt động khi lưu lượng được phép, không
phải lỗi profile. `False negative` chỉ xuất hiện khi có declaration
`complete_for_scope` hợp lệ cho assertion đó.

## 6. Giới hạn

- Chưa có bằng chứng lab nào chạy qua profile này. Test engine dùng event tổng
  hợp dựng trong test; bundle CLI tổng hợp bốn nguồn ở
  `tests/fixtures/cli/scn002-synthetic-prevented/` chứng minh đường
  `aegis validate` ra `Prevented`, và README của nó nói rõ đây không phải bằng
  chứng lab.
- Sysmon 3 ghi `dst_ip` theo góc nhìn máy gửi; pfSense LAN và Suricata LAN thấy
  tuple trước NAT. Nếu tuple khác nhau, profile dừng ở `Inconclusive`, không có
  NAT resolver.
