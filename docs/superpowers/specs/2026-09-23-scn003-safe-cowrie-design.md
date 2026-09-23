# SCN-003 — thiết kế kiểm chứng một phiên deception an toàn

Issue: #76. Chủ dự án đã duyệt hướng một kết nối Cowrie ngày 2026-09-23.
Tài liệu này cụ thể hóa hướng đó để review. Nó chưa cho phép tạo lưu lượng lab,
đổi ground truth, cài rule hoặc sửa cấu hình mạng.

## 1. Mục tiêu

SCN-003 chứng minh AEGIS có thể nối bốn nguồn bằng chứng của cùng một phiên
deception nội bộ đã được phê duyệt:

1. Suricata ghi nhận hoặc cảnh báo kết nối tới địa chỉ mồi.
2. pfSense ghi nhận hành động firewall/NAT dự kiến.
3. Cowrie ghi nhận đúng phiên và một lần đăng nhập thử bằng dữ liệu lab giả.
4. Wazuh sinh detection đã review từ telemetry Cowrie của phiên đó.

Kết quả mục tiêu giữ nguyên manifest hiện có: `Detected`. Lượt đầu chỉ tạo một
kết nối và một login attempt. Không scan, không brute force, không chạy command,
không tải file và không dùng credential thật.

## 2. Các hướng đã cân nhắc

### A. Một phiên Cowrie qua DNAT, nguồn và source port được giữ nguyên — chọn

Client kết nối tới decoy VIP/port; pfSense chuyển đích tới Cowrie. Suricata và
filterlog thấy tuple trước NAT, Cowrie và Wazuh thấy tuple sau NAT. Hai miền được
nối bằng source IP, source port, protocol, thời gian và các bindings đích riêng.
Đây là hướng phù hợp topology hiện tại và không cần thêm NAT resolver tổng quát.

Hướng này chỉ được dùng nếu readiness chứng minh source IP/source port không bị
viết lại và có thể đối chiếu chắc chắn. Nếu không, gate dừng trước live run.

### B. Route trực tiếp tới Cowrie, không DNAT

Tuple giống nhau ở bốn nguồn nên evaluation đơn giản hơn, nhưng không kiểm chứng
đường decoy VIP/NAT mà manifest hiện mô tả. Không chọn cho lượt chính.

### C. Xây NAT resolver tổng quát

Thu thập state/NAT evidence và chuẩn hóa cả original/translated tuple. Hướng này
phù hợp nhiều topology hơn nhưng mở rộng canonical contract và validation engine.
Chỉ mở issue riêng nếu readiness cho thấy hướng A không đủ căn cứ.

## 3. Hợp đồng hành vi an toàn

- Một initiator, một decoy VIP, một giao thức (`ssh` hoặc `telnet`) và một port
  được owner điền trong cấu hình riêng ngoài Git. Không có địa chỉ mặc định.
- Client bind đúng interface/IP lab và dùng một source port trống được ghi vào
  receipt. Một lần kết nối, một lần login attempt, không tự retry.
- Username và password là marker ngẫu nhiên chỉ dùng trong lab cho run đó.
  Không lấy từ environment, keychain, file người dùng hoặc tài khoản thật.
- Tổng thời gian client tối đa 30 giây. Không chấp nhận shell, không gửi command,
  không theo URL và không ghi host key bền vững ngoài thư mục tạm của run.
- Mỗi run có UUID riêng trong receipt và context. Run UUID không được giả thành
  field của network log nếu nguồn không quan sát nó.
- Receipt client là supporting evidence. Nó không thay thế canonical telemetry
  và không tự tạo verdict.

Login failed được ưu tiên vì không mở shell. Nếu cấu hình Cowrie chỉ tạo sequence
được review bằng login success, plan phải chứng minh không gửi command và đóng
session ngay; thay đổi này cần owner review trước live run.

## 4. Topology và NAT

Hai tuple được giữ riêng:

- `pre_nat`: initiator → decoy VIP/port, quan sát bởi Suricata và pfSense.
- `post_nat`: initiator → Cowrie IP/port, quan sát bởi Cowrie và Wazuh.

Profile dùng bindings riêng cho `decoy_ip`, `decoy_port`, `cowrie_ip` và
`cowrie_port`. Không sao chép một địa chỉ vào miền kia. Tương quan qua NAT chỉ
được phép khi readiness xác nhận:

- source IP và source port được giữ nguyên;
- protocol giống nhau;
- rule/port-forward identity được đối chiếu;
- source clocks đủ gần trong cửa sổ đã đo;
- không có flow khác trùng tuple trong cửa sổ.

Nếu source port hoặc source IP bị dịch, cần native NAT/state evidence và thiết kế
resolver riêng. Không nối log chỉ theo timestamp, hostname hoặc destination port.

## 5. Assertion và bằng chứng dự kiến

| Assertion | Vai trò dự kiến | Bằng chứng tối thiểu |
| --- | --- | --- |
| SCN-003-A01 | detection | Suricata EVE alert với SID đã review, pre-NAT tuple đúng scope |
| SCN-003-A02 | telemetry | pfSense filterlog pass/redirect path với tracker/rule đã đối chiếu |
| SCN-003-A03 | telemetry | Cowrie `session.connect` và `login.failed` cùng source session; canonical login event làm witness chính |
| SCN-003-A04 | detection | Wazuh alert rule ID đã review, sinh từ Cowrie login/session của cùng interaction |

A01 cần một SID cụ thể được version-control và test trước lab. Không dùng flow
thuần làm detection nếu manifest/profile gọi assertion là detection.

A02 không chứng minh detection. Hành động `allowed` hoặc dữ kiện redirect/NAT
phải phản ánh record thực tế; không đổi thành `blocked` vì SCN-003 có outcome
`Detected`, không phải `Prevented`.

A03 dùng canonical fields cho tuple, protocol, username và action `login`.
`session_key` cùng authentication outcome hiện nằm trong provenance, trong khi
validation engine chỉ đọc canonical event. Implementation phải chọn một hợp đồng
review được: đưa identity phiên cần thiết vào report/intake an toàn, hoặc chứng
minh tuple + username marker + thời gian là đủ. Không đọc provenance ngầm trong
engine và không đưa password vào profile/report.

A04 cần sample Wazuh thật trước khi chốt parser. Parser `cowrie-wazuh-v1` hiện
phát canonical source `cowrie`, nên nó không tự đáp ứng assertion nguồn Wazuh.
Khả năng cần một profile `wazuh-cowrie-alert-v1`, tương tự đường alert Suricata
đã làm cho SCN-002, chỉ được triển khai sau khi shape/rule ID thật được review.

## 6. Evaluation profile

Profile SCN-003 được xây fixture-first và pin:

- scenario ID/version/fingerprint;
- literal Suricata SID và Wazuh rule ID đã review;
- bindings pre/post NAT riêng;
- protocol/port và username marker của run;
- cửa sổ correlation lấy từ số đo clock readiness, không chọn để vừa dữ liệu.

Detection rules phải correlation tới một telemetry root hợp lệ theo engine.
Nếu engine hiện không biểu diễn được mối quan hệ cần thiết, implementation plan
phải mở issue nhỏ cho contract trước profile. Không giảm assertion xuống
`unsupported` chỉ để có verdict xanh.

Collection declarations mặc định `unknown`. Zero hit không tự trở thành false
negative nếu chưa có chứng nhận collection hoàn chỉnh.

## 7. Pipeline fixture-first

Thứ tự triển khai:

1. Xác minh shape nguồn bằng mẫu hữu hạn, read-only, không tạo traffic.
2. Tạo fixture synthetic/sanitized với lineage và exact byte hashes.
3. Hoàn thiện parser/profile/engine path offline và test negative cases.
4. Viết client/runbook hữu hạn, preflight và rollback.
5. Sau review mới chạy một live interaction và thu evidence riêng ngoài Git.
6. Sanitize derivative, chạy `aegis validate`, review evidence IDs rồi mới kết
   luận `Detected`.

Native Cowrie JSONL và Wazuh-wrapped Cowrie parsers hiện có được tái sử dụng.
Suricata EVE và pfSense filterlog parsers được tái sử dụng. Không thêm daemon
live collection trong milestone đầu.

## 8. Preflight lab và rollback

Trước live run phải xác nhận:

- Cowrie service hoạt động và chỉ lắng nghe interface/port đã duyệt;
- decoy VIP/port-forward và firewall rule đúng scope;
- Suricata sensor/rule hoạt động ở interface cần quan sát;
- Wazuh nhận Cowrie event và rule ID dự kiến;
- đồng hồ nguồn đủ gần;
- không có session/flow trùng tuple trong cửa sổ;
- backup cấu hình và cách hoàn nguyên đã ghi lại.

Rollback chỉ hoàn nguyên rule/SID/NAT tạm được thêm cho bài thử, sau khi review
diff. Dừng client/session của run và giữ nguyên evidence. Một check kết nối sau
rollback chỉ thực hiện nếu runbook đã duyệt nó.

## 9. Tiêu chí nghiệm thu

SCN-003 được đánh giá `Detected` khi:

- cả bốn assertion của cùng run đều `satisfied`;
- mọi assertion trỏ tới evidence ID và raw hash;
- pre/post NAT relationship đã được chứng minh theo gate mục 4;
- Wazuh detection có rule ID thật và liên hệ được với Cowrie interaction;
- không dùng evidence từ run khác hoặc dữ liệu ngoài cửa sổ;
- report/fixture đã sanitize và review;
- thay đổi lab đã rollback và owner xác nhận.

Các trường hợp thiếu nguồn, sai tuple, sai SID/rule, NAT không chứng minh được,
clock không đạt, trùng flow, username khác, parse error và chéo run phải cho
`Missing telemetry`, `False negative` hoặc `Inconclusive` đúng hợp đồng engine;
không được suy `Detected` từ việc Cowrie có một login bất kỳ.

## 10. Phạm vi ngoài milestone

- Quét nhiều host/port, port-scan detection và brute force.
- Command execution, malware/download hoặc shell interaction.
- NAT resolver tổng quát cho nhiều firewall/topology.
- Live continuous Cowrie/pfSense/Suricata connector.
- Thay `status: draft` hoặc sửa ground truth SCN-003 trong cùng thay đổi.
- Chứng minh toàn bộ deception coverage của hệ thống.

## 11. Test matrix bắt buộc cho implementation plan

- Happy path đủ bốn nguồn của một run.
- Thiếu từng nguồn; detection rule mismatch; telemetry có nhưng detection thiếu.
- Pre/post NAT bindings đúng và sai; source port bị rewrite; flow trùng cửa sổ.
- Sai username marker; login event khác session; event chéo run.
- Source time ngoài cửa sổ; BSD year/offset context sai hoặc thiếu.
- Wazuh Cowrie alert đúng/sai rule ID và shape không hỗ trợ.
- Credential không xuất hiện trong report, fixture public hoặc lỗi chẩn đoán.
- Client từ chối đích ngoài scope, retry, scan, command và runtime vượt giới hạn.

