# SCN-004 A04 — Bản ghi duyệt và pins (2026-10-08)

Tài liệu này ghi lại quyết định của chủ dự án đối với A04 và scenario/profile
`0.2.0` sau khi review bộ handoff Lab C. Quyết định gắn với đúng snapshot và
fingerprint dưới đây; log thô, địa chỉ, tài khoản và bằng chứng private giữ ngoài Git.
Kết quả từng lượt và hồ sơ truy xuất nằm ở
[SCN004_LAB_C_ACCEPTANCE.md](SCN004_LAB_C_ACCEPTANCE.md); quy trình chạy lại nằm ở
[LABC_RUNBOOK.md](LABC_RUNBOOK.md).

## 1. Bản ghi duyệt của chủ dự án

| Mục | Nội dung |
| --- | --- |
| Người duyệt | Chủ dự án, người dùng trực tiếp trong chat của đợt review Lab C |
| Ngày ghi nhận quyết định | **2026-10-08**, sau khi nhận audit bộ handoff và danh sách gate còn mở |
| Lời duyệt nguyên văn | “duyệt và sửa runbook giúp tôi” |
| Phạm vi quyết định | Duyệt A04 trong SCN-004 và profile `0.2.0` của snapshot được review; cập nhật runbook và hồ sơ để phản ánh quyết định và các gate còn lại |
| Commit được review | `21dd2dcfb5a08b5de42d93ca22f229d2f1f9c60d` |
| Bản chất tài liệu | Bản ghi quyết định đã nhận, do agent soạn; không phải chữ ký hay kết quả của người vận hành độc lập |

Đây là phê duyệt **tại thời điểm review hiện tại**. Hai lượt live `0.2.0` lúc
`09:50:45Z` và `09:56:33Z` ngày 2026-10-08, cùng các lần đánh giá lại bằng chứng cũ,
đã xảy ra trước quyết định này. Hồ sơ không hồi tố quyết định thành phê duyệt trước
những lần đo đó. Quyết định đóng gate chủ dự án review A04/scenario/profile của
snapshot này; trạng thái các gate lúc phê duyệt được giữ ở mục 4, quyết định nghiệm thu mới nhất ở mục 5.

## 2. Phạm vi A04 được duyệt

| Hạng mục | Giá trị đã pin |
| --- | --- |
| Assertion | `SCN-004-A04`, vai trò `detection`, nguồn canonical `wazuh` |
| Parser | `wazuh-snort-alert-v1`, đọc alert SIEM từ `alerts.json` của Wazuh manager |
| Scope | `src_ip = sender_ip`, `dst_ip = receiver_ip`, `dst_port = receiver_port`, `event_provider = snort`, `protocol = UDP` |
| Điều kiện khớp | `rule_id = 130110` của Wazuh và `signature_id = 1000010` của Snort |
| Neo tương quan | `SCN-004-A01`; cùng `src_ip`, `dst_ip`, `src_port`, `dst_port`; cửa sổ **±2 s** |
| Scenario/profile | `SCN-004` `0.2.0` / `scn004-udp-marker-prevention` `0.2.0` |

A04 yêu cầu alert của bước SIEM cho cùng luồng đã có telemetry endpoint; alert IDS
tại sensor được A02 đánh giá riêng. Thiếu bằng chứng A04 và chưa khai báo thu đầy đủ
cho phạm vi đó vẫn cho `collection_not_confirmed` / `Inconclusive`. Phê duyệt không
thay thế bằng chứng hay khai báo thu thập của từng lượt.

## 3. Pins của snapshot được review

| Pin | Giá trị |
| --- | --- |
| Commit thêm A04 | `2473b4b67b2c38f9cb886cba21ad3ae59f3c2aeb` |
| Commit handoff được review | `21dd2dcfb5a08b5de42d93ca22f229d2f1f9c60d` |
| Scenario fingerprint `0.2.0` | `8de00c64cfe8b7b7aff54e81a01cd937b4f9e09dab3083b5ec123a95a72e2185` |
| Profile fingerprint `0.2.0` | `b529215d02eaba678729a849dc37e5647cedbcb0147727c022e782e2ead8ee3e` |
| Handoff ZIP SHA-256 | `7759e65e82d54864bc9e86c30fd2486db1fbf4f1d4c8dfd76b8bb4c910056eac` |

Scenario là
[`SCN-004-attempted-exfiltration-lab-c.yaml`](../scenarios/SCN-004-attempted-exfiltration-lab-c.yaml),
profile là [`profile.json`](../scenarios/profiles/scn-004/profile.json).
Fingerprint scenario/profile là fingerprint do engine tính, không phải SHA-256 của
bytes file; pin của ZIP là SHA-256 của bytes gói handoff.

Manifest ở snapshot này vẫn ghi `status: draft`. Approval được ghi riêng trong tài
liệu này để giữ đúng fingerprint đã review. Nếu sửa manifest/profile, kể cả đổi
`status`, phải tính lại pins và review snapshot mới.

## 4. Trạng thái lịch sử ngay sau phê duyệt A04 (2026-10-08)

| Gate | Trạng thái tại thời điểm 2026-10-08 |
| --- | --- |
| Chủ dự án review A04/scenario/profile tại các pins trên | **Đã duyệt**, ngày 2026-10-08, bằng lời duyệt ở mục 1 |
| Người vận hành khác chạy lại theo runbook, gồm ít nhất một lượt live | **Chưa làm** |
| Review bằng chứng và tests của chuỗi PR, merge theo thứ tự phụ thuộc, replay trên commit main cuối | **Chưa hoàn tất** |

16 lượt nghiệm thu ngày 2026-10-07 thuộc scenario/profile `0.1.0`; hai lượt live mới
ngày 2026-10-08 thuộc `0.2.0`. Hai report đánh giá lại bằng chứng cũ dưới `0.2.0`
được ghi riêng và không tăng số lượt live. Approval hiện tại không biến các lượt đã
đo thành lần chạy của người vận hành độc lập và không thay kết quả replay trên main.

## 5. Chốt nghiệm thu kỹ thuật và ảnh/dashboard (2026-10-09)

Sau khi audit gói bổ sung, chủ dự án xác nhận: "chốt họ chạy rồi chưa gửi ảnh thui",
sau đó "oke chot di". Quyết định này chốt nghiệm thu kỹ thuật Lab C và ghi nhận
lượt người khác đã chạy theo thông tin chủ dự án cung cấp. Không có raw/report
của lượt độc lập đó trong các gói đã nhận, nên không tuyên bố đã xác minh trực
tiếp lượt đó hoặc đặt `lab_verified` cho các report hiện có.

Gói ảnh/dashboard tiếp theo đã được audit: 17 tệp ZIP khớp bản trích xuất,
16/16 manifest hashes khớp, chín ảnh đọc được. Ảnh CLI/dashboard khớp ba report
`7b409794`, `445b3ab2`, `1b0c1a3f` đã được replay chính xác; đây là ảnh đọc lại
kết quả đã lưu, không phải lượt live mới. Chủ dự án chốt mục bổ sung ảnh/dashboard.

| Gói bàn giao ngoài Git | SHA-256 |
| --- | --- |
| `LAB-C-HANDOFF-20261008.zip` (bản `(1)` cùng byte) | `7759e65e82d54864bc9e86c30fd2486db1fbf4f1d4c8dfd76b8bb4c910056eac` |
| `LAB-C-HANDOFF-BOSUNG-20261008.zip` | `e97af1902c833ccfb84a0e99e86581fe6c7957a3dcd2bbcb9b1e90936881223e` |
| `LAB-C-ANH-VA-DASHBOARD-20261008.zip` | `6aaea6a88b69d58d41365e1578003719039a210327a9c4843f51259088e8cecf` |

Chủ dự án tiếp tục yêu cầu áp dụng runbook và merge lên main ngày 2026-10-09.
Việc này cho phép tích hợp sau review/tests; cần replay trên SHA main cuối và
bàn giao kết quả. Quyết định nghiệm thu không tự thay đổi ground truth, pins,
collection assurance hoặc evidence IDs. Bản gốc bằng chứng và export VM giữ
ngoài Git; kiểm tra backup trước khi dọn VM.
