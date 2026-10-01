# Nghiệm thu MVP theo PRD — 2026-09-27, cập nhật 2026-10-01

Đối chiếu từng yêu cầu của [PRD](PRD.md) với bằng chứng trong repo. Bằng chứng lab
thô nằm ngoài Git; tài liệu kết quả ghi run ID và SHA-256 để ai giữ hồ sơ riêng
đối chiếu được. "Lab thật" nghĩa là chạy trên lab riêng của chủ dự án (pfSense,
Suricata, Wazuh 4.14.4, Cowrie, Windows có Sysmon), đánh giá offline bằng engine.

Nghiệm thu lần đầu trên `main` @ `6b7eeef` (2026-09-27). Cập nhật 2026-10-01 trên
`main` @ `1f9f354` (sau release 0.3.0 và dashboard Tổng quan, issue #124). Kết luận
không đổi; số kiểm ở mục 5, thay đổi từ lần đầu ở mục 7.

## 1. Phạm vi MVP (PRD mục 5)

| Yêu cầu | Trạng thái | Bằng chứng |
| --- | --- | --- |
| 3 security scenarios | ✅ cả ba đã chạy trên lab thật | SCN-001 [v2](SCN001_V2_APPROVAL_AND_PINS.md), [v3](SCN001_V3_RESULT_2026-09-27.md); SCN-002 [kết quả](SCN002_RESULT_2026-09-22.md); SCN-003 [kết quả](SCN003_RESULT_2026-09-26.md) |
| 4 connectors | ✅ Wazuh, Suricata, pfSense, Cowrie; parser riêng trong `connectors/`, đầu ra canonical | [README](../README.md) bảng parser key; Wazuh Indexer đọc live (chỉ đọc): [WAZUH_LIVE_CONNECTOR.md](WAZUH_LIVE_CONNECTOR.md); thu lab chỉ đọc cho SCN-002/003: [`aegis collect`](SCN002_COLLECT.md) |
| Canonical Event Model | ✅ | [CANONICAL_EVENT.md](CANONICAL_EVENT.md), [CANONICAL_EVENT_V2.md](CANONICAL_EVENT_V2.md) |
| Validation Engine | ✅ | [VALIDATION_ENGINE.md](VALIDATION_ENGINE.md); profile công khai `scenarios/profiles/` |
| Evidence Timeline | ✅ timeline trong report CLI, sắp theo thời gian, giá trị thiếu để trống | `aegis validate` report; tab Timeline của dashboard |
| Detection Pass/Fail | ✅ theo từng assertion, có evidence ID | [CLI_VALIDATE.md](CLI_VALIDATE.md) |
| Rule Regression Comparison | ✅ `aegis compare`; SCN-001 B→C `Regression Passed` hai lần (v2, v3); bộ v3 tái lập trùng byte trên `main` ngày 2026-10-01 | [CLI_COMPARE.md](CLI_COMPARE.md); [SCN-001 v3, mục 9](SCN001_V3_RESULT_2026-09-27.md) |
| Một dashboard đơn giản | ✅ chỉ đọc report, không tính lại verdict; issue #10 đóng 2026-09-27. Từ 2026-10-01 có trang Tổng quan theo kịch bản, trạng thái hệ thống và chi tiết kịch bản (#119); report thật của cả ba kịch bản hiển thị được | [DASHBOARD.md](DASHBOARD.md) |

## 2. Chỉ số thành công (PRD mục 7)

| Chỉ số | Trạng thái | Bằng chứng |
| --- | --- | --- |
| Mỗi kết luận liên kết được với raw evidence | ✅ mỗi witness có evidence ID, `raw_event_ref`, `raw_event_hash`; bundle ghim SHA-256 | report CLI; bảng hash trong các tài liệu kết quả |
| Cùng một scenario chạy lại được nhiều lần | ✅ SCN-003 bảy lượt (lượt 7 thu bằng `aegis collect scn003`); SCN-002 các lượt đối chứng và Block ngày 22/9, thêm ba lượt đối chứng và một lượt Block ngày 27/9 thu bằng `aegis collect scn002`; SCN-001 hai bộ A/B/C | các tài liệu kết quả |
| Phân biệt Detected, Prevented, Missing Telemetry và Failed | ✅ đủ các trạng thái trên dữ liệu lab thật | `Detected` SCN-003; `Prevented` SCN-002 Block; `Missing telemetry` SCN-003 lượt 1; `False negative` (tức Failed) SCN-001 Run B; `Inconclusive` SCN-002 đối chứng |
| Hiển thị khác biệt giữa hai lần chạy | ✅ | `aegis compare`; màn so sánh trên dashboard |
| Demo Gap → Rule Fix → Re-test → Pass | ✅ trên lab thật | [SCN-001 v3](SCN001_V3_RESULT_2026-09-27.md); kịch bản kể lại cho khách: [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md) |

## 3. Ngoài MVP (PRD mục 6): không xây

Không có SIEM riêng, SOAR, multi-tenant, billing, phản ứng tự động hay detection
bằng machine learning. Operations chỉ đọc (inventory, collection) cho một người
vận hành cục bộ.

## 4. Giới hạn cần nói rõ

- Collection assurance là **caller-attested**: "đầy đủ" do người vận hành xác nhận
  kèm số đo (SCN-001 v3: EVTX = manager = snapshot), không phải xác minh độc lập.
- Run binding của SCN-001 vẫn `unknown` vì script block companion của PowerShell.
- Manifest cả ba scenario vẫn `status: draft`; đổi trường này sẽ đổi fingerprint
  mà profile và study đang ghim, nên giữ có chủ đích.
- Fingerprint gắn với phiên bản canonical model: đánh giá lại bằng chứng cũ trên
  đúng phiên bản code đã tạo ra nó ([Validation Engine](VALIDATION_ENGINE.md)).
- Collector live chỉ retry khi gặp HTTP 429; quyền tối thiểu do người vận hành
  rà; chưa gây lỗi thử trên lab thật.
- Trên máy gửi của lab, giờ của Sysmon 3 lệch dần sau khi Sysmon khởi động và sau mỗi lần
  chỉnh nhảy đồng hồ. Mỗi lượt SCN-002 phải xem `source_minus_send_s` trước khi đọc verdict
  ([SCN002_COLLECT.md](SCN002_COLLECT.md#đọc-độ-lệch-giờ-issue-102)).
- Python 3.13 kiểm chứng chỉ chặt hơn: CA của Wazuh Indexer phải có Key Usage. Lab
  của chủ dự án đã cấp lại CA cùng key (#112); lab khác xem
  [WAZUH_LIVE_CONNECTOR.md](WAZUH_LIVE_CONNECTOR.md), không nới kiểm chứng.
- Công cụ cho một người vận hành, lab riêng; không phải sản phẩm production.

## 5. Kiểm chứng phần mềm

| Kiểm | Kết quả |
| --- | --- |
| Backend đầy đủ, CI GitHub trên `main` @ `1f9f354`, Windows (Python 3.11 và 3.13) | mỗi job 3357 passed, 3 skipped; `pip check` đạt |
| Backend đầy đủ, CI GitHub trên `main` @ `1f9f354`, Linux (Python 3.11, 3.12 và 3.13) | mỗi job 3233 passed, 90 skipped; `pip check` đạt |
| Frontend, CI GitHub trên `main` @ `1f9f354` (Node 24) | Vitest 107 passed (6 file); TypeScript và Vite build đạt |
| Tái lập SCN-001 v3 bằng code `main` @ `c0479f6`, 2026-10-01 | 10/10 file đầu ra trùng byte với bộ đã lưu ([mục 9](SCN001_V3_RESULT_2026-09-27.md)) |
| Diễn tập [demo](DEMO_WALKTHROUGH.md) trên clone sạch, 2026-09-27 | mọi lệnh cho đúng kết quả ghi trong kịch bản |
| CI GitHub | chạy lại từ 2026-10-01, `main` xanh. PR chạy Linux/Python 3.12, cộng Windows/3.13 nếu PR đổi code riêng của Windows; `main` chạy Linux 3.11–3.13 và Windows 3.11, 3.13 ([CI.md](CI.md)) |

Lần nghiệm thu đầu (2026-09-27) đo local khi CI hết quota: Windows/Python 3.12
3284 passed, 2 skipped (`main` @ `4f238c5`); Linux/Python 3.11 3202 passed, 84
skipped (`main` @ `cec9e5d`); frontend 86 passed.

## 6. Việc chủ dự án quyết

- ~~Đặt tag phát hành~~: đã đặt `v0.2.0-lab` ngày 2026-09-27 ([ghi chú](RELEASE_NOTES_0.2.0-lab.md)).
- ~~Chọn license~~: Apache-2.0, 2026-10-01 ([LICENSE](../LICENSE), release 0.3.0).
- Đánh dấu GitGuardian incident 37636143 là false positive (tên field `password`
  trong danh sách field chẩn đoán, không phải bí mật).
- Giữ hay gỡ quyền truy cập lab đã cấp cho tự động hoá (sudoers hẹp, key SSH kể cả key
  vào máy khởi tạo SCN-003, quyền ssh trong cài đặt Claude Code cục bộ).
- ~~Bật lại w32time trên máy gửi SCN-002~~: đã chạy lại và đồng bộ ngày 2026-09-27.
- Lab: chỉnh giờ máy host. Agent Wazuh trên firewall cùng phiên bản với manager (4.14.4),
  nên không nâng riêng được. Lần agent ngừng đẩy log ngày 2026-09-27 chưa rõ nguyên nhân;
  trước mỗi lượt, kiểm manager có event mới từ agent firewall
  ([SCN002_COLLECT.md](SCN002_COLLECT.md#đọc-độ-lệch-giờ-issue-102)).
- Lab đối tác (Lab B, Lab C): đang chờ phản hồi sau khi chạy thử bản 0.3.0 theo
  [LAB_ONBOARDING.md](LAB_ONBOARDING.md); lỗi họ báo sẽ thành issue riêng.

## 7. Thay đổi sau lần nghiệm thu đầu (2026-09-27 → 2026-10-01)

| Thay đổi | Issue |
| --- | --- |
| `aegis collect scn003` nghiệm thu bằng lượt 7: hash trùng với công cụ riêng | #95 |
| `aegis collect scn002` báo độ lệch giờ từng nguồn so với lúc gửi (`source_minus_send_s`) | #102 |
| Python 3.13 trên Windows: thư mục bằng chứng riêng được tạo với ACL chỉ cho người dùng hiện tại | #110 |
| Python 3.13: CA của Wazuh Indexer cấp lại có Key Usage; thu bằng chứng đạt | #112 |
| CI chạy Windows cho PR đổi code riêng của Windows; `main` thêm Python 3.13 | #114 |
| Release 0.3.0: license Apache-2.0, hướng dẫn lab đối tác ([ghi chú](RELEASE_NOTES_0.3.0.md)) | #117 |
| Dashboard: trang Tổng quan theo kịch bản, trạng thái hệ thống, chi tiết kịch bản | #119 |
| SCN-001 v3 tái lập trùng byte trên `main`; report hiển thị trên trang Tổng quan | #122 |

Không thay đổi nào trong số này đổi ground truth, profile hay kết luận của các lượt
lab đã ghi.
