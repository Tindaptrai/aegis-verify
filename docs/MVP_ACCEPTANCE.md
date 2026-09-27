# Nghiệm thu MVP theo PRD — 2026-09-27

Đối chiếu từng yêu cầu của [PRD](PRD.md) với bằng chứng trong repo. Bằng chứng lab
thô nằm ngoài Git; tài liệu kết quả ghi run ID và SHA-256 để ai giữ hồ sơ riêng
đối chiếu được. "Lab thật" nghĩa là chạy trên lab riêng của chủ dự án (pfSense,
Suricata, Wazuh 4.14.4, Cowrie, Windows có Sysmon), đánh giá offline bằng engine.

Commit đối chiếu: `main` @ `6b7eeef`. Kiểm local trên commit đó: xem mục 5.

## 1. Phạm vi MVP (PRD mục 5)

| Yêu cầu | Trạng thái | Bằng chứng |
| --- | --- | --- |
| 3 security scenarios | ✅ cả ba đã chạy trên lab thật | SCN-001 [v2](SCN001_V2_APPROVAL_AND_PINS.md), [v3](SCN001_V3_RESULT_2026-09-27.md); SCN-002 [kết quả](SCN002_RESULT_2026-09-22.md); SCN-003 [kết quả](SCN003_RESULT_2026-09-26.md) |
| 4 connectors | ✅ Wazuh, Suricata, pfSense, Cowrie; parser riêng trong `connectors/`, đầu ra canonical | [README](../README.md) bảng parser key; Wazuh Indexer đọc live (chỉ đọc): [WAZUH_LIVE_CONNECTOR.md](WAZUH_LIVE_CONNECTOR.md); thu lab chỉ đọc cho SCN-002/003: [`aegis collect`](SCN002_COLLECT.md) |
| Canonical Event Model | ✅ | [CANONICAL_EVENT.md](CANONICAL_EVENT.md), [CANONICAL_EVENT_V2.md](CANONICAL_EVENT_V2.md) |
| Validation Engine | ✅ | [VALIDATION_ENGINE.md](VALIDATION_ENGINE.md); profile công khai `scenarios/profiles/` |
| Evidence Timeline | ✅ timeline trong report CLI, sắp theo thời gian, giá trị thiếu để trống | `aegis validate` report; tab Timeline của dashboard |
| Detection Pass/Fail | ✅ theo từng assertion, có evidence ID | [CLI_VALIDATE.md](CLI_VALIDATE.md) |
| Rule Regression Comparison | ✅ `aegis compare`; SCN-001 B→C `Regression Passed` hai lần (v2, v3) | [CLI_COMPARE.md](CLI_COMPARE.md) |
| Một dashboard đơn giản | ✅ chỉ đọc report, không tính lại verdict; issue #10 đóng 2026-09-27 | [DASHBOARD.md](DASHBOARD.md) |

## 2. Chỉ số thành công (PRD mục 7)

| Chỉ số | Trạng thái | Bằng chứng |
| --- | --- | --- |
| Mỗi kết luận liên kết được với raw evidence | ✅ mỗi witness có evidence ID, `raw_event_ref`, `raw_event_hash`; bundle ghim SHA-256 | report CLI; bảng hash trong các tài liệu kết quả |
| Cùng một scenario chạy lại được nhiều lần | ✅ SCN-003 sáu lượt; SCN-002 hai lượt; SCN-001 hai bộ A/B/C | các tài liệu kết quả |
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
- Công cụ cho một người vận hành, lab riêng; không phải sản phẩm production.

## 5. Kiểm chứng phần mềm

| Kiểm | Kết quả |
| --- | --- |
| Backend đầy đủ (Windows, Python 3.12, local, code của `main` @ `4f238c5`) | 3284 passed, 2 skipped (FIFO và POSIX mode, bình thường trên Windows) |
| Frontend: Vitest, TypeScript và Vite build | 86 passed; build đạt |
| CI GitHub | hết quota Actions miễn phí tháng 9; tự chạy lại từ 2026-10-01. PR chỉ chạy Linux/Python 3.12, `main` chạy đủ ma trận ([CI.md](CI.md)) |

## 6. Việc chủ dự án quyết

- ~~Đặt tag phát hành~~: đã đặt `v0.2.0-lab` ngày 2026-09-27 ([ghi chú](RELEASE_NOTES_0.2.0-lab.md)).
- Chọn license nếu định phân phối (repo chưa có file LICENSE).
- Đánh dấu GitGuardian incident 37636143 là false positive (tên field `password`
  trong danh sách field chẩn đoán, không phải bí mật).
- Giữ hay gỡ quyền truy cập lab đã cấp cho tự động hoá (sudoers hẹp, key SSH kể cả key
  vào máy khởi tạo SCN-003, quyền ssh trong cài đặt Claude Code cục bộ).
- ~~Bật lại w32time trên máy gửi SCN-002~~: đã chạy lại và đồng bộ ngày 2026-09-27.
- Lab: chỉnh giờ máy host. Agent Wazuh trên firewall cùng phiên bản với manager (4.14.4),
  nên không nâng riêng được. Lần agent ngừng đẩy log ngày 2026-09-27 chưa rõ nguyên nhân;
  trước mỗi lượt, kiểm manager có event mới từ agent firewall
  ([SCN002_COLLECT.md](SCN002_COLLECT.md#đọc-độ-lệch-giờ-issue-102)).
