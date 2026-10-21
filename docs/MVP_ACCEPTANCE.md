# Nghiệm thu MVP và tổng hợp Lab A/B/C — cập nhật 2026-10-21

Đối chiếu [PRD](PRD.md) với bằng chứng và quyết định nghiệm thu của từng lab.
MVP gốc của **Lab A** được nghiệm thu ngày **2026-09-27**; **Lab C** chốt nghiệm
thu kỹ thuật và ảnh/dashboard ngày **2026-10-09**; **Lab B** hoàn tất nghiệm thu
kỹ thuật trong phạm vi bằng chứng đã kiểm ngày **2026-10-21**, với ngoại lệ
DK-02 được giữ nguyên. Chi tiết kết quả, ngoại lệ và giới hạn ở mục 8.

Các lab chạy kịch bản an toàn trên môi trường của mình, xuất bằng chứng rồi đánh
giá bằng engine. Bằng chứng thô giữ private ngoài Git; report nguồn giữ EID,
`raw_event_ref` và hash để truy nguyên từng kết luận. Replay report/bundle và đọc
lại ảnh không được tính thành lượt thực nghiệm live mới.

Mốc lịch sử: `main` @ `6b7eeef` (2026-09-27), cập nhật @ `1f9f354` (2026-10-01).
Mốc tổng hợp hiện tại là `main` @ `2033c147faca53df6d2f8c3439fc42a091bbc052`, sau
[PR #147](https://github.com/Tindaptrai/aegis-verify/pull/147). Đây là mốc tài liệu
nghiệm thu; kết quả từng run vẫn gắn với commit, scenario/profile và evidence
fingerprint đã pin của run đó. Package vẫn **0.3.0**; tài liệu này không đặt tag
hoặc tạo release mới.

## 1. Phạm vi MVP (PRD mục 5)

| Yêu cầu | Trạng thái | Bằng chứng |
| --- | --- | --- |
| 3 security scenarios | ✅ phạm vi PRD gốc: SCN-001/002/003 đã chạy trên Lab A | SCN-001 [v2](SCN001_V2_APPROVAL_AND_PINS.md), [v3](SCN001_V3_RESULT_2026-09-27.md); SCN-002 [kết quả](SCN002_RESULT_2026-09-22.md); SCN-003 [kết quả](SCN003_RESULT_2026-09-26.md) |
| 4 connectors | ✅ bốn họ nguồn gốc Wazuh, Suricata, pfSense, Cowrie; parser riêng trong `connectors/`, đầu ra canonical | [README](../README.md) bảng parser key; Wazuh Indexer đọc live (chỉ đọc): [WAZUH_LIVE_CONNECTOR.md](WAZUH_LIVE_CONNECTOR.md); thu lab chỉ đọc cho SCN-002/003: [`aegis collect`](SCN002_COLLECT.md) |
| Canonical Event Model | ✅ | [CANONICAL_EVENT.md](CANONICAL_EVENT.md), [CANONICAL_EVENT_V2.md](CANONICAL_EVENT_V2.md) |
| Validation Engine | ✅ | [VALIDATION_ENGINE.md](VALIDATION_ENGINE.md); profile công khai `scenarios/profiles/` |
| Evidence Timeline | ✅ timeline trong report CLI, sắp theo thời gian, giá trị thiếu để trống | `aegis validate` report; tab Timeline của dashboard |
| Detection Pass/Fail | ✅ theo từng assertion, có evidence ID | [CLI_VALIDATE.md](CLI_VALIDATE.md) |
| Rule Regression Comparison | ✅ `aegis compare`; SCN-001 B→C `Regression Passed` hai lần (v2, v3); bộ v3 tái lập trùng byte trên `main` ngày 2026-10-01 | [CLI_COMPARE.md](CLI_COMPARE.md); [SCN-001 v3, mục 9](SCN001_V3_RESULT_2026-09-27.md) |
| Một dashboard đơn giản | ✅ chỉ đọc report, không tính lại verdict; issue #10 đóng 2026-09-27. Từ 2026-10-01 có trang Tổng quan theo kịch bản, trạng thái hệ thống và chi tiết kịch bản (#119); report thật của cả ba kịch bản hiển thị được | [DASHBOARD.md](DASHBOARD.md) |

Phần mở rộng đã tích hợp đưa tổng hiện hành lên **6 scenario manifests, 7 họ
nguồn và 18 parser keys**: thêm SCN-004/Lab C (OPNsense, Snort 3, Wazuh) và
SCN-005/006/Lab B (Elastic cùng các nguồn endpoint/network). Đây là phạm vi mở
rộng có hồ sơ riêng, không sửa ngược chỉ tiêu PRD gốc thành 6 scenario hay suy
ra có 18 live collectors. Tất cả manifest vẫn `status: draft`.

## 2. Chỉ số thành công (PRD mục 7)

| Chỉ số | Trạng thái | Bằng chứng |
| --- | --- | --- |
| Mỗi kết luận liên kết được với raw evidence | ✅ mỗi witness có evidence ID, `raw_event_ref`, `raw_event_hash`; bundle ghim SHA-256 | report CLI; bảng hash trong các tài liệu kết quả |
| Cùng một scenario chạy lại được nhiều lần | ✅ SCN-003 bảy lượt (lượt 7 thu bằng `aegis collect scn003`); SCN-002 các lượt đối chứng và Block ngày 22/9, thêm ba lượt đối chứng và một lượt Block ngày 27/9 thu bằng `aegis collect scn002`; SCN-001 hai bộ A/B/C | các tài liệu kết quả |
| Phân biệt Detected, Prevented, Missing Telemetry và Failed | ✅ đủ các trạng thái trên dữ liệu lab thật | `Detected` SCN-003; `Prevented` SCN-002 Block; `Missing telemetry` SCN-003 lượt 1; `False negative` (tức Failed) SCN-001 Run B; `Inconclusive` SCN-002 đối chứng |
| Hiển thị khác biệt giữa hai lần chạy | ✅ | `aegis compare`; màn so sánh trên dashboard |
| Demo Gap → Rule Fix → Re-test → Pass | ✅ trên Lab A; Lab C có thêm cặp lịch sử dưới scenario/profile 0.1.0 | [SCN-001 v3](SCN001_V3_RESULT_2026-09-27.md); [Lab C](SCN004_LAB_C_ACCEPTANCE.md); [demo walkthrough](DEMO_WALKTHROUGH.md). Không suy kết quả này sang Lab B hoặc Lab C 0.2.0 |

## 3. Ngoài MVP (PRD mục 6): không xây

Không có SIEM riêng, SOAR, multi-tenant, billing, phản ứng tự động hay detection
bằng machine learning. Operations chỉ đọc (inventory, collection) cho một người
vận hành cục bộ.

## 4. Giới hạn cần nói rõ

- Collection assurance có thể là **caller-attested** khi có khai báo đầy đủ cho
  phạm vi cụ thể; nơi chưa có khai báo vẫn `unknown`. Count/hash khớp chứng minh
  tính nhất quán của dữ liệu đã thu, không tự chứng minh upstream không mất log.
- Run binding SCN-001 vẫn `unknown` vì script block companion; các report Lab B/C
  cũng không được tự nâng thành `lab_verified` do nghiệm thu hoặc có ảnh dashboard.
- Manifest cả **sáu** scenario vẫn `status: draft`; đổi trường này sẽ đổi fingerprint
  mà profile và study đang ghim. Duyệt nội dung một snapshot không tự đổi trạng thái này.
- Fingerprint gắn với phiên bản canonical model: đánh giá lại bằng chứng cũ trên
  đúng phiên bản code đã tạo ra nó ([Validation Engine](VALIDATION_ENGINE.md)).
- Wazuh có collection chỉ đọc trong phạm vi được tài liệu hóa; Lab B dùng export
  Elastic offline, chưa có live Elastic collector. Operations không tự chạy
  scenario hoặc sửa rule. Những lỗi restart/source-fault chưa được gây thử trong
  milestone Operations không được coi đã kiểm chỉ vì Lab C có thử outage riêng.
- Wazuh collector chỉ retry HTTP 429 có giới hạn; quyền tối thiểu do người vận
  hành rà, không được xác minh tự động từ việc search thành công. Xem
  [giới hạn collector](WAZUH_LIVE_CONNECTOR.md).
- Lab A: SCN-001 Run B dựa trên khai báo thu thập của người chạy, dù số đối chiếu
  EVTX/manager/snapshot khớp. SCN-002/003 dùng witness dương, không xác nhận đã thu
  đầy đủ mọi log. Ngoại lệ runner/rule SCN-001 là nội dung demo có phạm vi lab.
- SCN-002 chỉ kiểm luồng UDP có giới hạn; giờ Sysmon3 có thể lệch sau khởi động,
  suspend/resume hoặc chỉnh đồng hồ. Mỗi lượt phải xem `source_minus_send_s`
  ([SCN002_COLLECT.md](SCN002_COLLECT.md#đọc-độ-lệch-giờ-issue-102)).
- SCN-003 kiểm kết nối và đăng nhập thất bại an toàn; không chứng minh khả năng
  chịu tải, brute-force, HA hay độ ổn định dài hạn.
- Python 3.13 kiểm chứng chỉ chặt hơn: CA của Wazuh Indexer phải có Key Usage. Lab
  của chủ dự án đã cấp lại CA cùng key (#112); lab khác xem
  [WAZUH_LIVE_CONNECTOR.md](WAZUH_LIVE_CONNECTOR.md), không nới kiểm chứng.
- Các scenario khác nhau giữa A/B/C chứng minh tính khả thi của các tích hợp đã
  kiểm; chưa chứng minh cùng mọi scenario cho kết quả tương đương trên mọi stack.
- Nghiệm thu kỹ thuật không tự cấp quyền xóa VM. Giới hạn timing/replica và backup
  của Lab B, nguồn xác nhận người vận hành khác của Lab C được giữ riêng ở mục 8.
- Công cụ cho một người vận hành trong lab; chưa công nhận production readiness
  hoặc giám sát liên tục toàn bộ hệ thống.

## 5. Kiểm chứng phần mềm

### 5.1 Kết quả lịch sử, giữ đúng commit và thời điểm

Các số dưới đây thuộc lần nghiệm thu/cập nhật đã ghi, không phải số test được
chạy lại trên commit tài liệu hiện tại.

| Kiểm | Kết quả |
| --- | --- |
| Backend đầy đủ, CI GitHub trên `main` @ `1f9f354`, Windows (Python 3.11 và 3.13) | mỗi job 3357 passed, 3 skipped; `pip check` đạt |
| Backend đầy đủ, CI GitHub trên `main` @ `1f9f354`, Linux (Python 3.11, 3.12 và 3.13) | mỗi job 3233 passed, 90 skipped; `pip check` đạt |
| Frontend, CI GitHub trên `main` @ `1f9f354` (Node 24) | Vitest 107 passed (6 file); TypeScript và Vite build đạt |
| Tái lập SCN-001 v3 bằng code `main` @ `c0479f6`, 2026-10-01 | 10/10 file đầu ra trùng byte với bộ đã lưu ([mục 9](SCN001_V3_RESULT_2026-09-27.md)) |
| Diễn tập [demo](DEMO_WALKTHROUGH.md) trên clone sạch, 2026-09-27 | mọi lệnh cho đúng kết quả ghi trong kịch bản |

Lần nghiệm thu đầu (2026-09-27) đo local khi CI hết quota: Windows/Python 3.12
3284 passed, 2 skipped (`main` @ `4f238c5`); Linux/Python 3.11 3202 passed, 84
skipped (`main` @ `cec9e5d`); frontend 86 passed.

### 5.2 Các mốc tích hợp Lab C và Lab B

| Mốc | Kiểm chứng và phạm vi |
| --- | --- |
| Lab C tích hợp tại `5e8b2f6baf1e8e1a18c2256b03631796955b6864`, 2026-10-09 | Chuỗi 13 PR đã merge; CI 6 job đạt. Local Windows: 3.655 passed / 3 platform skips; frontend 108 passed và build đạt. Replay **23/23 report JSON và exit code**, **2/2 compare JSON** khớp; không tính thành 23 lượt live mới. [Hồ sơ tích hợp](../README.md#lab-c-integration-verification--2026-10-09) |
| Lab B tích hợp tại `a8c894f8ad4e1ddecace4a9d73b2e35c9fbe4b22`, 2026-10-19 | [PR #144](https://github.com/Tindaptrai/aegis-verify/pull/144) đã merge; SCN-005 replay đúng bytes report đã review. Nguồn code của run không được đổi thành commit tài liệu mới hơn |
| Tổng hợp quyết định tại `2033c147faca53df6d2f8c3439fc42a091bbc052`, 2026-10-21 | [Fixture CI run 39557369386](https://github.com/Tindaptrai/aegis-verify/actions/runs/39557369386): **6/6 job thành công**, gồm backend Ubuntu Python 3.11–3.13, Windows 3.11/3.13 và frontend tests/build |

CI kiểm phần mềm với fixtures, không thay bằng chứng lab hoặc xác nhận thu thập
đầy đủ. Commit tài liệu tiếp theo vẫn cần CI của chính nó. Cấu hình CI ở [CI.md](CI.md).

## 6. Việc chủ dự án quyết

- ~~Đặt tag phát hành~~: đã đặt `v0.2.0-lab` ngày 2026-09-27 ([ghi chú](RELEASE_NOTES_0.2.0-lab.md)).
- ~~Chọn license~~: Apache-2.0, 2026-10-01 ([LICENSE](../LICENSE), release 0.3.0).
- ~~Đánh dấu GitGuardian incident 37636143 là false positive~~: theo bản ghi của
  chủ dự án tại [issue #126](https://github.com/Tindaptrai/aegis-verify/issues/126),
  đã đánh dấu ngày **2026-10-01**; tên field `password` trong danh sách field chẩn
  đoán không phải bí mật. Đây là nguồn xác nhận quản trị, không suy từ CI xanh.
- Giữ hay gỡ quyền truy cập lab đã cấp cho tự động hoá (sudoers hẹp, key SSH kể cả key
  vào máy khởi tạo SCN-003, quyền ssh trong cài đặt Claude Code cục bộ).
- ~~Bật lại w32time trên máy gửi SCN-002~~: đã chạy lại và đồng bộ ngày 2026-09-27.
- Lab: chỉnh giờ máy host. Agent Wazuh trên firewall cùng phiên bản với manager (4.14.4),
  nên không nâng riêng được. Lần agent ngừng đẩy log ngày 2026-09-27 chưa rõ nguyên nhân;
  trước mỗi lượt, kiểm manager có event mới từ agent firewall
  ([SCN002_COLLECT.md](SCN002_COLLECT.md#đọc-độ-lệch-giờ-issue-102)).
- Lab B/C đã có quyết định nghiệm thu nêu ở mục 8; không còn trạng thái chờ phản
  hồi chung. Lab mới tiếp tục theo [LAB_ONBOARDING.md](LAB_ONBOARDING.md); lỗi mới
  và phạm vi thực nghiệm bổ sung được ghi nhận riêng.
- Việc giữ/gỡ VM Lab B chờ nhóm gửi inventory lưu trữ, kết quả hash bản backup và
  danh sách đường dẫn dự kiến xóa để Tín duyệt. DK-03 đã đóng trong phạm vi kiểm
  phục hồi cục bộ; quyết định đó không thay cho xác nhận dọn VM hoặc chứng minh có
  bản lưu trên thiết bị vật lý độc lập.

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

### 7.1 Mở rộng và quyết định nghiệm thu sau 2026-10-01

| Mốc | Quyết định / tham chiếu |
| --- | --- |
| Lab C, 2026-10-09 | Nghiệm thu kỹ thuật và ảnh/dashboard của SCN-004; A04 trong scenario/profile 0.2.0 đã được duyệt trước đó. Chuỗi tích hợp gồm [PR #142](https://github.com/Tindaptrai/aegis-verify/pull/142) đã lên main |
| Lab B, 2026-10-19 | [PR #144](https://github.com/Tindaptrai/aegis-verify/pull/144) tích hợp parser Elastic offline và profile SCN-005/006 |
| Lab B, 2026-10-20 | Chấp nhận kỹ thuật có điều kiện; DK-02 có ngoại lệ riêng cho software-operated run đã review |
| Lab B, 2026-10-21 | Đóng DK-03 theo hồ sơ backup/phục hồi, đóng DK-01 theo xác nhận review trực tiếp của Tín; [PR #147](https://github.com/Tindaptrai/aegis-verify/pull/147) cập nhật README và đã merge |

Các quyết định chấp nhận giới hạn không sửa lại log, EID, threshold hoặc kết quả
lịch sử. Nghiệm thu từng lab cũng không tự phát hành phiên bản mới.

## 8. Tổng hợp phần đã nghiệm thu, ngoại lệ và giới hạn theo lab

| Lab | Stack / scenario | Phần đã nghiệm thu | Phạm vi cần giữ |
| --- | --- | --- | --- |
| **A** | Wazuh, pfSense, Suricata, Cowrie, Windows; SCN-001/002/003 | MVP gốc ngày 2026-09-27; cập nhật hồ sơ/tái lập ngày 2026-10-01 | Lab riêng, kết quả theo từng run; collection có khai báo của người chạy hoặc còn unknown |
| **B** | Elastic, Windows, Suricata, pfSense và DMZ; SCN-005/006 | Hoàn tất nghiệm thu kỹ thuật trong phạm vi bằng chứng đã kiểm ngày 2026-10-21 | DK-01/DK-03 đóng; DK-02 ngoại lệ có phạm vi. Timing contract chưa đạt; chưa chứng minh vận hành độc lập hoặc ổn định dài hạn |
| **C** | OPNsense, Snort 3, Wazuh, Windows; SCN-004 | Nghiệm thu kỹ thuật và ảnh/dashboard ngày 2026-10-09; chuỗi PR đã tích hợp main | Tách 0.1.0/0.2.0 và live/replay; lượt người vận hành khác được chủ dự án xác nhận, chưa audit raw/report riêng |

### 8.1 Lab A — kết quả đã kiểm

- **SCN-001 v3:** A `Detected`, B `False negative` với collection caller-attested,
  C `Detected`; B→C `Regression Passed`. Report giữ EID/witness của từng assertion.
  Tái lập **10/10 đầu ra đúng bytes** ngày 2026-10-01 thuộc `c0479f6`, không gán
  số này cho HEAD mới. [Kết quả, run IDs và pins](SCN001_V3_RESULT_2026-09-27.md).
- **SCN-002:** hai lượt Block ngày 22/9 và 27/9 đều `Prevented`, 4/4 assertion.
  Đối chứng `Inconclusive` đúng thiết kế; so đối chứng→Block không phải bằng chứng
  `Regression Passed`. [Kết quả và nguồn report](SCN002_RESULT_2026-09-22.md).
- **SCN-003:** bảy lượt, lượt 1 `Missing telemetry`, lượt 2–7 `Detected`; lượt 7
  nghiệm thu collector và hash khớp bộ thu riêng. [Kết quả và run IDs](SCN003_RESULT_2026-09-26.md).

[OPERATIONS_ACCEPTANCE.md](OPERATIONS_ACCEPTANCE.md) giữ milestone lịch sử
SCN-001 ngày 20/9, không thay phạm vi nghiệm thu MVP sau đó. Các câu lịch sử
SCN-002/003 chưa nghiệm thu trong milestone đó không phải trạng thái hiện hành.

### 8.2 Lab B — quyết định DK-01/DK-02/DK-03

**SCN-005:** run `LABB-OP-PS-20261019-01`, code
`a8c894f8ad4e1ddecace4a9d73b2e35c9fbe4b22`, có đối chiếu native→Elastic **28/28
về định danh và nội dung sự kiện**, engine **Detected 3/3**, 29 parsed / 5
referenced / 0 skipped và replay report đúng bytes. Native/export XML không
giống nguyên byte do `RenderingInfo`; đối chiếu ngữ nghĩa không thay cho hash raw.
Ba cặp witness host/PID/time của engine không đồng nghĩa ba exact ancestries:
audit nguồn xác nhận **một** exact source-document ancestry tới marker record 8375.

Report SHA-256: `f76a567e4979dcf8ba0db9ccfd41b3a4d4e10b6560bd55131dad8ecd57eaf72a`.
Các EID chính, đã được ghi trong hồ sơ công khai tại README:

- Child Sysmon1: `elastic:evidence-v1:f2337755b8c2a2d8671232677c3c7d0473443a4647aa8e8db66ef84829b8f60b`.
- Marker PowerShell: `elastic:evidence-v1:bb74454425768bef7e27600b1323131921c772a378684e10d4c6eaba56edc023`.
- Alert nối nguồn: `elastic:evidence-v1:52cac63fbf7e0f12d7fc4c88d82bdbf01d5076cfe19248f297558f342abaccc3`.

**SCN-006:** kết quả lịch sử `Detected` 3/3 là endpoint telemetry, Suricata IDS
và pfSense **allow** cho luồng đã thử. Accepted Elastic network alerts = **0**;
PowerShell alert cũ trong NET export không phải detection network mới. Không có
kết luận prevention, Gap→Fix/regression hoặc detection outage→recovery cho Lab B.

| Điều kiện | Quyết định và phạm vi |
| --- | --- |
| **DK-01 — review thực tế** | **Đóng ngày 2026-10-21.** Nguyễn Lê Trọng Tín trực tiếp xác nhận đã xem hồ sơ, chấp nhận hai timing variance và thay đổi replica trong phạm vi lab; không dùng review Codex thay xác nhận của Tín |
| **DK-02 — người khác tự vận hành** | **Giữ ngoại lệ ngày 2026-10-20**, chỉ cho `LABB-OP-PS-20261019-01` do Codex software thực hiện và bằng chứng đã kiểm. Chưa chứng minh một người khác tự vận hành; không áp dụng cho run khác |
| **DK-03 — backup/phục hồi** | **Đóng ngày 2026-10-21.** Chấp nhận inventory, hash và proof boot/dữ liệu/dịch vụ cục bộ của pfSense, Elastic, Windows, Sensor, DMZ; không yêu cầu gửi toàn bộ đĩa VM |

**Timing chưa đạt, giữ nguyên sau nghiệm thu:** Δ = `EventData.UtcTime − System.TimeCreated`.
Record 43836/PID2612 là **−3,5660511 s**, record
43842/PID4676 là **−3,5847297 s**, đều vượt ngưỡng độ lớn 3 s. Đây là record phụ
trợ, không thuộc child PID3116 hoặc witness assertion của report. **Whole prepared
timing contract vẫn false**, nguyên nhân chưa xác minh; không sửa threshold hoặc
ground truth để coi đạt. Hai EID variance:

- 43836: `elastic:evidence-v1:07627d2dbbe6950059ec9acabe25a5ff09638395098cdddff191de5bcdf4c652`.
- 43842: `elastic:evidence-v1:579741c51fc916b9b608858d4bb413e9e3d9491bb43936a2fa3eba9bbb789bad`.

**Replica và backup:** `index.number_of_replicas` đổi **1→0** trên đúng hai index
`.ds-.lists-default-2026.10.19-000001` và `.ds-.items-default-2026.10.19-000001`,
có request/readback GET/PUT/GET. Green trên một node không tạo dự phòng mất node.
Catalog bản sao sau phục hồi là **225 tệp / 227.965.087.382 bytes**, khác trạng
thái nguồn trước repair/boot. Lần review hồ sơ không trực tiếp đọc lại toàn bộ
đĩa VM tại máy dự án. Nguồn chưa chứng minh application consistency; bốn bản sao
cần repair đĩa; chưa kiểm toàn bộ topology hoặc mọi snapshot RAM. Elastic/Windows
có nguồn và bản sao cùng ổ, chưa chứng minh chống mất cả ổ vật lý.

Nguồn công khai: [quyết định và phạm vi tại README](../README.md#lab-b-conditional-technical-acceptance),
[tích hợp Elastic](LABB_ELASTIC.md), profile [SCN-005](../scenarios/profiles/scn-005/README.md)
và [SCN-006](../scenarios/profiles/scn-006/README.md). Hồ sơ quyết định gốc và raw
evidence giữ private, xem mục 8.4. Không còn DK-01/DK-03 chờ nghiệm thu trong phạm
vi này; ngoại lệ DK-02 không đổi thành bằng chứng vận hành độc lập đã đạt.

### 8.3 Lab C — phân tách phiên bản và nguồn xác nhận

Chủ dự án chốt nghiệm thu kỹ thuật và ảnh/dashboard ngày **2026-10-09**, theo
[bản ghi duyệt và pins](SCN004_A04_APPROVAL_AND_PINS.md). SCN-004 scenario/profile
**0.2.0** đã duyệt A04 cho alert SIEM, ngoài A02 kiểm alert IDS tại sensor.

- **0.1.0:** 16 lượt live hợp lệ, 16/16 đúng kỳ vọng; có cặp Gap→Fix
  `f12e4fa7` → `9099c31e` đạt `Regression Passed`, A02 sau sửa có EID rút gọn
  `640286c663c4…`. Không gán cặp lịch sử này thành Gap→Fix dưới 0.2.0.
- **0.2.0:** năm lượt live được ghi riêng. Hai đánh giá lại bằng chứng cũ không
  tính live. Chuỗi sau duyệt A04 là `7b409794` **Prevented 4/4** → `445b3ab2`
  **Inconclusive**, A04 `collection_not_confirmed` → `1b0c1a3f` **Prevented 4/4**.
  Alert SIEM recovery là alert mới, sau probe **0,687 s**. EID A04 normal/recovery
  rút gọn là `4a58a8983c02…` / `8c04e74f25b6…`; full EID và raw hash trong report
  private, theo [hồ sơ kết quả](SCN004_LAB_C_ACCEPTANCE.md).
- **Người vận hành khác:** chủ dự án xác nhận đã có lượt chạy riêng và chấp nhận
  kỹ thuật. Raw/report của lượt đó chưa được cung cấp để audit trực tiếp. Ba lượt
  normal/outage/recovery nêu trên cùng người chạy, không tự chứng minh vận hành
  độc lập; không nâng report thành `lab_verified`.
- **Tích hợp:** chuỗi 13 PR merge tại `5e8b2f6baf1e8e1a18c2256b03631796955b6864`;
  23/23 replay report/exit code và 2/2 compare khớp như mục 5.2. Đây là kiểm tích
  hợp trên bằng chứng đã lưu, không phải lượt live mới hoặc kiểm phục hồi backup VM.

Collection assurance giữ theo khai báo/unknown của từng report. Bản ảnh đọc lại
report không nâng mức bảo đảm thu thập. [Runbook Lab C](LABC_RUNBOOK.md) giữ rõ
Gap→Fix 0.1.0 và chuỗi gián đoạn/khôi phục 0.2.0; chưa công nhận độ ổn định dài
hạn, production readiness hoặc đã kiểm phục hồi VM Lab C.

### 8.4 Bằng chứng private và tài liệu lịch sử

Các đường dẫn sau tương đối với root repository, **chỉ có trong workspace của chủ
dự án, bị Git bỏ qua và không được lấy về khi clone**:

| Nguồn | Vai trò |
| --- | --- |
| `raw-evidence/lab-b/LAB-B-CURRENT-STATUS.json` | Trạng thái hiện hành và hash của nguồn xác nhận/nghiệm thu Lab B |
| `raw-evidence/lab-b/nghiem-thu-2026-10-21-dong-dk01/` | Xác nhận nguyên văn của Tín, phiếu DK-01 đã hoàn tất và phụ lục hoàn tất nghiệm thu kỹ thuật |
| `raw-evidence/lab-b/nghiem-thu-2026-10-21-dk01-dk03/` | Gói tổng hợp gốc, raw log/ảnh phục hồi và kết quả đối chiếu manifest |
| `raw-evidence/lab-b/README-LAB-B-MAIN-MERGE-20261021.json` | Biên nhận PR #147 đã merge, main/local đồng bộ tại `2033c147…` |
| `raw-evidence/lab-b/CHECKLIST-LUU-TRU-VA-DON-VM-LAB-B-20261021.md` | Checklist lưu trữ, hash backup và danh sách VM cần Tín duyệt trước khi dọn bản làm việc |
| `raw-evidence/lab-c/nghiem-thu-2026-10-09/` | Gói handoff/ảnh, báo cáo audit và biên nhận tích hợp Lab C |

Biên bản Lab B ngày 20/10 và hồ sơ trung gian từng ghi DK-01/DK-03 còn mở được
giữ nguyên làm lịch sử; quyết định ngày 21/10 ở trên là trạng thái hiện hành.
Tương tự, các gate Lab C trước khi chủ dự án chốt không thay thế quyết định mới
nhất. Không sửa các bản gốc, fingerprints, scenario/profile hoặc log để khớp văn
bản nghiệm thu.
