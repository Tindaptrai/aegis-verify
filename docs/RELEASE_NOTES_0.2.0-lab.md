# v0.2.0-lab — ghi chú phát hành (bản nháp)

Trạng thái: **bản nháp, chờ chủ dự án duyệt tag**. Không tự tăng version package
hay đặt tag. Mốc trước: `v0.1.0-lab.1`. Đề xuất đặt tag trên commit merge tài liệu
này (hoặc `6b7eeef` nếu muốn tag trước tài liệu).

## Điểm chính

- **Cả ba scenario của PRD đã chạy trên lab thật.** SCN-001 Gap → Fix → Re-test
  (`Regression Passed`), SCN-002 `Prevented`, SCN-003 `Detected`.
  [Nghiệm thu MVP](MVP_ACCEPTANCE.md).
- **Kịch bản demo offline** cho cả ba scenario và dashboard, dựa trên bundle đã
  sanitize: [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md).

## Thay đổi từ v0.1.0-lab.1 (41 PR)

**CI, launcher:** CI fixture Windows/Linux (#34); launcher một lệnh (#35) và nhập
credential tuỳ chọn (#45); PR chỉ chạy Linux để tiết kiệm phút Actions (PR thêm
tài liệu này).

**Operations (chỉ đọc, SCN-001):** service (#40), inventory agent (#41), UI (#42),
bàn giao (#43), test khôi phục sau crash và mất nguồn (#47).

**SCN-002 attempted exfiltration:** parser archives, pfSense syslog không hostname,
nhãn nguồn, provenance bản dẫn xuất (#51, #53, #55, #57); rule marker Suricata (#59);
Sysmon event 3 (#62); profile công khai và wording A04 (#64, #65); parser alert
Wazuh từ Suricata (#66); bundle CLI (#68); runbook lượt Block (#70, #71); cửa sổ
±2 s (#72); kết quả `Prevented` (#73); bundle lab đã sanitize (#75).

**SCN-003 internal deception:** thiết kế và review (#81); nội dung detection SID
1000012 và rule 120003 (#82); canonical `session_key` và parser alert Wazuh cho
Cowrie (#83); profile hai root qua NAT (#84); parser bỏ qua mật khẩu người gõ (#85);
bundle lab đã sanitize (#87); kết quả và NTP bền vững cho lab (#88, #89); cửa sổ
±2 s (#90).

**SCN-001 v3:** rule ngoại lệ level 4 cho preflight của runner, kit 0.3.0, bộ
A/B/C chạy lại trên lab (#92).

**Tài liệu:** đồng bộ README/ARCHITECTURE/OPERATIONS (#78, #79, #80); kịch bản
demo, runbook SCN-003, quy tắc fingerprint (#93); đóng #10, #11 (#94).

## Thay đổi cần lưu ý khi nâng cấp

- Thêm field canonical `session_key` (#83) làm đổi `event_set_fingerprint` của mọi
  bằng chứng cũ; approval tạo trước đó chỉ tái lập được trên code cũ (đã kiểm với
  SCN-001 v2 trên `v0.1.0-lab.1`).
- Kit SCN-001 lên 0.3.0; runner chỉ nhận 0.3.0; study nhận 0.2.0 và 0.3.0.
- Profile SCN-002 và SCN-003 dùng cửa sổ tương quan ±2 s.

## Giới hạn

Xem [MVP_ACCEPTANCE.md](MVP_ACCEPTANCE.md) mục 4. Chưa chọn license phân phối.
