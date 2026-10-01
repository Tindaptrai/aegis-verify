# AEGIS Verify 0.3.0 (2026-10-01)

Bản đầu tiên phát hành theo **Apache License 2.0**, dành cho các thành viên dự án tự
cài và chạy trong lab của họ. Bắt đầu từ [hướng dẫn tham gia](LAB_ONBOARDING.md).
Bản trước: [0.2.0-lab](RELEASE_NOTES_0.2.0-lab.md).

## Mới

- **License Apache-2.0**: thêm `LICENSE` và `NOTICE`. Metadata license có trong
  wheel (`License-Expression`) và `frontend/package.json`.
- **Hướng dẫn tham gia** ([LAB_ONBOARDING.md](LAB_ONBOARDING.md)). Gồm:
  - cài đặt và smoke test;
  - quy tắc nhánh và dữ liệu;
  - bảng nguồn dữ liệu, parser có sẵn và khoảng trống cho lab gốc, lab Elastic
    Security và lab OPNsense + Snort 3;
  - cách thêm connector, `SourceType` và profile;
  - các bẫy về đồng hồ đã gặp.
- **`aegis collect scn002` báo độ lệch giờ** của từng nguồn so với receipt
  (`source_minus_send_s`) (#102, #103). Chỉ để chẩn đoán; bundle không đổi.

## Sửa lỗi

- **Thư mục bằng chứng trên Windows với Python 3.13** (#110, #111). Python 3.13 biến
  `mkdir(mode=0o700)` thành ACL có thêm SYSTEM và Administrators, nên Operations từ
  chối chính thư mục nó vừa tạo. Giờ thư mục được tạo bằng `CreateDirectoryW` với một
  DACL chỉ cấp quyền cho người dùng hiện tại, trong cùng một lần gọi. Bản sửa đầu tiên
  trong PR làm 311 test đỏ trên runner Windows có quyền Admin, và đã được viết lại
  trước khi merge.
- **Chứng chỉ Indexer với Python 3.13** (#112, #113, #116). Root CA của lab thiếu Key
  Usage nên bị kiểm chặt từ chối. CA được cấp lại với cùng khoá, không đổi dịch vụ
  Wazuh nào. Bộ thu live đã chạy nghiệm thu trên Python 3.13. Tài liệu ghi cách xử lý
  cho lab khác.

## CI

- Pull request đổi code riêng của Windows chạy thêm backend trên Windows/Python 3.13
  (#114, #115).
- `main` chạy Linux 3.11/3.12/3.13 và Windows 3.11/3.13.
- Lần chạy đầu trên `main`: Windows/3.13 3329 passed; Linux/3.13 3207 passed,
  89 skipped (test chỉ chạy Windows).

## Bằng chứng lab bổ sung (2026-09-27 tới 2026-10-01)

- SCN-003 lượt 7 thu bằng `aegis collect scn003` trùng 4 hash với script thu riêng,
  kết quả `Detected` (#95, #104).
- SCN-002 thu bằng `aegis collect scn002` (#104, #106):
  - lượt đối chứng ra `Inconclusive` đúng thiết kế;
  - lượt Block thật ra `Prevented`, 4/4 event được tham chiếu;
  - hai lỗi lab được ghi lại: agent Wazuh trên firewall ngừng đẩy log, và đồng hồ
    ETW của Sysmon.
- Diễn tập demo trên bản clone sạch; chạy toàn bộ test trên Linux khi Actions hết
  phút (#109).

## Giới hạn (không đổi)

- Công cụ cho một người vận hành, lab riêng; không phải production.
- Collection assurance do người vận hành xác nhận.
- Ba manifest kịch bản vẫn `status: draft`.
- Parser hiện có chỉ cho Wazuh, Suricata, pfSense và Cowrie. Elastic, OPNsense và
  Snort 3 cần connector mới (xem hướng dẫn tham gia).

## Nâng cấp

Không đổi định dạng bundle, profile, report hay fingerprint. Cài lại bằng
`pip install -e ".[test]"`. Bằng chứng cũ đánh giá lại được như trước.
