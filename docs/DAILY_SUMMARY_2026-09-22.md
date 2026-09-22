# Tổng kết ngày 2026-09-22 — SCN-002 đạt `Prevented`

## Đã merge vào `main`

| PR | Nội dung |
| --- | --- |
| #59 | Rule marker Suricata SID 1000010 (template, test, tài liệu) |
| #62 | `wazuh-sysmon3-archive-v1` nối vào bundle intake (#60) |
| #64 | EvaluationProfile công khai SCN-002, bindings để trống, test offline (#63) |
| #65 | Sửa mô tả A04 theo đúng detection chứng minh được, pin lại fingerprint |
| #66 | Parser `wazuh-suricata-alert-v1` cho A04 (#61) |
| #68 | Bundle CLI tổng hợp bốn nguồn chạy end-to-end ra `Prevented` (#67) |
| #70, #71 | Runbook lượt Block gate D và điều kiện vào bổ sung (#69) |
| #72 | Cửa sổ tương quan ±2 s theo số đo lab |
| #73 | Tài liệu kết quả này |

## Trên lab, do chủ dự án thao tác từng bước

- Phát hiện agent Wazuh máy gửi đã dừng từ ngày 21; bật lại, xác nhận Active.
- Máy nhận mất IP; đặt lại bằng NetworkManager.
- Lượt đối chứng `72340d49…`: `Inconclusive` đúng kỳ vọng, A01, A02, A04 đạt.
- Đo lệch giờ, siết cửa sổ ±2 s (PR #72).
- Sao lưu pfSense, thêm rule chặn có log cho một máy gửi, kiểm `pfctl -sr`.
- Lượt Block `2fb0b770…`: **`Prevented`**, exit 0.
- Hoàn tác: disable rule, kiểm, probe đối chứng `93e61a39…`.

Chi tiết và hash: [SCN002_RESULT_2026-09-22.md](SCN002_RESULT_2026-09-22.md).

## Việc còn lại

- Chủ dự án xác nhận receiver và việc xoá rule (mục 8 của tài liệu kết quả).
- Đóng issue thiết kế SCN-002 sau khi review verdict.
- Việc sau, không gấp: chuẩn hoá `protocol` ở parser Suricata; trạng thái so
  sánh riêng cho "được phép → bị chặn" trong `aegis compare`; rule Wazuh tương
  quan nhiều nguồn nếu muốn A04 theo nghĩa cũ.
