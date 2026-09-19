# V1 demo/lab — dự thảo ghi chú phát hành

Trạng thái: chủ dự án đã duyệt push và tạo PR tài liệu; chưa duyệt merge PR này
hoặc tạo tag/GitHub Release.
Baseline code: `a3990089d7a05b6f59a0ef7a35b5eafa7da10944`.
Tài liệu bàn giao bổ sung chưa nằm trong baseline này.

## Nội dung

- PR #28: optional native-review input cho demo evaluator; giữ nguyên quy tắc verdict.
- PR #29: collector Wazuh Indexer HTTPS chỉ đọc, giới hạn dữ liệu, scroll cleanup,
  adaptive split cho overflow, provenance và canonical parser dùng chung.
- PR #30: biểu đồ dashboard, hardening cấu trúc dữ liệu và hiển thị run binding.
- CLI, comparison và safe-demo workflow hiện có được giữ nguyên.

## Kiểm thử trước merge (2026-09-19)

- 2660 backend tests đạt; 1 FIFO test bỏ qua trên Windows (259.47 giây).
- 59 frontend tests đạt; TypeScript/Vite build đạt.
- Integration tree và main sau merge giống nhau: `15cd65013d2c3030748553b34e96ff8d30943f7e`.
- Wheel và HTTP smoke checks đạt trong lượt tích hợp trước đó.
- Đây là kiểm thử local, không phải GitHub Actions CI hay production certification.

## Giới hạn công bố

- Dashboard chỉ đọc báo cáo, không phải bộ điều phối scenario hoặc fleet monitor.
- Historical binding unknown; collection declaration không phải xác minh độc lập.
- Quyền tài khoản Indexer đã được operator review qua giao diện: chỉ role đọc
  được review, không role khác theo xác nhận của chủ dự án. Chưa có kiểm chứng
  tự động toàn bộ quyền hiệu lực/action groups; không gọi đây là chứng nhận bảo mật.
- Không công bố dữ liệu lab riêng, credential, certificate hoặc raw telemetry.
- Rule demo có giới hạn precision; cần follow-up riêng trước dùng ngoài lab.
- Chưa chọn license phân phối. Không tự thay version package hay scenario ground truth.

## Cần duyệt trước phát hành

1. Review và duyệt merge PR tài liệu bàn giao (push/tạo PR đã được duyệt).
2. Xác nhận phạm vi demo/lab cùng các giới hạn trên.
3. Chọn tag, ví dụ `v0.1.0-lab.1`, và commit cuối cùng sau khi tài liệu được merge.
4. Quyết định nơi backup riêng được phép nhận evidence; không upload mặc định.
