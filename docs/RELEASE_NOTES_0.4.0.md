# AEGIS Verify 0.4.0 — Windows pilot packages

## Hai cách phân phối, cùng lõi đánh giá

| Gói | Dành cho | Tên artifact |
| --- | --- | --- |
| Windows Portable | Người vận hành, demo và dùng thử cục bộ | `AEGIS-Verify-0.4.0-Portable-x64.zip` |
| Windows MSI | IT cài ứng dụng cục bộ cho nhiều máy theo cùng phiên bản | `AEGIS-Verify-0.4.0-x64.msi` |

Cả hai dùng core **0.4.0**, cùng dashboard, sáu manifest và dữ liệu replay đã
review. EXE có PE FileVersion **0.4.0.0**, ProductVersion **0.4.0**; MSI dùng
ProductVersion **0.4.0**. Đây là artifact pilot chưa ký số, chưa công bố bản GA.

## Thay đổi

- Tích hợp gói standalone của PR #149, đã merge vào main tại `17dc5f9` sau khi
  sáu check đạt và review không còn lỗi chặn merge.
- Gán phiên bản Windows từ metadata của đúng installed wheel dùng để freeze.
- MSI thật chứa toàn bộ onedir runtime, giấy phép và metadata; cài per-machine
  vào Program Files, có shortcut Console và Quickstart. Không tự mở ứng dụng.
- Có cài im lặng, repair, gỡ cài và major upgrade; chặn hạ phiên bản. Nâng cấp
  dùng giao dịch Windows Installer, không giả phiên bản cho DLL phụ thuộc.
- Dữ liệu, evidence và cấu hình riêng của người dùng nằm ngoài thư mục cài;
  installer chỉ quản lý runtime/registration của ứng dụng.
- Thêm kiểm database MSI, đối chiếu bytes sau administrative extraction và bài
  thử lifecycle trên Windows runner dùng tạm. Xem hồ sơ JSON/log theo artifact.

Không đổi ground truth, fixture, connector, canonical schema hoặc engine.
Không tự chạy scenario, thay rule, truy cập SIEM hay tạo bằng chứng mới.

## Vận hành và kiểm chứng

Portable: làm theo `QUICKSTART.md` trong ZIP. MSI: xem
[hướng dẫn IT](WINDOWS_MSI.md). Lưu artifact cùng SHA-256, ProductCode,
UpgradeCode, build info, giấy phép và source commit.

[Hướng dẫn kiểm MSI](MSI_VALIDATION.md) phân biệt đọc database, extraction và
cài thật. Administrative extraction không đồng nghĩa đã thử cài/nâng cấp.
Bài upgrade dùng một MSI baseline **mô phỏng riêng cho CI**, không phải một
phiên bản production từng phát hành. Không lấy kiểm CI thay nghiệm thu chính
sách EDR, ký số hoặc người dùng thật của doanh nghiệp.

## Giới hạn còn lại

- Cần kiểm chính artifact được bàn giao với tài khoản thường trên máy Windows
  thuộc môi trường triển khai; cơ chế/phân quyền IT và chính sách ký số do bên
  triển khai duyệt. Không yêu cầu tắt EDR hay bỏ qua policy.
- MSI cài cùng phiên bản trên nhiều máy; không cung cấp tài khoản, RBAC, chia sẻ
  report hoặc chạy tác vụ đồng bộ giữa nhiều người.
- Chưa có Windows service, lịch chạy nền hay live Elastic collector. Operations
  và SSH vẫn cần cấu hình, quyền đọc, CA và kiểm nghiệm riêng.
- Mọi manifest vẫn `draft`; replay công khai không phải một lượt thử mới trên
  hệ thống doanh nghiệp. Các ngoại lệ/giới hạn nghiệm thu Lab A/B/C giữ nguyên.
- Quy trình build pin công cụ riêng, không thêm dependency runtime. WiX 5.0.2
  có giới hạn vòng đời được ghi tại hướng dẫn MSI; cần review lại pin khi chuẩn
  bị phát hành tiếp theo.

Hướng máy chủ nhiều người được mô tả riêng trong
[lộ trình doanh nghiệp](ENTERPRISE_DEPLOYMENT.md).
