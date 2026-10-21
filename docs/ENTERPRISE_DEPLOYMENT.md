# AEGIS: lộ trình triển khai trong doanh nghiệp

## Ba hướng dùng chung core

Mong muốn hỗ trợ cả ba mô hình được ghi nhận; phiên bản EXE đầu tiên chỉ đưa
engine và giao diện hiện có đến máy Windows của người vận hành. Cài đồng loạt
cùng phiên bản và chia sẻ dữ liệu/tác vụ là hai khả năng cần kiểm riêng.

| Mô hình | Bản cục bộ cung cấp được gì | Còn phải hoàn thiện |
| --- | --- | --- |
| Mỗi máy chạy riêng | CLI, dashboard cục bộ, bundle offline và replay công khai | Pilot trên máy sạch, ký số/phê duyệt EDR theo chính sách và MSI cho rollout |
| Một người SOC thu từ nhiều thiết bị | Operations Wazuh với cấu hình riêng, allowlist và cửa sổ lịch sử có giới hạn; nhập bundle các nguồn được hỗ trợ | Onboarding môi trường, tài khoản quyền đọc, CA, chính sách dữ liệu và thử quy trình với người khác |
| Nhiều người dùng qua intranet | Dùng lại canonical schema, connectors và engine làm lõi | Dịch vụ, đăng nhập/phân quyền, HTTPS, lưu trữ và điều phối tác vụ, audit, vận hành và kiểm tải |

EXE/MSI không tự cài agent lên mọi endpoint, không tự chạy scenario, không tự sửa
rule và không bật thu liên tục cho mọi connector. Sự có mặt của connector parser
không đồng nghĩa đã có live reader của nguồn đó. Thu thập hoàn tất vẫn không tự
trở thành khai báo bảo đảm collection hay kết luận detection.

## Mốc 1 — Windows offline preview

Đóng gói từ installed wheel sạch; kiểm onedir rồi onefile. Giữ dashboard loopback,
chế độ report chỉ đọc và Operations opt-in. Không thay ground truth, canonical
schema hoặc logic đánh giá để làm bộ cài chạy qua. Bản preview chưa ký là artifact
thử nghiệm, phải ghi rõ nền tảng đã kiểm và giới hạn.

**Gate:** demo, UI/scenario, validation/comparison, EID và lỗi input chạy bằng
artifact ngoài checkout; kiểm trên máy không có Python/Node; giữ output bên ngoài
runtime. Xem [quy trình Windows](WINDOWS_DISTRIBUTION.md).

## Mốc 2 — Một người SOC, môi trường nhiều thiết bị

Giữ mô hình người vận hành duy nhất. Cấu hình môi trường và agent được cho phép,
tài khoản chỉ đọc và CA được doanh nghiệp quản lý; không nhúng endpoint hay
credential thật trong artifact phát hành. Chuẩn bị hướng dẫn nhập bundle từ các
nguồn ngoài live Wazuh, runbook, lưu giữ/xóa evidence và quy trình backup/restore.

**Giới hạn hiện tại:** Operations là cấu hình một môi trường, tối đa 100 agent
được khai báo; một collection worker chạy tại một thời điểm; tối đa 100 job trong
job store. Report store của dashboard giới hạn 200 file và report theo giới hạn
intake. Đây là giới hạn phần mềm, không phải số đo hiệu năng được bảo đảm cho
100 thiết bị hay 100 người dùng. Hai phiên không cùng ghi một output root.

**Gate:** người ngoài nhóm tự cài/chạy runbook, một collection được cho phép và
đối chiếu thật, quyền đọc được kiểm, xử lý lỗi mạng/CA/credential/thiếu đĩa, hash
và nguồn EID giữ được qua export. Đo khối lượng thực tế trước khi tăng giới hạn;
không mở lại các ngoại lệ nghiệm thu lab đã chốt để thay mốc pilot mới.

## Mốc 3 — MSI và quản lý phiên bản cho rollout

Tạo MSI thật cho cùng payload onedir đã kiểm, có thể dùng WiX làm dependency
build riêng với lý do và pin được review. Dữ liệu do người dùng tạo nằm ngoài
thư mục cài, có ACL và được giữ khi gỡ/nâng cấp; không chứa credential trong MSI.

**Gate:** ký số theo yêu cầu doanh nghiệp, silent install/uninstall, detection
rule/version, upgrade/rollback và repair, kiểm tài khoản thường/admin và không
tự reboot. Thử bằng chính gói tải xuống trong công cụ quản lý endpoint của doanh
nghiệp. Installer log và return code cần có runbook vận hành.
[Microsoft Installer command-line options](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options)

Triển khai MSI đồng loạt chỉ bảo đảm phần mềm được cài theo phiên bản. Nếu cần
đồng bộ report/baseline, lịch kiểm hoặc nhiều người cùng thao tác, thực hiện mốc
dịch vụ bên dưới với thiết kế riêng.

## Mốc 4 — Dịch vụ intranet nhiều người

Không đưa `http.server` hiện tại lên mạng để công bố một bản enterprise server.
Operations hiện bắt buộc loopback; token phiên/same-origin của nó không phải
tài khoản người dùng hoặc phân quyền. Thay host binding không bổ sung những
kiểm soát này.

Thiết kế/issue mới cần chốt tối thiểu:

1. **Danh tính và quyền:** đăng nhập tích hợp hệ thống doanh nghiệp; viewer,
   operator, admin; phạm vi theo môi trường; kiểm quyền trên API và evidence,
   không chỉ ẩn nút giao diện.
2. **Biên dịch vụ:** HTTPS, quản lý phiên, CSRF, kiểm request/body và rate limit;
   API/service phù hợp production, worker riêng, không cho browser giữ credential
   nguồn. Kiểm threat model và chính sách reverse proxy.
3. **Tác vụ/trạng thái:** persistent store, ownership theo người dùng, idempotency,
   concurrency, recovery sau crash, lịch kiểm có người chịu trách nhiệm và quota.
4. **Bằng chứng:** lưu giữ bất biến theo chính sách, hash/EID, đường truy nguyên,
   ACL, retention và xóa có kiểm soát; phân biệt raw evidence và dữ liệu trình bày.
5. **Audit:** ghi ai nhập dữ liệu, chọn profile, bắt đầu collection/evaluation,
   xem/xuất/xóa và duyệt kết quả; không đưa credential hoặc raw secret vào log.
6. **Vận hành:** service identity, secret store, certificate rotation,
   backup/restore, nâng cấp/rollback và health; kiểm tải theo số người dùng,
   nguồn, report, dung lượng và tần suất cụ thể.

**Gate:** review bảo mật và kiểm thử quyền chéo người dùng/môi trường; kiểm
backup phục hồi, restart/concurrency, upgrade và giới hạn tải thực tế. Dịch vụ
vẫn tái sử dụng canonical engine; mỗi kết luận phải dẫn về bằng chứng. Multi-tenant
giữa nhiều khách hàng là phạm vi riêng, hiện PRD chưa nhận yêu cầu đó.

## Hồ sơ cần có trước khi công bố sản phẩm

- Artifact theo phiên bản, hash, license/notice, source commit và build info.
- Quickstart, điều kiện hỗ trợ và giới hạn; phân biệt dữ liệu lab đã khử thông tin
  nhạy cảm, synthetic và bằng chứng gốc private.
- Biên bản kiểm runtime/pilot, lỗi còn mở và quy trình báo lỗi/nâng cấp.
- Danh sách tính năng thực có; không dùng nghiệm thu lab thay cho chứng nhận
  production, vận hành độc lập hoặc tính ổn định dài hạn chưa được đo.

Các mốc sau EXE cục bộ là kế hoạch, chưa được triển khai hoặc nghiệm thu bởi tài
liệu này. Phạm vi và acceptance criteria cần được duyệt trước khi thực hiện.
