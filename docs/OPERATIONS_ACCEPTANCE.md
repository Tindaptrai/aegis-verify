# SCN-001 local lab MVP — nghiệm thu và bàn giao

Ngày ghi nhận: 2026-09-20 (Asia/Saigon). Phạm vi: local single-operator,
read-only source inventory/collection; không phải dịch vụ production hay bộ tự
động chạy scenario. Xem [hướng dẫn vận hành](OPERATIONS.md).

## Trạng thái quyết định

**Chủ dự án đã chốt phạm vi SCN-001 local lab MVP ngày 2026-09-20;
chưa merge/tag/release.** Milestone gồm workflow demo/evidence/evaluation và
so sánh trước–sau của SCN-001, Reports cùng hai luồng live Agents/Collections
đã kiểm chứng bên dưới. Việc tích hợp vẫn cần review bộ PR phụ thuộc, CI của
đúng commit và bằng chứng riêng.

SCN-002/003 chỉ có manifest draft, chưa nghiệm thu live; chủ dự án đồng ý để
giai đoạn sau. Chúng **không phải điều kiện đóng milestone SCN-001 này**.
Quyết định thu hẹp milestone không sửa PRD gốc, manifest, ground truth hoặc
nâng mức bảo đảm của evidence. Đây không phải nghiệm thu toàn bộ PRD hay
tuyên bố production-ready.


## Phiên bản và kiểm chứng

- Source revision: `3fa2ab1df9b0dfd212bb7d05a57f515878e7670f`
  ([PR #42](https://github.com/Tindaptrai/aegis-verify/pull/42)), base
  `d5660177a0ecf26f1c2d9f609e8091337be8fc12` ([PR #41](https://github.com/Tindaptrai/aegis-verify/pull/41)).
- Live UI acceptance diễn ra trên working tree trước commit UI. Runtime source
  và frontend build không đổi từ lần live đó tới commit này; chỉ bổ sung hướng
  dẫn vận hành trước commit. Không gán kết quả live cho runtime revision khác.
- Local full backend trên source tree này: **2852 passed, 2 skipped**, 361.58s.
  Hai skip là FIFO không có trên Windows và phép kiểm POSIX mode. Dùng
  `-q -rs -p no:cacheprovider --basetemp <fresh-private-temp>`.
- Frontend: **78 passed**, TypeScript/Vite production build đạt; launcher suite
  riêng **52 passed**. `pip check` và isolated wheel build đạt; `git diff --check`
  không có lỗi whitespace.
- CI PR #40/#41 đã pass tại lần kiểm trước. Kiểm lại ngày 2026-09-20:
  UI #42 tại `3fa2ab1` và tài liệu #43 tại `4b5e814` đều pass bốn matrix
  Windows/Linux Python3.11/3.12, frontend và GitGuardian. Mọi commit tài liệu
  sau đó vẫn phải có CI riêng; kết quả này không đại diện cho HEAD mới.
- Issue39 chỉ thay tài liệu/README, không sửa runtime, tests, ground truth hoặc
  evidence. Commit tài liệu và trạng thái hosted CI cuối cùng nằm trong PR
  nghiệm thu; phải kiểm đúng HEAD trước merge, không dựa vào snapshot cũ này.

## Bằng chứng nghiệm thu (đã lược thông tin lab)

Các mã dưới đây là tham chiếu hồ sơ kiểm thử riêng, không phải canonical event
IDs hoặc chứng thực thu thập. Chúng không được dùng làm bằng chứng cho verdict.
Mật khẩu, CA, hostname, endpoint, raw responses và credential helper cục bộ không
nằm trong repository.

| Kiểm tra | Kết quả / căn cứ |
| --- | --- |
| Server API TLS | Xác minh CA/hostname bật; fingerprint chứng chỉ bản sao khớp thông tin từ operator. Không dùng insecure mode. |
| Quyền Server API | Operator chạy bằng identity riêng: login200; target đọc được; agent ngoài scope403; danh sách chỉ có target. Không bật run-as. |
| Inventory UI | PASS, `INV-UI-20260919T200147Z`: bấm refresh, đúng một agent, tên/OS/status/keepalive/fetch time hiển thị. Status không phải kết luận máy an toàn. |
| Collection rỗng | PASS, `COL-UI-20260919T200450Z`: một phút lịch sử, completed/0 records/query_complete=true, cleanup_failed=false. Không tạo false-negative từ dữ liệu rỗng. |
| Collection có dữ liệu | PASS, cùng hồ sơ: năm phút lịch sử, 157 records/157 canonical events, 5 collection thành công, 16 response files; tổng count và toàn bộ manifest/response hash khớp. |
| Lịch sử và reload | PASS: reload giữ job đã chọn và hai job hoàn tất, không tạo job mới. |
| Metadata HTTP | PASS với hai job quan sát: không có trường password, Authorization, session token, endpoint, CA path hoặc response-file body trong job metadata. Bootstrap có session token theo thiết kế, chỉ giữ trong bộ nhớ client. Không tuyên bố đây là audit đầy đủ mọi kênh. |
| Private evidence root | PASS trên Windows không nâng quyền, kiểm ownership/current-user-only inherited ACL bằng preflight thật. Bundle giữ ngoài source/reports/static. |
| Restart giữa job / gián đoạn nguồn | Có regression tests; chưa fault-inject trên lab thật trong đợt này. Không khai là live-pass. |
| Màn hình nhỏ / accessibility toàn diện | Keyboard confirmation và desktop đã kiểm; chưa chứng nhận mobile/audit accessibility đầy đủ. |

`collection_assurance` vẫn là `unknown`. Count/hash khớp chứng minh tính nhất
quán của bundle đã lưu, không chứng minh upstream không mất log. Chưa tạo verdict
mới từ hai bundle nghiệm thu; đánh giá vẫn qua workflow explicit hiện có.

Hai phiên launcher PowerShell trước đó báo authentication_failed, trong khi
operator chạy direct Python và production connector thành công. Phiên live đạt
dùng helper Python riêng nhập credential ẩn, giữ cùng giá trị trong tiến trình
server. Nhầm hai mật khẩu là giả thuyết operator nêu, chưa chứng minh nguyên
nhân. Không đổi quyền hoặc tắt TLS để vượt lỗi. Helper này không phải entrypoint
được phân phối trong repo; launcher chính thức là `Start-Aegis.ps1`.

## Đối chiếu PRD gốc

| Yêu cầu | Bằng chứng có sẵn / giới hạn |
| --- | --- |
| 3 scenarios | Ba manifest SCN-001/002/003 được test loader giữ nguyên bytes/IDs, đều còn draft. Chưa có nghiệm thu live SCN-002 và SCN-003 trong đợt này. |
| 4 connectors | Tests fixture Wazuh, Suricata, pfSense, Cowrie đi qua parser riêng và canonical model. Không tuyên bố bốn live connectors; chỉ Wazuh có live collection trong phạm vi này. |
| Canonical + validation | Suite models/validation và `test_cli_acceptance.py` kiểm evidence IDs, distinct activity/alert, thiếu evidence, prevention và attestation synthetic. Synthetic không thay lab proof. |
| Timeline + regression | `test_cli_timeline.py`, `test_cli_compare.py`, comparison contract; fixture và report UI dùng kết quả engine, không tự tính verdict. |
| Demo Gap → Rule Fix → Re-test | Hồ sơ lịch sử [SCN-001 v2](SCN001_V2_APPROVAL_AND_PINS.md) và [pins](evidence/scn001-v2-pins.json) chứa references/hash. Không chạy lại payload hoặc đổi rule trong đợt Operations. |
| Run binding / collection assurance | Report lịch sử vẫn có unknown/native_review_missing; không sửa ground truth hoặc tự nâng thành lab_verified. |

Milestone được trình review là **SCN-001 local lab MVP** theo quyết định trên,
không phải toàn bộ PRD đã nghiệm thu live đầy đủ. Live SCN-002/003 sẽ cần issue,
phạm vi và approval riêng ở giai đoạn sau; không tự mở rộng issue này.

## Checklist bàn giao còn mở

- CI trên đúng commit UI/acceptance; ghi lại commit và kết quả trước quyết định merge.
- Chủ dự án review tài liệu, các giới hạn và private evidence references.
- Review theo thứ tự backend → inventory → UI → acceptance; không bỏ qua check
  bảo mật hoặc force-push để làm xanh CI.
- Nếu chọn merge: chạy lại kiểm tra cần thiết trên tree tích hợp trước khi đặt tag.
- Tên tag/release và quyết định công bố cần chủ dự án duyệt; không tự tăng version.

## Vận hành và phục hồi

1. Dùng checkout đã duyệt, normal PowerShell, config riêng và root owner-only.
2. Nhập riêng credential Server API và Indexer; giữ tunnel nếu cấu hình dùng tunnel.
3. Reports mặc định; bật Operations bằng `-OperationsConfig`. GET snapshot không
   gọi Wazuh, refresh chủ động có cooldown; stale không đồng nghĩa disconnected.
4. Thu thập theo agent/UTC scope đã duyệt, review rồi submit, một job mỗi lần.
5. Chờ job kết thúc rồi Ctrl+C. Nếu dừng cưỡng bức, giữ evidence và điều tra
   interrupted/corrupt state; không xóa metadata để giả hoàn tất.
6. Sao lưu source đã commit và evidence riêng thành hai phần; so hash trước/sau.
   Backup cùng ổ không thay thế bản sao độc lập. Không đưa raw evidence vào Git.

Giới hạn đã biết: CLI startup có thể chỉ báo internal_error an toàn; xem cấu
hình/preflight thay vì nới ACL. Inventory nhiều trang không phải snapshot đồng
thời tuyệt đối. Deadline kiểm trước/sau I/O; socket đang chờ có thể kéo dài việc
dừng. Trust boundary là một operator cục bộ; không chống tiến trình độc hại chạy
cùng tài khoản. Không có queue, tự chạy scenario, tự đánh giá hay tự sửa rule.
