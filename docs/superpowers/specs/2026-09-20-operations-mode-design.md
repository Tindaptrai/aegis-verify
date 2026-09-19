# V1.1 — chế độ vận hành local: collection và Agents

Trạng thái: chủ dự án đã duyệt đặc tả trong hội thoại ngày 2026-09-20.
Kế hoạch triển khai cũng đã được duyệt, thực hiện trực tiếp trong task hiện tại.
Baseline: main `03a6fbb2293e56145cc6742085cdc315c9df00c9`.

## 1. Mục tiêu và ranh giới

Người vận hành muốn chọn máy/khoảng thời gian để thu evidence mà không phải
nhập lại nhiều lệnh, đồng thời xem trạng thái agent từ Wazuh. Thành công nghĩa
là thao tác được trên dashboard, có tiến độ/lỗi rõ, credential không ra browser,
và trạng thái máy không bị nhầm với verdict detection.

- Bước 3: điều phối collector Indexer hiện có từ UI.
- Bước 4: inventory/status từ Wazuh Server API, ghép vào UI theo agent ID và
  environment ID được cấu hình, không ghép theo tên máy.
- Giữ dashboard report-only mặc định. Không cấu hình live vẫn đọc report như cũ.
- Không chạy scenario, remote shell, active response, sửa rule, đăng ký/xóa/restart
  agent, tự cấp quyền, tự tạo attestation hoặc đổi scenario ground truth.
- Không biến collection thành evaluation. Trong đợt này không tự tạo report
  detection từ bundle mới: profile/context cần review qua luồng evaluation hiện có.
- Không multi-user/auth SaaS. Chỉ operator local; không phục vụ qua mạng LAN.

## 2. Lựa chọn kiến trúc

Đã chọn: mở rộng server stdlib hiện có bằng operations service **opt-in**, giữ
report-only routes và UI mặc định. Không tạo backend web framework mới.

Các phương án không chọn: bật write/job routes mặc định (đổi ranh giới tin cậy
của dashboard cũ); dựng service/web framework độc lập (thêm deployment và dependency
không cần thiết cho scope local hiện tại).

Phân tách trách nhiệm:

1. Transport/parser Indexer trong `connectors/wazuh/` giữ canonical schema và
   raw provenance hiện có. Operations gọi API Python có kiểu, không ghép shell command.
2. Adapter Server API chỉ đọc nằm ở lớp integration nguồn Wazuh. Nó trả inventory
   metadata theo schema riêng được review, **không tạo canonical event giả**.
   Đây là ngoại lệ metadata quản trị đã được nêu trong `ISSUE_11_CONNECTION_DESIGN.md`;
   mọi output evidence/security-event vẫn dùng canonical schema.
3. Operations service giữ config bất biến, một worker collection, snapshot inventory
   và trạng thái job. Validation engine không biết vendor fields hay inventory.
4. Frontend thêm các trang Agents và Collections khi backend báo operations enabled.
   Trang Reports hiện có không đổi semantics.

## 3. Cấu hình và credential

- Bật bằng tùy chọn CLI `--operations-config <local-file>`; launcher chuyển tiếp
  tùy chọn này chỉ khi operator truyền rõ. Không có tùy chọn: operations routes tắt.
- Config versioned chứa environment ID, danh sách agent ID cho phép (1..100),
  approved index pattern, private output root, và hai nhóm connection config.
- Endpoint HTTPS và đường dẫn CA là cấu hình local, không hard-code. Credential
  lấy từ environment phía process, tách nhóm Indexer và Server API.
- Không mặc định dùng lại `aegis_reader` cho Server API; quyền/token/TLS của nguồn
  inventory cần operator cấu hình và review riêng. Không dùng admin để chữa 403.
- UI không nhận credential, endpoint, index pattern, đường dẫn CA hay output root.
  Nó chỉ nhận tên environment hiển thị, allowlisted agent IDs và capability flags.
- Config sai cấu trúc, agent scope rỗng, output root không hợp lệ: không khởi động
  operations. Nguồn chưa cấu hình được hiển thị `not_configured`, không giả online.
- Chỉ file local; reject network/provider syntax, traversal, symlink/reparse
  và output root trùng/nằm trong thư mục Reports/static hoặc checkout source.
- Output root phải tồn tại, được operator chuẩn bị riêng với quyền owner-only.
  Preflight kiểm quyền: POSIX owner/mode; Windows dùng truy vấn ACL read-only qua
  PowerShell với đối số riêng, không ghép chuỗi từ request. Không xác minh được
  quyền thì collection bị khóa; không tự sửa ACL hay execution policy.

## 4. Ranh giới HTTP local

Operations mode chỉ bind địa chỉ loopback cố định; không wildcard host hoặc proxy.
Điều này không thay thế bảo mật máy operator: tiến trình local cùng user vẫn ở
trong ranh giới tin cậy.

- Kiểm Host chính xác với address/port đang bind, chống DNS rebinding.
- Không CORS. Operations bootstrap và API yêu cầu custom request header để chặn
  request từ form/image và cross-origin fetch đơn giản; reject cross-site Fetch
  Metadata, kiểm Origin đối với mutation.
- Sinh session token ngẫu nhiên khi server khởi động; cấp qua bootstrap chỉ cho
  request same-origin hợp lệ. Token nằm trong bộ nhớ UI, không URL/localStorage,
  không phải credential Wazuh. Mutation yêu cầu token + Origin chính xác + JSON.
- Request body tối đa 8 KiB; reject unknown keys/content type; không nhận raw
  query DSL, đường dẫn, câu lệnh hoặc URL từ browser. Token không ghi log.
- Mọi lỗi transport trả fixed code, không stack trace, raw response hay secret.
- Không HTTP endpoint để tải raw evidence. Server report-only không được trỏ
  vào output root; collection không tự thêm bundle thô vào danh sách Reports.

## 5. Collection: input, trạng thái và giới hạn

UI cho chọn một agent được phép, UTC start/end và adaptive on/off. Nhãn input
ghi rõ UTC; cửa sổ được chốt một lần khi xác nhận. Mặc định adaptive bật.
Server validate cả input, không chỉ frontend: start < end, end không tương lai,
cửa sổ tối đa 24 giờ, ID đúng allowlist, environment/index lấy từ config.

- Chỉ một job đang chạy, không queue. Request trùng client request ID trả lại job
  cũ; ID dùng lại với input khác hoặc job thứ hai trả conflict.
- State: running → completed hoặc failed; process khởi động lại đánh dấu job
  chưa kết thúc là interrupted. Không tự retry/resume hoặc chạy lại.
- Tiến độ chỉ hiển thị giai đoạn và số đếm đã xác nhận, không phần trăm giả.
  Có thể bắt đầu bằng trạng thái running và chỉ công bố record count khi collector
  trả kết quả; không đọc bundle chưa hoàn tất để suy ra kết quả.
- Giữ nguyên bounds collector: 100 records/leaf, TLS/timeout/bytes, cleanup,
  adaptive chỉ chia khi overflow; không nới limits để tránh lỗi.
- Success gồm record count, query completeness và cleanup flag. Empty là completed
  với 0 record, không thành False negative; cleanup failure là cảnh báo rõ.
- Adaptive child failures và mọi INCOMPLETE không được đánh dấu thành công.
- Server tự sinh UUID và thư mục mới dưới private root, không ghi đè. Metadata
  job không chứa credential; raw artifacts giữ nguyên provenance hiện có.
- Tối đa 100 job metadata mỗi root trong phiên bản đầu; đạt ngưỡng thì từ chối job
  mới và hướng dẫn operator lưu trữ riêng. Không tự xóa dữ liệu.
- Metadata được lưu local bằng atomic replace, đọc lại khi khởi động; giới hạn
  100 áp dụng cả các phiên trước. Metadata hỏng hoặc vượt giới hạn làm khóa submit
  với lỗi cố định, không bỏ qua để chạy thêm job và không tự sửa/xóa evidence.
- Admission kiểm ít nhất 2 GiB disk free trước job; I/O error vẫn giữ evidence
  và báo failed. Đây không phải cam kết đủ dung lượng cho mọi tình huống.
- Không nút cancel ở đợt này; khi dừng ứng dụng, ngừng nhận job mới, cho collector
  kết thúc theo bounds hiện có. Dừng cưỡng bức có thể để INCOMPLETE, UI nêu rõ.

## 6. Inventory/status

Server API sử dụng tài khoản read-only cho GET agents theo allowlist. Authentication
token chỉ ở backend, sống trong memory; endpoint login là ngoại lệ cần thiết để
lấy token, không mở các API quản trị. TLS/hostname bắt buộc, không redirect/proxy
ambient, không insecure fallback.

Inventory schema v1 gồm environment_id, agent_id, name, os_name, os_version,
source_status, last_keepalive, fetched_at. Trường nguồn thiếu là null; giữ raw
status không nhận diện với nhãn UI unknown, không đoán disconnected.

- Source status: active/disconnected/pending/never_connected; UI ghi rõ đây là
  trạng thái agent theo Wazuh, không phải ping máy hay xác minh máy an toàn.
- Giới hạn 100 agent cấu hình, page size 50, tối đa 10 pages, 1 MiB/response,
  5 MiB tổng, timeout socket 10 giây, deadline refresh 60 giây kiểm giữa requests.
  Request đang chạy có thể vượt deadline tối đa timeout; không gọi là hard deadline.
- Kiểm failed_items, duplicate IDs, scope và total trước publish snapshot. Không
  trộn nửa snapshot mới vào snapshot cũ nếu có lỗi; đây không phải atomic snapshot
  phía Wazuh và phải công bố giới hạn thay đổi giữa pages.
- Một refresh tại một thời điểm, khoảng cách tối thiểu 30 giây. Bản đầu chỉ refresh
  khi operator bấm nút Refresh, không tự gọi nguồn khi mở trang hoặc chạy nền.
  UI hiển thị cảnh báo rate-limit.
- Snapshot quá 60 giây hoặc lần refresh lỗi được đánh dấu stale. Giữ fetched_at,
  last_keepalive và safe error; chưa từng thành công thì hiển thị unavailable.
- Server API lỗi không khóa collection lịch sử của agent đã được cấu hình.
  Agent inactive cũng không ngăn đọc dữ liệu lịch sử; UI chỉ cảnh báo.

## 7. UI và API contract dự kiến

Routes namespace `/api/operations/`, không đổi report JSON contract hiện tại:

| Route | Chức năng |
| --- | --- |
| GET bootstrap | Capabilities, environment label, agent allowlist và session token |
| GET agents | Snapshot hiện có và freshness, không tự gọi Wazuh mỗi request |
| POST agents/refresh | Bắt đầu refresh bounded, chống trùng/rate-limit |
| GET collections | Tóm tắt tối đa 100 job metadata |
| POST collections | Submit validated agent/window/adaptive/client request ID |
| GET collections/{id} | Trạng thái và kết quả metadata của job |

UI poll trạng thái tối đa mỗi 2 giây khi đang xem job, dừng khi terminal hoặc rời
trang. Tách lỗi cấu hình, lỗi nguồn và lỗi collection. Reports vẫn có trang riêng;
không nối report với máy bằng tên gần giống hoặc ID suy đoán.

## 8. Tests và nghiệm thu

Fixture/transport fake trước, không cần credential/lab trong CI:

- Report-only mặc định vẫn từ chối operations và render báo cáo cũ.
- Host/Origin/token/content-type/body-size, replay request ID, allowlist, path
  traversal, thiếu config/credential và không rò secrets/raw payload.
- Job success/empty/overflow/error/cleanup-warning, duplicate submit, restart
  interrupted, giới hạn admission và evidence không ghi đè.
- Inventory mapping/null/unknown, pagination/partial/duplicate, expired token,
  TLS/401/403/429/timeouts, stale không biến thành disconnected.
- UI bằng synthetic fixtures: chọn agent/window, xác nhận, progress/error/stale,
  thao tác bàn phím, trạng thái disabled và không đổi verdict.
- Chạy full backend, frontend tests/build và CI Windows/Linux trước mỗi PR merge.
- Lab acceptance riêng: operator cấu hình Server API read-only + CA, đối chiếu
  một refresh agent và một collection ngắn với Wazuh. Không chạy payload để test.

## 9. Chia issue và trình tự

Sau khi đặc tả và kế hoạch được duyệt, tạo các issue nhỏ theo dependency:

1. Operations config/security/job service, default-off và API fixture-tested.
2. Wazuh inventory adapter/schema và snapshot refresh, fixture-tested.
3. Trang Agents/Collections và tích hợp launcher; end-to-end fixture tests.
4. Operator lab validation và hướng dẫn cấu hình, không trộn quyền quản trị.

Mỗi issue có acceptance criteria và PR riêng. Không merge/tag/release tự động.
Tag V1 và dashboard lab đang chạy không bị thay thế trong giai đoạn thiết kế.

## 10. Tài liệu tham chiếu

- [Ranh giới kết nối hiện có](../../ISSUE_11_CONNECTION_DESIGN.md)
- [Collector hiện có](../../WAZUH_LIVE_CONNECTOR.md)
- [Wazuh Server API](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html)

Endpoint/schema và quyền cụ thể phải được đối chiếu với phiên bản lab khi triển khai;
không giả định credential Indexer dùng được cho Server API. Không yêu cầu gửi mật
khẩu vào hội thoại và không tự thay đổi quyền để vượt lỗi kết nối.
