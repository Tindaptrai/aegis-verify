# Kết nối Wazuh chỉ đọc — thiết kế chuẩn bị Issue #11

Trạng thái: implementation và offline tests đã qua review; đã thu thử trên lab
và kiểm hash/parser replay. Giới hạn collection và các gate còn lại được ghi
trong WAZUH_LIVE_CONNECTOR.md; không tuyên bố production-ready.
Hướng sản phẩm đã được chủ dự án chốt: kết nối chỉ đọc → trang Máy/Agents
→ chọn máy và chạy scenario. Tài liệu này cụ thể hóa bước kết nối.

## Phạm vi và thứ tự giao

1. Hoàn tất review dashboard Issue #10; phần biểu đồ đang ở worktree riêng.
2. Issue #11: lấy evidence từ Wazuh Indexer theo agent và cửa sổ thời gian,
   chuyển qua parser hiện có về canonical events, chạy validation offline.
3. Issue riêng: inventory từ Wazuh Server API và trang Máy/Agents.
4. Issue riêng: điều phối safe scenario trên target đã duyệt.

Không gộp quản lý máy hoặc thực thi từ xa vào acceptance criteria của #11.
Không sửa scenario ground truth để hỗ trợ live access.

## Hai nguồn dữ liệu

| Nguồn | Mục đích | Nơi tiêu thụ |
| --- | --- | --- |
| Wazuh Indexer Search API | Event/alert trong scope đã chọn | Parser nguồn → canonical → validation → report |
| Wazuh Server API | ID/tên máy, hệ điều hành, trạng thái agent, last keepalive nếu có | Inventory service và trang Máy/Agents ở issue tiếp theo |

Source-specific parsing và transport evidence thuộc connectors/wazuh/.
Validation engine chỉ nhận canonical events. Inventory là metadata quản lý,
không phải security event; schema inventory riêng cần review ở issue trang máy.
Không tạo canonical event giả từ trạng thái online/offline.

## Hợp đồng kết nối Issue #11

- Endpoint, index scope, agent và khoảng UTC bắt đầu/kết thúc là cấu hình tường minh.
  Không dò mạng hoặc tự chọn mọi index khi cấu hình thiếu.
- Secret nạp phía backend từ environment hoặc secret store được duyệt; không đưa
  xuống browser, URL, log hoặc report. Tài khoản chỉ có quyền đọc index đã cho phép.
- Xác minh TLS/hostname bắt buộc, hỗ trợ CA bundle local. Không tự chuyển insecure
  khi certificate bị từ chối. Không commit CA/certificate hoặc credential.
- Phân trang có thứ tự ổn định theo khả năng của phiên bản Indexer lab; phải kiểm
  chứng cơ chế snapshot/pagination trước khi chốt implementation. Cửa sổ thời gian
  được ghim một lần cho toàn bộ lần thu thập.
- Giới hạn page size, tổng records, bytes, timeout và số lần retry. Retry có backoff
  hữu hạn cho lỗi tạm thời/429; authentication, permission và TLS failure trả lỗi
  có mã an toàn. Không ghi raw response vào exception/log.
- Mỗi response được lưu trong kho local private cùng hash, query scope và manifest;
  tham chiếu raw xác định response và record. Không reserialize rồi gọi đó là bytes
  gốc. Contract tests so sánh mapping với fixture, phân biệt transport provenance.
- Timeout, shard failure, pagination lỗi hoặc chạm giới hạn → collection incomplete;
  không trả batch dở như một lần thu thập thành công. Empty query không tự chứng minh
  missing telemetry hoặc false negative.
- Chỉ route các profile nguồn đã được hỗ trợ và kiểm thử tương đương. Profile khác
  có diagnostic rõ ràng; không tự suy đoán hoặc silently drop.

Indexer alert query chỉ chứng minh phạm vi alert đã truy vấn. Không suy ra rằng
mọi telemetry nền đã được thu hoặc collection complete chỉ vì đã đọc hết pages.
Kết luận thiếu detection vẫn cần scope/collection declaration phù hợp engine.

## Trang Máy/Agents ở bước tiếp theo

- Hiển thị ID, tên, OS, source status, last keepalive và thời điểm AEGIS refresh.
- Giữ bốn trạng thái nguồn: active, disconnected, pending, never_connected.
  Không gom lỗi kết nối AEGIS thành disconnected của tất cả máy.
- API lỗi: giữ snapshot cũ có nhãn stale, hiển thị lỗi refresh; trường thiếu là null.
- Bộ lọc/search và trang chi tiết dẫn tới report theo mapping agent identity đã review.
- Không gọi online là an toàn hoặc detection passed; dữ liệu inventory và verdict
  hiển thị riêng. Nút chạy scenario chỉ bổ sung sau khi execution workflow sẵn sàng.

## Kiểm chứng trước tích hợp

Unit/contract tests chạy hoàn toàn offline bằng transport giả và fixture sanitized:
TLS mặc định, redaction, 401/403, 429, retry exhaustion, timeout, nhiều pages, empty,
partial/shard failure, giới hạn input, profile không hỗ trợ và canonical equivalence.
Sau đó operator dùng quyền read-only đối chiếu lab version, CA, query scope, raw refs,
canonical fields và cleanup local artifact. Lab validation không thay unit tests.

## Thông tin cần xác nhận tại lab

- Chủ dự án xác nhận vẫn dùng Wazuh 4.14.4 trong phiên này; cần đối chiếu
  Indexer protocol/mapping và quyền truy cập khi kiểm chứng lab.
- Endpoint Indexer, index scope và CA bundle local; quyền đọc thực tế.
- Một agent thử nghiệm và khoảng thời gian có telemetry đã biết.

Các giá trị riêng tư cấu hình local; không yêu cầu gửi password/token vào chat.
Setup/teardown sẽ hướng dẫn nạp/gỡ cấu hình, dừng collector, thu hồi quyền khi cần,
và quản lý retention evidence local. Không ghi thay đổi vào Wazuh.

## Tài liệu nguồn

- https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html
- https://documentation.wazuh.com/current/user-manual/api/reference.html
- https://github.com/Tindaptrai/aegis-verify/issues/11

Tài liệu current được dùng để xác định vai trò hai API; chi tiết protocol phải
đối chiếu phiên bản lab trước implementation.

Implementation local dùng scroll snapshot với TTL một phút, xử lý offset Wazuh
không có dấu hai chấm, scope ba profile Windows tường minh và giới hạn 100 records
để tương thích intake. Hướng dẫn chạy/giới hạn: `WAZUH_LIVE_CONNECTOR.md`.
Không gọi lại scroll khi mất response vì cursor có thể đã tiến; chỉ retry 429
hữu hạn. Record derivatives được đánh dấu serialization và liên kết raw response.
