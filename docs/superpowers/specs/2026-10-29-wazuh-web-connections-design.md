# Kết nối Wazuh qua web và phục hồi kết nối agent

Ngày: 2026-10-29. Trạng thái: chủ sản phẩm duyệt thiết kế và giao triển khai
lát 1 cho Wazuh 4.14.4 kèm hướng dẫn account đọc/public CA ngày 2026-10-29.
Mốc nguồn đã đối chiếu: `ae7399b84c6a276dc7145e056ad33e6a7417ef89`.

## Mục đích và lựa chọn

Người dùng muốn cài một lần, vận hành AEGIS qua web hằng ngày, ít sao chép
lệnh và thông số kỹ thuật. Chủ sản phẩm đã đồng ý hướng HTTPS trực tiếp và
trang Kết nối có hướng dẫn. Chi tiết bên dưới là đề xuất của người thiết kế;
chưa phải hành vi đã triển khai hoặc kết quả lab.

Ba cách đã cân nhắc:

| Cách | Lợi ích | Đánh đổi |
| --- | --- | --- |
| Tunnel SSH tự chạy bằng systemd | Giữ nguyên source và PKI lab đang chạy | Thêm tài khoản/key SSH, chẩn đoán hai lớp kết nối |
| HTTPS trực tiếp, cấu hình Wazuh qua web — hướng được chọn | Ít thành phần vận hành; nhìn thấy trạng thái trong Manager | Cần mở đường mạng đúng phạm vi, SAN đúng tên/IP và quản lý source theo phiên bản |
| Tiếp tục tunnel thủ công | Không đổi triển khai hiện tại | Phụ thuộc cửa sổ SSH; không đáp ứng mục tiêu dễ dùng |

Giữ Django, React, reader HTTPS và engine hiện có. Không thêm dependency ở
bản đầu. Chưa chuyển source đang chạy; tunnel hiện tại vẫn phục vụ lịch sử
và tác vụ hiện có cho tới khi chuyển đổi được xác nhận.

## Phạm vi và thứ tự thực hiện

Đây là ba lát triển khai, mỗi lát có issue, nhánh, kiểm thử và review riêng:

1. **Kết nối Wazuh qua web**: nhập/test/lưu cấu hình riêng tư có phiên bản;
   hướng dẫn tích hợp theo phiên bản, worker quản lý cấu hình mới; trang trạng
   thái và gói nâng cấp Ubuntu.
2. **Agent chịu được gián đoạn tạm thời**: tái hiện lỗi transport execution,
   sửa phân loại lỗi nếu được chứng minh, kiểm tra tự kết nối lại cùng UUID.
3. **Thiết lập thực thi có hướng dẫn**: chọn source/release/máy, tự lấy các
   pin đã review, chuyển source bằng binding mới và xác nhận cục bộ khi cần.

Lát 1 kết thúc ở kiểm tra/lưu/chọn candidate, với managed worker ở trạng thái
chờ cấu hình. Không kích hoạt worker collection qua form binding kỹ thuật cũ;
không cung cấp đường kích hoạt CLI ngầm. Lát 3 mới kích hoạt nguồn, thay form
kỹ thuật bằng lựa chọn đơn giản và chuyển máy hiện tại sang nguồn mới. Các
test active worker ở lát 1 dùng state fixture riêng; lab chỉ nghiệm thu trạng
thái chờ an toàn. Không quảng bá lát 1 là toàn bộ onboarding một nút đã hoàn
tất. Mỗi lát cần chủ sản phẩm review và lab trước khi merge.

MVP vẫn là một môi trường, một nguồn Wazuh được quản lý đang hoạt động, một
tác vụ thực thi tại một thời điểm. Nguồn legacy được bảo tồn trong quá trình
chuyển đổi. Chưa hỗ trợ đội worker nhiều nguồn, chạy hàng loạt, tự sửa rule,
inventory Wazuh Server API hoặc thực thi Linux. Catalog ZIP không trở thành
script có quyền thực thi khi xuất bản. Ground truth không thay đổi.

## Trải nghiệm trang Kết nối

Giữ sidebar, logo, màu và typography Manager hiện tại. Mở mục **Kết nối**.

Trang chính hiển thị nguồn Wazuh với tên dễ nhớ, địa chỉ HTTPS, thời điểm kiểm
tra, trạng thái truy vấn và worker. Thẻ nguồn legacy ghi rõ chỉ đọc, đang dùng
đường kết nối hiện có. Không đưa credential/path vào phản hồi API.

Nút **Thêm Wazuh** mở ba bước:

1. **Thông tin kết nối**: tên hiển thị, địa chỉ HTTPS Indexer (khác địa chỉ
   Wazuh Dashboard), tài khoản chỉ đọc, mật khẩu và file public CA PEM.
   Index mặc định theo profile triển khai, hiển thị trong phần Nâng cao;
   không có trường UUID, revision, đường dẫn file hay ô bỏ kiểm tra TLS.
2. **Kiểm tra**: kiểm tra địa chỉ theo policy, chứng thư, xác thực và một
   truy vấn `size:0` có giới hạn trên index. Hiển thị từng kết quả và hướng
   xử lý bằng tiếng Việt. HTTP 401 chỉ xác nhận máy chủ trả lời, không đạt
   kiểm tra xác thực. Query thành công không chứng minh tài khoản không có
   quyền ghi; tài khoản chỉ đọc phải do quản trị Wazuh cấp đúng quyền.
3. **Xác nhận và lưu**: tên nguồn/địa chỉ, fingerprint CA, index và thời điểm
   kiểm tra. Nêu rõ: lưu nguồn không tự chuyển máy, không cấp quyền chạy.
   Chỉ cho lưu snapshot vừa kiểm tra thành công trong 5 phút; thay bất kỳ
   trường nào đều phải kiểm tra lại. Lưu thành công hiện bước tiếp theo.

Sau lưu có nút **Chuẩn bị nguồn** thuộc `manage_connections`: chọn chính xác
revision đã test làm candidate cho worker. Nút này không bật admission hoặc
đổi binding. Đổi candidate yêu cầu expected revision và snapshot còn hiệu lực.
Lát 1 không có nút tự di chuyển binding. Với lab hiện có, hiển thị **Nguồn mới
đã lưu — máy vẫn dùng nguồn cũ**, hướng dẫn bước chuyển đã review. Lát 3 thêm
**Gắn máy / Chuyển nguồn** theo quy trình bên dưới.

Trạng thái không gộp thành một chấm xanh:

| Trạng thái | Ý nghĩa |
| --- | --- |
| Chưa kiểm tra / kiểm tra hết hạn | Chưa có snapshot kiểm tra hợp lệ |
| Truy vấn thành công | TLS, đăng nhập và truy vấn có giới hạn đã đạt |
| Đã lưu, chưa gắn máy | Source tồn tại; chưa có scope thực thi được duyệt |
| Đang chờ worker | Đã gắn scope nhưng chưa có lease/probe mới |
| Đang phục vụ | Worker và probe đúng scope còn mới |
| Mất kết nối / cần quản trị | Nguồn lỗi hoặc cấu hình/worker cần xử lý |

Máy Online, nguồn truy vấn được và máy Ready là ba thông tin riêng. Không có
scope thì worker health hiện tại không được giả lập thành healthy.

Chỉ `manage_connections` được nhập, test, sửa hoặc xem chi tiết endpoint/CA.
Các tài khoản `run_jobs` chỉ thấy tên nguồn, trạng thái cần thiết và máy được
phép chạy; không nhận username, password, config path hoặc server exception.
API kiểm session generation, quyền hiện tại, CSRF và optimistic concurrency.
Ẩn nút trên UI không thay thế kiểm tra quyền phía server.

## Hướng dẫn tích hợp và đường mở rộng SIEM

Bổ sung từ phản hồi chủ sản phẩm ngày 2026-10-29: cần trang hướng dẫn riêng,
có ảnh theo phiên bản SIEM, cách tạo tài khoản/quyền và lấy public CA. Phần
này được duyệt cùng thiết kế tổng thể; không có connector live mới được
triển khai chỉ do bổ sung tài liệu.

Chọn cách kết hợp: một mục **Hướng dẫn tích hợp** dùng ngay trong Manager,
kèm link mở đúng bước bên cạnh trường tài khoản/CA của wizard. Một trang
ngoài ứng dụng đơn thuần dễ lệch phiên bản; một wizard chứa toàn bộ bài dài
làm luồng nhập khó dùng. Nội dung hướng dẫn được đóng gói cùng release,
đọc được trong lab không có Internet; nguồn hãng dùng để đối chiếu. Link
giữ vendor/version/deployment/step, không mang credentials hoặc endpoint lab.

Màn đầu chọn SIEM → phiên bản → Self-managed / Cloud (nếu đã có hướng dẫn
được review). Không tự suy sản phẩm từ một URL hoặc dùng phiên bản mới nhất
thay cho phiên bản người dùng chọn. Một connector live cần adapter riêng cho
auth, bounded query/pagination/cleanup, scope, time basis, telemetry và alert
mapping; mọi kết quả vẫn qua canonical schema/evidence IDs và engine chung.
Không đổi tên Wazuh reader thành generic SIEM reader hoặc mặc định các API
giống nhau. Registry đầu tiên chỉ mô tả capability đã có, chưa xây plugin
marketplace hoặc hỗ trợ nhiều nguồn live đồng thời.

Hiện tại trong source: Wazuh có reader live và luồng thực thi đã giới hạn;
Elastic có bốn parser export offline (`elastic-sysmon1-v1`,
`elastic-sysmon3-v1`, `elastic-powershell4104-v1`,
`elastic-security-alert-v1`), chưa phải live connection qua Manager; chưa
có adapter Splunk trong registry hiện tại. Giao diện phải phân biệt:

- Kết nối live đã hỗ trợ và đã kiểm chứng theo ma trận cụ thể.
- Nhập evidence offline theo export profile đã hỗ trợ.
- Hướng dẫn đang chuẩn bị / connector trong lộ trình; không có nút test/save
  live khả dụng khi chưa có implementation và acceptance tương ứng.

Tài liệu bản đầu ưu tiên **Wazuh 4.14.4 self-managed** theo lab hiện có. Dữ
liệu online của hãng tại thời điểm nghiên cứu không thay thế lab acceptance.
Không ghi cả dòng 4.x hoặc mọi phiên bản 4.14.x là đã kiểm thử chỉ từ một
phiên bản. Elastic live và Splunk thuộc issue sau; không làm đồng thời ba
connector và không đổi PRD/ground truth trong phần onboarding này.

Mỗi bài có cấu trúc cố định:

1. Kết nối tới thành phần nào: API/Indexer/Search endpoint, khác Dashboard;
   prerequisites, cổng, DNS/SAN, firewall egress từ Manager và kiểu triển khai.
2. Tạo tài khoản kỹ thuật riêng cho AEGIS, tách khỏi tài khoản người dùng.
   Nêu ai có quyền tạo, thao tác UI hoặc lệnh theo đúng phiên bản, không yêu
   cầu đưa tài khoản admin/khóa quản trị vào AEGIS.
3. Bảng quyền: API operation, privilege tương ứng, index/data stream được
   phép, lý do cần và cách đối chiếu effective permissions. Tài khoản xem
   Dashboard không mặc nhiên là tài khoản API phù hợp. Nếu nguồn cho phép,
   ưu tiên API key/token có scope và expiry; không ép mọi SIEM dùng password.
4. Lấy đúng public CA cho HTTP endpoint, phân biệt với node/server cert và
   private key. Đối chiếu fingerprint qua kênh quản trị đáng tin cậy, SAN và
   hạn dùng. `.pem` chỉ là định dạng: tên file không chứng minh nội dung là
   CA. Hướng dẫn không tự tải cert từ kết nối chưa được xác minh rồi tin luôn.
5. Kiểm tra từ Manager theo thứ tự network → TLS → auth → scoped query →
   schema/time/mapping nếu adapter hỗ trợ. Có kết quả mong đợi và lỗi thường
   gặp. Không có raw SIEM query editor hoặc nút chạy lệnh từ bài hướng dẫn.
6. Quay lại wizard, lưu cấu hình; hướng dẫn rotation/expiry/revoke và sửa
   trust khi đổi CA. Backup trước thay đổi phía SIEM; lệnh thay đổi quyền
   hoặc firewall có nhãn rõ, không trộn với lệnh chỉ đọc.

Với Wazuh bản đầu, account dùng cho Indexer evidence API chỉ có quyền đọc
đúng index đã chọn (ví dụ pattern alert đã được owner khai báo), các thao
tác search/scroll/clear-scroll cần được kiểm tra trên phiên bản hỗ trợ.
Không sao chép nguyên guide Dashboard read-only dùng index `*`, tenant và
Server API role nếu adapter không cần chúng. Không tự yêu cầu quyền sửa rule,
write/delete document hoặc cluster admin. `DELETE /_search/scroll` chỉ đóng
search context, khác xóa evidence; quyền chỉ đọc xét theo tác dụng thao tác,
không chỉ HTTP verb. Không thử ghi/xóa dữ liệu thật để chứng minh không có
quyền ghi. Probe thành công chỉ chứng minh thao tác đã test được phép; badge
"đã xác minh least privilege" cần proof riêng, không suy từ read success.

Với HTTPS dùng CA công khai được trust store tin cậy, hướng mở rộng cần lựa
chọn **CA hệ thống**; với CA nội bộ dùng **Upload public CA**. Cả hai luôn
verify chain và hostname. Lát Wazuh hiện tại vẫn giữ explicit private CA theo
reader đã review; chế độ system trust cho connector tương lai phải có schema,
transport và tests riêng trước khi bật. Không có nút skip verification.

Ảnh minh họa phải là screenshot thật từ lab được phép hoặc nguồn hãng có
ghi nguồn/quyền sử dụng; có alt text, chú thích phiên bản và bước tương ứng.
Che mật khẩu/token, danh tính lab và dữ liệu nhạy cảm trước khi lưu. Không dùng
ảnh AI dựng thành giao diện SIEM thật. Khi chưa có ảnh/version đã xác minh,
hiển thị "chưa có ảnh kiểm chứng" thay vì minh họa giả. Nội dung có các trường
`vendor`, `product`, `version_range`, `deployment`, `connector_release`,
`guide_revision`, `reviewed_at`, `validation_status`, official references và
provenance ảnh. Docs-reviewed và lab-verified là hai trạng thái khác nhau.

Kiểm thử bổ sung: guide links đúng sản phẩm/phiên bản/step, không có path secret
trong snippet/ảnh/URL, nội dung đọc offline, ảnh có alt text, dữ liệu chỉ dẫn
không được render HTML/script tùy ý. Test connector capability không hỗ trợ thì
không kích hoạt form live; unknown version hiển thị giới hạn thay vì tự nhận
tương thích. Với quyền/source mismatch, trả mã lỗi và link đúng bài xử lý.

## Cấu hình riêng tư và phiên bản

Tái sử dụng `RegisteredExecutionConnection`, private reader config và output
root fingerprint. Thêm metadata nguồn được quản lý: source ID, display name,
environment, source version, connection UUID/revision, lifecycle và audit.
Tên không phải authority. Mỗi source version đã lưu có một registration UUID
mới/revision 1; source version dùng optimistic concurrency riêng. Lý do: code
hiện yêu cầu binding dùng latest revision của connection UUID, nên append
revision ngay lúc lưu dưới cùng UUID sẽ vô hiệu hóa nguồn đang dùng trước khi
người quản trị duyệt chuyển. Không làm vậy. Registration legacy không đổi;
source version mới và cũ cùng tồn tại nhưng chỉ active pointer được admission.

File nằm dưới private root với thư mục 0700, file 0600, cùng service owner;
không dùng tên/path do trình duyệt cung cấp. CA công khai vẫn lưu cùng revision.
Credential lưu trong file riêng tư theo cơ chế hiện có, có backup được bảo vệ;
không tuyên bố mã hóa bằng khóa nằm cạnh file là secret vault. Không ghi vào
Git, DTO, audit, URL, exception, telemetry hay export evidence. Request body
không được log. Browser chỉ giữ mật khẩu trong memory của form, không dùng
localStorage/sessionStorage; xóa khi đóng hoặc hoàn tất.

Test tạo draft riêng tư có ID ngẫu nhiên gắn actor/session và fingerprint toàn
bộ đầu vào. Kết quả không trả credential. Draft hết hạn 5 phút; thao tác lưu
recheck quyền/session/bytes và idempotency key. File được tạo exclusive,
không symlink/reparse, ghi/fsync trước khi publish reference bằng transaction.
Crash giữa file và DB để lại draft không active; cleanup chỉ xóa draft mồ côi
đã hết hạn theo policy, không xóa file đã được registration/job tham chiếu.

Sửa credential/CA/endpoint/index tạo source version mới với registration riêng,
không ghi đè file hoặc tăng revision registration đang phục vụ. Endpoint hoặc CA
đổi yêu cầu nhập credential mới, không tự gửi secret cũ
sang đích mới. Credential-only rotation có lựa chọn dùng lại username; mật
khẩu không bao giờ được đọc ngược để điền form. Bản đầu không có xóa cứng
nguồn đã đăng ký. Audit ghi actor, action, revision, fingerprint, thời gian và
mã kết quả đã chuẩn hóa, không ghi body hoặc bí mật.

## Mạng, TLS và kiểm tra quyền truy vấn

HTTPS trực tiếp là mặc định. Một lần cài đặt quản trị viên khai báo policy
egress root-owned, không group/other writable: hostname/IP chính xác, port và
tập IP được phép của nguồn Wazuh. Web không sửa allowlist. Nếu đích chưa được
cho phép, trả hướng dẫn cấu hình một lần; không mở firewall từ request web.
Không tự hard-code địa chỉ lab vào source hoặc bật mọi mạng RFC1918.

Cho phép private IP đã khai báo nhưng chặn loopback, unspecified, link-local,
multicast và metadata destinations; nguồn legacy loopback chỉ được đọc qua
registration cũ, không mở cho wizard nhập URL mới. Không chấp nhận userinfo,
path tùy ý, query, fragment, scheme khác HTTPS, redirect hoặc proxy môi trường.

Mỗi kết nối TCP của probe, collection và scroll cleanup đều resolve/validate
đích theo policy; dial một IP đã được duyệt và giữ nguyên hostname gốc cho SNI
và SAN. Không để thư viện resolve lần hai sau kiểm tra. Nếu DNS trả IP ngoài
allowlist hoặc policy thay đổi thì fail closed trước khi gửi Basic auth.
Chính sách này phải áp dụng xuyên suốt transport mới, không chỉ ở bước test.

CA upload tối đa 64 KiB, chỉ certificate PEM, parse toàn bộ, từ chối block key,
dữ liệu thừa, chứng thư hết hạn hoặc cert không phải CA. Không nhận private key.
TLS xác minh chain và hostname/IP SAN; không có insecure mode. Tổng request
wizard tối đa 96 KiB với field cap; nginx chỉ nới body ở endpoint riêng.

Probe dùng connector HTTPS với route/body cố định, tối đa 10 giây mỗi thao tác,
response cap 64 KiB cho query thống kê, không scroll, không đọc raw event.
Lát 1 probe quyền đọc index; worker probe tiếp tục kiểm đúng Wazuh agent ID,
cửa sổ và scope binding. Không cần account admin hoặc thêm credential Wazuh
Server API chỉ để khai báo Indexer. Chưa xác minh inventory hoặc ánh xạ máy
chỉ từ tên host. Secret không được gửi tới đích nếu policy/TLS chưa đạt.

Wazuh phải được cấu hình phục vụ HTTPS trên đường mạng Manager được phép;
firewall chỉ cho Manager vào đúng port, SAN khớp URL. Đây là bước quản trị
Wazuh một lần, có backup/config test/rollback; không tự đổi cluster transport
hay cấp quyền rộng từ Manager. Cần metadata bind/SAN/network của lab trước
khi viết lệnh chuyển đổi thực tế; hiện chưa có bằng chứng đường HTTPS trực
tiếp sẵn sàng.

## Worker tự nhận cấu hình đã duyệt

Lát 1 cài một service cố định cho nguồn managed, chạy cùng service identity,
dùng command registry-mode mới. Web chỉ ghi metadata/reference được kiểm tra;
không sudo, không shell, không tạo unit hoặc gọi systemctl. Systemd unit và
egress policy do gói nâng cấp/root installer cài một lần.

Registry-mode có một candidate pointer và một active pointer tách biệt, giữ
tối đa một nguồn managed active, đọc đúng revision đã chọn;
không tự chọn row mới nhất và không nhận command/path tùy ý. Không có binding
enabled thì chờ cấu hình, không báo Ready và không claim công việc.

Để không bị vòng chờ bootstrap, thêm preparation probe riêng: chỉ đọc scope
binding disabled đã được người quản trị duyệt, dùng đúng identity/generation,
certificate, profile/release/artifact pins, agent ID và candidate revision.
Lưu proof fingerprint scope + CA/config/policy + thời điểm, TTL 30 giây;
không tạo healthy lease, không tái sử dụng làm source proof khi admission bật.
Probe này không nới `_scopes()` hoặc `_authority()` của worker đang chạy.
Scope bị thay, quyền actor bị thu hồi hoặc proof hết hạn thì phải probe lại.

Nút **Hoàn tất chuyển đổi** ở lát 3 là thao tác duy nhất đặt active pointer:
trong transaction giữ dispatch/authority locks, kiểm idle, candidate revision,
preparation proof mới và local readiness đúng grant; bật admission theo hàm
guard/audit hiện có và commit active pointer cùng nhau. Đặt active không có
nghĩa đã Ready: sau commit cần lease và authenticated scoped probe mới. Khi đủ
scope, tái sử dụng `WorkerHealth`, exact registration identity, OS lock theo
output root, dispatch lock, source proof và global single-flight hiện có.

Chuyển active pointer chỉ khi idle và không có collection cần đối soát. Worker
đang phục vụ revision cũ dừng claim, drain, đóng lease, rồi worker mới mở lease
cho registration/version mới; không dùng health/source proof của bản trước. Nếu lease
hoặc drain chưa chắc chắn, chuyển đổi bị chặn; không tự reconcile/reset job.
Khi khởi động lại, đọc active pointer đã commit, không kích hoạt draft. Unit
legacy giữ nguyên; service mới không claim legacy connections. Khi lab chuyển
sang managed source, service legacy được quản trị viên vô hiệu hóa sau khi
xác nhận idle/lease đóng, không do API web gọi root.

## Chuyển nguồn và đơn giản hóa binding — lát 3

Người quản trị chọn nguồn đã test, RunnerRelease đã review, máy Windows và
Wazuh agent ID đã xác nhận. Server lấy connection ID/revision, profile hash
và release pins từ dữ liệu đã được review; UI chỉ hiện chúng ở Chi tiết.
Không coi hash agent tự gửi là đã review và không suy map từ hostname.

Preview cho biết máy/source cũ → mới, release, quyền admission, việc cài xác
nhận cục bộ cần làm. Giữ cùng UUID/generation. Chỉ chuyển khi idle, không có
journal hoặc collection cần đối soát. Tạo binding revision mới ở trạng thái
disabled, không rewrite binding/approval/job cũ. Endpoint InstalledGrant ghim
binding revision: đổi source cần gói cấu hình cục bộ đã review cập nhật grant;
không giả định Manager có quyền tự ghi file trong Windows.

Binding disabled mới vẫn nhận local readiness đúng định danh như hiện tại.
Trong bước chờ kích hoạt, poll chỉ cho máy có certificate và exact current
binding hợp lệ trả 204/no job; không lease/start hoặc công bố Ready. Điều này
cần test bootstrap riêng để không lặp lại lỗi dừng service do poll 409. Với
binding sai/revoked, authorization và các mã từ chối vẫn giữ nguyên.

Gói chuyển đổi chỉ mang config/metadata/public key đã pin, không mang secret
Indexer, private key hoặc mã mới tải qua web để chạy tự do. Quản trị viên chạy
một lệnh cài xác nhận trên máy; không ghép nối lại. Chỉ bật admission sau khi
readiness báo đúng revision/profile/artifact set và worker probe đúng scope.
Thất bại giữ lịch sử, source cũ và chứng cứ; nếu cần quay lại cũng tạo revision
được review và grant phù hợp, không tua ngược journal hoặc current revision.

Ownership chuyển bằng một thao tác audit riêng, không chỉ gọi transfer hiện
có với UUID mới. Thêm retirement record bất biến cho resource cũ và migration
record liên kết old/new ownership, registration, binding, actor, reason và
review evidence refs. Giữ nguyên các row/audit/job cũ. Trong một transaction
giữ dispatch và khóa cả hai resource + thiết bị, recheck không còn job cần
đối soát, retirement association cũ rồi tạo ownership mới; không cho một máy
đồng thời làm executor của hai resource chưa retired. Chỉ retirement đang
có migration đã duyệt mới cho phép đổi association; không mở rộng transfer
chung bằng cách bỏ kiểm tra trùng. Mọi guard lookup phải phân biệt resource
retired với resource chưa có owner: resource retired bị chặn admission rõ
ràng, không fall through sang legacy mặc định. Concurrent rotation, grant
cũ, owner cũ và rollback bằng pin cũ phải có negative tests. Kích hoạt chỉ
sau chuyển ownership/disabled binding và xác nhận grant; không cho job chen
giữa các bước. Quyền chuyển vẫn theo authority hiện có, không gộp ngầm vào
quyền xem hoặc test kết nối.

## Tự phục hồi agent — lát 2 độc lập

Hiện presence loop đã retry tạm thời. Source trace cho thấy execution response
kiểm JSON trước status, nên proxy HTML 502/503 có thể thành lỗi terminal và
khiến supervisor dừng sibling loops. Đây là giả thuyết từ code, chưa chứng minh
nguyên nhân các lần service dừng trong lab.

Viết regression trước: TLS hợp lệ trả HTML 502/503/504 hoặc rate-limit 429,
sau đó response hợp lệ. Chỉ sửa khi reproducer chứng minh lỗi phân loại.
Các status này có thể được retry có giới hạn/backoff/jitter, body bị chặn kích
thước và không parse như success. Không downgrade TLS/SAN/signature/schema,
không tự bỏ lỗi định danh hoặc dữ liệu journal. 401/403, identity revoked/expired,
malformed 2xx, replay/conflict và unknown execution vẫn xử lý theo protocol.

Không retry blind start/receipt khi mất ACK: giữ exact request ID/bytes và
journal hiện tại; không chạy lại payload. Không thêm SCM restart vòng lặp cho
mọi lỗi. Chẩn đoán chỉ ghi fixed reason code, stage và UTC, không raw response.
Linux vẫn presence-only. Không thay Sysmon protection hoặc service identity.

## Tiêu chí nghiệm thu

Lát 1 cần fixture CI: RBAC/session/CSRF; request limits; URL/CA/SAN/SSRF và DNS
rebinding; response timeout/cap/redirect; draft expiry/session/concurrency;
idempotent save/crash/orphan; private file ownership; secret redaction; history
immutable; registry-mode restart/drain/lease/revision; empty scope không Ready.
Frontend kiểm keyboard/focus, trạng thái lỗi và không lưu password ở storage.

Lát 2 cần test transient → retry → success, denial → stop/drain, owner stop,
không double execution/start/receipt, không đổi identity/journal. Windows CI
native bắt buộc cho service semantics; không suy từ test host sang lab.

Lát 3 cần test chọn dữ liệu reviewed, explicit mapping, binding revision mới,
grant mismatch → chặn, stale probe/permission revoke → chặn, không tự Run.

Lab: backup rồi nâng Manager, giữ source cũ; xác minh direct TLS + authenticated
read query; test restart worker/Manager, tắt/mở Indexer và mạng; nâng agent giữ
UUID/generation; xác nhận nguồn phục hồi đúng scope trước khi duyệt job mới.
Đối chiếu report/evidence hash cũ không đổi. Chạy một lượt C có phê duyệt và
evidence IDs nếu chủ sản phẩm yêu cầu; lượt C dương tính riêng lẻ chưa là toàn
bộ nghiệm thu A/B/C. Không tự thay rule/ground truth để làm Pass.

Luồng sản phẩm tiếp tục là **Gap → Rule Fix → Re-test → Pass**. Kết luận cần
evidence IDs; thiếu alert khi collection assurance unknown không tự thành gap.

## Tài liệu tham khảo và bằng chứng thiết kế

Source: `execution_connections.py`, `manager_worker.py`, `worker_health.py`,
`ExecutionBindingEditor.tsx`, `ExecutionTypes.cs`, `ExecutionClient.cs`,
`AgentSupervisor.cs`. Đây là tham chiếu kiến trúc, không phải detection evidence.

- [Wazuh Indexer API configuration](https://documentation.wazuh.com/current/user-manual/indexer-api/configuration.html)
- [Securing the Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)
- [Wazuh internal users và RBAC](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)
- [Wazuh certificate deployment](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/certificate-deployment.html)
- [Elastic API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys)
- [Elastic index privileges](https://www.elastic.co/docs/reference/elasticsearch/security-privileges)
- [Splunk REST authentication và authorization](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-user-manual/9.2/rest-api-user-manual/basic-concepts-about-the-splunk-platform-rest-api)

References hãng hỗ trợ nghiên cứu hướng dẫn; chưa là ma trận tương thích lab.

Các quyết định nhỏ còn lại giao người triển khai: tên model/route theo conventions
của repo, chia test file và bố trí CSS. Các ranh giới authority, versioning,
worker lifecycle và không tự thực thi ở trên phải được giữ nguyên.

Slice-1 implementation constraint (2026-10-29): new onboarding supports explicitly pinned private/global IPv4 and globally routable IPv6 only, after rejecting loopback, link-local, unspecified, multicast and mapped addresses. Shared IPv4 space and non-global IPv6, including ULA, fail closed even if listed. This deliberately excludes CGNAT/ULA compatibility without embedding vendor metadata addresses or claiming exhaustive future metadata classification. The existing legacy path is unchanged.
