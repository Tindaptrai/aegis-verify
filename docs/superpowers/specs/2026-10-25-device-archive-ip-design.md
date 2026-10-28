# Thiết kế quản lý máy: xóa khỏi danh sách và cập nhật IP

**Ngày:** 25/10/2026. **Trạng thái:** owner duyệt và yêu cầu triển khai trong chat
ngày 25/10/2026; issue #157. Nâng cấp VM và merge vẫn cần human/lab review.

**Nền mã đối chiếu:** `26ea93388500d850d092003e64dd12a356efdc00`.
**Phạm vi tài liệu:** thiết kế chức năng và tiêu chí nghiệm thu. Chưa sửa sản phẩm,
chạy migration, nâng cấp VM, phát hành agent, tạo job hoặc thay đổi PKI.
Issue triển khai và kế hoạch công việc sẽ được chốt sau khi owner duyệt thiết kế.

## 1. Quyết định đã được owner chọn

1. Xóa máy khỏi danh sách quản lý, thu hồi danh tính, giữ lịch sử.
2. IP do agent Windows/Linux tự cập nhật.
3. Gửi thiết kế chi tiết để duyệt trước khi triển khai.

Các thông số, giới hạn và cách chia phiên bản dưới đây là đề xuất kỹ thuật của
người thiết kế, chưa phải các yêu cầu owner tự đưa ra.

Luồng ghép nối, heartbeat và tự kết nối lại trước đăng nhập sau reboot đã được
owner xác nhận trên hai VM hiện tại. Đây là baseline nghiệm thu thủ công; tài liệu
không chứa IP, UUID, chứng thư hay log thật. Lỗi ghép nối Windows từng xảy ra chưa
được xác định nguyên nhân gốc và không được coi là đã sửa bởi thiết kế này.

## 2. Mục tiêu và phạm vi

- Dọn các máy không còn quản lý, gồm các bản ghi đăng ký thử, mà vẫn tra cứu được
  danh tính cũ, job, evidence và audit.
- Nhìn thấy các địa chỉ IP hiện tại do agent khai báo, đồng thời phân biệt với
  địa chỉ kết nối mà reverse proxy quan sát được.
- Giữ hoạt động của agent hiện tại khi nâng Manager trước; nâng agent không làm
  đổi UUID, khóa hoặc chứng thư đang dùng.
- Giữ luồng pilot legacy, quyền tài khoản, CA/CRL, scenario và kết quả đánh giá.

**Đợt này:** xóa từng máy; xem danh sách máy đã xóa; cập nhật IP; tìm theo IP;
giao diện và kiểm thử tương ứng trên Windows/Linux.

**Chưa thuộc đợt này:** xóa nhiều máy cùng lúc; xóa vĩnh viễn; khôi phục máy đã
xóa; gỡ agent từ xa; đổi tên máy; sửa IP thủ công; quét mạng; điều khiển máy bằng
IP; chạy scenario qua presence agent; tự gia hạn chứng thư. Xóa nhiều máy là đợt
tiếp theo sau khi thao tác từng máy được nghiệm thu.

## 3. Các phương án đã cân nhắc

| Vấn đề | Phương án | Hệ quả |
|---|---|---|
| Xóa máy | Xóa hàng dữ liệu khỏi database | Làm mất liên kết lịch sử và xung đột các quan hệ `PROTECT`; owner không chọn |
| Xóa máy | Lưu dấu đã xóa và thu hồi danh tính | Owner chọn; giữ quan hệ, audit và khả năng tra cứu |
| IP | Nhập tay trên web | Dễ lỗi thời khi DHCP đổi IP; owner không chọn |
| IP | Agent tự khai báo | Owner chọn; hỗ trợ nhiều card mạng và cập nhật định kỳ |
| IP bổ sung | Địa chỉ proxy quan sát | Đề xuất bổ sung để phân biệt NAT; không thay thế IP agent khai báo |

Triển khai tiếp trên Django/PostgreSQL, React/TypeScript và agent .NET hiện có.
Không cần thư viện ngoài mới để đọc địa chỉ mạng hoặc phân tích IP.

## 4. Xóa khỏi danh sách và thu hồi danh tính

### 4.1. Ý nghĩa và dữ liệu

Thêm `Device.archived_at` và `Device.archived_by_id`, nullable; mặc định không có
giá trị. Actor được lưu dưới dạng ID chụp tại thời điểm thao tác, cùng cách tiếp
cận hiện có của enrollment audit. Không phụ thuộc tên hiển thị có thể đổi.

Một lần xóa thành công, trong cùng transaction:

1. Xác minh người dùng hiện còn quyền `manage_devices` và tài khoản còn hoạt động.
2. Kiểm tra loại máy và các tác vụ liên quan.
3. Đặt `revoked=true` nếu chưa thu hồi; ghi `device_revoked` nếu có thay đổi.
4. Ghi thời điểm/actor xóa và thêm sự kiện append-only `device_archived`.
5. Giữ nguyên UUID, fingerprint, generation, mã ghép nối đã dùng, job, báo cáo,
   evidence, thời gian heartbeat và snapshot IP cuối cùng.

Không xóa hàng `Device`, không đặt lại `PairingCode.consumed_at`, không sửa chứng
thư/khóa và không chỉnh trạng thái job để ép thao tác thành công.

Ràng buộc database yêu cầu máy có archived_at luôn có revoked=true. Trong Django
Admin, trường archive, snapshot IP và audit chỉ đọc; máy đã archive không được
sửa revoked hoặc xóa mốc archive để khôi phục bằng form quản trị. Giữ chính sách
không hard-delete của DeviceAdmin hiện có.

Máy đã thu hồi trước đó vẫn có thể được xóa khỏi danh sách. Gọi xóa lại cùng UUID
trả thành công mà không tạo thêm sự kiện hay đổi actor/thời điểm xóa ban đầu.

### 4.2. Máy nào được xóa

- Chỉ áp dụng cho `connection_kind=paired_presence` trong đợt này.
- Máy `legacy_v1` vẫn chỉ đọc; API trả `device_conflict` nếu yêu cầu xóa.
- Không dựa vào hostname hoặc IP để quyết định danh tính; luôn dùng UUID.
- Hai máy trùng hostname hoặc IP vẫn là hai bản ghi độc lập.

Chặn xóa khi còn tác vụ chưa xử lý xong. Cho phép khi mọi job liên quan thuộc một
trong hai nhóm sau:

- Execution là `draft`, `cancelled` hoặc `expired`, và collection là `pending`,
  `evaluated`, `empty` hoặc `reconciled`.
- Execution là `succeeded`, `failed` hoặc `execution_unknown`, và collection là
  `evaluated`, `empty` hoặc `reconciled`.

Mọi tổ hợp khác, gồm `queued`, `leased`, `started`, collection `collecting`/`failed`
hoặc giá trị lạ, đều bị chặn bằng `device_busy`. Owner xử lý/reconcile qua luồng
sẵn có rồi mới xóa. Draft được giữ nhưng không thể được duyệt cho máy đã xóa.
Presence agent hiện chưa nhận job; kiểm tra này vẫn phải tồn tại để bảo vệ lịch sử
và chuẩn bị cho mở rộng về sau.

### 4.3. Đồng thời và hiệu lực

Thứ tự khóa của thao tác xóa: `AccountMutationLock` → `DispatchLock` → hàng Device
→ các Job liên quan theo UUID tăng dần. Dùng cơ chế khóa hiện có của PostgreSQL;
không giữ transaction khi gọi mạng hoặc thao tác file.

Heartbeat cũng khóa hàng Device. Heartbeat hoàn tất trước khi xóa có thể được ghi
nhận; heartbeat kiểm tra sau commit xóa phải bị từ chối. Không được làm mất
`archived_at`, bỏ thu hồi hoặc đưa máy trở lại danh sách.

Các đường kiểm tra danh tính/duyệt job phải coi máy đã xóa là không khả dụng, kể cả
khi có dữ liệu bất nhất `archived_at != null` nhưng `revoked=false`. Không tự sửa
bất nhất bằng một request heartbeat.

Hiệu lực chặn liên hệ bắt đầu từ request xác thực tiếp theo sau commit. Xóa không
tự gỡ hay sửa cấu hình khởi động trên endpoint. Service có thể được hệ điều hành
khởi động lại nhưng Manager vẫn từ chối danh tính đã thu hồi. Không hứa service
sẽ tự bị disable trên hệ điều hành.

Ghép nối mới sau khi đã xóa cần mã mới và quy trình retire/replace được hỗ trợ;
tạo UUID mới. Đợt này không thêm nút tự khôi phục hoặc tự ghép nối lại.

### 4.4. API và quyền

- `POST /api/v2/devices/<uuid>/archive`, body `{}`, CSRF như các thao tác web hiện có.
- Thành công hoặc đã xóa: HTTP 204. Không tồn tại: HTTP 404 `device_not_found`.
- Sai body: 400 `invalid_request`; không quyền: 403 `permission_denied`;
  legacy: 409 `device_conflict`; còn tác vụ: 409 `device_busy`.
- Lỗi không trả traceback, nội dung chứng thư, mã ghép nối hay dữ liệu riêng tư.
- Nút trong UI dựa vào quyền; backend luôn kiểm tra lại quyền tại thời điểm ghi.
- Quyền xem danh sách/lịch sử tiếp tục là `view`. Không tạo preset quyền mới.

## 5. IP agent tự cập nhật

### 5.1. Những địa chỉ được thu thập

Agent dùng API mạng của hệ điều hành để lấy các unicast IP của interface đang
hoạt động. Bao gồm Ethernet, Wi-Fi, VPN và interface ảo nếu đang Up; không thu MAC,
gateway, DNS, SSID, thông tin tiến trình hoặc bảng kết nối.

- Hỗ trợ IPv4 và IPv6; giữ cả địa chỉ private và public.
- Loại loopback, unspecified, multicast, IPv4 link-local và IPv6 link-local.
- IPv6 có zone/scope ID không được gửi. IPv4-mapped IPv6 được chuẩn hóa thành IPv4.
- Loại trùng theo địa chỉ đã chuẩn hóa; sắp IPv4 trước IPv6, rồi theo byte địa chỉ.
- Tối đa 32 địa chỉ sau khi sắp xếp; `truncated=true` nếu còn địa chỉ hợp lệ bị cắt.
- Không đoán một địa chỉ là “IP chính” theo thứ tự card mạng hoặc hostname.

Thu thập lại ngay trước mỗi network heartbeat. Thời gian thu thập tối đa 2 giây;
không chồng các lần thu thập khi OS đang chậm. Dùng cùng chu kỳ heartbeat thành
công 15 giây và backoff mạng hiện có.

Nếu API OS không hủy được, chỉ giữ tối đa một tác vụ thu thập đang chờ; mỗi chu kỳ
vẫn trả unavailable khi quá hạn. Bỏ kết quả đến muộn của chu kỳ đã hết hạn, không
ghi nó thành snapshot mới hoặc tạo thêm tác vụ chồng lên tác vụ đang kẹt.

Nếu OS báo lỗi hoặc vượt thời gian: gửi `collection_status=unavailable`,
`reported_ips=null`, `truncated=false`; presence vẫn hoạt động. Khi đọc thành công
nhưng không có địa chỉ phù hợp: `collection_status=ok`, `reported_ips=[]`.
Không đưa thông báo lỗi OS vào payload.

### 5.2. Dữ liệu và độ mới

Thêm snapshot hiện tại trên Device:

| Trường | Ý nghĩa |
|---|---|
| `reported_ips` | JSON nullable: `null` chưa có/lỗi thu thập; `[]` thu thành công nhưng rỗng |
| `ip_collection_status` | `unknown`, `ok`, `unavailable` |
| `reported_ips_truncated` | Boolean; false nếu chưa có hoặc thu thất bại |
| `reported_ips_received_at` | Thời gian Manager nhận báo cáo mạng, nullable |
| `observed_ip` | IP proxy thực sự nhìn thấy, nullable |
| `observed_ip_received_at` | Thời gian Manager xác thực request chứa IP quan sát |
| `reported_agent_version` | Phiên bản binary đang chạy do heartbeat mới khai báo, nullable |

Một báo cáo mạng lỗi sẽ thay snapshot khai báo thành null và hiển thị “Không đọc
được IP”; không giữ IP cũ như thể nó đang hiện tại. IP quan sát vẫn có thể cập nhật
nếu request đó đã xác thực thành công.

Agent cũ gửi heartbeat 2.0 không chứng minh snapshot mạng còn hiện tại: đặt snapshot
khai báo về `unknown`/null nếu trước đó từng có; tiếp tục cập nhật IP quan sát khi
proxy cung cấp. Thời gian IP và thời gian heartbeat được trình bày riêng.

Máy Offline giữ snapshot cuối cùng, kèm thời điểm nhận và nhãn dữ liệu cũ. Máy đã
xóa giữ snapshot và thời gian tại thời điểm xóa. Không lưu lịch sử mọi lần đổi IP
trong đợt này; audit xóa và lịch sử job/evidence vẫn giữ nguyên.

IP agent khai báo là thông tin của endpoint đã xác thực, không phải chứng minh
độc lập về quyền sở hữu IP, kết nối đến được hay kết quả detection.

## 6. Hợp đồng heartbeat và tương thích

### 6.1. Agent hiện có

Giữ nguyên request/response của `/agent/v2/enroll` và `/agent/v2/heartbeat` đối với
agent 0.1.0: không thêm trường response vào các hợp đồng đóng đó. Heartbeat cũ vẫn
được nhận và vẫn cập nhật presence.

Thêm endpoint riêng `/agent/v2/network-heartbeat`, request protocol `2.1`:

```json
{
  "protocol": "2.1",
  "device_id": "<UUID>",
  "generation": 1,
  "network": {
    "collection_status": "ok",
    "reported_ips": ["<IP-LITERAL>"],
    "truncated": false,
    "agent_version": "0.2.0"
  }
}
```

Ví dụ dùng placeholder, không phải một payload hợp lệ để gửi thử.
Response có đúng `protocol=2.1`, `server_time`, `heartbeat_seconds=15`,
`offline_after_seconds=60`. Nhận báo cáo mạng và cập nhật presence trong một
transaction sau khi xác thực mTLS, UUID, generation và trạng thái Device.

Giới hạn body 16 KiB, depth 4; chỉ nhận đúng các khóa đã mô tả. IP chỉ là literal,
không port, URL, hostname, whitespace hoặc zone ID. Manager chuẩn hóa/loại trùng
theo cùng quy tắc, nhưng từ chối toàn request nếu phần tử sai, quá 32 phần tử,
trạng thái/mảng không nhất quán hoặc sai kiểu. Không lọc bỏ phần tử xấu rồi ghi
đè snapshot bằng dữ liệu còn lại. Request bị từ chối không cập nhật heartbeat/IP.

Địa chỉ thuộc nhóm bị loại ở mục 5.1 cũng bị từ chối phía Manager. truncated=true
chỉ hợp lệ khi có đúng 32 địa chỉ hợp lệ sau loại trùng. agent_version là chuỗi
phiên bản binary tối đa 32 ký tự, ba nhóm số ngăn bằng dấu chấm, mỗi nhóm tối đa
5 chữ số, không số 0 ở đầu trừ chính số 0; không suffix hoặc dữ liệu tự do.

Validator cho mảng IP chỉ áp dụng cho hợp đồng mới. Không nới lỏng bộ kiểm tra
JSON chung của giao thức cũ để chấp nhận mảng hay khóa lạ ở mọi nơi.

Agent mới thử network heartbeat. Chỉ khi endpoint trả HTTP 404 mới chuyển sang
heartbeat 2.0 cho phần đời còn lại của tiến trình; không fallback khi 400, 401,
403, 429, 5xx, lỗi chứng thư, TLS hoặc phản hồi sai. Khởi động lại sẽ thử lại khả
năng mới. Có thông báo cố định `network_reporting_unsupported`, không lặp mỗi
heartbeat. Điều này giữ presence khi nginx/Manager chưa mở endpoint mới.

### 6.2. Phiên bản và state

Đề xuất package mới 0.2.0. State 0.1.0 hiện có đọc được và được giữ nguyên khóa,
UUID, generation, certificate, CA pin và phiên bản ghi lúc ghép nối. Không sửa
state chỉ để thêm danh sách IP; thu IP trong bộ nhớ.

Agent mới chấp nhận state có phiên bản ghép nối 0.1.0 hoặc 0.2.0. Với ghép nối mới,
gửi `agent_version=0.2.0` trên enrollment 2.0; Manager mới chấp nhận cả 0.1.0/0.2.0
và vẫn trả response enrollment 2.0. `reported_agent_version` trên heartbeat mới
cho biết phiên bản binary hiện chạy; không suy ra nó từ phiên bản trong state.

Nâng Manager trước agent. Ghép nối mới bằng agent 0.2.0 yêu cầu Manager mới;
fallback chỉ dành cho heartbeat, không dành cho enrollment. Không yêu cầu đổi
chứng thư hoặc ghép nối lại các agent đang enrolled.

## 7. IP Manager quan sát và nginx

nginx ghi đè header `X-Aegis-Peer-IP` bằng `$remote_addr` cho hai endpoint heartbeat,
cùng các header mTLS hiện có. Client tự gửi header cùng tên sẽ bị ghi đè.

Manager chỉ nhận header khi request đi từ loopback proxy tin cậy, HTTPS được xác
nhận và client certificate đã được xác minh/bind vào Device. Không dùng trực tiếp
`REMOTE_ADDR` của Django làm IP máy vì đó là địa chỉ loopback của nginx. Không tin
`Forwarded`/`X-Forwarded-For` do endpoint gửi.

Đợt này giả định một nginx kết thúc TLS, không có load balancer phía trước. Không
bật hoặc nới `real_ip` trust trong thay đổi này. Nhiều proxy cần thiết kế riêng.

Header vắng: vẫn nhận heartbeat, IP quan sát null. Header có nhưng sai/đa giá trị:
từ chối request 400; không cập nhật dữ liệu. Không đoán từ IP agent khai báo.

Template và hướng dẫn nâng cấp phải bao gồm exact location cho endpoint mới,
client certificate bắt buộc, giới hạn body và ghi đè header. Giữ nguyên listener
legacy, CRL, trust, cổng triển khai, server SAN và CA. Không đưa cấu hình lab thật
vào repository. Mỗi môi trường dùng địa chỉ và đường dẫn do owner cung cấp.

## 8. Giao diện và API danh sách

Thêm `/api/v2/devices` cho UI mới, dùng phiên đăng nhập hiện có. Query:
`scope=managed|archived` (mặc định managed), `page`, `search`. Mỗi trang 50 máy.
Schema mới giữ thông tin danh tính/presence và thêm snapshot IP, archive actor/
thời gian. Có trường `can_archive` và mã lý do cố định `legacy_device`,
`device_busy`, `already_archived` hoặc null; UI vẫn dùng quyền phiên đăng nhập để
ẩn thao tác, backend kiểm tra lại khi POST.

`/api/v1/devices` giữ nguyên schema cho UI cũ, nhưng luôn loại máy đã archive khỏi
kết quả/count. Không thêm trường vào response v1 vì client hiện kiểm tra DTO đóng.
API auth, tài khoản và ghép nối của UI tiếp tục dùng v1.

Danh sách mới có hai chế độ:

- **Đang quản lý:** tất cả máy chưa archive, gồm máy đã thu hồi nhưng chưa xóa.
- **Đã xóa:** chỉ máy archive; hiển thị thời điểm/người xóa, dữ liệu cuối cùng;
  không có nút khôi phục/thu hồi lặp lại.

Cột IP hiển thị các IP agent khai báo (IPv4 trước), tối đa hai địa chỉ và nút mở
danh sách đầy đủ nếu còn. IP proxy được ghi nhãn riêng “IP kết nối Manager thấy”,
không trộn vào danh sách khai báo. Hiển thị rõ chưa ghi nhận, thu thất bại, rỗng,
truncated và dữ liệu cũ khi Offline.

Tìm kiếm giữ hostname/môi trường/Wazuh ID hiện có và thêm khớp chính xác IP đã
chuẩn hóa, cả reported và observed. Không tìm subnet, wildcard hay quét mạng.
Một chuỗi tìm kiếm là IP được chuẩn hóa để hỗ trợ các cách viết IPv6 tương đương.

Dialog xóa hiện hostname, UUID, trạng thái, hai nguồn IP và giải thích:
“Máy sẽ bị thu hồi danh tính và chuyển vào danh sách Đã xóa. Lịch sử được giữ lại.
Thao tác này không gỡ agent khỏi máy.” Có nút “Xóa máy” và “Hủy”. Không yêu cầu gõ
lại UUID trong đợt đầu. Không chọn máy chỉ theo hostname khi có bản ghi trùng tên.

Nếu bị `device_busy`, dialog giải thích còn tác vụ chưa xử lý xong và giữ nguyên
danh sách. Nếu quyền bị thu hồi hoặc phiên hết hạn trong lúc dialog mở, thao tác
không được thực hiện. Tự làm mới 15 giây như hiện tại; không ghi đè dialog đang mở
bằng một bản ghi khác hoặc để response tìm kiếm cũ làm máy đã xóa xuất hiện lại.

Chi tiết máy đã xóa vẫn đọc được qua API v2 bởi người có `view`, giữ liên kết lịch
sử. Màn hình người dùng hiển thị actor ID khi không tra được username; không suy
đoán người thao tác.

Bổ sung `GET /api/v2/devices/<uuid>` trả DTO máy mới, kể cả máy đã xóa, và
`GET /api/v2/devices/<uuid>/history?page=<n>` trả audit danh tính theo thời gian
mới nhất trước, 50 dòng/trang, cùng cấu trúc phân trang của danh sách. Mỗi dòng có
action, thời gian Manager ghi, actor_id, code_id và device_id nullable theo dữ liệu
gốc; không trả code hash, code thô, chứng thư hoặc key. Lịch sử gồm các enrollment
audit hiện có gắn device_id, audit tiêu thụ mã liên quan, và sự kiện archive.
Không tổng hợp một sự kiện xóa cho các máy chỉ mới thu hồi.

Chi tiết có lịch sử quản lý danh tính này; lịch sử job/report/evidence vẫn giữ
trong các quan hệ và công cụ tra cứu hiện có với quyền hiện có. Không xây thêm
portal đọc job/evidence hoặc nới quyền xem chúng trong issue này.

## 9. Kiểm thử và tiêu chí nghiệm thu

### Manager và dữ liệu

1. Migration thêm trường nullable/default mà không sửa Device, FK, job, audit hay
   evidence hiện có; trạng thái archived kéo theo revoked bằng ràng buộc dữ liệu.
2. Xóa hợp lệ thu hồi và archive nguyên tử; transaction lỗi không để lại một nửa.
3. Chặn sai quyền, phiên hết hạn, legacy, từng tổ hợp job bị chặn, input lạ.
4. Xóa lặp idempotent; giữ actor/thời gian ban đầu và không nhân đôi audit.
5. Kiểm thử PostgreSQL có heartbeat/xóa, worker/xóa, hai người xóa đồng thời;
   request sau commit bị từ chối, không khôi phục hay cập nhật snapshot đã archive.
6. Job, report, evidence, mã đã dùng và audit vẫn truy cập/đối chiếu được.
7. Cả heartbeat cũ và mới hoạt động đúng; nguồn IP/header, NAT và trường thiếu
   không bị thay bằng suy đoán. Request sai không làm mới presence.

### Agent Windows/Linux và proxy

8. Fixture nhiều card, trùng IP, IPv6, VPN, card down, link-local, lỗi OS, timeout,
   hơn 32 IP; kết quả chuẩn hóa ổn định và không chứa thông tin ngoài phạm vi.
9. DHCP đổi IP thay snapshot ở heartbeat thành công kế tiếp; mất mạng dùng backoff,
   không đổi UUID/khóa hoặc tự đăng ký lại. Đọc IP lỗi không làm dừng presence.
10. Chỉ 404 cho phép fallback; 403 thu hồi, lỗi TLS, 429, 5xx và response sai giữ
    nguyên cách xử lý an toàn. Không tự thử enrollment sau khi bị archive.
11. Header giả từ client bị nginx ghi đè; endpoint mới không hoạt động khi thiếu
    mTLS; listener/CRL legacy tiếp tục qua regression checks.
12. Native tests chạy đúng tài khoản service Windows và systemd Linux, không chỉ
    test từ terminal Administrator/root. State cũ và UUID giữ được sau nâng cấp.

### UI và nghiệm thu lab

13. Các nhãn IP/độ mới không gây hiểu nhầm, địa chỉ lạ không gây XSS, keyboard dùng
    được dialog; viewer/operator không có quyền quản lý không xóa được.
14. Bản ghi trùng hostname/IP thao tác đúng UUID; bộ lọc/count/pagination/search
    nhất quán khi xóa trong lúc tự làm mới.
15. Owner kiểm tra Windows/Linux: Online trước đăng nhập sau reboot, cùng UUID,
    IP được cập nhật; thay mạng/DHCP không tạo máy mới.
16. Xóa một danh tính thử: rời danh sách quản lý, còn trong Đã xóa, heartbeat cũ
    bị từ chối và lịch sử giữ nguyên. Không chọn danh tính pilot thật để test.

Fixtures được dùng trước; không tạo log detection hoặc sửa ground truth để chứng
minh kết quả. Báo cáo lab sau này liên kết evidence ID; không commit log riêng tư,
khóa, chứng thư triển khai, mã ghép nối hoặc IP/UUID thật.

## 10. Trình tự triển khai sau khi duyệt

1. Chốt issue và acceptance criteria từ tài liệu, lập kế hoạch triển khai riêng.
2. Backend/migration/archive/auth và kiểm thử transaction; review phần này.
3. Hợp đồng mạng, nginx và tương thích; review phần này.
4. Thu IP và heartbeat Windows/Linux, native service tests; review phần này.
5. UI quản lý/đã xóa/IP/tìm kiếm và tests; review phần này.
6. Kiểm tra tổng thể, đóng gói, hướng dẫn backup/nâng cấp rồi owner nghiệm thu lab.

Mỗi phần có kiểm thử và review riêng. Chưa triển khai chỉ vì tài liệu đã được lưu.
Chưa merge, phát hành, nâng cấp VM hoặc chạy scenario nếu chưa có bước duyệt tương
ứng. Không đưa thêm chức năng chạy job đa máy vào issue này.

## 11. Nâng cấp và rollback

Migration theo hướng bổ sung. Backup database/cấu hình trước nâng; Manager/nginx
trước, agent từng máy sau. Xác nhận heartbeat 0.1.0 vẫn hoạt động rồi mới nâng agent.

Snapshot identity hiện có phải đọc được bởi binary mới; không đổi certificate,
generation hay khóa chỉ để cập nhật IP. Agent cũ có thể đọc lại state 0.1.0 chưa
đổi phiên bản; agent 0.1.0 không được dùng để đọc state mới tạo bằng 0.2.0.

Sau khi đã archive một máy, không rollback Manager về mã chưa biết archived_at
trong hoạt động bình thường. Nếu cần rollback khẩn, đóng các endpoint heartbeat/
thao tác máy trước, kiểm tra thu hồi vẫn được giữ rồi mới mở lại. Không restore
backup cũ theo cách làm danh tính đã thu hồi hoạt động trở lại. Không tự đảo
migration/drop trường chứa lịch sử mới phát sinh.

## 12. Các lựa chọn kỹ thuật cần owner duyệt cùng tài liệu

- Xóa từng máy trước, bulk về sau; chưa có khôi phục hoặc xóa vĩnh viễn.
- Máy legacy vẫn chỉ đọc trong đợt này.
- IP khai báo và IP proxy hiển thị riêng; giữ snapshot cuối, chưa lưu lịch sử mọi
  lần thay đổi IP; không tự chọn IP chính.
- Giới hạn 32 IP, thời gian thu tối đa 2 giây, cập nhật theo heartbeat 15 giây.
- API/endpoint mở rộng riêng để giữ hợp đồng cũ; package đề xuất 0.2.0, Manager
  phải được nâng trước khi ghép nối mới bằng package mới.
- Tiếp tục dùng quyền manage_devices; backend kiểm tra lại khi ghi dữ liệu.

**Điểm dừng vận hành:** owner đã cho phép triển khai mã theo thiết kế này. Thực
hiện implementation plan của issue #157; không tự nâng cấp các VM hoặc merge.
