# AEGIS Manager, agents và catalog trên web — thiết kế đề xuất

Ngày: 2026-10-23; bổ sung đăng nhập và quản lý tài khoản ngày 2026-10-24.
Trạng thái: phạm vi và giao diện v3 đã được chốt qua trao đổi ngày 2026-10-24;
kế hoạch triển khai phần đầu (đăng nhập, tài khoản, phân quyền) chờ review trước khi sửa code.

## 1. Phần đã được người dùng chọn

- Manager cài trên Linux, có giao diện AEGIS riêng và logo ở header.
- Cài mới có tài khoản ban đầu `aegis/aegis`; không đặt lại tài khoản hiện có khi nâng cấp.
- Agent Windows và Linux khởi động, kết nối và hiện Online trên Manager.
- Bản đầu: Linux chỉ kết nối/Online; thực thi SCN-001 trên Windows.
- Chọn một hoặc nhiều máy Windows, chọn SCN-001, chạy đồng thời và theo dõi từng máy.
- Thêm kịch bản ngay trên web bằng cách tải lên gói ZIP chứa script và cấu hình đánh giá.
- Người dùng đã đồng ý bố cục bản phác thảo đầu, yêu cầu thêm logo và luồng nhập ZIP.
- Giao diện phải có đăng nhập/đăng xuất, tạo tài khoản và cấp quyền cho từng tài khoản.

Bản này thay thế đề xuất launcher cho ba VM ngày 2026-10-23. Đề xuất launcher cũ
chưa được duyệt. Hồ sơ pilot A/B/C và các báo cáo gốc vẫn là hồ sơ lịch sử riêng.

## 2. Cách xây dựng và phạm vi

Mở rộng Django Manager và React hiện có là phương án phù hợp với yêu cầu và mã
nguồn đang có: dùng lại đăng nhập, job đã ký, receipt, worker, connector và engine.
Chỉ trang trí Django Admin sẽ không cung cấp được trải nghiệm chọn nhiều máy,
agent Online và catalog ZIP. Viết lại một backend khác sẽ nhân đôi các ràng buộc
đã kiểm chứng. Vì vậy đề xuất này dùng một kiến trúc mở rộng hiện tại; không thêm
framework web hoặc cơ sở dữ liệu mới.

Đây là một đợt phát triển gồm các hạng mục có thể review riêng theo thứ tự:
UI và API Manager → catalog ZIP → agent/pairing → batch run → bộ cài và lab test.
Mỗi hạng mục cần issue có acceptance criteria, tests và review. Không gộp vào
hoặc tuyên bố đã hoàn thành draft PR #152. Thiết kế không tự cho phép merge/deploy.

### Kết quả người dùng nhìn thấy

1. Tải bộ cài Manager Linux, chạy một lệnh cài hoặc nâng cấp.
2. Mở HTTPS Manager, đăng nhập, vào **Thêm máy**.
3. Tải agent theo OS, chạy lệnh kết nối với mã ghép nối một lần; để agent mở.
4. Máy xuất hiện cùng OS, Online, phiên bản agent và kịch bản hỗ trợ.
5. Vào **Kịch bản**, dùng SCN-001 hoặc nhập gói ZIP mới, xem và phát hành phiên bản.
6. Chọn các máy phù hợp, xem tóm tắt và bấm **Chạy**; đây là bước duyệt lượt chạy.
7. Theo dõi thực thi, thu evidence và đánh giá riêng cho từng máy; xuất gói có hash.

### Chưa bao gồm

Thực thi Linux, shell tương tác từ web, soạn script trực tiếp trên web, tự cài
Wazuh/Sysmon hoặc thay rule Wazuh, bật/tắt VM, đa tenant, chạy Internet/public
service, sửa ground truth SCN-001 đã duyệt, hoặc khẳng định mọi Linux distro đều
được hỗ trợ. Bộ cài đầu tiên nhắm Ubuntu Server 24.04 x64. Agent đầu tiên có bản
Windows x64 và Linux x64 cho kết nối; thêm OS/kiến trúc cần acceptance riêng.

## 3. Giao diện

Menu gồm Tổng quan, Máy đích, Kịch bản, Lượt chạy, Kết nối, Tài khoản & quyền,
Cài đặt; mục quản trị chỉ hiện cho người có quyền tương ứng. Giao diện
sáng/tối, tiếng Việt, logo AEGIS hiện có ở header và sidebar. Dùng cùng logo được
lưu trong repo, không tạo nhận diện mới hoặc cần dịch vụ ảnh bên ngoài.

Máy đích hiển thị kết nối riêng với khả năng chạy kịch bản. Linux Online không
đồng nghĩa hỗ trợ SCN-001; máy Offline hoặc thiếu release không được chọn.
SCN-001 có luồng chọn nhiều máy và bảng cấu hình bên cạnh như bản phác thảo.

Thêm kịch bản mở bảng nhập ZIP. Hiển thị tên, mã, phiên bản, OS, thời lượng tối
đa, nội dung gói và tiêu chí đánh giá. Các trường định danh do manifest quyết định;
đổi ground truth phải tải phiên bản mới, không sửa ngầm bằng form metadata.
Luồng: **Nhập ZIP → Bản nháp → Kiểm tra → Xem nội dung và phát hành**.

Kết quả kiểm tra cấu trúc không được trình bày là đã chạy thử hoặc đã phát hiện
thật. Phiên bản đã phát hành hiển thị người duyệt, hash, thời điểm và khả năng
thực thi. Linux có thể lưu gói trong catalog nhưng vẫn ghi chưa có runner Linux.

Mỗi lượt chạy phân biệt: trạng thái thực thi, trạng thái thu thập, kết quả engine.
Không dùng phần trăm giả hoặc gộp `succeeded` thành `Detected`. UI mô phỏng có nhãn
dữ liệu minh họa; bản sản phẩm chỉ hiển thị dữ liệu API thực, có trạng thái rỗng/lỗi.

Trước khi vào workspace là trang **Đăng nhập** có logo, tên đăng nhập, mật khẩu,
hiện/ẩn mật khẩu và thông báo lỗi. Sau đăng nhập, góc phải luôn có nút tài khoản
với tên/role; mở menu **Tài khoản của tôi / Đăng xuất**. Cửa sổ hẹp vẫn có nút này,
không giấu chung với avatar như bản phác thảo đầu. Đăng xuất trở về trang login.

**Tài khoản & quyền** gồm bảng username/tên hiển thị/vai trò/trạng thái, tìm kiếm,
**Tạo tài khoản**, sửa quyền và khóa/mở khóa. Form tạo có username, tên hiển thị,
mật khẩu ban đầu, preset vai trò và checkbox quyền. Form sửa không đổi username;
không hiện lại mật khẩu. Khóa tài khoản giữ audit/history và thay cho xóa cứng.

Đề xuất của người triển khai là preset vai trò cộng checkbox theo tài khoản, dùng
Django Groups/Permissions hiện có. Chỉ có preset cứng sẽ không đáp ứng thao tác
cấp quyền riêng user; tự xây một hệ thống định danh khác là không cần thiết.
Chưa có trình tạo vai trò tùy ý trong bản đầu: checkbox lệch preset hiện **Tùy chỉnh**.

## 4. Manager API, tài khoản và dữ liệu

UI phục vụ cùng origin HTTPS với Django; API `/api/v1/` dùng Django session và CSRF.
Giữ `/admin/` cho quản trị kỹ thuật. Không dùng API Operations loopback làm API
quản lý thực thi hoặc vô tình bỏ qua xác thực của Manager.

Mặc định bản đầu chủ lab dùng tài khoản quản trị. Quyền áp dụng trên toàn một lab
(không chia theo máy/môi trường trong bản đầu). Ma trận đề xuất:

| Quyền sản phẩm | Quản trị | Vận hành | Chỉ xem |
| --- | --- | --- | --- |
| `view`: xem máy, catalog, lượt chạy, báo cáo | Có | Có | Có |
| `run_jobs`: duyệt/chạy và hủy job chưa chạy | Có | Có | — |
| `import_scenarios`: nhập ZIP và quản lý bản nháp | Có | — | — |
| `publish_scenarios`: phát hành/ngừng phát hành phiên bản | Có | — | — |
| `manage_devices`: tạo mã ghép nối, cấu hình mapping, revoke | Có | — | — |
| `manage_connections`: cấu hình nguồn Wazuh/reader | Có | — | — |
| `export_evidence`: xuất evidence/báo cáo | Có | Có | — |
| `manage_users`: tạo/khóa/reset mật khẩu/cấp quyền user | Có | — | — |

Checkbox có hiệu lực thay cho preset; `view` là quyền nền để dùng workspace.
Tài khoản được cấp các quyền hành động phải có `view`. Cài đặt giao diện và thay
mật khẩu của mình dành cho mọi user đang active; `manage_connections` mới được
ghi config nguồn chung. Reconcile job trạng thái mơ hồ vẫn yêu cầu quản trị có
đủ quyền hoặc owner qua Admin, không ngầm mở cho Vận hành chỉ vì được Run.

Preset dùng ba Django Groups do ứng dụng quản lý; chuyển sang Tùy chỉnh gỡ các
group preset này rồi ghi các permission sản phẩm đã chọn. Django hợp quyền từ
groups/direct permissions, không có ô deny: quyền kế thừa từ group ngoài ba
preset (nếu tồn tại khi nâng cấp) phải hiện rõ là kế thừa, không vờ tắt được bằng
checkbox. Không xóa group/permission ngoài namespace AEGIS. Django superuser
active có quyền hiệu lực đầy đủ, không thể hạ đặc quyền đó bằng form sản phẩm.

Server kiểm quyền lại ở mọi endpoint và trong service thực hiện hành động, cùng
với readiness/approval invariants hiện có. `OwnerAdmin` và `owner` trong jobs.py
hiện yêu cầu superuser: bổ sung authorization service được test cho API mới,
không chỉ đổi nút UI hoặc cho Vận hành thành Django superuser. `/admin/` giữ quyền
quản trị kỹ thuật hiện tại. User quản trị sản phẩm có đủ tám quyền không tự có
`is_superuser`/`is_staff`; form web không nhận hai trường đặc quyền Django đó.
`manage_users` chỉ quản lý tài khoản sản phẩm không có `is_staff/is_superuser`.
Tài khoản quản trị kỹ thuật hiện có được hiển thị read-only trong trang này;
không reset password, khóa hay đổi nhóm của tài khoản đó từ API quản trị sản
phẩm. Thao tác quản trị kỹ thuật cần đường `/admin/` có quyền tương ứng. Mọi
user vẫn được đổi mật khẩu của chính mình sau khi xác nhận mật khẩu hiện tại.

Danh sách quyền được server xác định, không tin capability từ session payload
hoặc JSON client. Direct URL/API không đủ quyền trả 403, chưa login trả 401 hoặc
redirect login đối với trang HTML. Read API không xuất mật khẩu, password hash,
secret của reader/key hoặc token ghép nối. Vận hành/Chỉ xem không tự đổi quyền.

Login dùng Django authentication/session/CSRF, rotate session lúc thành công;
lỗi đăng nhập dùng thông báo chung. Redirect sau login chỉ cho origin/đường dẫn
nội bộ. Session cookie Secure/HttpOnly/SameSite phù hợp, không lưu auth trong
localStorage. Session hết hạn tuyệt đối sau 8 giờ từ lúc login (đề xuất cấu hình);
polling trạng thái hoặc mở tab nền không gia hạn mốc này.
Logout là POST có CSRF, flush session và xóa dữ liệu workspace trong UI; Back
không được dùng dữ liệu/API đã đăng xuất (no-store cho dữ liệu xác thực/quản trị).

Tạo user hash mật khẩu bằng Django, audit actor/target/role/permission set; không
ghi mật khẩu vào audit, response hoặc export. Đổi/reset mật khẩu làm mất hiệu lực
session cũ; tự đổi mật khẩu có thể giữ phiên hiện tại bằng cơ chế Django. Khóa
user có hiệu lực ở request kế tiếp, không chỉ chặn lần login sau. Thay quyền cũng
được đọc lại ở request kế tiếp, không dựa trên cache đăng nhập kéo dài tám giờ.
Khóa user phải thu hồi mọi session hiện có bằng session generation/revocation
được server kiểm tra hoặc xóa session tương ứng; mở khóa không làm cookie cũ
sống lại và phải login mới. Không chỉ kiểm tra `is_active` trong lúc đang khóa.

Khóa user không đổi trạng thái hay chạy lại job đã duyệt; actor/snapshot đã lưu
vẫn giữ trong audit. Đổi quyền không sửa lịch sử approval. Bản đầu không tự xóa
user để tránh mất liên kết lịch sử. Transaction kiểm tra không khóa/hạ quyền
người quản trị active cuối cùng; tính cả Django superuser active đang có. Không
cho user tự khóa mình trong UI. Các thao tác thay quyền đồng thời phải test để
không vượt qua điều kiện còn ít nhất một admin. Bọc cả UserAdmin/GroupAdmin mặc
định và các bulk action liên quan qua cùng policy để `/admin/` không là đường
vòng hạ admin cuối cùng hoặc sửa quyền ngoài audit. Điều kiện admin active tính
effective permissions sau thay đổi, gồm memberships/direct perms/superuser,
không dựa riêng vào tên vai trò; tài khoản còn lại phải có mật khẩu usable và
có thể đăng nhập, không chỉ có cờ active. Thiết kế không thêm SSO/tenant.

Bộ cài mới dùng cơ chế hash mật khẩu Django cho `aegis/aegis`; không log mật khẩu,
không dùng tài khoản web làm mật khẩu agent/DB/SSH/Indexer. Nâng cấp không reset
user, DB, key, cert, mapping, catalog, journal hoặc evidence. Không tự đặt lại mật
khẩu ở mỗi lần restart. Không bắt đổi mật khẩu ở lần đăng nhập đầu trong phạm vi
người dùng đã yêu cầu; trang tài khoản vẫn có thao tác đổi mật khẩu bình thường.

Mở rộng `Device` với OS, kiến trúc, agent/protocol version, capabilities, thời điểm
server nhận heartbeat, trạng thái enrollment. Client tự khai hostname là metadata;
identity là UUID/generation/chứng thư, không ghép nhầm chỉ bằng tên máy.

Thêm `ScenarioPackageVersion` (ID/version/hash, storage reference, trạng thái nháp/
kiểm tra/phát hành/lưu trữ, kết quả kiểm tra, reviewer/time), bản ghi readiness theo
device/release, `RunBatch`, liên kết child `Job` và audit các thao tác mới. Trạng
thái catalog nằm ngoài manifest: model manifest hiện yêu cầu `status: draft`;
không đổi YAML sang `published` chỉ để biểu diễn publication của catalog.

Các endpoint cụ thể và mã lỗi được chốt trong implementation plan; tài nguyên gồm
auth/login/logout/me/password, users/permissions, devices/heartbeat, pairing,
scenario versions/import/validate/publish, batch
preview/approve/status, report/export. Đọc trạng thái không được lease công việc.

## 5. Gói ZIP kịch bản

Đề xuất format `aegis-scenario-package/1`, dùng namespace tương đối cố định:

```text
package.json          format, scenario ID/version, platform, runner contract,
                      relative file paths, runtime limit, file SHA-256 map
scenario.yaml         ground truth theo schema hiện có
profile.json          evaluation profile, pin đúng manifest fingerprint
payload/              các file script/dữ liệu được liệt kê trong package.json
README.md             mục đích, cách dùng, điều kiện, tác động/cleanup
```

Inventory hash mọi file ngoại trừ chính `package.json`; SHA-256 của toàn ZIP
ràng buộc cả inventory. Resolver mới tra đúng ID/version/digest, không dùng
registry dashboard cũ vốn chỉ chấp nhận một entry cho mỗi ID hoặc chọn latest
khi đọc job/report lịch sử.

`package.json` có schema kín; không URL tải phụ, dependency installer, hook cài
đặt hoặc đường dẫn tuyệt đối. Runner là thành phần agent đã phát hành, không lấy
binary/runner tùy ý từ ZIP. Bản đầu cung cấp runner Windows PowerShell cho payload
an toàn, timeout hữu hạn, thư mục làm việc và output theo UUID; engine không chạy
script. Không tự động hạ execution policy hoặc chạy dưới quyền cao hơn agent.

Runner mới `windows-powershell-script@1` nhận một entrypoint `.ps1` UTF-8 và
cleanup `.ps1` tùy chọn đã nằm trong inventory, các file cấu hình văn bản UTF-8
được liệt kê rõ. Không nhận EXE/DLL hoặc module runner từ gói. Tham số job chỉ là
typed values theo schema gói (không shell command), truyền thành argv riêng;
runtime limit bao gồm cleanup. Runner ghi launch/exit/cleanup thực tế, quản lý
process tree, dọn workspace theo UUID; nếu cleanup side effect bên ngoài chưa
xác nhận thì receipt không được báo cleanup thành công. Preview hiển thị mức
quyền của account agent; package đòi quyền khác không có readiness để chạy.

Đọc ZIP vào vùng staging private, tính hash và kiểm tra trước khi giải nén. Giới
hạn ban đầu là lựa chọn của người triển khai: upload 20 MiB, tổng mở rộng 100 MiB,
200 file, tối đa 100 lần nén, file văn bản riêng 1 MiB trừ manifest YAML dùng limit
256 KiB hiện có. Streaming giới hạn byte thực tế, không chỉ tin kích thước header.
Từ chối path traversal, absolute/drive/UNC paths, dấu phân cách mơ hồ, file trùng
sau chuẩn hóa/case fold, symlink/hardlink/special file, encrypted/nested archives,
file không có trong manifest và thiếu hash. Không thực thi nội dung khi nhập/kiểm tra.

Parse YAML/profile bằng loader hiện có; validate ID/version, assertion/source,
manifest fingerprint và hash tất cả file. Giá trị riêng lab đi qua context/bindings,
không ghép IP/credential thật vào source. Không nạp plugin Python, parser hoặc
connector mới từ gói; connector outputs vẫn theo canonical event schema.

Validation tạo báo cáo cấu trúc và khả năng runner; không chứng nhận script an
toàn chỉ vì hash đúng. Người có quyền xem payload text, tiêu chí, runtime/cleanup
và xác nhận phát hành cụ thể hash đó. Bản nháp không được dispatch. Nội dung gói
bất biến sau nhập; duplicate cùng ID/version/hash trả về bản cũ, cùng ID/version
nhưng khác hash bị từ chối và yêu cầu version mới. Archive/ngừng phát hành chỉ chặn
lượt mới, không làm mất gói cần để kiểm chứng lịch sử.

Phiên bản mới của kịch bản đã có phải hiển thị thay đổi ground truth/profile cho
owner duyệt rõ ràng. Không sửa SCN-001, report cũ hoặc profile cũ để làm bài test
mới đạt. Gói mới có ID riêng; khi thay cùng ID thì version mới và approval riêng.

## 6. Kết nối agent và phân phối catalog

Tách core kết nối khỏi Windows runner. C#/.NET hiện có được tái sử dụng nơi phù
hợp nhưng không giả định code hiện tại chạy được trên Linux: path, chứng thư,
PowerShell và Windows Job Object hiện phụ thuộc Windows.

Agent `connect` tạo key tại máy, gửi CSR và token ghép nối qua HTTPS đã kiểm trust.
Owner tạo token từ trang Thêm máy; thao tác đó cho phép ghép một máy vào environment
đã chọn. Token dùng một lần, hết hạn sau 10 phút, lưu hash và tiêu thụ nguyên tử.
Kết nối thành công tạo identity và chứng thư, máy hiện Online qua heartbeat; không
bắt thêm một lần duyệt enrollment sau khi owner đã cấp token. Token không phải
account web và không lưu trong URL/log/history. Nhập token bằng prompt ngoài
command line. Khả năng thực thi do server đối chiếu OS/protocol/runner đã hỗ trợ,
không cho quyền chạy chỉ vì agent tự khai capability.

Thêm issuer enrollment có giới hạn riêng trên Manager là thay đổi PKI mới, không
giả là CA pilot đã có API. Tạo enrollment CA riêng ở cài mới; giữ CA/identity pilot
hiện có cho agent cũ. Chứng thư mới client-auth, identity UUID, đời 30 ngày; issuer
chỉ đọc key bởi service và không cung cấp export private key. Public trust bundle
do bộ cài/owner cấp; luôn kiểm server certificate, không mặc định bỏ TLS validation.
Expiry/revocation hiển thị rõ; bản đầu reenroll qua owner, không cần rotation tự động.

Sau chấp nhận, agent gửi mTLS heartbeat riêng mỗi 15 giây; Online nếu heartbeat
server mới hơn 60 giây, quá hạn hiện Offline. Retry bounded/backoff, không dựng
timestamp Online từ đồng hồ client. Ngắt agent khiến Offline, không tự revoke.

Windows mặc định có chế độ foreground `run` giữ kết nối và poll việc; launcher
bấm đúp hiện status/wait để tránh hiểu nhầm không output. Giữ `--once` cũ tương
thích với cấu hình legacy. Linux foreground chỉ heartbeat, không poll thực thi
Windows. Không cần cài Windows Service hoặc chạy bằng account khác trong bản đầu.

Thiết kế protocol v2 cho capabilities/release download và runner chung; v1 giữ
nguyên strict envelope cũ, không chèn field mới mà agent v1 sẽ từ chối. Server
chỉ dispatch đúng protocol/capability đã xác thực. Agent tải gói đã phát hành qua
mTLS vào cache private, kiểm signature/release/file hashes, đường dẫn và giới hạn
giải nén lần nữa; job chỉ dùng đúng release cache. Không tải file/URL tùy ý theo
tham số job hoặc gói. Receipt, journal, timeout/cleanup giữ nguyên nguyên tắc cũ.

Legacy SCN-001 chạy qua adapter giữ kit/runner/profile/pins riêng; package mới dùng
runner contract v2. Không thay đồng loạt catalog legacy của máy 009. Readiness xác
nhận riêng per-device: hostname/Wazuh ID/environment/generation, package installed,
release/profile bindings, logging và nguồn thu. Chỉ Online chưa đủ để Run.

## 7. Chạy nhiều máy

Preview xác định danh sách máy, cùng phiên bản scenario, release của từng máy,
capabilities, Wazuh mapping, timeout và cửa sổ thu. Bấm Chạy duyệt đúng snapshot.
Mỗi batch có UUID và mỗi máy có Job UUID/approval/window riêng. Target-specific
bindings/pins của 009 không được sao chép mù sang máy khác.

Idempotency key gắn với snapshot/actor; retry cùng nội dung trả batch cũ, nội dung
khác cùng key trả lỗi. Admission nguyên tử: nếu một máy trong selection không còn
ready thì tạo 0 job, trả danh sách lý do để user chọn lại. Không bỏ bớt máy âm thầm.

Thay global single-flight hiện tại bằng một job chưa kết thúc cho mỗi device;
transaction khóa device theo thứ tự ổn định để tránh hai batch tranh cùng máy.
Hai máy khác nhau có thể chạy đồng thời. Start trong cửa sổ được duyệt, không hứa
bắt đầu cùng mili giây. Phần UI hiển thị queued/started/succeeded/failed/unknown
theo receipt thực tế, không dùng CLI exit 0 thay kết quả thực thi.

Worker tự thu đúng job sau collection end cộng delay, scheduler dùng cơ chế
systemd worker hiện có. Bản đầu cho phép thu lần lượt sau khi máy thực thi song
song; hiển thị chờ thu. Khóa thu theo job và atomic claim tránh hai worker đánh giá
cùng job. Lỗi một device không chặn collection device khác; cấu hình reader chung
lỗi thì hiển thị lỗi nguồn chung. Job mơ hồ/cleanup chưa rõ giữ reconcile riêng
per-device, không tự chạy lại. Wazuh rule maintenance nếu có vẫn chặn dispatch toàn
môi trường cho đến owner xác nhận, không bị bypass vì batch mới.

Manager tự tạo cửa sổ tương đối lúc duyệt; không dùng timestamp pilot cố định.
Không tự sửa đồng hồ/NTP; UI cho biết readiness lỗi. Receipt/journal giữ lại khi
Ctrl+C, crash hoặc mất mạng, không tạo job mới hoặc chạy payload lần hai khi retry.

## 8. Đánh giá, evidence và Wazuh

Giữ execution tách evaluation. Thu bằng reader/connector hiện có, canonical events
→ profile/manifest/context → engine. Mỗi máy dùng scope và raw evidence reference
riêng. UI kết luận phải liên kết được evidence IDs; `unknown` assurance và
`Inconclusive` không đổi nhãn để báo xanh. Comparison phải đúng điều kiện engine.

Wazuh vẫn là hệ thống có sẵn. Wizard lưu endpoint, trust CA public và tài khoản
chỉ đọc tại private config trên Manager, không trả secret trong GET/API/log/export.
Có nút kiểm tra phân biệt TLS/auth/permission/query/ingestion. Import scenario
không tự cài rule lên Wazuh. Rule cần thiết được mô tả trong readiness; owner cài
và kiểm tra riêng. Indexer chỉ loopback có thể dùng tunnel do owner mở như pilot;
UI hiện disconnected nếu tunnel đóng, không bỏ TLS hoặc tự mở port 9200.

Export theo batch hoặc job gồm metadata, pinned package/profile/context, inputs,
raw/canonical evidence, reports, audit lifecycle được chọn và SHA-256 manifest.
Không đóng gói private key, password, pairing token hay reader config. Chỉ user
có quyền xem/export; server kiểm identity của object thay vì tin tên file client.
Pilot dossier không bị ghi lại hay bổ sung kết quả giả từ UI.

## 9. Bộ cài, nâng cấp và khôi phục

Gói Manager release có version/hash, frontend build, wheel/source và support tools;
installer Ubuntu x64 thiết lập service account, venv, PostgreSQL, migration, nginx,
HTTPS/private paths và worker. OS dependencies dùng package manager chính thức;
không thêm dependency ứng dụng nếu không giải thích. Endpoint/hostname/cert được
nhập hoặc lấy config; không hard-code IP lab, token, connector URL hoặc cert thật.

Cài mới hỏi hostname và nhận TLS certificate/trust bundle của lab hoặc tạo local
lab CA riêng có hướng dẫn trust; không dùng TLS bypass. Cài lại phát hiện instance,
backup config/database trước migration, không tạo lại CA/DB/users. Tách install,
start/status/upgrade và uninstall; uninstall không xóa dữ liệu mặc định.

Windows/Linux agent phát hành theo OS, có hash, lệnh connect/run/status và file
launcher tương ứng. Cấu hình riêng được tạo ngoài code checkout, quyền file phù
hợp, key không export trong gói. Cài trên máy hiện có bảo toàn cấu hình legacy;
không tự reenroll máy 009. Không cần mật khẩu SSH Wazuh để agent kết nối Manager.

Trước triển khai lab: backup DB/config, kiểm migration, dừng phát job trong lúc
nâng cấp, thử bản mới trên môi trường staging. Rollback dùng backup DB cùng source
và private config tương ứng; không hứa downgrade schema tự động. Không thay nguồn
đang chạy hoặc restart VM của owner chỉ do đã duyệt thiết kế.

## 10. Acceptance và kiểm chứng

- Test fixture end to end import ZIP → validate → publish → preview/approve batch
  → fake agent receipts → fixture evidence → report/export trước live lab.
- Test quyền/session/CSRF/object access, upload budgets/path/link/duplicates,
  hash/schema/profile mismatch, duplicate immutable version và publish snapshot.
- Test login đúng/sai, session rotation/expiry/logout, redirect nội bộ, reset mật
  khẩu và khóa user vô hiệu session cũ; không trả/log password/hash/reader secret.
  Cookie trước khóa vẫn bị từ chối sau khi mở khóa; API quản lý user sản phẩm
  không reset/khóa/đổi quyền tài khoản quản trị kỹ thuật để chiếm `/admin/`.
- Test đủ ba preset và quyền tùy chỉnh: server/service chặn direct API trái quyền,
  user không tự nâng quyền, khóa/hạ admin cuối cùng (kể cả request đồng thời) bị chặn,
  user được cấp quyền ngay request sau và không cần thành Django superuser.
- Test mới tạo `aegis/aegis` một lần, upgrade không reset tài khoản/DB/key/history.
- Test token expiry/one-use/concurrent redemption, mTLS identity/revocation,
  heartbeat server time, Linux no-dispatch, protocol v1/v2 isolation.
- Test batch atomic admission/idempotency/per-device concurrency/worker claim,
  failure/reconcile không tự replay và process tree timeout/cleanup.
- UI test chọn nhiều máy, không chọn Linux/offline/unsupported, import errors,
  draft không Run, version/hash/reviewer, thực thi và detection hiển thị riêng.
- UI test login/logout trên màn hình rộng/hẹp, account menu luôn tìm thấy, tạo
  user/đổi preset/checkbox/khóa user; Chỉ xem không có nút Run/Import/User admin,
  Vận hành có Run/Export và thiếu Publish/Manage users theo ma trận.
- Regression test giữ bộ canonical/intake/engine/compare và legacy SCN-001.
- Sau review: lab Ubuntu Manager, Windows 009 hiện có, một Windows thứ hai có
  mapping riêng, một Linux Online-only. Không đánh dấu multi-device đã kiểm chứng
  nếu chỉ có một Windows sẵn sàng; ghi rõ kết quả fixture và kết quả live riêng.
- Lab có ít nhất một gói ZIP mới ID riêng đi qua publish và Windows run, report có
  evidence IDs. Không sửa ground truth SCN-001 cho việc test catalog mới.
- Human review, evidence review và lab validation trước merge. Không secret,
  certificate hoặc unsanitized evidence được commit.

## 11. Các lựa chọn giao cho người triển khai

Tên endpoint/model/file chi tiết, cách chia React components và issue/commit,
trình bày log/progress, test harness và hash storage layout. Các giới hạn ZIP,
heartbeat, token và certificate trên là đề xuất có thể chỉnh qua config trong
phạm vi tests. Thay đổi ground truth, chạy Linux, thêm nền tảng hoặc quyền agent
mới vượt phạm vi này phải có quyết định riêng của owner.
