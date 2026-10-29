# Bộ chuẩn bị HTTPS Wazuh tùy chọn

Bộ operator của issue #163 chỉ dành cho chủ lab cần mở HTTPS trực tiếp từ
Manager tới Indexer. Nếu Indexer đã có HTTPS phù hợp, bỏ qua hoàn toàn bước này.
AEGIS không gọi bộ này lúc khởi động, không bắt buộc cài nó và không thay đổi
connector, tài khoản, binding, scenario hoặc agent.

## Điều kiện phát hành và giới hạn bằng chứng

Chỉ bàn giao bản đã review, có source commit đầy đủ, checksum ZIP, manifest và
native CI thành công **đúng commit đó**. Thay đổi dù một module phải được qualify
lại. `native-results.json` phải có `mode=native`, `status=passed`, không lỗi hoặc
skip; đủ tám ID trong `REQUIRED_NATIVE` phải `passed`, gồm gate mới
`test_ufw_disabled_wrapper_preserved` và bảy gate cũ. `native-source.json` phải
khớp source SHA và SHA-256 đủ 18 file canonical (10 code, runner, 5 test module,
workflow và tài liệu này). Metadata này giúp đối chiếu; nó
không phải chữ ký hay giấy cấp quyền thực thi.

Native CI dùng VM Ubuntu 24.04/Python 3.12 và hệ thống thật: OpenSSL ký CA giả;
quyền Unix, O_NOFOLLOW, directory-fd, flock, fsync, renameat2; nft trong network
namespace riêng; và systemd với dịch vụ TLS giả chạy non-root. Hai nguồn được
chứng minh kết nối TLS được trước guard; sau guard chỉ nguồn cho phép còn vào
được. systemd kiểm tra lại guard ở mỗi lần start/restart, kể cả khi oneshot guard
đang active nhưng table bị xóa hoặc bị sửa.

Harness sao chép nguyên byte module vào cây root-owned. Proof khai báo các
relocation: code/profile/compatibility record, tên unit, root vendor và netns.
Gate strict ánh xạ truy vấn ba loader sang ba unit fixture thực sự
inactive/disabled, giữ nguyên facts và không dùng exception UFW. Đây là inventory
fixture, không qualify loader của CI host. CLI, manifest, guard và nft verifier
thực vẫn chạy. Hai guard driver dùng adapter fixture `Commands._execute` để
kiểm tra lại root và inode netns ngay trước mỗi lần gọi executor production;
command/argv/input và giới hạn của executor được giữ nguyên. Startup check không
thay thế kiểm tra tại boundary này. Mỗi thay đổi firewall phải kiểm tra inode netns. Cleanup phải xác
nhận unit dừng, netns không còn process và host firewall không đổi; không chắc
chắn thì gate thất bại và giữ cây fixture.

Gate mới dùng nguyên byte pin từ Ubuntu `ufw_0.36.2-6_all.deb`; không cài package
hay gọi UFW của host. Script/unit/default/hook giữ SHA-256 riêng, config tổng hợp
`ENABLED=no`, hook không executable. Wrapper chạy trong root tối thiểu/netns riêng.
Gate thử stop/restart, direct `restart`/`force-reload`, từ chối `systemctl reload`
vì không có ExecReload; start/stop đồng thời trong một transaction systemd. Qua
các bước đó phải giữ Manager TLS allowed, nguồn khác denied, owned table và
foreign rules. Unit dùng một lần cung cấp 17 thuộc tính dependency thực và stop
propagation trực tiếp/bắc cầu/kết hợp, với ánh xạ vai trò song ánh được ghi lại.

Dependency fixture chuẩn hóa song ánh toàn bộ danh tính unit đã quan sát, kể cả
unit ngoài fixture trùng tên vai trò. Mọi query đảo ánh xạ về unit thực, giữ
nguyên 17 thuộc tính và mọi edge; proof giữ mapping và hash canonical raw facts.
Cùng mapper phải admit baseline an toàn trước khi thêm dependency để thử refusal.
Unit ngoài fixture chỉ được đọc; start/stop/restart/reload chỉ chấp nhận danh sách
unit fixture đã sở hữu, không dùng alias để gửi action tới UFW thật.

Proof tách hành vi vendor/packet/order thực; file/backend/typed D-Bus thực; và
admission dương qua reader tổng hợp. RootDirectory/FragmentPath khác stock phải
bị classifier production từ chối, không sửa facts để giả stock. Reader tổng hợp
chỉ thay package/unit/backend/dependency facts; record IO, `LinuxHost.guard`, fresh
nft read và verifier thực vẫn chạy. Child root riêng chứng minh JSON empty/foreign
với handles, partial UFW chain refusal, baseline và lock vắng mặt/sentinel có sẵn
không đổi. Không gọi UFW CLI, compatibility-list/save hay init-status. Runner và
workflow cùng validate schema, hashes, packet/order/preservation/cleanup; chỉ
upload proof không đủ qualify. Không upload fixture tree, CA/key hay journal.

Đây là **qualification Linux tổng hợp**, chưa phải kiểm chứng Wazuh/OpenSearch,
Dashboard, Manager thật, cấu hình vendor thật hay sự bền vững sau reboot. Chạy
portable trên Windows chỉ cho bằng chứng logic portable; thiếu Linux/systemd/nft
hoặc một native gate bị skip phải làm native qualification thất bại. Không chạy
native suite trên máy lab đang cài Wazuh: fence từ chối footprint/unit/package
Wazuh. Chỉ dùng VM dùng một lần, không có dữ liệu thật.

## Ngoại lệ duy nhất: wrapper UFW với policy disabled

Ngoài đường strict inactive/disabled, chỉ nhận Ubuntu UFW 0.36.2-6 đã qualify:
root oneshot/RemainAfterExit, active/exited và enabled, nhưng `ENABLED=no`.
Policy active, package/hook/unit tùy biến, drop-in, command/environment bổ sung,
backend khác nf_tables, pending work hoặc loader xung đột đều không được hỗ trợ.
Config được parse như dữ liệu, không source. Package references/hash local là
kiểm tra nhất quán trong trusted-root boundary, không phải chứng minh nguồn
package độc lập hay chống root đã bị chiếm quyền.

Quan sát là `probe={"method":"nft-no-ufw-chains-v1"}`: production tự đọc fresh
complete nft JSON, chỉ nhận subset table/chain/rule thông thường đã review, từ
chối mọi chain prefix `ufw-`/`ufw6-`. Đây là absence predicate trên backend đã chọn,
không phải `ufw status`, ruleset rỗng, view legacy hay phát hiện root đổi tên
chain. Normal CLI tạo/truncate lock nên không được gọi trong check. Unknown hoặc
partial JSON/policy ngoài hợp đồng đều từ chối, không đoán trạng thái inactive.

Record `/etc/aegis-wazuh-https/ufw-compat.json`, root 0600 dưới parent 0700, bind
profile và fingerprint static; ghi bền vững trước guard. Mỗi ensure và Indexer
verify qualify lại kể cả guard active. Thiếu record, method cũ hoặc drift không
tự refresh/migrate. Guard và Indexer chỉ `After=ufw.service`, không Wants/Requires
để tự start UFW; effective graph phải không truyền stop/restart ngược tới UFW.

Kit không stop/restart/reload/enable/disable, sửa file/hook hay flush UFW. Rollback
khôi phục HTTP/drop-in và verify localhost cũ trước khi bỏ owned table; không
khôi phục UFW. Trước thay policy/package/hook/backend hoặc dùng force-stop/
flush-all, đưa Indexer về trạng thái bảo trì an toàn đã duyệt rồi qualify lại.
Ordering/next-start checks không bảo vệ liên tục trước root sửa hệ thống; refusal
về sau không đóng khoảng hở đã xảy ra khi đang phục vụ.

**Owner full-class read-only check vẫn pending trước apply**, kể cả native CI
pass. Ghi evidence ID riêng như `HTTP-UFW-CHECK-01` để reviewer đối chiếu facts
thực; không suy ra từ reader tổng hợp. `vendor_lab_acceptance` luôn false trong
CI. Manager/denied-source/Dashboard/readiness và reboot vẫn là acceptance riêng.
Amendment cần ZIP mới, pin mới từ Git blobs đã qualify; giữ kit/check/bằng chứng
owner cũ, không vá chúng để mô tả là đã chứng minh hành vi mới.

## Chuẩn bị biến triển khai riêng

Chủ lab review profile riêng ngoài Git dựa trên
[`https-profile.json.example`](../../deploy/wazuh/https-profile.json.example).
Ví dụ công khai cố ý không dùng được. Không thay placeholder bằng giá trị lab
trong source, workflow hay artifact công khai.

| Nhóm | Giá trị chủ lab phải xác nhận |
| --- | --- |
| Danh tính | `hostname`, đúng host Indexer; phiên bản Wazuh 4.14.4/OpenSearch 2.19.4 |
| Đường mạng | `indexer_ip`, `manager_ip`: IPv4 chính xác, khác nhau, không wildcard; xác nhận địa chỉ source thực tế sau routing/NAT |
| Vendor | `config_path`, `ca_path`, `leaf_path` dưới cấu hình Indexer; chủ sở hữu và dedicated service group hiện có |
| CA archive | `ca_archive` trên chính Indexer; `ca_member`, `key_member` chính xác, duy nhất |
| Pin public | SHA-256 byte CA file, DER CA, DER leaf hiện tại; lấy từ file công khai đã review, không đoán |
| Bản bàn giao | source SHA, checksum ZIP, native run/artifact, danh sách file và module hashes đã review |

Không chép CA signing key ra khỏi Indexer, không upload archive, không ghi mật
khẩu vào argv hoặc terminal transcript. Plain tar chỉ đọc hai member đã chọn;
gzip phải decode phần đã bỏ qua theo giới hạn, rồi bỏ dữ liệu đó, không giữ hoặc
giải nén cả archive. `check` chỉ stat archive và stock keys, không đọc body CA key.

Môi trường được hỗ trợ: Python 3.12 stdlib, OpenSSL, nftables, systemd và package
Debian đã review. Không thêm Python dependency. Preflight từ chối unit/drop-in,
sandbox, firewall loader, YAML hoặc metadata ngoài hợp đồng; không tự sửa owner,
mode hay tắt firewall loader để vượt qua lỗi.

## Bàn giao và lệnh đầu tiên: check chỉ đọc

Chuyển ZIP đã đối chiếu checksum vào Indexer. Giải nén bản đã review vào staging
riêng với mọi ancestor root-owned, không symlink, không group/world writable.
Code/profile/manifest/work giữ root-only: thư mục 0700, file 0600. Không chạy bản
staged dưới home của user có thể ghi. Chỉ chép whitelist đã review, không dùng
`chown -R` hoặc `chmod -R` lên cây vendor.

Staging chứa `Setup-Wazuh-HTTPS.py`, tổng cộng mười mục module/entrypoint trong
`KIT-MANIFEST.json`, tests/runner để đối chiếu, và profile owner riêng. Manifest
có đúng `schema_version`, `source_commit`, `native_proof`, `files`; `files` đúng
whitelist của `host.KIT_FILES`. Không sửa code đã qualify, kể cả đổi newline.
Builder phải lấy byte từ Git blob/archive của commit đã qualify, không lấy bản
working tree CRLF. Manifest/profile phải có trước frozen check cuối cùng.

Chủ lab đặt hai biến sau tới đường dẫn staging/profile **đã kiểm tra trên máy**;
không sao chép giá trị giả hoặc lấy địa chỉ từ ví dụ. Sau khi verify checksum,
lệnh bàn giao đầu tiên chỉ là:

```sh
sudo /usr/bin/python3 -I -B "$STAGED_KIT/Setup-Wazuh-HTTPS.py" check --profile "$OWNER_PROFILE"
```

Lưu kết quả riêng trên host (root-only) với evidence ID do operator đặt, ví dụ
`HTTP-CHECK-01`. JSON `ready` gồm `profile_sha256`, `check_sha256`, `facts`.
Check không tạo lock/intent, không dừng service và không đọc CA private key.
Không đưa toàn bộ facts có giá trị lab vào PR/artifact. Profile hash là hash của
**byte file đầu vào**, không phải JSON được format lại.

Reviewer đối chiếu facts: đúng host/phiên bản, interface/listener, CA/leaf pin,
metadata file/unit/environment, group membership, firewall baseline, staged code
và archive inode/stat. Hash lỗi hoặc drift cần check mới và review mới; không
đoán hash, không sửa output cũ. Nếu manifest/profile/code thay đổi sau check,
check lại. Kết quả ready không thay thế quyền thực hiện bảo trì của chủ lab.

## Frozen apply và khoảng gián đoạn ngắn

Sau review bằng chứng check thật và cho phép bảo trì, controller mới cung cấp
lệnh apply đã pin: cùng profile, cùng staging, cùng `--profile-sha256` và
`--check-sha256` lấy nguyên từ check vừa duyệt. Tài liệu này không cấp một lệnh
apply có pin đoán sẵn. Apply kiểm tra lại trạng thái trước khi ghi; drift phải
dừng, không tự cập nhật baseline hoặc retry mù.

Chỉ Indexer được restart, tạo khoảng gián đoạn ngắn cần thông báo trước. Guard
được tạo và verify trước khi HTTP mở ra địa chỉ Indexer. HTTP giữ localhost;
transport/cluster/node/security, CA tin cậy, old cert/key và mọi cấu hình client
được giữ. Chỉ tuple địa chỉ Indexer/TCP 9200 có hạn chế nguồn; table riêng policy
accept với traffic khác. Không flush ruleset, không bật UFW.

Privileged profile được cài tại `/etc/aegis-wazuh-https/profile.json` dưới parent
root 0700; code tại `/usr/local/lib/aegis-wazuh-https`. TLS mới vẫn nằm trong cây
vendor `/etc/wazuh-indexer/aegis-http/tls`, root:service 0750 và file 0640. Không
đổi owner/mode cấu hình vendor hiện có. Mỗi start Indexer có root verifier bằng
`ExecStartPre=+... guard-verify`; guard oneshot active không đủ để bỏ qua verifier.
Stop guard không xóa firewall.

`renameat2` NOREPLACE/EXCHANGE và directory-fd bảo vệ publication. Đây không phải
compare-and-swap inode: writer đúng cửa sổ cuối có thể bị chuyển inode sang vùng
evidence root-only. Helper giữ displaced inode và snapshot byte đã quan sát,
dừng không restart/rollback ghi đè. Writer có fd cũ vẫn có thể sửa displaced
inode; snapshot không được mô tả là ảnh chụp đồng bộ dưới mọi concurrent writer.
Cần maintenance yên tĩnh; không chỉnh tay vendor config trong giao dịch.

Thành công cục bộ chỉ trả `pending_external_validation`. Đặt evidence ID cho
output apply và local verification, ví dụ `HTTP-APPLY-01`; chưa đánh dấu lab pass.

## Status, rollback và evidence phục hồi

Sau apply, dùng entrypoint **đã cài** đã review để đọc trạng thái hoặc rollback:

```sh
sudo /usr/bin/python3 -I -B /usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py status
sudo /usr/bin/python3 -I -B /usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py rollback
```

Rollback là hành động bảo trì rõ ràng, dùng theo quyết định chủ lab khi thất bại
hoặc phục hồi; không chạy như một phần check. Nếu cài đặt còn dang dở, dùng lại
entrypoint staged đúng bản đã review để đọc status/rollback. Intent cũ luôn chặn
apply mù. Giữ nguyên `/var/backups/aegis-wazuh-https/intent.json`, `operator.lock`,
`recovery.jsonl`, backup child và mọi
`/etc/aegis-wazuh-https/publication-*`; không xóa intent để ép retry.

Rollback khôi phục cấu hình/drop-in, restart và verify service localhost cũ trước
khi bỏ đúng owned table. Nếu không chắc chắn hoặc phát hiện vendor drift, giữ
guard, intent, snapshot và evidence; dừng để người review đối chiếu displaced
inode/snapshot. Không force-copy file cũ đè bản đã sửa, không flush table lạ.
Sau `rolled_back`, evidence vẫn được giữ để chủ lab quyết định xử lý riêng.
`filesystem_unsupported` chặn khi thiếu renameat2/flag hoặc khác mount; không có
fallback copy/replace để vượt qua giới hạn.

## Chấp nhận ngoài host và sau reboot

Ghi evidence ID, thời gian, người kiểm tra và kết quả cho từng bước trong hồ sơ
lab riêng. Chỉ public bản tóm tắt đã lọc, không gửi key, archive, credential,
profile thật hoặc output có giá trị nội bộ vào Git/CI.

1. Từ **Manager thật**, dùng CA tin cậy và kiểm tra hostname/IP của endpoint;
   chứng minh TLS chain/leaf/SAN đúng và truy cập Indexer với quyền đã có. Không
   dùng `-k` hoặc tắt verification. Ghi `HTTP-MANAGER-01`.
2. Từ **nguồn khác thực sự có route tới Indexer**, chứng minh bị chặn TCP 9200;
   đối chiếu route/source thực tế và bằng chứng gói thử tới Indexer cùng table
   guard chính xác để không kết luận nhầm chỉ từ timeout do thiếu đường mạng.
   Thu thập quan sát giới hạn theo quyền chủ lab; không tạm xóa guard khi listener
   thật đang mở. Nếu thiếu bằng chứng đường mạng, giữ acceptance pending và thống
   nhất phép thử riêng. Native CI đã chứng minh cùng tuple có thể truy cập từ cả
   hai nguồn trước guard; điều đó không tự chứng minh routing của lab thật.
   Ghi `HTTP-DENIED-01`.
3. Kiểm tra localhost HTTPS, transport còn loopback, Dashboard và các client
   legacy cũ vẫn hoạt động; CA/transport/config ngoài phạm vi không đổi.
   Ghi `HTTP-LEGACY-01`.
4. Kiểm tra worker/source Manager cũ và độ mới dữ liệu sau outage; kiểm tra agent
   ready trước khi tạo job. Nếu worker/source hoặc agent chưa sẵn sàng, xem
   journal và identity, giữ data/UUID, chỉ restart theo quy trình an toàn được
   review riêng. Không tự đổi agent/service/binding hoặc chạy scenario để thử.
   Ghi `HTTP-READINESS-01`.
5. Chỉ khi **được cho phép reboot riêng**, xác nhận boot ordering, table guard,
   mỗi-start verification và lặp lại Manager/denied/Dashboard/readiness sau boot.
   Không tự reboot. Nếu chưa được phép, ghi `HTTP-REBOOT-01: pending`; không coi
   persistence đã pass chỉ vì synthetic systemd CI thành công.

Chủ lab/reviewer kết luận dựa trên evidence ID từng mục; không nâng trạng thái
chỉ từ output status. Chỉ merge sau khi test/evidence đã được người review và
lab validation duyệt.
