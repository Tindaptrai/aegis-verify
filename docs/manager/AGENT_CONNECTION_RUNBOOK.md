# Kết nối máy Windows / Ubuntu và tự chạy khi khởi động

Hướng dẫn cho presence agent `0.2.0`: enrollment và legacy heartbeat `2.0`,
network heartbeat `2.1`. Windows 11, Windows 10
LTSC/Enterprise còn hỗ trợ, hoặc Windows Server 2019/2022/2025 x64 có SCM và
PowerShell 5.1; Ubuntu 24.04 LTS x64 có systemd
là PID 1. Manager chạy Linux theo `docs/manager/FIRST_FLOW_RUNBOOK.md` trong source
commit ghi ở `version.json`.
Gói tự chứa .NET runtime `10.0.13`; máy đích không cần .NET SDK.
Các bản Windows cần còn được nhà cung cấp hỗ trợ/cập nhật trong môi trường của owner;
đối chiếu [bảng .NET trên Windows của Microsoft](https://learn.microsoft.com/en-us/dotnet/core/install/windows#supported-versions)
cho edition/build cụ thể. Windows 10 thông thường đã hết hỗ trợ không thuộc baseline này.

Agent này đăng ký danh tính và heartbeat. **Online không có nghĩa là sẵn sàng chạy
scenario.** Máy `paired_presence` không nhận lease/kịch bản. Legacy Windows v1 và
pilot 009 tiếp tục dùng quy trình, CA và CurrentUser certificate riêng của chúng.

## 1. Chuẩn bị Manager Linux

Owner chuẩn bị các giá trị, dùng placeholder phù hợp với môi trường:

| Biến | Ý nghĩa |
|---|---|
| `MANAGER_ORIGIN` | `https://<MANAGER_IP_OR_DNS>[:<TLS_PORT>]`, không dấu `/` cuối |
| `MANAGER_HOST` | IP/DNS được phép trong `AEGIS_MANAGER_ALLOWED_HOSTS` |
| `SERVER_CERT` / `SERVER_KEY` | Chứng chỉ HTTPS và private key trên nginx |
| `SERVER_CA` | Một public PEM CA được chuyển cho endpoint qua kênh đáng tin |
| `ENROLLMENT_CA_KEY` / `ENROLLMENT_CA_CERT` | Issuer mới, riêng biệt dưới private root |
| `CLIENT_CA_BUNDLE` | Bundle public CA gồm cả legacy pilot CA và enrollment CA mới |

Nếu dùng IP, server certificate phải có **iPAddress SAN đúng IP**; DNS SAN chứa
chuỗi IP hoặc chỉ CN không đủ. Chuỗi phải hợp lệ về thời gian, serverAuth và trust.
Không tải CA từ một server chưa xác minh rồi tự tin cậy nó. Không tắt TLS verification.
Không đưa private key, certificate cá nhân, cấu hình triển khai, pairing code hoặc
evidence thật vào repository, archive công khai hay báo cáo CI.

Áp dụng migration và khởi tạo issuer bằng môi trường service hiện có. File
`EnvironmentFile` dùng cú pháp systemd; không `source` như shell. Ví dụ owner thay
`<MANAGER_ROOT>`, `<MANAGER_PYTHON>`, `<MANAGER_USER>`, `<MANAGER_GROUP>`,
`<MANAGER_ENV_FILE>` bằng đường dẫn tuyệt đối và account tương ứng. Với layout
đang dùng trong `FIRST_FLOW_RUNBOOK.md`, source root là `/opt/aegis/current`, còn
interpreter hiện có là `/opt/aegis/venv/bin/python`. Dùng interpreter của service
đã triển khai; không tạo hoặc giả định `.venv` dưới source root khi nâng cấp:

```bash
sudo systemd-run --wait --pipe --collect \
  --uid=<MANAGER_USER> --gid=<MANAGER_GROUP> \
  --working-directory=<MANAGER_ROOT> \
  --property=EnvironmentFile=<MANAGER_ENV_FILE> \
  <MANAGER_PYTHON> manager/manage.py migrate
sudo systemd-run --wait --pipe --collect \
  --uid=<MANAGER_USER> --gid=<MANAGER_GROUP> \
  --working-directory=<MANAGER_ROOT> \
  --property=EnvironmentFile=<MANAGER_ENV_FILE> \
  <MANAGER_PYTHON> manager/manage.py init_enrollment_ca
```

Đặt `AEGIS_MANAGER_ENROLLMENT_CA_KEY` / `AEGIS_MANAGER_ENROLLMENT_CA_CERT` tới hai
đường dẫn riêng dưới `AEGIS_MANAGER_PRIVATE_ROOT` trước lệnh init. Kiểm tra tên biến
với `manager/aegis_manager/settings.py` trong source commit của phiên bản đang dùng.
Issuer chỉ được tạo khi cả hai file chưa tồn tại, từ chối trạng thái thiếu một file,
key/cert không khớp hoặc quyền không an toàn. Không xóa file lỗi để tự động tạo CA mới.
Key enrollment được bảo vệ trên Manager; không sử dụng lại key server/job/pilot.

Sửa nginx theo `deploy/manager/nginx.conf.example` trong source commit: đúng origin,
server certificate/key, `server_name`, client trust bundle và upstream loopback.
Giữ public legacy CA trong bundle; không thay thế pilot CA/key. Bootstrap chỉ là
`/agent/v2/enroll` không cần client certificate, có giới hạn body/rate và loại bỏ
identity header. Cả exact location `/agent/v2/heartbeat` (2.0) và
`/agent/v2/network-heartbeat` (2.1, body tối đa 16 KiB) bắt buộc certificate đã xác
minh; nginx ghi đè identity header từ TLS và `X-Aegis-Peer-IP` bằng `$remote_addr`
ở **cả hai route**. Không lấy IP từ `X-Forwarded-For`, `Forwarded` hay header client;
không bật real_ip để thay đổi provenance. Giữ nguyên mTLS `/agent/v1/` và không mở
upstream ra mạng. Nếu deployment dùng listener v2 riêng, thêm exact location mới
vào listener v2 hiện có; không chép đè toàn bộ template lên deployment. Giữ nguyên
port/listener, certificate/key, CA bundle và CRL legacy hiện có.
Sau khi kiểm tra cấu hình và quyền file, `sudo nginx -t` rồi reload nginx và restart
Manager theo runbook hiện có. `ALLOWED_HOSTS`, SAN và origin phải thống nhất.

## 2. Xác minh gói công khai

Chọn đúng archive:

- `AEGIS-Agent-Connection-<VERSION>-win-x64.zip`
- `AEGIS-Agent-Connection-<VERSION>-linux-x64.tar.gz`

Nhận archive và file cùng tên thêm `.sha256` từ bản phát hành đã review. Đối chiếu
source commit trong `version.json` và kết quả CI của **đúng commit build**. Gói gồm
`bin/`, installer/uninstaller, Linux unit nếu áp dụng, guide, `version.json`,
`SHA256SUMS.txt`; không chứa CA triển khai, private identity, pairing code hay config.
`bin/LICENSE.TXT`, `bin/THIRD-PARTY-NOTICES.TXT` và
`bin/DOTNET-RUNTIME-NOTICES.json` giữ nguyên notice của runtime đúng RID/version,
nguồn package và SHA-256; chúng được manifest kiểm tra và giữ cùng runtime khi cài.
Installer kiểm tra tất cả file theo manifest trước thay đổi máy. Hash xác minh tính
toàn vẹn; owner vẫn cần nguồn phân phối đáng tin và đối chiếu CI/source.

Windows PowerShell (Administrator):

```powershell
$Archive = '<ABSOLUTE_ARCHIVE_PATH>'
$Expected = ((Get-Content -LiteralPath ($Archive + '.sha256')) -split '  ')[0]
if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ine $Expected) { throw 'archive_hash_mismatch' }
Expand-Archive -LiteralPath $Archive -DestinationPath '<NEW_ABSOLUTE_PACKAGE_DIRECTORY>'
```

Ubuntu:

```bash
cd '<DOWNLOAD_DIRECTORY>'
sha256sum --check 'AEGIS-Agent-Connection-<VERSION>-linux-x64.tar.gz.sha256'
mkdir '<NEW_PACKAGE_DIRECTORY>'
tar -xzf 'AEGIS-Agent-Connection-<VERSION>-linux-x64.tar.gz' -C '<NEW_PACKAGE_DIRECTORY>'
cd '<NEW_PACKAGE_DIRECTORY>'
sha256sum --check SHA256SUMS.txt
```

Ubuntu 24.04 cần các native dependencies sau dù gói đã chứa runtime:

```bash
sudo apt-get update
sudo apt-get install ca-certificates libc6 libgcc-s1 libgssapi-krb5-2 libicu74 libssl3t64 libstdc++6 tzdata zlib1g
```

Danh sách theo [Microsoft .NET Ubuntu 24.04](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install).
Không áp dụng tên package của Ubuntu phiên bản khác.

## 3. Mint mã trên giao diện

Đăng nhập Manager bằng tài khoản có `view` + `manage_devices`, mở **Máy → Thêm máy**,
nhập environment được duyệt rồi tạo mã. Mã hiển thị một lần, dùng thành công một lần,
hết hạn sau **600 giây**. Máy đích không đăng nhập tài khoản web. Chỉ nhập mã tại
prompt ẩn của installer/CLI; không đặt mã trong command, URL, argv, biến môi trường,
file, clipboard tự động, log, ticket hay shell history. Đóng dialog khi xong.
Code hết hạn/thu hồi/đã dùng hoặc issuer mất quyền đều bị từ chối với cùng lỗi.

## 4. Cài Windows

Mở **Windows PowerShell 5.1 với Administrator**, chuyển tới thư mục giải nén. CA
server công khai phải ở đường dẫn tuyệt đối, nhận qua kênh đáng tin:

Trước mọi lần chạy script (cài, nâng cấp, gỡ hoặc phục hồi trong shell mới), hoàn
tất mục 2: nhận gói/hash từ nguồn đã review, đối chiếu source/CI, xác minh archive
rồi giải nén vào thư mục mới. Đọc/review hai script trong gói đã xác minh. Quyền
Administrator không tự cho phép chạy script: mặc định Windows client là
`Restricted`; `RemoteSigned` còn chặn script unsigned mang dấu tải từ Internet.

Kiểm tra policy trước khi chạy. `MachinePolicy`/`UserPolicy` do **Group Policy**
áp đặt có ưu tiên cao hơn lựa chọn process; nếu chính sách tổ chức chặn script,
dừng và dùng quy trình/script signing được tổ chức phê duyệt, không cố vượt policy:

```powershell
Get-ExecutionPolicy -List
```

Các lệnh dưới gọi đúng Windows PowerShell 5.1 bằng đường dẫn hệ thống, với
`-NoProfile -ExecutionPolicy Bypass -File` cho **một process con** chạy script vừa
review. Lựa chọn này xử lý cả Restricted mặc định và dấu Internet của script
unsigned khi Group Policy cho phép; nó hết hiệu lực khi process kết thúc, không
lưu policy vào registry/user/machine. Chỉ dùng với gói đã xác minh ở trên, không
dùng cho script khác. Xem [Microsoft về execution policy và ưu tiên scope](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1).

```powershell
$ManagerOrigin = 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>'
$ServerCa = '<ABSOLUTE_PUBLIC_SERVER_CA_PEM>'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\Install-Agent.ps1 -Manager $ManagerOrigin -ServerCa $ServerCa
```

Nhập mã khi prompt yêu cầu, không truyền mã như parameter. Installer tạo service
`AegisAgent` lúc đầu disabled, áp ACL rồi connect. Chỉ khi identity hợp lệ mới bật
Automatic (Delayed Start) và khởi chạy. Service dùng **`NT SERVICE\AegisAgent`**,
không chạy LocalSystem. Binary ở `%ProgramFiles%\AEGIS Agent\bin`; private state ở
`%ProgramData%\AEGIS\Agent`, chỉ admin/SYSTEM và service SID được truy cập phù hợp.
Service chỉ đọc/chạy binary, được sửa state. Không tự nới ACL để chữa lỗi.

```powershell
$Agent = Join-Path $env:ProgramFiles 'AEGIS Agent\bin\aegis-agent.exe'
$State = Join-Path $env:ProgramData 'AEGIS\Agent'
```

| Việc | Lệnh Windows PowerShell Administrator |
|---|---|
| Service status | `Get-Service AegisAgent` |
| Identity status | `& $Agent status --state-dir $State` |
| Start | `Start-Service AegisAgent` |
| Stop | `Stop-Service AegisAgent` |
| Restart | `Restart-Service AegisAgent` |
| Kiểm tra account/path/autostart | `sc.exe qc AegisAgent` |
| Kiểm tra delayed start | `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AegisAgent').DelayedAutoStart` |
| Log lifecycle | `Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 30` |

`status` hiển thị UUID, trạng thái và lần acknowledgement cuối, không xuất key/code.
Log SCM cho biết lifecycle; đối chiếu heartbeat trong Manager. Không đọc/chia sẻ
`state.json` khi lấy log. Trên Windows, Schannel dùng key container tạm của tài khoản
đang chạy; kiểm thử SCM cần xác minh chính virtual account sử dụng được key đó.

## 5. Cài Ubuntu

Chạy trên host systemd thực, không container có PID 1 khác:

```bash
cd '<ABSOLUTE_PACKAGE_DIRECTORY>'
sudo bash ./install.sh --manager 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>' --server-ca '<ABSOLUTE_PUBLIC_SERVER_CA_PEM>'
```

Nhập mã tại prompt ẩn. Installer dùng user/group hệ thống `aegis-agent`, shell
`/usr/sbin/nologin`; binary root-owned ở `/opt/aegis-agent/bin`, state owned bởi
service account ở `/var/lib/aegis-agent` (directory `0700`, file `0600`). Connect
chạy với quyền service account. Unit `aegis-agent.service` được enable sau connect,
Type=simple, network-online ordering và Restart=on-failure; binary không service-writable.

| Việc | Lệnh Ubuntu |
|---|---|
| Start | `sudo systemctl start aegis-agent.service` |
| Stop | `sudo systemctl stop aegis-agent.service` |
| Restart | `sudo systemctl restart aegis-agent.service` |
| Service status | `sudo systemctl status aegis-agent.service --no-pager` |
| Kiểm tra boot enable | `systemctl is-enabled aegis-agent.service` |
| Identity status | `sudo -u aegis-agent /opt/aegis-agent/bin/aegis-agent status --state-dir /var/lib/aegis-agent` |
| Log | `sudo journalctl -u aegis-agent.service --since '-15 min' --no-pager` |

Không chạy `connect` mỗi lần boot. Khi mạng chưa sẵn sàng, loop dùng bounded retry
2–60 giây, heartbeat sau thành công mỗi 15 giây; Manager chuyển Offline sau 60 giây
không nhận heartbeat hợp lệ. Khởi động lại/mất mạng phải dùng lại **cùng UUID**.
Revoke hoặc certificate hết hạn cần owner xử lý; agent không tự đăng ký lại.

## 6. Nâng cấp, gỡ cài và phục hồi

Đợt 0.2.0: backup database và cấu hình private theo quy trình owner trước nâng.
Nâng **Manager + migrations + nginx trước**, kiểm tra heartbeat 0.1.0 vẫn hoạt động,
rồi nâng agent từng máy và kiểm tra UI mới. Không init lại issuer hay đổi PKI khi
nâng từ 0.1.0. Ghép nối mới bằng 0.2.0 cần Manager mới; enrollment vẫn protocol 2.0.
Network heartbeat dùng 2.1 và báo phiên bản binary đang chạy 0.2.0; phiên bản ghi
khi ghép nối vẫn được giữ riêng. State cũ 0.1.0 giữ UUID, generation, khóa, CSR,
certificate, origin và CA pin; không ghi IP vào protected state.

Chỉ HTTP 404 tại route network cho phép fallback sang heartbeat 2.0 trong suốt
process hiện tại; restart sẽ thử route mới lại. Fallback giữ presence nhưng không
có IP agent khai báo. 403, lỗi TLS/trust, 429, 5xx hoặc response sai không bật
fallback. Nếu rollback binary, 0.1.0 chỉ dùng state vốn được tạo bằng 0.1.0;
không dùng nó để đọc state mới tạo bằng 0.2.0. Không rollback database để phục hồi
identity đã revoked/archived, và không sửa version trong private state.

IP khai báo là các địa chỉ interface Up agent thu được, tối đa 32; không suy đoán
IP chính. IP kết nối Manager thấy là peer quan sát bởi nginx, có thể khác do NAT.
`[]` là thu thành công nhưng không có địa chỉ hợp lệ; null/chưa ghi nhận hoặc thu
thất bại không có nghĩa máy không có mạng. Offline hiển thị snapshot cũ cùng thời
gian nhận. Xóa máy trên Manager archive + revoke, giữ snapshot cuối và lịch sử;
không uninstall endpoint. Agent bị từ chối heartbeat và không tự re-enroll.

Xác minh gói mới rồi chạy installer mới. Với state enrolled hợp lệ, installer dùng
lại identity và không hỏi code. Nếu cung cấp origin/CA khác state đã pin, installer
từ chối. Service/path/account có cấu hình khác hoặc state không an toàn cũng bị từ
chối. Không sửa service sang LocalSystem/root hay xóa state để vượt qua kiểm tra.

Windows: trong mỗi shell Administrator mới, xác minh gói mới theo mục 2 và policy
theo mục 4, chuyển tới thư mục gói đã review. Nâng cấp/cài lại state enrolled:

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\Install-Agent.ps1
```

Lệnh này dùng origin/CA đã pin và không cần mint code mới cho identity còn hợp lệ.
Để gỡ, dùng uninstaller trong gói đã xác minh và cùng prerequisite mục 2/4,
kể cả khi vừa mở shell Administrator mới.

Gỡ service và binary, **giữ identity/config được bảo vệ**:

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-Agent.ps1
```

```bash
sudo bash ./uninstall.sh
```

Gỡ cài không revoke trên Manager. Cài lại giữ state thì vẫn cùng UUID. Lỗi start hay
upgrade không phải lý do tạo key mới; xem fixed diagnostic và quyền tài khoản trước.
Khi pairing thất bại, service giữ disabled và pending key/CSR được giữ lại.

Nếu owner cần chạy connect trực tiếp để xử lý pending state, trước hết stop service
và giữ nguyên thư mục/quyền đã được installer tạo. Trong shell Administrator mới,
đặt lại biến như dưới; trước khi chạy lại installer, hoàn tất prerequisite mục 2/4.
Các lệnh vẫn hỏi code ở prompt ẩn:

```powershell
$Agent = Join-Path $env:ProgramFiles 'AEGIS Agent\bin\aegis-agent.exe'
$State = Join-Path $env:ProgramData 'AEGIS\Agent'
$ManagerOrigin = 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>'
$ServerCa = '<ABSOLUTE_PUBLIC_SERVER_CA_PEM>'
Stop-Service AegisAgent
& $Agent connect --manager $ManagerOrigin --server-ca $ServerCa --state-dir $State
```

```bash
sudo systemctl stop aegis-agent.service
sudo -u aegis-agent /opt/aegis-agent/bin/aegis-agent connect --manager 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>' --server-ca '<ABSOLUTE_PUBLIC_SERVER_CA_READABLE_BY_SERVICE>' --state-dir /var/lib/aegis-agent
```

Không nới quyền state để chạy lệnh này; public CA cần nằm ở đường dẫn service
account đọc được. Sau khi connect hợp lệ, chạy lại installer để bật service theo
cấu hình autostart đã kiểm tra.

`enrollment_outcome_unknown`: response có thể mất sau khi Manager đã dùng code.
Owner kiểm tra danh sách Máy, revoke orphan Offline nếu có, tạo mã thay thế, chạy
lại installer/connect với cùng pending state và cùng origin/CA. Không dùng lại code
đã tiêu thụ; không có tự động recovery bằng code cũ.

Thay thế identity expired/revoked: owner revoke UUID cũ trên Manager, stop service,
rồi retire đúng UUID hiện tại. Lệnh retire cần quyền truy cập state và lock độc quyền;
nó copy snapshot vào `retired/<UUID>-<random>/state.json` được bảo vệ, flush file và
đồng bộ hierarchy thư mục archive trước khi bỏ active snapshot, rồi đồng bộ thư mục
nguồn. Lỗi có thể để lại cả archive được bảo vệ và active bytes để phục hồi; không
tự động xóa archive:

Windows recovery trong shell Administrator mới: hoàn tất mục 2/4 với gói đã review,
chuyển tới thư mục gói; đặt lại các biến sau trước stop/retire/install. Code mới
chỉ được nhập tại prompt ẩn sau khi owner revoke UUID cũ:

```powershell
$Agent = Join-Path $env:ProgramFiles 'AEGIS Agent\bin\aegis-agent.exe'
$State = Join-Path $env:ProgramData 'AEGIS\Agent'
$ManagerOrigin = 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>'
$ServerCa = '<ABSOLUTE_PUBLIC_SERVER_CA_PEM>'
Stop-Service AegisAgent
& $Agent retire --state-dir $State --device-id '<CURRENT_DEVICE_UUID>'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\Install-Agent.ps1 -Manager $ManagerOrigin -ServerCa $ServerCa
```

```bash
sudo systemctl stop aegis-agent.service
sudo -u aegis-agent /opt/aegis-agent/bin/aegis-agent retire --state-dir /var/lib/aegis-agent --device-id '<CURRENT_DEVICE_UUID>'
sudo bash ./install.sh --manager 'https://<MANAGER_IP_OR_DNS>:<TLS_PORT>' --server-ca '<ABSOLUTE_PUBLIC_SERVER_CA_PEM>'
```

Nhập code mới tại prompt. UUID mismatch/lock đang giữ/archive không an toàn sẽ bị
từ chối; giữ nguyên trạng thái để điều tra. Đổi CA/origin là thao tác thay thế có
owner review, không sửa trực tiếp private JSON.

## 7. Checklist lab của owner trước triển khai

- Review source commit, CI thực của đúng commit, archive hash và manifest công khai.
- Xác minh TLS SAN/trust/expiry, ALLOWED_HOSTS và bundle giữ được legacy pilot 009.
- Cài trên Windows/Ubuntu đích, xác minh service account và quyền state/binary.
- Ghi UUID và heartbeat, reboot disposable endpoint được duyệt; **không đăng nhập**,
  quan sát Manager nhận heartbeat cùng UUID. Kiểm tra sau delayed startup/mạng chậm.
- Ngắt mạng rồi phục hồi, quan sát Offline → Online cùng UUID, không có enrollment mới.
- Kiểm tra nhiều card/DHCP/VPN trên endpoint được duyệt; IP khai báo và peer NAT
  có nhãn/thời gian riêng, không gộp hoặc chọn IP chính.
- Archive đúng UUID từ UI; máy rời danh sách quản lý, có trong Đã xóa cùng lịch sử,
  snapshot cuối không đổi, heartbeat bị từ chối và endpoint không tự re-enroll.
- Revoke; xác minh không heartbeat cập nhật, status yêu cầu xử lý và không tự re-enroll.
- Thử code expiry/reuse/demotion; xác minh từ chối, không lộ code trong logs/history.
- Kiểm tra certificate expiry/replacement, retire bảo toàn identity cũ, UUID mới sau connect.
- Kiểm tra stop/restart/upgrade/uninstall giữ identity và user thường không đọc key,
  service không sửa binary, Windows virtual account thực sự dùng được Schannel key.

CI native start/stop/configuration là bằng chứng cho các gate đó; **không chứng minh
reboot trước login**. Kết quả owner lab 0.1.0 trước đây không thay cho gate 0.2.0.
Chỉ đánh dấu reboot/network/expiry lab gate đã chạy khi có
quan sát thực và owner review. Human review + lab validation bắt buộc trước merge.
