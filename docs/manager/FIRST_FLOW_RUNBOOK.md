# Vận hành first flow Manager → một Windows VM

Mốc này dùng agent foreground, đăng ký chứng thư thủ công và Django admin. Chưa có service/MSI Windows hay nghiệm thu pilot/live. Contract: [FIRST_FLOW_PROTOCOL.md](FIRST_FLOW_PROTOCOL.md).

## 1. Gate trước khi bật VM

Windows được chủ lab chọn: `I:/may_ao/Windows Admin Soc/Windows Admin Soc.vmx`. Wazuh được chủ lab xác nhận là `F:/vm_ware/DACS/Wazuh Server/Wazuh Server.vmx`; cả hai VM nối VMnet5. Chủ lab xác nhận **chưa có VM Linux Manager**. Tại thời điểm kiểm inventory, các VM đang tắt. Chỉ tiến hành phần lab sau khi ghi quyền thử, snapshot, baseline rule, hostname, mạng cô lập, thời gian UTC/NTP, dung lượng, người duyệt và điều kiện dừng. Không chạy runner trên host phát triển. Credential dùng qua cấu hình private, không gửi vào chat hoặc ghi trong source.

Chuẩn bị VM Manager riêng: Ubuntu Server 24.04 LTS được cập nhật, 2 vCPU, RAM 4 GB, đĩa 40 GB, kết nối mạng lab VMnet5. Đây là ngân sách khởi đầu, chưa phải benchmark. Xác định DHCP/địa chỉ, DNS, gateway và quyền truy cập package repository theo mạng lab thực tế; không lấy một địa chỉ IP mẫu làm cấu hình thật. Ghi inventory và tạo tài khoản triển khai/SSH theo chính sách lab trước khi cài mục 2. Không thay Windows/Wazuh bằng Linux guest dùng chung hoặc clone giữ nguyên danh tính.

Chủ lab phải cung cấp kit SCN-001/profile được duyệt, Wazuh agent mapping và tài khoản Indexer chỉ đọc. Không dùng evidence lịch sử làm evidence của job mới. Không sửa ground truth để vượt gate.

## 2. Cài Manager Linux (chủ lab thực hiện)

Ví dụ dưới cho Linux dùng apt/systemd; kiểm package phù hợp với distro trước khi chạy. Thay mọi `REPLACE_*` trong bản private. Source/build đã review ở `/opt/aegis/current`; service account không có quyền sửa source/venv. Không cài từ bản source chưa kiểm hash.

```sh
sudo apt-get install python3-venv postgresql nginx openssl
sudo useradd --system --home /var/lib/aegis-manager --shell /usr/sbin/nologin aegis-manager
sudo install -d -o aegis-manager -g aegis-manager -m 0700 /var/lib/aegis-manager
sudo install -d -o aegis-manager -g aegis-manager -m 0700 /var/lib/aegis-manager/keys /var/lib/aegis-manager/catalog /var/lib/aegis-manager/evidence
sudo install -d -o root -g aegis-manager -m 0750 /etc/aegis-manager
sudo python3 -m venv /opt/aegis/venv
sudo /opt/aegis/venv/bin/pip install -r /opt/aegis/current/manager/requirements.txt
sudo /opt/aegis/venv/bin/pip install /REPLACE_REVIEWED_ARTIFACT_DIR/aegis_verify-0.4.0-py3-none-any.whl
sudo -u postgres createuser --pwprompt aegis_manager
sudo -u postgres createdb --owner=aegis_manager aegis_manager
```

PostgreSQL chỉ lắng nghe local; dùng `scram-sha-256` cho DB/user này trong `pg_hba.conf`, không dùng `trust`. Xác minh đăng nhập DB local và kiểm quyền DB trước migrate. SQLite chỉ dành cho test/development.

Sao chép `deploy/manager/manager.env.example` ra `/etc/aegis-manager/manager.env`, điền private secret ngẫu nhiên ít nhất 50 ký tự, hostname và DB password; đặt `root:aegis-manager`, mode `0640`. Đây là cú pháp systemd EnvironmentFile, không `source` bằng shell. Giữ khóa CA, khóa TLS, khóa ký job và mật khẩu riêng biệt; không đưa vào git/kit trình bày.

Tạo khóa ký job **trên VM** bằng lệnh sau, không chạy trong checkout. Bảo vệ public key khỏi bị thay thế khi chuyển sang Windows qua kênh đã kiểm hash.

```sh
sudo -u aegis-manager openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /var/lib/aegis-manager/keys/manager-signing.pem
sudo chmod 0600 /var/lib/aegis-manager/keys/manager-signing.pem
sudo -u aegis-manager openssl pkey -in /var/lib/aegis-manager/keys/manager-signing.pem -pubout -out /var/lib/aegis-manager/keys/manager-public.pem
```

Chủ lab cấp TLS server certificate có SAN đúng hostname và EKU serverAuth; agent certificate riêng có EKU clientAuth, private key riêng và thời hạn được duyệt. Agent CA ở nginx chỉ chứa CA dành cho agent; không đặt private CA key trên web server. Cài chain/key/agent CA theo đường dẫn trong nginx template, key `root:root 0600`. Cấu hình CRL nếu CA triển khai thu hồi; dù vậy phải đặt `Device.revoked` khi thu hồi agent. Không tắt xác minh chain/hostname/revocation để chữa lỗi TLS.

## 3. Migrate, static và HTTPS

Sao chép hai unit từ `deploy/manager/` vào `/etc/systemd/system/`. Để chạy lệnh quản trị với cùng env private và user, dùng transient unit (không đưa secret vào command line):

```sh
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py migrate
sudo systemd-run --wait --pty --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py createsuperuser
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py collectstatic --noinput
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py check --deploy
```

Sau collectstatic, xuất bản **chỉ static** sang `/srv/aegis-manager-static/`, thuộc root, thư mục `0755`, file `0644`; nginx chỉ đọc thư mục này. Không nới quyền private root để phục vụ static. Bản static chỉ gồm output Django collectstatic đã review, không symlink. Giữ mọi evidence/catalog ngoài web root. Khi xuất bản lần đầu, kiểm không có symlink rồi sao chép:

```sh
sudo find /var/lib/aegis-manager/static -type l -print
# Nếu có bất kỳ symlink nào: dừng và review trước khi copy.
sudo install -d -o root -g root -m 0755 /srv/aegis-manager-static
sudo cp -R /var/lib/aegis-manager/static/. /srv/aegis-manager-static/
sudo chown -R root:root /srv/aegis-manager-static
sudo find /srv/aegis-manager-static -type d -exec chmod 0755 {} +
sudo find /srv/aegis-manager-static -type f -exec chmod 0644 {} +
```

Thay hostname trong `nginx.conf.example`, cài vào nginx `http{}`; bỏ default site nếu nó chiếm route. TLS tối thiểu 1.2, HSTS 1 năm; chỉ bật khi hostname/CA đã ổn định. Không cấu hình redirect HTTP mang theo agent POST. Firewall chỉ cho HTTPS từ mạng lab được duyệt; PostgreSQL và Gunicorn không công bố LAN. `localhost:8001` là biên proxy tin cậy: không cho người dùng/process không tin cậy chạy trên VM Manager. Nginx ghi đè certificate/proto headers; Django tự tính fingerprint DER. Không thêm proxy ngoài chưa được review.

```sh
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl start aegis-manager
sudo systemctl reload nginx
sudo ss -lntp
```

Xác minh port 8001 chỉ loopback, nginx upstream kết nối được trên distro đã chọn; không dùng dashboard `http.server` cũ trên LAN. Kiểm `/admin/` HTTPS đăng nhập/CSRF; `/agent/v1/poll` thiếu cert trả 403 kể cả khi tự gửi `X-Aegis-Client-*`; cert lạ/sai chain bị chặn; cert hợp lệ nhưng chưa enroll bị app từ chối. Kiểm TLS 1.0/1.1 không bắt tay được và static không đọc được file ngoài thư mục. Không bật worker trước gate nguồn dữ liệu.

## 4. Enroll thủ công và catalog private

Trên **Windows VM đã chọn**, nhập CA Manager vào OS trust của user chạy agent, certificate cùng private key vào `Cert:\CurrentUser\My` (Certificate Import Wizard hoặc `Import-PfxCertificate` với mật khẩu nhập tương tác). Không đặt PFX/password trong repo. Xác minh chứng thư có private key, clientAuth, đúng chain, hạn dùng; fingerprint cấu hình là SHA-256 DER lowercase, không phải thumbprint SHA-1 của Windows.

Trong `/admin/` tạo `Device`: ghi UUID, environment, generation dương, fingerprint certificate, đúng Wazuh agent ID và hostname. Clone/khôi phục VM phải enrollment mới, không chia sẻ private key. Sao chép `agent/windows/private.example.json` vào thư mục private có ACL chỉ owner/agent sửa; điền UUID/generation/hostname khớp Device. Kiểm `COMPUTERNAME` đúng VM đã duyệt. Agent dùng `CurrentUser/My`, không service account khác.

Chuyển nguyên byte runner đã review, scenario/profile và kit private tới catalog ở hai máy; đối chiếu SHA-256 ngoài băng trước đăng ký `RunnerRelease`. `kit_sha256` là hash byte `kit.json`; `payload_sha256` là hash safe payload (cả `lab_update.ps1`, `maintenance_check.ps1` phải khớp). Ghi hash runner, scenario, profile, baseline.xml, behavioral.xml vào release và catalog agent; paths chỉ cấu hình local, không nhận từ job. Profile và scenario Manager ở private root; không sửa sau khi có job. Kit version/runner version phải `0.3.0`, scenario `SCN-001`. Giữ `allow_rehearsal=false` trừ khi được duyệt. Tạo trước run parent/spool; không dùng symlink/reparse point hoặc quyền cho user khác sửa.

## 5. Duyệt một job và thu evidence

Tạo private `/var/lib/aegis-manager/wazuh-reader.json` đúng các trường `endpoint`, `username`, `password`, `ca_file`, `index`, `collection_mode` của `load_connection`; endpoint HTTPS và CA file tuyệt đối đã tin cậy, `collection_mode` theo cấu hình collector đã review (`unknown` khi chưa có cơ sở). File thuộc `aegis-manager`, mode `0600`; evidence root `0700`, tồn tại, không symlink, ngoài repo. Không thêm completeness declarations.

Trong admin tạo draft cho đúng Device/Release và parameters đúng contract. Ghi UTC: cửa sổ start dương tối đa 300 giây, timeout 180–300 giây; collection bắt đầu không muộn hơn not_before, kết thúc không sớm hơn expires_at + timeout, tổng tối đa 900 giây. A/B baseline; C behavioral; rule_sha256 đúng revision thực tế. Người duyệt đối chiếu inventory, Wazuh mapping, hash và clock rồi chọn **Approve selected bounded jobs** trước khi chạy agent trong cửa sổ.

```powershell
# Chỉ chạy trong VM Windows đã duyệt, bằng user giữ certificate.
dotnet run --project C:\AEGIS\agent\windows\Aegis.Agent -- --config C:\AEGISPrivate\private.json --once
```

Hoặc chạy binary .NET 10 đã publish/review với cùng arguments. Đây là foreground một lần poll; giữ console để Ctrl+C. Không cài Windows Service/MSI. Nếu chưa có job, exit 0 không có nghĩa đã thực thi. Không approve lại job mơ hồ để chạy trùng.

Sau `collection_end` cộng settle delay mặc định 30 giây, kiểm một lần bằng:

```sh
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py manager_worker --config /var/lib/aegis-manager/wazuh-reader.json --output-root /var/lib/aegis-manager/evidence --once
# Sau kiểm nguồn/config mới bật vòng worker:
sudo systemctl start aegis-manager-worker
```

Đối chiếu execution state, receipt và collection state riêng trong admin. Lưu job/approval/audit, agent journal/output, bundle mới theo job UUID, ledger/input hashes và report. Với mỗi kết luận, mở evidence ID/witness trong report, lần theo raw_event_ref và kiểm hash tới bytes gốc. Receipt không phải detection evidence. Empty/error/thiếu alert giữ empty/failed/Inconclusive theo engine; không gọi execution succeeded là Pass. `manager_metadata` giữ run_binding/collection_assurance unknown; chưa chứng minh toàn bộ study SCN-001.

## 6. Dừng, backup và rollback

Điều kiện dừng: sai VM/hash/certificate, cleanup thất bại, process ngoài scope, đĩa thấp, lỗi nguồn hoặc clock. Hủy job chưa start trong admin; Ctrl+C agent để đóng cây process thuộc Job Object. Không có endpoint cancel job đang chạy trong slice này. Dừng worker/web bằng `sudo systemctl stop aegis-manager-worker aegis-manager`; nginx có thể dừng riêng theo quy trình lab. Giữ spool/journal/evidence, không xóa để thử lại.

Nếu worker crash khi job `collecting`, không reconcile trực tiếp và không collect lại vào thư mục cũ. Thực hiện đúng thứ tự:

1. Dừng service worker và xác minh process worker đã kết thúc. Giữ web tắt trong khi phục hồi nếu có thao tác restore DB/identity.
2. Chạy lệnh dưới với **đúng evidence root đã dùng**. Lệnh lấy cùng OS lock; nếu worker còn sống hoặc root sai thì từ chối. Nó chỉ đổi collection gián đoạn thành `failed / worker_interrupted`, ghi audit và thoát; không đọc Wazuh và không chạy agent.
3. Chủ lab kiểm journal, bundle/INCOMPLETE, trạng thái process và audit rồi mới chọn **Reconcile** trong admin. Chỉ sau đó duyệt job UUID mới nếu cần; không xóa journal hay tái sử dụng output cũ.

```sh
sudo systemd-run --wait --pipe --collect --uid=aegis-manager --gid=aegis-manager -p WorkingDirectory=/opt/aegis/current/manager -p EnvironmentFile=/etc/aegis-manager/manager.env /opt/aegis/venv/bin/python manage.py manager_worker --output-root /var/lib/aegis-manager/evidence --recover-interrupted
```

Khi không còn job hoạt động, backup PostgreSQL (`sudo -u postgres pg_dump -Fc aegis_manager` tới nơi backup private), env, catalog, evidence, journal và các khóa cần phục hồi theo quy trình mã hóa/ACL riêng. Kiểm exit code/hash bản backup và bản sao độc lập ngoài đĩa VM. Không đưa secrets/raw evidence vào ZIP trình bày. Snapshot không thay backup.

Rollback: giữ nguyên DB/evidence, dừng dịch vụ, chuyển `/opt/aegis/current` về artifact đã review. Không đảo migration mù quáng; nếu schema không tương thích, restore DB và evidence đồng bộ trong lab cô lập sau owner review. Không restore journal/DB cũ rồi resume identity đang hoạt động: reconcile execution, thu hồi identity cũ, tăng generation/enroll lại theo contract. Thực hành restore riêng và ghi evidence trước khi tuyên bố phục hồi thành công.

## 7. Gate còn chờ trước live acceptance

- Tạo Linux Manager riêng và xác nhận OS/version, network và quyền; Windows/Wazuh đã chọn nhưng chưa được triển khai bởi thay đổi này.
- Private kit/profile, rule revisions, Wazuh reader và clocks được review; dependency/artifact inventory và hashes được ký duyệt.
- `nginx -t`, systemd verification, PostgreSQL concurrency, HTTPS/mTLS thật, header spoof, admin CSRF/static isolation và certificate revocation được kiểm trên VM.
- Một lượt live có approval → đúng agent → bounded execution/cleanup → fresh Wazuh bundle → EID/raw hash; các lỗi retry/crash/timeout và backup restore được người review lab xác nhận.
- Code/security review và lab evidence được duyệt trước merge. Test synthetic/offline hoặc cross-language local không thay nghiệm thu live; full v1 RBAC/service/MSI/campaign vẫn ngoài slice.
