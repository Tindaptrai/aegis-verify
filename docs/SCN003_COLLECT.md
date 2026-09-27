# `aegis collect scn003`: thu một lượt SCN-003 chỉ đọc (issue #95)

Lệnh này thu bằng chứng của **một** lượt đối chứng SCN-003 từ lab qua SSH, lọc đúng
các bản ghi của lượt đó rồi ghi thành bundle cho `aegis validate`. Probe vẫn do người
vận hành chạy; lệnh này không chạy probe, không sửa rule hay cấu hình lab, không nhận
mật khẩu.

```powershell
.\.venv\Scripts\python.exe -m aegis_verify collect scn003 `
  --config <config riêng>.json `
  --key <đường dẫn private key SSH> `
  --probe-line "connected <IP khởi tạo>:<cổng> -> <decoy>:<cổng>  run=<32 hex>  user=AEGIS-SCN003-<8 hex>  label=control" `
  --out <thư mục mới, ngoài repository>
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-003-internal-deception.yaml --fixture <thư mục đó> --profile scenarios\profiles\scn-003\profile.json --format json
```

Tuỳ chọn: `--ssh <đường dẫn ssh>` (mặc định `ssh` trong PATH), `--skip-preflight`.

## Lệnh làm gì

1. **Kiểm trước khi chạy** (bỏ được bằng `--skip-preflight`):
   - firewall `ntpq -pn` phải có peer được chọn (`*`) và lệch không quá `max_clock_offset_ms` (mặc định 500);
   - manager `chronyc tracking` phải ở `Leap status : Normal`;
   - honeypot `ss -ltn` phải đang nghe `cowrie_port`.
2. **Đọc nguồn**, luôn là lệnh đọc cố định:

   | Nguồn | Lệnh từ xa | Chọn ở local |
   | --- | --- | --- |
   | pfSense filterlog | `grep -F -- <tracker> <filterlog>` | dòng `pass` **đầu tiên** có đúng tracker và 4-tuple sau NAT |
   | Suricata eve | `grep -F -- 1000012 <eve>` | mọi dòng SID 1000012 có đúng cổng nguồn |
   | Cowrie | `cat` hoặc `sudo -n -u <honeypot_read_as> /usr/bin/cat <honeypot_log>` | `session.connect` và `login.failed` của phiên **đầu tiên** có đúng cổng nguồn |
   | Wazuh alerts | `grep -F -- <marker> <alerts>` | mọi dòng rule 120003 có đúng marker |

   Bytes giữ nguyên từng dòng. Số dòng phải đúng 1, 1, 2, 1. Sai là dừng, không ghi
   gì và không tự thử lại (thường là thu quá sớm: chờ 30 s rồi chạy lại).
3. **Ghi bundle**: bốn file, cùng `inputs.json` (SHA-256 từng file) và `context.json`
   với đủ binding của [profile SCN-003](../scenarios/profiles/scn-003/README.md).
   Cửa sổ là từ 1 phút trước tới 2 phút sau phút có `session.connect`. Thư mục đích
   phải mới hoặc rỗng, và **không được nằm trong một Git working tree**, vì bằng chứng
   là dữ liệu riêng.

Kết quả in ra stdout là một JSON `kind: collection`, gồm run ID, SHA-256, số dòng và
kết quả kiểm trước khi chạy. Lỗi in ra stderr là một JSON có mã cố định, gợi ý và
tên nguồn (firewall/manager/honeypot); không in IP, đường dẫn hay nội dung log.

## Config

Một file JSON riêng, ngoài Git. Mẫu dùng địa chỉ tài liệu RFC 5737:
[`examples/scn003-collect.example.json`](examples/scn003-collect.example.json).
Mọi trường đều được kiểm chặt trước khi ghép vào lệnh SSH:

- IP phải là IPv4 dạng chuẩn; cổng 1–65535;
- tên máy, user và `honeypot_read_as` theo regex hẹp;
- đường dẫn phải là đường dẫn POSIX tuyệt đối, chỉ chữ, số, `._-/`, không có `.` hay `..`;
- tracker chỉ gồm chữ số;
- không nhận field lạ.

Không có cách nào đưa ký tự shell vào lệnh từ xa.

`honeypot.jump` cho phép đi qua một máy trung gian khi máy chạy lệnh không có route
tới honeypot. `honeypot_read_as` dùng khi user SSH chỉ được đọc log qua một quyền
sudo hẹp kiểu `soc ALL=(cowrie) NOPASSWD: /usr/bin/cat <honeypot_log>`.

## SSH

Dùng OpenSSH của hệ thống với `BatchMode=yes`, `StrictHostKeyChecking=yes`,
`ConnectTimeout=10`: phải có key và host key đã biết. Máy trung gian đi qua
`ProxyCommand` với cùng key. Private key không nằm trong config và không được in ra.

## Giới hạn

- Chỉ đọc file log **hiện hành**. Lượt chạy trước khi log xoay vòng (nửa đêm theo
  giờ lab với Wazuh alerts và Cowrie) phải thu tay theo [runbook](SCN003_CONTROL_RUN_RUNBOOK.md).
- Receipt của máy khởi tạo không được thu; nó không vào engine.
- Chỉ SCN-003. SCN-002 cần issue riêng.
