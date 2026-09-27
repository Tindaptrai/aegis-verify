# `aegis collect scn002`: thu một lượt SCN-002 chỉ đọc (issue #98)

Giống [`aegis collect scn003`](SCN003_COLLECT.md), nhưng cho lượt đối chứng hoặc lượt
Block của SCN-002. Lệnh không gửi probe, không sửa rule, không nhận mật khẩu. Dùng
chung phần lõi SSH, kiểm config và cách ghi bundle với SCN-003.

```powershell
.\.venv\Scripts\python.exe -m aegis_verify collect scn002 `
  --config <config riêng>.json --key <private key SSH> `
  --probe-line "sent 66 bytes  run=<32 hex>  label=<control|block>" `
  --out <thư mục mới, ngoài repository>
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-002-attempted-exfiltration.yaml --fixture <thư mục đó> --profile scenarios\profiles\scn-002\profile.json --format json
```

`--probe-line` là dòng `sent ...` mà `Send-Scn002Probe.ps1` in ra trên máy gửi.

## Lệnh làm gì

1. **Kiểm trước khi chạy** (bỏ được bằng `--skip-preflight`):
   - pfSense `ntpq -pn`;
   - manager `chronyc tracking`;
   - máy gửi `w32tm /stripchart /computer:<clock_reference_ip> /samples:1 /dataonly`.

   Mỗi đồng hồ phải lệch không quá `max_clock_offset_ms`. Profile SCN-002 tương quan
   Sysmon với Suricata trong ±2 s, nên đồng hồ máy gửi cũng quan trọng như firewall.
2. **Đọc receipt trên máy gửi**: `type <receipt_dir>\scn002-sender-<run>.json`. Run,
   label, marker và đích phải khớp dòng probe và config. Cổng nguồn và thời điểm gửi
   lấy từ receipt.
3. **Đọc nguồn và chọn chính xác ở local**:

   | Nguồn | Lệnh từ xa | Chọn |
   | --- | --- | --- |
   | Sysmon 3 (archive manager) | `grep -F -- '"sourcePort":"<cổng>"' <archives>` | agent của máy gửi, Sysmon event 3, đúng IP/cổng nguồn và đích |
   | Suricata LAN | `grep -F -- 1000010 <eve_lan>` | SID 1000010, đúng cổng nguồn và cổng đích |
   | pfSense filterlog (chỉ lượt Block) | `grep -F -- <tracker> <filterlog>` | dòng `block` đầu tiên có đúng tracker và tuple |
   | Wazuh 86601 | `grep -F -- <run> <alerts>` | rule 86601 có `run=<run>` |

   Số dòng phải là 1/1/1 với lượt đối chứng (không đọc filterlog) và 1/1/1/1 với lượt
   Block. Sai thì dừng, không ghi gì.
4. **Ghi bundle** với binding `sender_ip`, `receiver_ip`, `receiver_port`,
   `block_rule_tracker`. Cửa sổ là từ 1 phút trước tới 2 phút sau phút gửi. Thư mục
   đích phải mới và nằm ngoài mọi Git working tree.

Kỳ vọng khi `validate`: lượt đối chứng ra `Inconclusive` (A03 không có hành động
chặn, đúng thiết kế); lượt Block ra `Prevented`.

## Config

Mẫu RFC 5737: [`examples/scn002-collect.example.json`](examples/scn002-collect.example.json).
Kiểm như SCN-003, thêm:
- `receipt_dir` là đường dẫn Windows tuyệt đối, không có khoảng trắng hay `..`;
- `sender_agent_id` là mã agent Wazuh gồm 3–8 chữ số;
- `clock_reference_ip` là IPv4.

## Giới hạn

- Chỉ đọc file log hiện hành của manager. Lượt chạy trước khi log xoay vòng (nửa đêm
  theo giờ lab) phải thu tay theo [runbook](SCN002_BLOCK_RUN_RUNBOOK.md) mục 4.
- Nếu sensor không thấy gói bị chặn, alert Suricata và Wazuh có thể thiếu ở lượt
  Block. Lệnh sẽ dừng với số dòng 0 thay vì tự bỏ qua. Trường hợp đó phải thu tay và
  ghi nhận giới hạn quan sát, không mượn alert của lượt khác.
