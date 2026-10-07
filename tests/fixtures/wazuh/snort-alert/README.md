# Fixture: alert Wazuh 130110 sinh từ alert Snort 3 (Lab C, đã sanitize)

`wazuh-snort-alert-labc.sanitized.json` là **một bản ghi thật** của Lab C ngày
2026-10-07, lấy từ `alerts.json` của manager: rule Wazuh `130110` nổ cho alert
Snort `1:1000010:1` của lượt `8541573e`. Bản gốc nằm ngoài Git; SHA-256 dưới đây
để người giữ bằng chứng riêng kiểm được nguồn gốc.

Fixture này cho test chạy lại **đúng hình dạng nguồn thật** qua parser mà không
cần lab. Test xanh nghĩa là parser còn map đúng hình dạng đó; nó **không** phải
bằng chứng về lab. Kết quả lab nằm ở `docs/SCN004_LAB_C.md`.

## Phép thay thế (mức byte, áp dụng theo thứ tự này)

| Bản gốc | Thay bằng | Vì sao |
| --- | --- | --- |
| tên agent Wazuh của sensor | `lab-sensor` | bí danh |
| địa chỉ quản trị của sensor | `192.0.2.30` | RFC 5737 |
| tên manager | `lab-manager` | bí danh |
| địa chỉ máy gửi | `192.0.2.10` | RFC 5737; cùng bí danh với các fixture Snort, OPNsense và bundle Lab C |

Địa chỉ nhận `203.0.113.10` là địa chỉ tài liệu ngay trong lab nên giữ nguyên.
Mọi thứ khác giữ nguyên từng byte: thời gian, cổng, SID `1000010`, rule Wazuh
`130110`, group, level, record ID, đường dẫn log và nội dung `full_log` (với cùng
các phép thay thế bên trong).

## Nguồn gốc

| Tệp | SHA-256 bản gốc (ngoài Git) | SHA-256 bản phái sinh | Byte |
| --- | --- | --- | --- |
| `wazuh-snort-alert-labc.sanitized.json` | `b8d8cea23576fd2f4fb5fe7fb19f03cf4d1773dcb27339f42f73d484ce5a1e09` | `cae4a28fde4b0695526a512e2b2926833ca0c78ddd2ce4e58bbf6c6e0e4b1e1e` | 1178 → 1170 |

Bản gốc là **một dòng đúng nguyên văn** của tệp nguồn, kèm số dòng và SHA-256 của
tệp lúc thu:

| Tệp nguồn | SHA-256 lúc thu | Dòng |
| --- | --- | --- |
| Wazuh `alerts.json` (284 dòng) | `e3c4897658123d88050119b02c55443c59e6db3b773d57cd55ff4f88a3040437` | 252 |

Dòng trong `full_log` của bản ghi này là **cùng một alert Snort** với
`tests/fixtures/cli/scn004-lab-c-sanitized/block/snort-alert.jsonl` (một test
khẳng định điều đó): hai bằng chứng của cùng một alert, một tại nguồn và một do
SIEM tạo.

Test: `backend/tests/test_wazuh_snort_alert.py`. Parser:
[`docs/WAZUH_SNORT_ALERT.md`](../../../../docs/WAZUH_SNORT_ALERT.md). Đổi bản phái
sinh thì phải cập nhật hash ở đây và xem lại; đừng sửa cho khớp một cách mù quáng.
