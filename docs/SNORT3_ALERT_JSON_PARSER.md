# Snort 3 — đọc file `alert_json` trực tiếp (`snort3-alert-json-v1`)

Parser đọc file `alert_json` thô do Snort 3 ghi trên sensor, mỗi dòng một JSON object,
và trả Canonical Event v2 với `source_type: snort`. Parser chỉ đọc bytes; không mở mạng,
không chạy Snort, không suy ra giá trị nguồn không có.

## 1. Đầu vào phải đúng cấu hình đã pin

Parser chỉ nhận file do logger `alert_json` sinh với **đúng danh sách trường và thứ tự**
dưới đây, cùng giờ UTC có năm. Cấu hình Snort (ví dụ trong một file tweak Lua):

```lua
process = { utc = true }
output = { show_year = true }
alert_json = { file = true, limit = 100,
  fields = 'seconds timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port service rule action msg class priority' }
```

Lý do pin: mặc định Snort gộp địa chỉ và cổng (`src_ap`), và `timestamp` mặc định không có
năm hay múi giờ. Hai tùy chọn trên cộng trường `seconds` (epoch) làm thời điểm không mơ hồ.
Ghi cấu hình logger vào bundle cùng file log.

Kiểm chứng trên Snort 3.12.2.0 (DAQ 3.0.27). Đổi phiên bản hay danh sách trường thì phải
lấy mẫu lại; parser từ chối mọi tập trường khác bản pin.

## 2. Context

Giống `suricata-eve-jsonl-v1`: `ingested_at`, `sensor_id`, `deployment_mode`
(`ids`/`ips`/`unknown`). Sensor nhận mirror (thụ động) là `ids`.

## 3. Ánh xạ sang Canonical Event v2

| Canonical | Lấy từ | Ghi chú |
| --- | --- | --- |
| `timestamp` | `seconds` + 6 chữ số micro giây của `timestamp` | `timestamp` dạng `YY/MM/DD-hh:mm:ss.uuuuuu` phải trùng `seconds` theo UTC, nếu không thì từ chối |
| `src_ip`, `dst_ip` | `src_addr`, `dst_addr` | IPv4/IPv6; từ chối scope ID (`%`) |
| `src_port`, `dst_port` | `src_port`, `dst_port` | Snort chỉ in hai khóa này cho TCP/UDP; ICMP để `null` |
| `protocol` | `proto` | giữ nguyên chữ hoa Snort in ra (`TCP`, `UDP`, `ICMP`, `IP`) |
| `signature_id` | `sid` trong `rule` = `gid:sid:rev` | `gid`, `rev` vào provenance |
| `event_action` | `action` | `allow`/`trust` → `allowed`; `drop`/`block`/`reset` và `force_*` → `blocked`; mọi chuỗi khác Snort in ra (`would_*`, `cant_*`, `rewrite`, `hold`, `retry`, `error`) → `null` |
| `severity` | `priority` | `0` nghĩa là rule không đặt classtype/priority → `null` |
| `event_provider` | hằng `snort` | |

`rule_id`, `hostname`, `username` luôn `null`. Provenance giữ `msg`, `class`, `service`,
`dir`, `pkt_gen`, `pkt_len`, `pkt_num`, `seconds`, chuỗi `action` và `priority` gốc.
`pkt_num` là số thứ tự gói trong một lần chạy Snort, không phải định danh bền.

Với `deployment_mode: ids`, event `blocked` mang cảnh báo
`ids_blocked_action_requires_review`, giống parser Suricata.

`event_id` là SHA-256 của danh tính bằng chứng (environment, sensor, `source_ref`, số dòng,
hash dòng). `raw_event_ref` là `<source_ref>#L<n>-L<n>`; `raw_event_hash` là SHA-256 của
đúng bytes dòng, kể cả ký tự xuống dòng.

## 4. Từ chối và bỏ qua

Mọi lỗi dùng mã cố định, có số dòng, không chứa giá trị nguồn. Một dòng lỗi làm hỏng cả
lượt đọc (API bytes không trả kết quả dở dang), như các parser khác.

| Trường hợp | Kết quả |
| --- | --- |
| Thừa khóa, thiếu khóa bắt buộc, sai thứ tự | `unsupported_profile` |
| `timestamp` không có năm (thiếu `show_year`) | `unsupported_profile`, trường `timestamp` |
| `timestamp` lệch `seconds` (sensor không chạy UTC), sai định dạng | `invalid_event_time` |
| IP, cổng, `rule`, `action`, `dir`, `proto`, số nguyên sai kiểu hay ngoài miền | `invalid_field` |
| Cổng có ở ICMP, hoặc thiếu ở TCP/UDP; chỉ có một trong hai địa chỉ | `invalid_field` |
| JSON hỏng, khóa trùng, gốc không phải object, BOM ngoài dòng 1 | `invalid_json`, `duplicate_key`, `invalid_root`, `invalid_bom` |
| Dòng trống | `skipped`, lý do `blank_line` |
| Alert không có IP header (Snort không in địa chỉ) | `skipped`, lý do `no_ip_header` |

Năm hai chữ số của `show_year` giới hạn `seconds` tới hết năm 2099.

## 5. Bản sao qua Wazuh không phải bytes gốc

Khi Wazuh agent đọc file này bằng `log_format json`, Wazuh ghi lại mỗi dòng thành JSON gọn
(bỏ dấu cách). Bản trong `archives.json` vì vậy không trùng hash với file trên sensor.
Thu file gốc trên sensor cho bundle.

## 6. Fixture và kiểm thử

`tests/fixtures/snort/` có 9 dòng thật từ Lab C (lượt thử ngày 2026-10-06, rule thử vô hại
sid 1000001–1000003: ICMP, DNS qua UDP, DNS qua TCP), chỉ thay địa chỉ IPv4 sang
`192.0.2.0/24`. `manifest.json` ghi hash file gốc, hash từng dòng gốc và dòng dẫn xuất.
`backend/tests/test_snort_alert_json.py` phủ ánh xạ, định danh, mọi hành động Snort và các
trường hợp từ chối.

Ngoài fixture, parser còn được thử trên 9 dòng của lượt thử 1 (giữ riêng, không đưa vào
Git) và trên nguyên file gốc 18 dòng: đọc được hết, không lỗi.

## 7. Chưa làm

Alert Wazuh sinh từ Snort được hỗ trợ bởi `wazuh-snort-alert-v1`; xem
[WAZUH_SNORT_ALERT.md](WAZUH_SNORT_ALERT.md).

- Mẫu thật cho IPv6, cho `would_*`/`drop` (IPS) và cho alert không có IP header.
