# OPNsense — đọc `filterlog` qua syslog BSD (`opnsense-filterlog-bsd-v1`)

Parser đọc các dòng `filterlog` mà OPNsense gửi qua syslog BSD (RFC 3164), được bộ thu
ghi nguyên bytes, và trả Canonical Event v2 với `source_type: opnsense`. Parser chỉ đọc
bytes; không mở mạng, không đọc đồng hồ, không suy ra giá trị nguồn không có.

Không dùng parser pfSense cho OPNsense: cột 4 của OPNsense là nhãn rule (UUID với rule
người dùng tạo, mã MD5 với rule tự động) chứ không phải tracker dạng số, và dòng ICMP,
ICMPv6 kết thúc bằng một ô `datalength=N`.

## 1. Đầu vào

Mỗi dòng có dạng:

```text
<134>Oct  6 11:11:52 fixture-fw filterlog[26883]: 86,,,f18da9d8-ba44-4a26-8909-effe55135cb6,em2,match,block,in,4,...
```

- `<PRI>` có thì phải là số 0–191, không có số 0 ở đầu; không có cũng nhận.
  Provenance giữ nguyên chuỗi PRI (`syslog_pri`).
- Hostname có thể vắng; khi vắng, `hostname` là `null`. `sensor_id` của caller không
  bao giờ được chép sang `hostname`.
- Chương trình phải là `filterlog`, `[pid]` có thể vắng.
- Không nhận syslog dạng RFC 5424 và không nhận dòng của chương trình khác.

Cấu hình bộ thu của Lab C (rsyslog) ghi đúng bản tin nhận được:

```text
template(name="OpnRaw" type="string" string="%rawmsg%\n")
```

Kiểm chứng trên OPNsense 26.7 (FreeBSD 15.1). Đổi phiên bản thì phải lấy mẫu lại.

## 2. Context

Giống `pfsense-filterlog-bsd-ipv4-tcp-udp-v1`: `ingested_at`, `sensor_id`,
`source_year`, `source_utc_offset`. Giờ BSD không có năm và múi giờ, nên caller phải
khai báo; mọi event mang cảnh báo `year_and_offset_supplied_by_caller`.

Lab C đặt OPNsense ở múi giờ UTC, nên `source_utc_offset` là `+00:00`. Cách kiểm: so một
thao tác có giờ UTC đã biết với dòng log của nó. Ví dụ, ping lúc 11:11:51.6 UTC từ
endpoint có dòng block lúc 11:11:52.

Một bản ghi vượt qua đêm giao thừa sẽ nhận sai năm. Bundle nên chia file theo năm.

## 3. Các bố cục cột được nhận

Chín cột chung: số rule, subrule, anchor, nhãn rule, interface, lý do, hành động
(`pass`/`block`), chiều (`in`/`out`), phiên bản IP. Sau đó:

| IP | Cột header IP | Tầng 4 | Tổng số cột |
| --- | --- | --- | --- |
| IPv4 | tos, ecn, ttl, id, offset, flags, số protocol, tên protocol, length, src, dst | TCP: port nguồn, port đích, độ dài dữ liệu, cờ, seq, ack, window, urg, options | 29 |
| IPv4 | như trên | UDP: port nguồn, port đích, độ dài dữ liệu | 23 |
| IPv4 | như trên | ICMP: `datalength=N` | 21 |
| IPv6 | class, flow label, hop limit, **tên** protocol, **số** protocol, length, src, dst | UDP | 20 |
| IPv6 | như trên | ICMPv6 (`ipv6-icmp`): `datalength=N` | 18 |

Chỉ năm bố cục trên có mẫu thật trong Lab C. Phiên bản IP khác 4 và 6 được bỏ qua với lý
do `unsupported_ip_version`. Protocol khác, kể cả TCP trên IPv6, được bỏ qua với lý do
`unsupported_protocol`. Dòng bị bỏ qua vẫn phải có chín cột chung hợp lệ và vẫn có
trong ledger; parser không đoán bố cục chưa thấy.

## 4. Ánh xạ sang Canonical Event v2

| Canonical | Lấy từ | Ghi chú |
| --- | --- | --- |
| `timestamp` | giờ BSD + `source_year` + `source_utc_offset` | đổi sang UTC |
| `hostname` | hostname trong header syslog | `null` nếu vắng |
| `event_action` | hành động | `pass` → `allowed`, `block` → `blocked`; giá trị khác bị từ chối |
| `protocol` | tên protocol, viết thường | `tcp`, `udp`, `icmp`, `ipv6-icmp`; phải khớp số protocol |
| `src_ip`, `dst_ip` | địa chỉ nguồn, đích | bắt buộc, đúng phiên bản IP của dòng; từ chối scope ID (`%`) |
| `src_port`, `dst_port` | port | chỉ TCP/UDP; ICMP để `null` |
| `rule_id` | nhãn rule (cột 4) | ổn định qua các lần nạp lại rule; `null` nếu trống |
| `event_provider` | hằng `OPNsense-filterlog` | |

`signature_id`, `severity`, `username` và các trường process luôn `null`.

Provenance giữ:

- `rule_number`, `subrule`, `anchor`, `label`;
- `interface`, `direction`, `reason`, `ip_version`, `protocol_id`, `protocol_text`;
- `syslog_pri`, `timestamp_text`.

Số rule có thể đổi khi OPNsense nạp lại bộ rule (trong mẫu, cùng một nhãn lúc là 86,
lúc là 89), nên dùng nhãn để nhận diện rule.

## 5. Interface, chiều và NAT

pf ghi gói tại interface nơi rule khớp:

- `in` là gói khi vào interface đó, `out` là gói khi rời interface đó.
- Một gói đi xuyên firewall và được log ở cả hai đầu xuất hiện hai lần: `in` ở
  interface vào, `out` ở interface ra, với TTL đã giảm. Đó là hai bằng chứng của cùng
  một gói, không phải hai kết nối.

Theo tài liệu pf, phép dịch địa chỉ (NAT, port forward) chạy trước rule lọc. Vì vậy
địa chỉ trên dòng log là địa chỉ sau khi dịch, tại interface có NAT. Parser không suy ra
NAT: `nat_context` luôn `null`, và interface, chiều được giữ nguyên trong provenance.
Mẫu Lab C chưa có dòng nào đi qua NAT, nên điểm này chưa được kiểm bằng mẫu thật.

## 6. Từ chối và bỏ qua

Mọi lỗi dùng mã cố định, có số dòng, không chứa giá trị nguồn. Một dòng lỗi làm hỏng cả
lượt đọc: API bytes không trả kết quả dở dang, API file dừng ở dòng lỗi.

| Trường hợp | Kết quả |
| --- | --- |
| Header không đúng dạng BSD, chương trình khác `filterlog`, dạng RFC 5424 | `malformed_header` |
| PRI ngoài 0–191 hoặc có số 0 ở đầu | `invalid_field`, trường `pri` |
| Ngày giờ không hợp lệ | `invalid_timestamp` |
| Nhãn rule không phải UUID hay MD5 viết thường | `invalid_field`, trường `label` |
| Hành động hay chiều lạ | `unsupported_value` |
| Số không hợp lệ hoặc vượt miền, địa chỉ sai phiên bản, ô `datalength` sai dạng | `invalid_field` |
| Thiếu ô bắt buộc (cột chung, địa chỉ, port TCP/UDP) hoặc thiếu cột | `missing_field` |
| Thừa cột | `invalid_field` |
| Ký tự điều khiển, dấu nháy, BOM ngoài dòng 1, UTF-8 hỏng | `invalid_field`, `invalid_bom`, `invalid_encoding` |
| Dòng trống | `skipped`, lý do `blank_line` |
| Phiên bản IP hay protocol chưa có mẫu | `skipped`, `unsupported_ip_version` / `unsupported_protocol` |

## 7. Dòng hỏng do bộ thu dừng đột ngột

File gốc của Lab C có một dòng hỏng (dòng 1707). Bản tin lúc 04:28:11 bị cắt khi máy thu
log dừng, rồi bản tin lúc 08:21:13 ghi nối tiếp trên cùng dòng. Parser từ chối dòng này
(`invalid_field`, trường `label`), nên đọc nguyên file sẽ dừng ở dòng 1707.

Không sửa tay file gốc. Để tránh lỗi này, tắt máy thu bằng "Shut Down Guest" hoặc dừng
rsyslog trước, không tắt nguồn ảo.

## 8. Fixture và kiểm thử

`tests/fixtures/opnsense/` có hai file dẫn xuất từ file gốc ngày 2026-10-06:

- 16 dòng thật phủ đủ năm bố cục, `pass`/`block`, `in`/`out`, bốn interface và cả hai
  kiểu nhãn, gồm các ping block của lượt thử;
- dòng 1707 nói ở mục 7.

Địa chỉ được thay theo RFC 5737; hai địa chỉ IPv6 link-local đổi thành `fe80::1`,
`fe80::2`; hostname đổi thành `fixture-fw`. `manifest.json` ghi hash file gốc, hash từng
dòng gốc và dòng dẫn xuất.

`backend/tests/test_opnsense_filterlog.py` phủ ánh xạ, định danh, các trường hợp từ chối,
bỏ qua, framing và giới hạn tài nguyên. Ngoài fixture, parser đọc được toàn bộ 12.810
dòng còn lại của file gốc, không bỏ qua dòng nào.

## 9. Chưa làm

- Syslog dạng RFC 5424.
- TCP trên IPv6 và các protocol khác (IGMP, CARP...): cần mẫu thật trước.
- Dòng log của rule NAT hay port forward.
- Parser cho alert Wazuh sinh từ OPNsense.
