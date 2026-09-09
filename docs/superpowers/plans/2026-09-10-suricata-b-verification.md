# Suricata B — triển khai và kiểm chứng ngày 10/09/2026

## Trạng thái

A đã được người dùng chạy 826 tests và pip check thành công. B được triển khai
trên nhánh `codex/issue-4-suricata-direct-eve`, kế thừa A tại `f872eb2`.
Chưa push, merge hoặc đóng Issue #4. Code/test B sẵn sàng cho human review;
standalone flow vẫn cần mẫu lab thật để hoàn tất đối chiếu.

## Kết quả triển khai

- Atomic bytes API `parse_suricata_eve_jsonl` và streaming file API
  `iter_suricata_eve_file` cho alert/flow, trả parsed/skipped outcome theo dòng.
- Evidence hash/ref/identity theo bytes và số dòng, có sensor scope khai báo.
- Timestamp nguồn chính xác, flow.start/end metadata riêng, ICMP canonical ports
  null nhưng giữ source ports/type/code trong provenance.
- Action alert và flow được phân biệt phạm vi, IDS+blocked có warning. Không trả
  detection/prevention conclusion và không dùng flow ID làm record ID.
- Giữ API/mapping/hash mẫu A; tách shared context và prefix-aware mapping.
- Không thêm dependencies, schema fields, ground truth, live access hay engine.
- Làm rõ ARCHITECTURE: direct EVE file offline thuộc V0; continuous/live ingestion
  vẫn là V1. Đây là clarification phù hợp với phạm vi B được người dùng yêu cầu.

## Bốn file thật

| Interface | Dòng | Parsed alert | Parsed flow | Skipped |
|---|---:|---:|---:|---:|
| WAN | 56 | 41 | 0 | 15 |
| LAN | 10598 | 199 | 0 | 10399 |
| MGMT | 10697 | 1411 | 0 | 9286 |
| DMZ | 1185 | 0 | 0 | 1185 |
| Tổng | 22536 | 1651 | 0 | 20885 |

Đọc hết tất cả file bằng B thành công, không parser error hoặc warning IDS conflict.
Các loại khác gồm DNS/TLS/HTTP/SSH/QUIC/fileinfo/DHCP được skip theo hợp đồng.
Không có standalone event_type=flow, dù alert có object flow đi kèm.

Chỉ bốn derivative được commit: WAN dòng1, LAN dòng15, MGMT dòng7, DMZ dòng1.
Manifest `tests/fixtures/suricata/eve-fixture-manifest.json` ghi source export hash,
source line/hash, derivative line/hash và mọi operation sanitize. Kiểm tra tự động
đã xác nhận: original bytes không đổi; chỉ các operation trong manifest khác nhau;
mọi trường còn lại giữ nguyên kiểu/giá trị; committed fixture khớp bytes working file.
IP aliases nhất quán, packet/payload và sensitive metadata/DNS subtree đã bỏ khỏi
derivative. Không commit raw exports. Các flow trong unit tests là dữ liệu mô phỏng.

## Test và review

- Baseline B: 826 tests passed.
- Initial RED: public B API test thất bại đúng vì chưa có API.
- Implementation GREEN: 917 tests passed, sau resource-boundary hardening là 921.
- Independent reviewer đọc diff `f872eb2..4a07807`, chạy lại 921 tests thành công;
  thêm 273 malformed/optional probes và 6 ICMP casing variants không có lỗi bất ngờ.
- Một minor finding: skip records ghi timestamp_basis dù chưa map timestamp.
  Hai regression cases trước sửa đều fail; sau sửa skip basis null, parsed basis
  eve.timestamp. Fix commit `4082056` được reviewer kiểm tra lại: 97 focused tests
  pass, finding resolved, không thêm finding.
- Full suite sau fix: **923 passed in 3.99s**; dependency check sạch.
- Wheel được build lại sau fix, cài vào venv tách biệt. Import xác nhận từ
  `build/package-check-b/Lib/site-packages`.
- Wheel full suite chạy từ build với `--import-mode=importlib`: **923 passed in 4.31s**;
  `pip check`: No broken requirements found.
- Hai Python examples lấy trực tiếp từ hướng dẫn đều chạy: sample literal identity
  assertions pass và cả bốn file aggregate counts COMPLETE như bảng trên.

Test bao gồm timestamp0..9, unknown offsets, null/type/range, duplicate JSON keys,
nonfinite/Unicode, skipped unknown types, BOM/LF/CRLF/final newline, per-line identity,
ICMP direction/ports, integer precision, action scope, lazy late failure/file closure,
256KiB line bound, 32MiB total bound và 100000-line bound. Không dùng unit test để
khẳng định log thật đã được xác thực hoặc IDS đã ngăn chặn.

## Giới hạn bàn giao

Standalone flow chưa có real fixture hoặc human lab validation. Lab version/clock
accuracy chưa xác nhận. Không có correlation/dedup hoặc scenario association mới.
Mọi source label/sensor label trong ví dụ là nhãn caller khai báo, không phải auto
discovery hay asset mapping. Streaming partial import phải đánh dấu incomplete nếu
dòng sau lỗi; API không tạo snapshot của file đang được ghi.

Đọc `docs/SURICATA_EVE_JSONL.md` để chạy test, xem mẫu và chuẩn bị flow riêng.
Sau human review: tích hợp A trước, B sau, kiểm tra lại acceptance criteria Issue #4
và bằng chứng flow trước khi quyết định đóng issue.
