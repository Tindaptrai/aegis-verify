# Suricata B — triển khai và kiểm chứng ngày 10/09/2026

## Trạng thái

A đã được người dùng chạy 826 tests và pip check thành công. B được triển khai
trên nhánh `codex/issue-4-suricata-direct-eve`, kế thừa A tại `f872eb2`.
Chưa push, merge hoặc đóng Issue #4. Code/test B sẵn sàng cho human review.
Mẫu standalone flow thật đã được bổ sung và kiểm chứng ở phần cập nhật cuối tài liệu.

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

Standalone flow đã có real fixtures TCP/UDP và parser validation; người dùng còn
chạy đối chiếu bản bổ sung. Lab version/clock accuracy chưa xác nhận. Không có
correlation/dedup hoặc scenario association mới.
Mọi source label/sensor label trong ví dụ là nhãn caller khai báo, không phải auto
discovery hay asset mapping. Streaming partial import phải đánh dấu incomplete nếu
dòng sau lỗi; API không tạo snapshot của file đang được ghi.

Đọc `docs/SURICATA_EVE_JSONL.md` để chạy test và xem mẫu flow thật.
Sau human review: tích hợp A trước, B sau, kiểm tra lại acceptance criteria Issue #4
và bằng chứng flow trước khi quyết định đóng issue.

## Cập nhật: export MGMT có flow thật

Input: `suricata-mgmt-flow-20260910-030813.jsonl`, 10.138.493 bytes, 14.587 dòng.
SHA-256 `11332034f69ec798d75393c79dfebb59fbaeff1d2bd72b1ba06e2d49b025d30f`.
Streaming API đọc hết: 1.806 alert, 32 flow parsed; 12.749 skipped; không lỗi/warning.
Skipped: DNS 4.024, QUIC 4.507, TLS 2.124, fileinfo 2.085, SSH 9.
Không cộng export mới vào tổng cũ để suy ra số event duy nhất.

Đối chiếu độc lập toàn bộ 14.587 hash/ref theo bytes và số dòng; với cả 32 flow,
so lại IP/cổng/protocol, timestamp UTC bằng thư viện datetime, start/end, counters,
state/reason/alerted, flow ID và các canonical field phải null. Tất cả khớp.
Script audit ban đầu so IP object với JSON string nên assertion thất bại; đã sửa
phép so trong script sang chuỗi IP, không thay đổi parser, rồi chạy lại đến EOF.

Flow: TCP 18 / UDP 14; new 25 / closed 1 / established 6; timeout 32;
alerted false 29 / true 3. Không record nào có flow.action: canonical action null.
Mẫu đầu tiên có timestamp 03:03:01.045948+0700, flow.start/end
03:01:57.969970+0700. Đây là bằng chứng cụ thể bản ghi được xuất sau mốc flow,
không phải cam kết mọi flow sẽ được ghi sau cùng một thời gian chờ.

Đã thêm derivative TCP-new dòng 14518, TCP-closed dòng 14577, UDP-alerted dòng
14579. Chỉ alias flow_id/in_iface/src_ip/dest_ip. Audit cả 7 derivative xác nhận:
hash nguồn/dòng/derivative khớp, chỉ thay đổi trường được manifest ghi lại, alias
nhất quán không va chạm và originals không thay đổi. Raw vẫn ở Downloads ngoài Git.
Các flow test nhân tạo cũ giữ nguyên và vẫn được ghi rõ nguồn gốc.

Ba regression cases dùng literal kỳ vọng độc lập kiểm tra UTC qua ngày trước,
6 chữ số phần giây, flow.start/end riêng, hướng IP/cổng, 0/False, counters, state,
reason, alerted không tạo SID/action, raw hash/ref và canonical round-trip.
Cả bytes API và streaming API chạy trên mỗi derivative. Một test bổ sung kiểm tra
manifest bao phủ fixture và hash đúng bytes (kể cả newline). Đây là bổ sung coverage
cho behavior đã có, không có production fix hoặc tuyên bố chu kỳ RED/GREEN mới.

- Focused suite: **101 passed in 1.37s**.
- Full suite: **927 passed in 3.85s**.
- `pip check`: No broken requirements found.
- `git diff --check`: không lỗi whitespace; Git cảnh báo CRLF cho file text,
  còn JSONL evidence được giữ bytes nhờ `.gitattributes` hiện có.
- Wheel 923-test đã kiểm chứng trước đó; lượt này không build wheel mới vì production
  code không thay đổi. Kết quả 927 là checkout hiện tại, không gọi là wheel run.

Giới hạn: chưa có flow ICMP/action pass/drop từ lab, chưa xác thực clock/version,
chưa làm alert-flow correlation hay kết luận detection/prevention. Chờ người dùng
chạy 927 tests và review thay đổi mới tại thời điểm kiểm tra đầu tiên.

## Pre-merge review và xác nhận người dùng

- Người dùng chạy bản bổ sung: **927 passed in 3.24s**, `pip check` sạch và yêu cầu
  thực hiện review/commit/push/tích hợp A trước B.
- Reviewer độc lập chạy lại: **927 passed in 2.98s**, dependency/whitespace sạch;
  audit cả 7 derivative, 14.587 hash/ref nguồn và 32 flow mappings khớp.
- Không có finding blocking/important; một P3: README thư mục fixtures còn nói flow
  chỉ là dữ liệu nhân tạo. Đã sửa để phân biệt 3 real derivatives với boundary inputs.
- A được kiểm tra lại 826 tests trước merge và đã merge qua PR #18 tại `c958f26`.
  GitGuardian Security Checks pass; repo chưa có GitHub Actions test workflow.
- B không đổi production code trong lượt bổ sung flow/review này. Không sửa ground
  truth hoặc dữ liệu raw. Xem PR B/Issue #4 cho trạng thái tích hợp cuối cùng.
