# Issue #5 — Thiết kế pfSense filterlog fixture parser

Ngày: 10/09/2026. Trạng thái: **người dùng đã duyệt phạm vi IPv4 TCP/UDP,
pass/block, offline; chuyển sang lập kế hoạch triển khai**.
Chưa triển khai parser, chưa đóng Issue #5, chưa mở PR hoặc merge.
Base: `370cd2a`; nhánh: `codex/issue-5-pfsense-fixture-parser`.

Xác nhận tiếp theo của người dùng: làm profile giới hạn trước; xem xét mở rộng
giao thức và kiểu syslog vào buổi sau. Đây không phải cam kết hỗ trợ mọi format
trong Issue #5, cũng không phải tác vụ tự động được lên lịch.

## 1. Đọc nhanh: bạn cần hiểu và làm gì?

Mục tiêu là đọc file firewall log đã xuất, chuyển mỗi bản ghi được hỗ trợ thành
Canonical Event v2 để engine sau này có thể sử dụng. Không kết nối trực tiếp
pfSense, không thay rule, không chạy tấn công và không thay cấu hình hệ thống.

Bạn đã cung cấp đủ mẫu để thiết kế và bắt đầu triển khai phạm vi IPv4 TCP/UDP.
Hiện bạn chỉ cần duyệt tài liệu này. Khi code sẵn sàng, bạn chạy test trên máy
Windows chứa dự án AEGIS; không chạy pytest trong Shell pfSense.

Ba quyết định quan trọng:

1. Timestamp thiếu năm/múi giờ: caller phải cung cấp rõ, parser không đoán.
2. Bắt đầu IPv4 TCP/UDP; loại ngoài phạm vi có kết quả `skipped` rõ ràng.
3. `block` là hành động firewall ghi nhận, không tự biến thành kết luận scenario
   `Prevented`. Kết luận thuộc engine và phải tham chiếu evidence IDs.

## 2. Phạm vi và các phương án

Đây là một connector mới (thay đổi kiến trúc ở mức subsystem), không phải sửa
một hàm đang có. Chỉ xử lý [Issue #5](https://github.com/Tindaptrai/aegis-verify/issues/5).

| Phương án | Lợi ích | Giới hạn |
| --- | --- | --- |
| **Đề xuất: profile IPv4 TCP/UDP, pass/block, offline** | Có nhiều mẫu thật; phạm vi nhỏ, review được; đáp ứng hướng IPv4 MVP của issue | IPv6, IGMP và giao thức khác chưa được chuẩn hóa |
| Hỗ trợ mọi giao thức và nhiều kiểu syslog ngay | Độ phủ rộng hơn | Cần thêm mẫu, quy tắc protocol-specific và test; không phù hợp phạm vi buổi này |
| Chỉ làm block theo mẫu hiện có | Ít việc nhất | Không đủ acceptance criteria pass/block; không chọn |

Không thêm dependency, không đổi canonical schema, không làm CSV export từ
dashboard, live syslog/SSH, NAT correlation, engine, CLI hay dashboard trong issue này.

## 3. Mẫu thực tế đã kiểm tra

Tên file: `pfsense-filter-20260910-205359.log`.
SHA-256 toàn file:
`7c32779ba3825a2183b5eeae182af1ceb96d240b1f299cbb0d14f35f6de30f0c`.

| Thuộc tính | Kết quả kiểm tra cấu trúc, chưa phải parser production |
| --- | --- |
| Kích thước | 245.311 bytes, UTF-8 đọc được, newline LF |
| Tổng dòng | 1.592 |
| Filterlog | 1.591, đều action block; không có pass |
| Dòng khác | Dòng 1 là thông báo newsyslog xoay vòng file |
| IPv4 TCP/UDP trong phạm vi | 34 TCP + 1.369 UDP = 1.403 |
| Ngoài phạm vi | 69 IPv4 IGMP + 119 IPv6 = 188 |
| Timestamp ghi trong file | Từ Sep 8 23:01:00 đến Sep 10 20:53:30; không có năm/offset |

Mục tiêu đối chiếu sau triển khai: 1.403 parsed, 189 skipped (188 ngoài profile
và 1 rotation notice), không thất thoát dòng. Đây là kỳ vọng để test, không phải
cam kết parser đã chạy thành công. Nếu gặp nội dung sai, phải điều tra thay vì
nới validation để ép đạt số đếm.

Log gốc ở Downloads ngoài Git; không sao chép toàn bộ vào worktree hoặc tài liệu.
Kiểm tra này chưa chứng minh nguồn đáng tin, đồng hồ đúng lịch sử hoặc một
scenario cụ thể được ngăn chặn.

## 4. Hợp đồng thời gian — không đoán dữ liệu thiếu

Đối chiếu người dùng cung cấp:

- Đồng hồ nguồn: `2026-09-10T21:02:05+0700`.
- Mtime file đang hoạt động: `2026-09-10 21:01:57`.
- Ba dòng cuối tại lúc kiểm tra: `Sep 10 21:01:41`.

Ba thông tin khớp về bối cảnh hiện tại. Chúng không chứng minh toàn bộ lịch sử
máy chưa từng đổi giờ hoặc khôi phục snapshot. Không gọi năm 2026 là năm nằm
trong bản ghi gốc. Mtime trên máy nhận cũng không phải timestamp sự kiện.

API yêu cầu `source_year` (int thật, 1..9999, không bool) và
`source_utc_offset` (chuỗi `+/-HH:MM`, không `-00:00`, giờ 00..23, phút 00..59).
Giữ hai giá trị này cùng `timestamp_basis="bsd_syslog_with_caller_context"`
trong provenance; thêm cảnh báo `year_and_offset_supplied_by_caller`.

Đối với mẫu hiện tại, cấu hình đề xuất là 2026 và +07:00, ghi rõ căn cứ đối chiếu
hệ thống ở trên và lịch sử chưa xác minh. Không hard-code chúng trong parser.

- Parse tháng tiếng Anh cố định, ngày hợp lệ, HH:MM:SS đúng giới hạn; không phụ
  thuộc locale Windows. Không nhận leap second hoặc 24:00.
- Ghép năm và offset do caller cung cấp, chuyển UTC bằng PreciseTimestamp;
  giữ độ chính xác giây, không tự thêm microsecond hoặc nanosecond giả.
- Thiếu/sai context, ngày không tồn tại hoặc UTC vượt range: báo lỗi.
- Không dùng năm máy chạy, tên file, mtime hoặc ingested_at để điền timestamp.
- Profile một năm và một fixed offset cho mỗi lần nhập. File qua năm hoặc có
  thay đổi offset phải được chia thành các phần với context riêng và manifest
  bảo toàn dòng gốc. Không tự suy ra rollover hoặc DST từ thứ tự dòng.
- Parser không thể tự chứng minh caller khai đúng năm; tài liệu và provenance
  phải giữ giới hạn này. Không sửa timestamp để khớp scenario ground truth.

## 5. Profile đầu vào và quy tắc validation

Profile version: `pfsense-filterlog-bsd-ipv4-tcp-udp-v1`.

Nhận bytes UTF-8 strict, một bản ghi trên mỗi dòng; LF/CRLF hoặc dòng cuối không
newline. BOM chỉ được phép ở đầu file; BOM nơi khác và UTF-8 lỗi bị từ chối.
Header nhận đúng dạng BSD local log với hostname và chương trình
`filterlog` hoặc `filterlog[PID]`. Không nhận RFC5424, payload trần, định dạng
clog nhị phân hoặc CSV có header của dashboard trong profile này.

Sau header là các trường phân cách bởi dấu phẩy, giữ vị trí trường rỗng; không
dùng split theo khoảng trắng cho payload. Không hỗ trợ quoting CSV kiểu bảng
tính; quote, newline nhúng hoặc trường dư trong bản ghi TCP/UDP đều là lỗi.

- Common fields: rule number, subrule, anchor, tracker, real interface, reason,
  action, direction, IP version. Mã action chỉ pass/block; direction chỉ in/out
  trong profile này. Giá trị lạ phải báo unsupported value, không map thành allowed.
- IPv4: kiểm tra field count (UDP 23, TCP 29), version 4, protocol number/text
  nhất quán (6/tcp hoặc 17/udp, text so sánh không phân biệt hoa thường).
- Địa chỉ khi có phải là IPv4 thực, không CIDR/hostname/số thay cho địa chỉ. Ports là
  chữ số ASCII thập phân 0..65535; giữ giá trị 0. Không nhận dấu, float hoặc bool.
- Các trường số của header IP/transport có dữ liệu phải có dạng và range tương
  ứng: TTL/TOS/ECN 0..255 (TOS/ECN cho phép hex có prefix), IP ID/length/window
  0..65535, TCP sequence/ACK 0..2^32-1; URG 0..65535. Offset nhận số thập phân
  không âm trong giới hạn 128 chữ số, giữ ở raw; không tự diễn giải đơn vị offset.
  Không ép chuyển chuỗi lạ thành 0. Dữ liệu rỗng không phải số 0.
- Trường canonical tùy chọn rỗng (ví dụ tracker hoặc port) thành null; không
  dịch cột. Thiếu cả cột, sai kiểu hoặc token sai là malformed, không phải null.
- Protocol/type ngoài phạm vi: chỉ skip sau khi header và common fields đủ
  cấu trúc để phân loại. Skip không chứng nhận payload protocol-specific hợp lệ.
  Bản ghi tự nhận TCP/UDP IPv4 nhưng hỏng tuyệt đối không được đổi thành skip.
- Dòng trống có `blank_line`. Chỉ nhận diện thông báo rotation của newsyslog
  theo header và message pattern hẹp; không skip mọi dòng non-filterlog.
  Dòng không nhận diện phải báo lỗi để tránh che giấu input sai.

Giới hạn: 256 KiB mỗi dòng (kể newline/BOM), 32 MiB mỗi file, 100.000 dòng vật lý,
128 ký tự cho token số trước khi chuyển int. Thông báo lỗi không chứa raw log,
IP, hostname, đường dẫn máy hoặc giá trị người dùng cung cấp.

## 6. Mapping canonical và metadata

| Dữ liệu nguồn/context | Canonical Event v2 |
| --- | --- |
| Timestamp BSD + năm/offset tường minh | timestamp UTC |
| Loại connector/profile | source_type=pfsense; event_provider=pfSense-filterlog |
| Caller environment_id, ingested_at | Hai trường tương ứng; không tự tạo thời gian ingest |
| Header hostname | hostname (máy firewall ghi log, không phải endpoint đích) |
| Source/destination IPv4, ports | src_ip, dst_ip, src_port, dst_port |
| Protocol number/text đã kiểm tra | protocol=tcp hoặc udp |
| pass / block | event_action=allowed / blocked |
| Tracker nguồn khi có | rule_id dạng chuỗi; không fallback sang rule number |
| Không có ID bản ghi độc lập | source_record_id=null; PID syslog không phải event ID |
| Không có dữ liệu nguồn | asset_id, username, severity, signature_id, technique_ids, process/file fields=null |

Metadata riêng của connector giữ interface, direction, reason, rule number,
subrule, anchor, tracker gốc, protocol ID/text gốc, timestamp text gốc, năm/offset,
profile/mapping version, sensor_id và provenance dòng/hash. Raw reference giữ
toàn bộ trường còn lại; không nhét raw payload vào canonical.

Profile này không chứa mapping trước/sau NAT đáng tin cậy. Metadata
`nat_context=null`; không suy NAT từ private/public IP, interface, anchor hay
direction. Không dùng source/destination IP làm asset_id.

Chỉ `record.event` (CanonicalEventV2) được truyền cho engine. Envelope metadata
phục vụ audit, không tạo một loại security event ngoài canonical. Nếu engine
sau này cần interface/NAT làm điều kiện chung, cần issue thay đổi hợp đồng
riêng; không âm thầm để engine đọc vendor metadata trong Issue #5.

## 7. API, lỗi và ranh giới module

API dự kiến trong `aegis_verify.connectors.pfsense`:

```python
parse_pfsense_filterlog(raw: bytes, *, source_ref, environment_id, sensor_id,
                       ingested_at, source_year, source_utc_offset)
iter_pfsense_filterlog_file(path, *, source_ref, environment_id, sensor_id,
                           ingested_at, source_year, source_utc_offset)
```

Bytes API trả tuple đầy đủ hoặc raise, không trả tuple một phần. File API đọc
binary có giới hạn, yield từng outcome; lỗi muộn nghĩa là toàn lần nhập
**INCOMPLETE** dù một số dòng trước đã parse được. Consumer phải xử lý lỗi và
không báo hoàn tất khi dừng iterator sớm; đóng file khi xong hoặc close iterator.

Outcome bất biến, extra-forbid, validate tổ hợp trường:

- `parsed`: có CanonicalEventV2, reason=null, provenance có cùng event_id/hash/ref.
- `skipped`: event=null, event_id=null; reason thuộc blank_line,
  rotation_notice, unsupported_ip_version hoặc unsupported_protocol.
- Malformed/input/context/I/O error: exception với mã lỗi cố định, line index,
  field name cho phép; không lộ input hoặc exception gốc.

Source_ref và sensor_id là nhãn an toàn ASCII 1..128 ký tự
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, không phải URL hoặc đường dẫn tự mở.
Environment_id là chuỗi UTF-8 không rỗng sau strip, tối đa 128 bytes, giữ nguyên
giá trị hợp lệ; ingested_at được PreciseTimestamp validate. Parser không kết nối
mạng hoặc tự tải raw_event_ref.

Tách trách nhiệm trong `connectors/pfsense/`: framing/API, header/time context,
field validation/mapping, outcome/provenance models và safe errors. Không import
private helper Suricata để dùng như thư viện chung; chỉ reuse public canonical,
PreciseTimestamp và hash helper. Không refactor connector khác trong issue này.
Thêm package entry khi triển khai; không thêm dependency.

## 8. Evidence identity và sanitization

Raw hash là SHA-256 của đúng bytes từng dòng, gồm newline và BOM nếu có.
`raw_event_ref = source_ref + "#L<n>-L<n>"`, n bắt đầu từ 1 và tính cả dòng skip.
source_ref phải định danh một artifact bất biến trong manifest.

Event ID dùng SHA-256 của JSON array encode UTF-8, ensure_ascii=True,
separators=(",", ":"), theo thứ tự:

```text
["pfsense-filterlog-evidence-v1", environment_id, sensor_id, source_ref,
 line_index, raw_line_hash, source_year, source_utc_offset]
```

Prefix ID: `pfsense:filterlog-evidence-v1:`. Cùng context và bytes cho cùng ID;
khác dòng/môi trường/sensor/artifact/năm/offset cho ID khác. ingested_at không
nằm trong ID, vì đọc lại evidence không tạo event nguồn mới. Chỉnh bối cảnh thời
gian phải tạo kết quả nhập mới, không ghi đè kết quả cũ dưới cùng evidence ID.

Fixture đưa Git phải là derivative đã review: thay địa chỉ/hostname/định danh
nhạy cảm bằng alias nhất quán, giữ timestamp, action và cấu trúc trường. Manifest
ghi source file hash, line number/hash gốc, derivative hash, các phép thay thế và
bối cảnh thời gian. Không ghi bảng ánh xạ ngược chứa giá trị nhạy cảm vào Git.
Raw_event_hash trong output fixture luôn là hash derivative, không tráo hash
gốc vào dữ liệu đã thay đổi. Unit fixtures nhân tạo phải dán nhãn synthetic;
không biến bản ghi block thật thành pass rồi gọi đó là lab evidence.

## 9. Kiểm thử và acceptance criteria

| Yêu cầu Issue #5 | Kiểm chứng cần thực hiện khi viết code |
| --- | --- |
| Schema-valid canonical outputs | Validate/serialize/roundtrip v2 cho mọi parsed fixture |
| Pass/block, time, interface, network, firewall/NAT context khi có | Bảng mapping ở mục 6; test metadata và null NAT, không suy đoán |
| Document IPv4/profile MVP | Profile mục 5; IPv6/IGMP skip rõ với provenance |
| Absent fields=null | Empty optional cell; port 0; tracker rỗng; không tạo asset/severity |
| Stable evidence ID và line raw reference | Replay, trùng dòng, đổi context, byte hash LF/CRLF/BOM, đổi năm/offset |
| Pass/block/missing/malformed unit tests | Pass synthetic được ghi nhãn; block derivative thật; missing column khác empty cell |
| Không live dependency | Toàn bộ test offline; không SSH/syslog/network trong parser |
| Regression không hỏng | Full backend suite, pip check và wheel/import check trước bàn giao code |

Các ca bổ sung: leap day, thiếu năm/offset, -00:00, bool year, invalid date/UTC
overflow, locale độc lập, số quá dài, protocol ID/text mâu thuẫn, port >65535,
IPv6 trong cột IPv4, CSV quoting/trailing field, UTF-8/BOM sai, rotation notice
giả/malformed, input quá lớn, skip-only/empty file, lỗi dòng cuối và I/O failure.

Đối chiếu toàn mẫu gốc chỉ thực hiện offline ngoài Git, in aggregate số đếm và
lỗi an toàn; không dump raw lên terminal/CI. Hiện chưa có pass lab fixture:
test synthetic không thay thế lab validation pass. Ghi rõ giới hạn này trong PR;
reviewer quyết định mức đủ để merge, không tuyên bố live pass đã kiểm chứng.

## 10. Trình tự sau khi duyệt và điều kiện dừng

1. Người dùng đọc bản thiết kế và xác nhận phạm vi/thời gian/skip policy.
2. Viết implementation plan riêng, sau đó TDD theo từng phần nhỏ.
3. Sanitize fixture, triển khai, chạy regression và review code/evidence.
4. Người dùng chạy đối chiếu trên Windows có dự án, gửi kết quả.
5. Chỉ push/PR/merge sau khi có yêu cầu và đáp ứng review/lab gate của AGENTS.md.

Dừng để hỏi khi gặp format ngoài profile cần hỗ trợ, năm/múi giờ không đủ căn
cứ cho mục đích đánh giá thật, cần đổi canonical, hoặc muốn thêm live dependency.
Không đổi ground truth và không mở rộng sang issue khác.

## 11. Kiểm chứng ở bước tài liệu

Worktree tạo từ main `370cd2a`; chỉ thêm tài liệu này, không sửa code/test.
Baseline chạy bằng môi trường wheel đã cài từ cùng base (không cài editable
trỏ sang nhánh khác): **927 passed**, `pip check` không có dependency hỏng.
Lượt đầu có 12 setup errors do thiếu thư mục cha `build` của basetemp; tạo đúng
thư mục rồi chạy lại toàn suite thành công, không sửa code hoặc quyền truy cập.
Kết quả baseline không chứng minh parser Issue #5 hoạt động vì parser chưa viết.
Trước khi triển khai phải tạo môi trường riêng của worktree và kiểm tra import
đúng code nhánh mới; không dùng wheel baseline để test code mới.

## Nguồn tham chiếu

- [Netgate: Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html)
- [Netgate: General Configuration Options — timezone](https://docs.netgate.com/pfsense/en/latest/config/general.html)
- Hợp đồng dự án: [PRD](../../PRD.md), [Architecture](../../ARCHITECTURE.md),
  [Canonical Event](../../CANONICAL_EVENT.md), [Canonical v2](../../CANONICAL_EVENT_V2.md).
- Mẫu thiết kế envelope/streaming hiện hữu: `connectors/suricata/eve.py`
  và `connectors/suricata/eve_models.py`; chỉ tham khảo, không sửa trong bước này.
