# Issue #3 — thiết kế Wazuh fixture parser, profile Windows 4688

**LỊCH SỬ, KHÔNG DÙNG ĐỂ IMPLEMENT:** Sau merge Issue #15/PR #16, thay bằng
[thiết kế v2 lossless](2026-09-08-wazuh-win4688-v2-design.md).

Ngày: 2026-09-08. Trạng thái: TẠM DỪNG — PHƯƠNG ÁN CẮT PRECISION ĐÃ BỊ THAY THẾ.

Người dùng chọn giữ nguyên độ chính xác thời gian và tách nâng cấp canonical
thành [Issue #15](https://github.com/Tindaptrai/aegis-verify/issues/15).
KHÔNG triển khai floor-microsecond-v1, discarded_nanoseconds hoặc việc cắt 7–9
chữ số xuống 6 theo nội dung lịch sử bên dưới. Issue #3 chờ hợp đồng mới được
review/kiểm chứng, sau đó sửa thiết kế parser sang kiểu thời gian lossless.
Phần dưới giữ lại để truy vết thiết kế cũ, không phải spec hiện hành để viết code.

Người dùng đã duyệt hướng ưu tiên thời gian sự kiện và phân biệt máy nguồn với
agent thu thập. Các quy tắc chi tiết dưới đây được trình duyệt trước kế hoạch code.
Tài liệu này thay thế đề xuất mapping ban đầu dùng thời gian alert Wazuh.
Không thay đổi schema canonical, scenario ground truth hay cấu hình Wazuh.

## 1. Mục tiêu, bằng chứng và giới hạn

Issue #3 yêu cầu đọc Wazuh JSON đã làm sạch thành canonical events hợp lệ, map
alert/rule/agent/process/command line/timestamp khi có, giữ missing optional là
null, có stable evidence ID và raw reference, lỗi rõ ràng không lộ dữ liệu, test
representative/missing/malformed và không phụ thuộc live Wazuh.

Đầu vào khảo sát hiện có: một document từ Document Details trên Dashboard,
đã làm sạch thành `wazuh-sample-001.sanitized.json`. Profile xác nhận từ nội dung:
provider `Microsoft-Windows-Security-Auditing`, channel `Security`, eventID `4688`.
Không xác nhận đây là evidence của INC-002 hoặc scenario cụ thể.

Phạm vi triển khai đầu tiên được thiết kế ở đây:

- Một file UTF-8 chứa một JSON object có `_source` object; giữ cả wrapper.
- Profile process creation Windows 4688. Không đoán profile theo rule description.
- Không hỗ trợ CSV, JSONL, JSON array, bulk search response, Linux, Sysmon hay
  PowerShell event khác trong vòng đầu. Đầu vào ngoài profile báo lỗi unsupported.
- Không thực thi command line, không gọi API, không đọc log live, không đánh giá
  detected/prevented, không sửa hoặc suy ra ground truth.

Đây là mốc đầu của Issue #3, không tự thu hẹp acceptance criteria để đóng issue.
Trước PR hoàn tất cần người dùng/reviewer xác nhận tập profile/format đại diện
đủ phạm vi Issue #3; lấy thêm fixture nếu còn thiếu. Không tuyên bố hỗ trợ mọi log
Wazuh dựa trên một mẫu. Bản fixture chưa được commit trong bước thiết kế này.

## 2. Quyết định thời gian

Ba lựa chọn đã cân nhắc:

1. Dùng thời gian alert Wazuh: đơn giản nhưng có thể lệch thời điểm hành vi.
2. Dùng thời gian Windows, chuẩn hóa microsecond có ghi nhận: lựa chọn đề xuất.
3. Mở rộng canonical để giữ độ chính xác cao hơn: cần thay đổi hợp đồng riêng,
   không thực hiện ngầm trong Issue #3.

### Quy tắc của profile `wazuh-win4688-v1`

- Canonical timestamp chỉ lấy `_source.data.win.system.systemTime`.
- Chấp nhận chuỗi RFC 3339 có giây, `T`, múi giờ `Z` hoặc `+/-HH:MM`, phần thập
  phân tùy chọn từ 1 đến 9 chữ số. Không đoán epoch, local time hay ngày đơn lẻ.
- Từ chối offset không xác định `-00:00`, leap second, ngày/giờ không tồn tại,
  hoặc kết quả UTC vượt phạm vi model.
- Từ 0 đến 6 chữ số thập phân: giữ giá trị, thêm số 0 nội bộ nếu cần.
- Từ 7 đến 9 chữ số: bỏ phần sau chữ số thứ 6, không làm tròn; thao tác bằng
  chuỗi/số nguyên, không dùng float. Chuẩn hóa UTC sau kiểm tra offset.
- Metadata ghi rõ số chữ số nguồn và số nanosecond bị bỏ (0..999). Kết quả
  canonical sớm hơn hoặc bằng thời điểm nguồn, sai số nhỏ hơn 1 microsecond.
- Ví dụ từ mẫu: `.6479839Z` -> `.647983Z`, phần bị bỏ là 900 ns.
- Thiếu/null/hỏng systemTime -> lỗi; KHÔNG fallback sang timestamp alert,
  `fields.timestamp`, `sort` hoặc giờ hệ thống.
- `_source.timestamp` Wazuh và systemTime nguyên gốc vẫn nằm nguyên trong raw.
  Không sửa mẫu, không ép hai timestamp bằng nhau, không suy diễn clock skew.

Chuẩn hóa này diễn ra tường minh trong connector và được ghi nhận trong metadata;
canonical schema 1.0 vẫn từ chối trực tiếp timestamp text quá 6 chữ số như hiện tại.
Không dùng Pydantic model_construct hoặc model_copy để vượt validation.

Mapping có version. Khi thay chính sách thời gian phải tăng mapping_version,
chạy lại từ evidence giữ nguyên và lưu kết quả mới; không ghi đè kết quả lịch sử.
Engine sau này không được coi hai bản mapping khác nhau là kết quả tương đương
chỉ vì cùng evidence ID, hoặc suy ra thứ tự các event cách nhau dưới 1 microsecond.

## 3. Máy nguồn và agent thu thập

- `hostname` lấy `data.win.system.computer`: máy được ghi là nguồn Windows event.
- Missing/null hostname -> null, không lấy agent.name thay thế.
- Caller khai báo `collection_mode`: `direct`, `forwarded` hoặc `unknown`.
  Đây là thông tin thu thập đã xác nhận bên ngoài, không phải giá trị parser đoán.
- Chế độ direct: `asset_id` lấy `agent.id` nếu có, gắn trong environment_id;
  missing/null -> null. Không dùng hostname làm asset ID. Caller chịu trách nhiệm
  không khai báo direct cho record được chuyển tiếp; tên trùng nhau không đủ chứng minh.
- Chế độ forwarded/unknown: `asset_id` để null vì chưa có mapping inventory giữa
  collector agent ID và endpoint phát sinh event.
- Metadata provenance giữ `collector_agent_id`, `collector_agent_name`,
  `collector_manager_name` từ agent/manager tương ứng; missing/null -> null.
- `agent.ip` giữ trong raw, không trở thành src_ip/dst_ip.
- Tên agent trùng computer không chứng minh hai danh tính tương đương. Không dùng
  so sánh tên hoặc nhóm `WEF` để tự quyết định topology.

Người dùng xác nhận ngày 2026-09-08: mẫu hiện tại được đọc trực tiếp trên chính
máy phát sinh sự kiện. Lần kiểm thử mẫu này dùng collection_mode=direct, nên
asset_id là `901` (ID giả danh đã làm sạch). Xác nhận này chỉ áp dụng mẫu đã gửi,
không tự biến thành quy tắc cho mọi record khác.

Canonical không có trường collector riêng; vì thế thông tin agent nằm trong
provenance của kết quả parse, không nhét field vendor vào CanonicalEvent.
Điểm diễn giải acceptance criteria này cần reviewer duyệt: agent phải truy vết
được cả khi asset_id là null trong trường hợp forwarded/unknown.

## 4. Mapping các trường còn lại

Đường dẫn trong bảng tính từ `_source`; `win` viết tắt cho `data.win`.

| Canonical field | Quy tắc profile v1 |
| --- | --- |
| schema_version | `1.0` |
| source_type | `wazuh`, do connector xác định, không lấy từ giá trị tùy ý của log |
| source_record_id | `id` dạng chuỗi, không thay bằng wrapper `_id` hoặc Windows eventRecordID |
| event_provider | `win.system.providerName` |
| username | `win.eventdata.subjectUserName`: creator subject, không khẳng định tài khoản chạy tiến trình mới |
| process_name | `win.eventdata.newProcessName`, giữ nguyên chuỗi đường dẫn |
| process_id | `win.eventdata.newProcessId`, chuyển hex có prefix `0x`/`0X` và ít nhất một hex digit thành int |
| parent_process_name | `win.eventdata.parentProcessName`, giữ nguyên chuỗi |
| command_line | `win.eventdata.commandLine`, giữ nguyên chuỗi |
| rule_id | `rule.id`: chuỗi giữ nguyên hoặc JSON integer không âm chuyển sang chuỗi; từ chối bool/float |
| severity | `rule.level`: JSON integer không âm; không đổi thang mức độ |
| src_ip, dst_ip, src_port, dst_port, protocol | null trong profile này; không suy đoán kết nối từ context agent |
| file_path, file_hash, signature_id, technique_ids, event_action | null trong profile này; không suy từ process/rule text |
| environment_id, ingested_at | Bên gọi cung cấp và validate theo canonical; không có mặc định ngầm |
| event_id, raw_event_ref, raw_event_hash | Theo mục provenance bên dưới |

PID của process mới trong mẫu là `0x1ed4` -> `7892`, không phải creator PID
`eventdata.processId` hay metadata `system.processID`. Process ID 0 vẫn hợp lệ.
Không nhận decimal text hoặc JSON number cho newProcessId trong profile hex v1.
Chuỗi hex dài tối đa 128 ký tự kể cả prefix, không dấu hoặc khoảng trắng;
từ chối vượt giới hạn trước int conversion để bảo đảm serialize an toàn.

Missing/null của optional mapped field -> null; empty string giữ nguyên nếu
canonical cho phép. Một trường có giá trị sai kiểu -> lỗi, không đổi thành null.
Các container tùy chọn như agent, manager, rule, eventdata: missing/null là vắng
context; nếu có phải là object. `_source`, data, win, system và selector
providerName/channel/eventID là bắt buộc để xác định profile. Selector sai kiểu
báo invalid field; selector đúng kiểu nhưng profile khác báo unsupported profile.

Chỉ parse JSON một lần. Không gộp dấu gạch chéo, không unicode_escape thêm, không
trích từ message để ghi đè structured data. Chuỗi phải là Unicode hợp lệ, UTF-8
serializable. Trường vendor chưa map vẫn nằm trong raw, không đưa vào canonical.
Không đặt thêm mapping cho các loại event mới mà không có test và review.

## 5. API và provenance đề xuất

Hai public entry points dưới package `aegis_verify.connectors.wazuh`:

- `parse_wazuh_document(raw: bytes, *, source_ref: str, environment_id: str,
  ingested_at: datetime | str, collection_mode: str) -> WazuhParseResult`.
- `load_wazuh_document(path: str | Path, *, source_ref: str, environment_id: str,
  ingested_at: datetime | str, collection_mode: str) -> WazuhParseResult`.

collection_mode là chuỗi bắt buộc, chỉ nhận đúng direct/forwarded/unknown;
không có mặc định direct. Giá trị khác hoặc sai kiểu báo invalid_context.

Không nhận dict đã parse: cần đúng bytes để hash và phát hiện duplicate keys.
File loader chỉ đọc tối đa limit + 1 byte rồi gọi parser, không ghi file.
Path do caller có thẩm quyền chọn; loader không phải sandbox đường dẫn.

`WazuhParseResult` là envelope bất biến, gồm:

- `event`: một CanonicalEvent được validate đầy đủ. Đây là event duy nhất được
  emit; engine chỉ nhận event, không đọc field vendor.
- `provenance`: metadata bất biến gồm mapping_version=`wazuh-win4688-v1`,
  timestamp_basis=`windows.systemTime`, timestamp_policy=`floor-microsecond-v1`,
  source_fraction_digits (0..9), discarded_nanoseconds (0..999),
  source_ref, record_index=1, event_id, raw_event_hash, collection_mode và ba trường collector
  đã nêu. Không sao chép raw message hoặc command line vào provenance.
  Các tên collector vẫn là chuỗi nguồn có thể nhạy cảm; caller phải làm sạch
  trước. Envelope không phải bộ phát hiện hoặc loại bỏ secret.

Provenance là thông tin đi kèm để caller lưu cùng kết quả, không thay thế model
chung và không được âm thầm bỏ khi lưu artifact để so sánh run về sau.
Trong Issue #3 chưa xây kho evidence hay engine/API/UI mới.

### Ranh giới record, hash và ID

- Một file/bytes input là một record, index 1. Toàn bộ bytes bao gồm wrapper,
  khoảng trắng, UTF-8 BOM đầu file nếu có và newline cuối file đều được hash.
- Decoder chấp nhận tối đa một UTF-8 BOM ở đầu, hash vẫn bao gồm BOM.
- `source_ref`: logical filename do caller cung cấp, không phải absolute path;
  chỉ `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, không có slash/backslash/fragment.
  Không tự suy từ path; giữ reference ổn định giữa các lần replay.
- `raw_event_ref = source_ref + "#record=1"`.
- `raw_event_hash`: helper hash_raw_event hiện có, SHA-256 lowercase.
- `event_id = "wazuh:evidence-v1:" + sha256(identity_bytes).hexdigest()`.
- identity_bytes là UTF-8 của JSON array theo đúng thứ tự
  `["wazuh-evidence-v1", environment_id, source_ref, 1, raw_event_hash]`,
  JSON compact separators `(comma, colon)`, ensure_ascii=True, không newline.
- Không đưa ingested_at hoặc mapping_version vào evidence ID: ID chỉ nhận diện
  evidence, không nhận diện một cách diễn giải. Khóa phiên bản diễn giải cần bộ
  `(event_id, mapping_version, collection_mode)`; không cache chỉ theo event_id.
  collection_mode không nằm trong evidence ID vì không sửa bytes bằng chứng,
  nhưng phải nằm trong khóa diễn giải do có thể ảnh hưởng asset_id.
  Đây không phải khóa duy nhất cho mọi lần ingestion: caller phải giữ run/ingestion
  context riêng và không tái dùng ingested_at cũ khi đọc lại trong lần thu nhận mới.
- Khác source_ref/môi trường/bytes -> ID khác. Không deduplicate các file giống nhau.

Thay đổi hash chứng minh bytes khác, không chứng minh nguồn tin cậy hay alert đúng.
Không hash dữ liệu parse rồi tái serialize thay cho evidence đã làm sạch.

## 6. Đầu vào không tin cậy và diagnostic

Giới hạn mặc định cố định v1: 256 KiB/document, độ sâu container 20 (root=1),
tổng 10.000 node (mỗi container hoặc scalar value tính một node, không tính key).

- Preflight lexical đếm độ sâu có nhận biết string/escape trước json.loads;
  không dùng regex đơn giản đếm dấu ngoặc trong chuỗi. Giới hạn bytes trước decode.
- Sau decode, duyệt cây giới hạn node và UTF-8 của mọi key/string kể cả unknown.
- Từ chối duplicate object keys, NaN/Infinity hoặc float overflow thành infinity,
  invalid UTF-8, unpaired surrogate, trailing document và root không phải object.
- Giới hạn numeric token tối đa 128 ký tự trước chuyển số để tránh phụ thuộc
  ngưỡng integer của runtime; áp dụng cả unknown fields. Đây là policy V0 có tài liệu.
- Chặn lỗi parse/type/calendar/overflow/IO dự kiến thành public diagnostic; không
  catch mọi exception để che programming bug.

`WazuhParseError` có diagnostic bất biến: code thuộc vocabulary cố định,
field_path được tạo từ allowlist nội bộ, record_index=1, line/column nếu có.
Không chứa input value, arbitrary unknown key, raw text, path thật hoặc original
exception message. Không in payload trong thông báo hoặc chained exception.
Không log trực tiếp Pydantic errors()/JSONDecodeError hoặc traceback locals.
Python debugger có thể truy cập dữ liệu nội bộ; public error không phải bảo đảm
bảo mật cho mọi chế độ debug của caller.

Vocabulary: input_type, input_too_large, invalid_encoding, invalid_unicode,
invalid_json, duplicate_key, invalid_number, max_depth, max_nodes, invalid_root,
missing_source, invalid_field, unsupported_profile, missing_event_time,
invalid_event_time, invalid_context, canonical_validation, io_error.

Fail-fast, không trả partial event. Metadata precision reduction là policy
normalization có ghi nhận, không phải malformed record hoặc diagnostic lỗi.

## 7. Bố trí code và dependencies khi được duyệt

- Source parsing/provenance/error trong `connectors/wazuh/`.
- Đóng gói explicit `aegis_verify.connectors` -> `connectors/`,
  `aegis_verify.connectors.wazuh` -> `connectors/wazuh/`, có __init__.py tương ứng.
  Không yêu cầu PYTHONPATH thủ công và không đưa parser vào backend models.
- Test trong backend/tests; fixture đã review vào tests/fixtures/wazuh/ cùng
  provenance note, không gọi mẫu là INC-002 khi chưa được xác nhận.
- Dùng json/hashlib/datetime và Pydantic đã có; chưa cần dependency mới.
- Không mở rộng schema canonical để giải quyết collector hoặc precision trong
  bước này; nếu envelope không được reviewer chấp nhận thì review contract riêng.

## 8. Verification và điều kiện bàn giao

Viết regression tests trước code cho:

1. Mẫu thực đã làm sạch: đúng mapping, PID, hostname, asset_id=901 ở chế độ direct
   (chuỗi), cùng collector; forwarded/unknown cho asset_id=null và giữ collector.
2. systemTime từ 0..9 chữ số thập phân; mẫu bỏ 900 ns; giữ precision metadata;
   offset UTC, invalid date, missing timezone, overflow, không fallback alert time.
3. Creator/target user khác nhau; ba PID khác nhau; không suy IP mạng từ agent.
4. Collector khác computer, trùng computer và thiếu computer: không đoán chế độ;
   kiểm tra đủ ba collection_mode, mode sai kiểu/giá trị và trách nhiệm caller.
5. Missing/null optional, sai kiểu, PID0, bad hex, giữ nguyên command line/backslash.
6. Stable evidence ID, khác source/context/bytes, hash BOM/newline/whitespace;
   thay ingested_at không làm đổi ID; canonical serialize/deserialize hợp lệ.
7. Các lỗi JSON/Unicode/duplicate/depth/size/node/numeric ở cả mapped và unknown
   fields; diagnostic không chứa chuỗi marker nhạy cảm hoặc raw input.
8. Chạy toàn bộ backend tests, pip check và wheel install/import smoke riêng.

Không tạo giả evidence lab: malformed/missing-field variants nhân tạo phải ghi
rõ là unit-test data; không thay dữ liệu gốc để làm scenario pass.

Human review cần xem timestamp precision policy, collector vs origin, mapping
coverage, reference/hash và đối chiếu output với file đã làm sạch. Cần xác nhận
tập mẫu/profile đủ acceptance criteria trước khi đóng Issue #3. Có thể hoàn thành
mốc 4688 trước, nhưng không coi đó tự động là hoàn tất toàn bộ issue.

## 9. Bước tiếp theo và nguồn

Người dùng duyệt spec -> viết kế hoạch implementation -> chuẩn bị môi trường
nhánh/worktree được phép và baseline tests -> TDD -> human review/lab đối chiếu.
Chưa có quyền tự push/merge Issue #3 chỉ từ việc duyệt thiết kế.

Nguồn: AGENTS.md, docs/PRD.md, docs/ARCHITECTURE.md, docs/CANONICAL_EVENT.md,
Issue #3 và mẫu JSON đã làm sạch người dùng cung cấp.

- [Issue #3](https://github.com/Tindaptrai/aegis-verify/issues/3)
- [Microsoft: Event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
