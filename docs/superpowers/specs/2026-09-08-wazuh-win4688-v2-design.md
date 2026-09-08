# Issue #3 — Wazuh Windows 4688, canonical v2

Ngày 2026-09-08. Hướng triển khai được người dùng xác nhận trong cuộc trao đổi:
fixture trước, giữ nguyên thời gian bằng canonical v2 sau merge Issue #15/PR #16.
Đây là subsystem connector (architectural), tiếp nối thiết kế đã trao đổi, không
thêm profile, live dependency hoặc thay đổi schema/ground truth.

## Scope và acceptance

Issue #3 yêu cầu schema-valid outputs, map alert/rule/agent/process/command line/
timestamp khi có, absent=null, stable evidence ID + record reference, lỗi an toàn,
tests representative/missing/malformed, không live Wazuh, regression xanh.

Mốc này đọc một JSON UTF-8 object có wrapper `_source`, profile chính xác:
providerName=`Microsoft-Windows-Security-Auditing`, channel=`Security`,
eventID=`4688` (các selector dạng string). Profile khác hoặc array/JSONL/CSV/bulk
chưa hỗ trợ. Thiếu optional để null; sai kiểu không được chuyển thành null.
Một mẫu 4688 không chứng minh coverage toàn bộ Wazuh. Không tự đóng Issue #3;
cần người dùng xác nhận coverage trước PR hoàn tất. Mẫu không được gán INC-002.

Thiết kế cũ nằm trong git history và tài liệu cũ có nhãn obsolete. Thay đổi:
schema_version=2.0, mapping_version=`wazuh-win4688-v2`,
timestamp_policy=`lossless-nanosecond-v2`; bỏ discarded_nanoseconds.

## Time và identity

- timestamp chỉ từ `_source.data.win.system.systemTime`, parse bằng PreciseTimestamp.
- Giữ 0..9 chữ số và UTC. Không fallback alert timestamp/fields/sort/current time.
- Missing/null => missing_event_time; sai kiểu/format/calendar/precision => invalid_event_time.
- ingested_at do caller cung cấp; không tự lấy giờ hiện tại.
- hostname chỉ từ system.computer, không fallback agent.name.
- Caller khai báo collection_mode direct/forwarded/unknown, không có mặc định.
- direct: asset_id=agent.id khi có; forwarded/unknown: asset_id=null.
- Không suy topology từ nhóm WEF hoặc tên trùng nhau. Xác nhận direct của người
  dùng chỉ áp dụng mẫu đã gửi. agent.ip không trở thành src_ip/dst_ip.

## Field mapping (đường dẫn tính từ _source)

| Canonical | Input / rule |
|---|---|
| source_type | wazuh (connector constant) |
| source_record_id | id, optional string |
| event_provider | data.win.system.providerName |
| hostname | data.win.system.computer |
| username | data.win.eventdata.subjectUserName (creator, không target user) |
| process_name | data.win.eventdata.newProcessName, giữ nguyên path |
| process_id | data.win.eventdata.newProcessId: hex 0x/0X, 1..126 hex digits |
| parent_process_name | data.win.eventdata.parentProcessName |
| command_line | data.win.eventdata.commandLine, không thực thi hoặc decode lần hai |
| rule_id | rule.id: string hoặc integer >=0 -> string, không bool/float |
| severity | rule.level: integer >=0, không bool/float/string |
| environment_id, ingested_at | validated caller context |
| asset_id | agent.id nếu direct, optional string; không suy từ hostname |
| event_action, network, file, signature, technique | null; không suy từ message/rule text |

Optional string nhận empty string nếu canonical cho phép; bytes/numeric từ chối.
Các container agent/manager/rule/eventdata thiếu/null là vắng context; nếu có phải
là object. _source/data/win/system và ba selector bắt buộc. Unknown fields nguyên
trong raw evidence; không copy vào canonical, không xóa hay viết lại input.

## API và output

`aegis_verify.connectors.wazuh` exports:

```python
parse_wazuh_document(raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
    collection_mode: str) -> WazuhParseResult
load_wazuh_document(path: str | Path, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
    collection_mode: str) -> WazuhParseResult
```

Result immutable gồm event: CanonicalEventV2 và provenance immutable. Provenance:
mapping_version, timestamp_basis=`windows.systemTime`, timestamp_policy,
source_fraction_digits, source_ref, record_index=1, event_id, raw_event_hash,
collection_mode, collector_agent_id/name và collector_manager_name (optional string).
Không đưa raw message/command line vào provenance. Collector names vẫn nhạy cảm;
parser không phải sanitizer. Engine chỉ nhận canonical event.

Hash toàn bộ bytes wrapper, whitespace, newline và BOM. Decoder chấp nhận một UTF-8
BOM đầu file nhưng không bỏ BOM khỏi hash. source_ref là logical filename khớp
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; không absolute path hoặc slash.
raw_event_ref=`source_ref + '#record=1'`.
event_id=`'wazuh:evidence-v1:' + sha256(identity_bytes).hexdigest()` với identity_bytes
là UTF-8 JSON compact, ensure_ascii=True, không newline, của array theo thứ tự:
`['wazuh-evidence-v1', environment_id, source_ref, 1, raw_event_hash]`.
Khác bytes/environment/source_ref đổi ID; ingested_at/mapping_version/mode không đổi ID.
Khóa cách diễn giải dùng (event_id, mapping_version, collection_mode), run context
lưu riêng. Hash không chứng minh nguồn đáng tin, không phải kết luận detection.

## JSON và lỗi công khai

Giới hạn raw 256 KiB, depth 20 containers (root=1), 10.000 nodes (values/container,
không đếm key), numeric token 128 ký tự. Preflight depth nhận biết string/escape.
Từ chối duplicate keys, nonfinite, numeric overflow, UTF-8 hỏng, surrogate kể cả
unknown keys/values, trailing document, root không phải object. Không sửa input.
Loader đọc tối đa limit+1 bytes, không ghi; path caller chọn không phải sandbox.

WazuhParseError giữ diagnostic immutable: code allowlist, field_path allowlist,
record_index=1, line/column optional. Không input values, path thật, unknown keys,
raw payload, exception chaining hoặc traceback locals trong output công khai.
Vocabulary: input_type, input_too_large, invalid_encoding, invalid_unicode,
invalid_json, duplicate_key, invalid_number, max_depth, max_nodes, invalid_root,
missing_source, invalid_field, unsupported_profile, missing_event_time,
invalid_event_time, invalid_context, canonical_validation, io_error.
Fail-fast, không partial event. Không catch mọi exception để che programming bug.

## Bố trí và kiểm chứng

Code chỉ trong connectors/wazuh: parser.py (mapping/context/provenance),
_json.py (bounded decoder), errors.py (diagnostic), __init__.py (API).
pyproject đóng gói aegis_verify.connectors -> connectors và subpackage wazuh.
Không thêm dependency; dùng stdlib + Pydantic hiện có. Unit tests ở backend/tests.
Fixture chỉ đưa vào tests/fixtures/wazuh sau đọc/scan toàn bộ bản sanitized; ghi
nguồn/mốc làm sạch và giới hạn. Không đưa file gốc Downloads vào git.

Test positive mapping, exact 0..9 fractions, no fallback, 3 PID phân biệt, user
creator/target khác nhau, direct/forwarded/unknown, missing/null/wrong types,
hash/ID và wrapper/BOM/newline, limits/error privacy, bounded loader và wheel import.
Chạy toàn bộ backend + pip check + review độc lập rồi người dùng đối chiếu mẫu.

## Khung thời gian tối nay

Mốc mục tiêu, không phải bảo đảm hoàn thành: 21:40–22:00 merge/setup/spec;
22:00–23:00 parser và tests; 23:00–23:30 review/wheel; 23:30–00:00 người dùng
đối chiếu và xác định fixture còn thiếu. Không chạy lab hoặc tạo automation ngầm.
