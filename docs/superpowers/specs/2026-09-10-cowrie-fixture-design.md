# Cowrie fixture parser — bản đề xuất sau khảo sát mẫu

Trạng thái: **DRAFT, chưa duyệt phạm vi triển khai**. Ngày 10/09/2026 (UTC+7).
Nhánh chuẩn bị: `codex/issue-6-cowrie-fixture-parser`, xuất phát từ `664880d`.
Chưa viết production parser, chưa thêm fixture hoặc thay canonical/scenario.

## 1. Mục tiêu và căn cứ

Chuẩn bị connector thứ tư cho luồng offline của AEGIS Verify: Cowrie evidence
được chuẩn hóa thành CanonicalEventV2, kèm provenance để truy vết bản ghi nguồn.
Đây là thiết kế connector mới, không phải mở live connection tới honeypot.

Căn cứ đã đọc: AGENTS.md, docs/PRD.md, docs/ARCHITECTURE.md,
docs/THREAT_MODEL.md, tests/fixtures/README.md, canonical fields/v2 và các parser
Wazuh/Suricata/pfSense hiện có. Nội dung acceptance criteria trực tiếp của
Issue #6 chưa truy cập được qua công cụ GitHub. Phạm vi dưới đây là đề xuất,
không phải bản chép acceptance criteria hoặc cam kết rằng toàn Issue #6 đã đủ.

## 2. Mẫu thực tế đã có

- Tên file người dùng cung cấp: `cowrie-sample-001.sanitized.json`.
- Kích thước: 1.715 bytes; một JSON object, dạng Wazuh search-hit.
- SHA-256: `cfe730f1e74412d7f37f2133761357ceb5c0a8f32cf22be375cd838b5b06aee5`.
- `_source.data.eventid`: `cowrie.session.params`.
- `_source.rule.groups`: có `cowrie` và `honeypot`; decoder là `json`.
- `_source.full_log` là JSON nằm trong string, không phải một event thứ hai.
- Các trường eventid, timestamp, src_ip, session, sensor, protocol, arch, uuid,
  @source, @service trùng giữa data và JSON trong full_log khi đối chiếu cục bộ.
- `protocol=ssh`; arch có mặt. Không cần message dạng string để nhận params.
- Timestamp Cowrie: `2026-05-02T01:02:46.697252+07:00`.
- Timestamp Wazuh: `2026-05-02T01:03:21.836+07:00`.
- Không có src_port, dst_ip, dst_port, username, password hoặc input trong data.

Chưa có session.connect, login.success, login.failed, command.input hoặc
session.closed trong mẫu này. Không suy diễn có login/command từ event params.
Chênh lệch hai timestamp không tự chứng minh độ trễ ingest vì đồng hồ và pipeline
chưa được kiểm chứng. Nội dung file gốc được giữ ở Downloads, chưa thêm vào Git.
Chữ sanitized trong tên file không thay thế review quyền riêng tư và fixture.

## 3. Các hướng và đề xuất

| Hướng | Lợi ích | Giới hạn |
| --- | --- | --- |
| A: Wazuh-exported Cowrie JSON | Có mẫu thực tế ngay; khớp cách người dùng đang export; tái dùng mẫu kiến trúc Suricata A | Chỉ thấy event được Wazuh lưu/export; chưa chứng minh bao phủ toàn bộ session |
| B: Cowrie JSONL trực tiếp từ file offline | Phù hợp đọc chuỗi connection/login/command, không lệ thuộc lọc alert ở Wazuh | Cần mẫu trực tiếp; thêm API stream, outcomes và giới hạn đọc file |
| A+B cùng lượt | Hai đường nhập ngay từ đầu | Phạm vi review lớn hơn; hiện chỉ có một mẫu A thuộc params |

**Đề xuất A trước, B tiếp theo khi có file**, với lõi mapping đặt trong
`connectors/cowrie/` để B có thể tái dùng. Profile A đề xuất nhận sáu event types
ở bảng dưới; chỉ params được gọi là có real-sample coverage hiện tại. Nếu
acceptance của Issue #6 bắt buộc native JSONL, A chỉ là phần bổ sung và không đủ
đóng issue. Không biến JSON trích từ full_log thành bằng chứng đã lấy native file.

Theo kiến trúc chung, đọc file JSONL offline vẫn là V0. Dòng README Cowrie cũ
"Direct Cowrie JSON access is V1" cần làm rõ là live access, không phải định
dạng JSON trực tiếp; việc sửa sẽ đi cùng profile được duyệt.

## 4. Hợp đồng đầu vào và đầu ra dự kiến cho A

```python
parse_cowrie_wazuh_document(
    raw: bytes, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> CowrieParseResult

load_cowrie_wazuh_document(
    path: str | Path, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> CowrieParseResult
```

Đây là API đề xuất, chưa tồn tại để chạy. `CowrieParseResult` chứa một `event`
v2 và `provenance` bất biến; source-specific data không truyền vào engine.
Chỉ nhận một search-hit object có `_source.data` và Wazuh group `cowrie`.
Không tự nhận array, hits.hits, CSV hoặc native event qua cùng API.

Nguồn mapping duy nhất là `_source.data`; không lấp trường thiếu từ full_log,
agent, rule description, message hoặc document fields/sort. full_log cùng mọi
trường không map được giữ trong artifact mà raw_event_ref trỏ tới. Provenance
ghi rõ `payload_basis=wazuh._source.data`; không khẳng định đã xác thực mọi bản
sao trong full_log. Mẫu hiện tại đã được đối chiếu, không áp đặt kết quả đó cho
mọi export tương lai.

source_ref và sensor_id là nhãn bất biến ASCII theo
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; không phải URL để parser tải về.
environment_id là UTF-8 không trắng, tối đa 128 bytes; giữ nguyên giá trị hợp lệ.
ingested_at bắt buộc, có timezone, caller cung cấp; parser không đọc đồng hồ.
sensor_id là namespace caller xác nhận; không tự lấy Wazuh agent làm honeypot.

## 5. Mapping nguồn sang canonical và provenance

| Event nguồn | canonical.event_action | Ý nghĩa còn giữ trong provenance |
| --- | --- | --- |
| cowrie.session.params | observed | source_event_type, arch, session |
| cowrie.session.connect | observed | source_event_type, session |
| cowrie.session.closed | observed | source_event_type, session |
| cowrie.login.success | login | authentication_outcome=success, session |
| cowrie.login.failed | login | authentication_outcome=failure, session |
| cowrie.command.input | command | source_event_type, session |

Các trường chung:

- source_type và event_provider là `cowrie`.
- timestamp lấy data.timestamp, giữ 0–9 chữ số phần giây, chuẩn hóa UTC. Thiếu,
  sai kiểu hoặc thiếu timezone gây lỗi; không fallback sang timestamp Wazuh.
- data.src_ip/src_port/dst_ip/dst_port đi vào network fields tương ứng nếu có.
- data.protocol giữ `ssh`/`telnet` theo nguồn; không tự đổi thành tcp. Khác profile
  cần từ chối rõ hoặc duyệt mở rộng, không đoán.
- data.username chỉ map cho login; thiếu hoặc null giữ null.
- data.input chỉ map thành command_line cho command.input; không thực thi chuỗi.
- data.sensor giữ trong provenance như source_sensor; hostname canonical để
  null vì sensor label không bảo đảm là hostname thật.
- source_record_id là Wazuh `_source.id` nếu có, với namespace provenance
  `wazuh.alert.id`; không dùng eventid/session/uuid làm record ID.
- rule_id, signature_id, severity, asset_id, process/file/technique fields để
  null trong profile này. Wazuh rule ID/level nằm riêng ở provenance; rule alert
  không trở thành severity hay kết luận detection của Cowrie.
- Session, uuid nguồn, Wazuh timestamp và collector identity có mặt thì giữ
  riêng trong provenance; không suy uuid là event ID nếu chưa biết semantics.

Optional field vắng/null giữ null; present nhưng sai kiểu/IP/port gây lỗi.
Không coerce bool thành số, không dùng số nguyên làm IP; port 0 vẫn hợp lệ.
Trường eventid/timestamp là bắt buộc; session vắng thì provenance.session=null,
không tự tạo session hoặc gán event vào session trước đó.

## 6. Giới hạn canonical cần quyết định công khai

Canonical hiện có action `login` nhưng không có authentication_outcome và
session_id. Vì vậy engine chỉ nhận canonical v2 chưa thể phân biệt login
success/failure hoặc khẳng định các events cùng Cowrie session từ provenance.
Event params chỉ mang action observed, không tự đại diện một connection record.

Đề xuất giữ metadata ở provenance trong #6, ghi rõ parser này là chuẩn hóa facts,
chưa triển khai session-aware security verdict. Khi #7 cần outcome/session,
phải duyệt thay đổi canonical riêng hoặc giới hạn assertion rõ ràng. Không nhét
outcome vào rule_id, session vào source_record_id, hay cho engine đọc raw Cowrie
để lách hợp đồng. Ground truth SCN-003 hiện tại không bị sửa.

## 7. Evidence identity và lỗi

Hash là SHA-256 đúng bytes toàn search-hit, kể whitespace, BOM và newline.
Reference là source_ref cộng `#L1-L<n>` của artifact gốc. Không hash JSON đã
serialize lại hoặc full_log con rồi gắn hash đó cho wrapper.

ID đề xuất: `cowrie:wazuh-evidence-v1:` + SHA-256 của UTF-8 JSON array compact
`["cowrie-wazuh-evidence-v1", environment_id, sensor_id, source_ref, 1, raw_hash]`,
với ensure_ascii=True và separators=(",", ":"). ingested_at không tham gia ID.
Cùng bytes/context cùng ID; đổi artifact/sensor/môi trường/bytes đổi ID. Session
được namespace khi sử dụng về sau, không coi session string là duy nhất toàn cục.

Một-document API trả một result hoặc raise CowrieParseError; không partial
success. Event không thuộc sáu types báo unsupported_profile, không gọi là
missing telemetry. JSON invalid, duplicate keys, NaN/Infinity, Unicode hỏng,
field sai hoặc I/O lỗi trả code/path/vị trí an toàn, không in raw input,
message, command, password hoặc exception I/O gốc.

Giới hạn đề xuất theo decoder hiện có: 256 KiB/document, depth 20, 10.000 nodes,
128 ký tự token số. Load file chỉ đọc tối đa limit+1 trước kiểm tra. Không thêm
dependency. Có thể bọc decoder JSON sẵn có, chuyển WazuhParseError thành
CowrieParseError, không mở refactor chung ngoài scope.

## 8. Kiểm thử và dữ liệu cần thêm

| Nhóm | Tiêu chí kiểm chứng |
| --- | --- |
| Nhận dạng | wrapper/group/event type đúng; sai nguồn/type/array bị từ chối |
| Mapping | cả sáu event types; login outcome không bị biến thành verdict |
| Null/types | thiếu fields, null, rỗng/sai kiểu, bool, invalid IP, port 0/65535/ngoài biên |
| Thời gian | offset, 0–9 digits, ngày sai, thiếu zone, không fallback Wazuh |
| Evidence | exact bytes/BOM/LF/CRLF, line ref, ID lặp lại, namespace, đổi ingested_at |
| Input bất thường | duplicate keys, encoding, depth/nodes/size/numeric limits, lỗi không rò input |
| Fixture thật | derivative của params, manifest/hash/sanitize review, không thêm event giả vào nguồn |
| Đóng gói | public imports, pytest/pip check; wheel verification trước tích hợp |

Synthetic unit inputs phải được ghi nhãn rõ; không xem chúng là lab validation.
Để xác nhận profile đầy đủ cần các event connect, login result, command và nếu
có closed cùng session từ hoạt động lab đã được cho phép. Không yêu cầu người
dùng chạy tấn công mới hay đổi rule để có dữ liệu. Login log có thể chứa password,
command có thể chứa bí mật; remove/alias nhất quán cả data và full_log, không chỉ
ẩn một bản sao. Không commit credentials hoặc reverse alias map.

## 9. Các file dự kiến khi scope được duyệt

- connectors/cowrie/: parser.py, _mapping.py, _fields.py, _context.py, models.py,
  errors.py, __init__.py và README.md.
- backend/tests/: test_cowrie_parser.py, test_cowrie_mapping.py,
  test_cowrie_fixtures.py.
- tests/fixtures/cowrie/: derivative params đã review, manifest và README.
- docs/COWRIE_FIXTURE_PARSER.md; pyproject.toml thêm package Cowrie khi code có.

Không sửa canonical model, scenario manifests, rule content, live adapter,
engine/CLI hoặc connector nguồn khác trong phần việc này.

## 10. Điều kiện chuyển sang implementation

1. Đối chiếu mô tả/acceptance Issue #6 mà người dùng cung cấp hoặc GitHub cho đọc.
2. Người dùng duyệt profile A và giới hạn canonical ở mục 6, hoặc chọn B trước.
3. Chốt coverage lab còn thiếu là follow-up hay bắt buộc trước merge theo issue.
4. Sau đó lập implementation plan và chạy test-first; không tự đóng issue/merge.

Nguồn tham khảo: [Cowrie Output Event Code Reference](https://docs.cowrie.org/en/stable/OUTPUT.html)
giải thích params, connection, login và command events. Tài liệu hiện hành không
chứng minh phiên bản Cowrie đang chạy trong lab; mapping phải kiểm tra bằng mẫu.
