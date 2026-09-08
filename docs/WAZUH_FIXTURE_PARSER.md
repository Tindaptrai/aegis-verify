# Đọc trước: Wazuh fixture parser — Issue #3

## Bạn đang có gì?

Một bộ chuyển đổi **file JSON Wazuh đã ẩn danh → canonical event v2**.
Mốc đầu chỉ nhận Windows Security Event **4688 — tạo tiến trình**.
Đây chưa phải bộ kết luận tấn công, chưa chạy scenario và không kết nối SIEM.
Canonical v2 đã merge qua PR #16; parser này còn chờ bạn đối chiếu và review.

Mẫu bạn cung cấp đủ để triển khai mốc này. Không cần export toàn bộ SIEM.
Mẫu được dùng để kiểm tra cấu trúc thực tế, không phải bằng chứng cho INC-002
hay một cuộc tấn công. Hash chứng minh byte có thay đổi hay không, không xác minh
nguồn gốc hoặc đồng hồ máy đúng giờ.

## Chạy thử trong PowerShell

Dùng đúng worktree và Python bên dưới, không dùng `.venv` của thư mục root:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-3-wazuh-fixture-parser'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
```

Để xem kết quả của mẫu đã ẩn danh, mở Python bằng
`& '.\.venv\Scripts\python.exe'`, dán đoạn sau, rồi `exit()` khi xong.
Thời điểm ingest và environment bên dưới là **ngữ cảnh kiểm thử cố định**, không
phải thời điểm thu thập thực tế. Khi dùng dữ liệu khác phải truyền đúng ngữ cảnh.

```python
from aegis_verify.connectors.wazuh import load_wazuh_document

result = load_wazuh_document(
    'tests/fixtures/wazuh/win4688.sanitized.json',
    source_ref='win4688.sanitized.json',
    environment_id='unit-lab',
    ingested_at='2026-09-08T14:00:00Z',
    collection_mode='direct',
)
print(result.model_dump_json(indent=2))
assert result.event.timestamp.isoformat() == '2026-09-08T13:31:34.6479839Z'
assert result.event.process_id == 7892
assert result.event.src_ip is None
```

`event` là canonical event dùng cho phần đánh giá sau này. `provenance` ghi cách
chuyển đổi và danh tính collector; không thay đổi hợp đồng canonical.
Khi bàn giao/lưu kết quả, giữ cả hai phần cùng file JSON gốc đã ẩn danh.

## Những trường cần đối chiếu

Đường dẫn nguồn bên dưới tính từ `_source`:

| Canonical / metadata | Nguồn hoặc quy tắc |
|---|---|
| `timestamp` | `data.win.system.systemTime`, giữ nguyên độ chính xác, chuyển UTC |
| `ingested_at` | Người gọi truyền rõ ràng, không tự lấy giờ hiện tại |
| `source_record_id` | `id`, không lấy `_id` của search hit |
| `hostname` | `data.win.system.computer`, không fallback sang agent name |
| `asset_id` | `agent.id` chỉ khi `collection_mode='direct'` |
| `username` | `data.win.eventdata.subjectUserName` — người tạo, không phải target user |
| `process_name` | `data.win.eventdata.newProcessName` — giữ toàn bộ đường dẫn |
| `process_id` | `data.win.eventdata.newProcessId`, chuỗi hex → số nguyên |
| `parent_process_name` | `data.win.eventdata.parentProcessName` |
| `command_line` | `data.win.eventdata.commandLine`, giữ nguyên, không thực thi |
| `rule_id`, `severity` | `rule.id`, `rule.level` |
| Collector metadata | `agent.id`, `agent.name`, `manager.name` |
| `src_ip`, `dst_ip`, ports, protocol | `null`; IP agent không được coi là IP kết nối |
| Action, file, signature, technique IDs | `null`; profile này không suy đoán thêm |

Trường tùy chọn thiếu hoặc `null` → canonical `null`. Có trường nhưng sai kiểu →
báo lỗi; không lén đổi dữ liệu hỏng thành `null`.
Mẫu có đường dẫn chứa hai ký tự backslash tại mỗi dấu phân cách sau khi JSON
decode; parser giữ đúng dữ liệu đó, không tự sửa thành một ký tự.

### Vì sao hỏi bạn log đọc trực tiếp hay WEF?

- `direct`: agent đọc log trên chính máy phát sinh. Bạn đã xác nhận mẫu này như vậy.
- `forwarded`: agent có thể là máy thu gom; không gán agent ID cho máy phát sinh.
- `unknown`: chưa rõ topology, để `asset_id=null`.

Không suy ra topology từ tên group `WEF`. Caller phải chọn rõ chế độ mỗi lần gọi.
Hostname luôn lấy từ Windows `computer`. Các collector metadata được giữ riêng
trong cả ba chế độ, kể cả khi không có hostname.

### Thời gian có thay đổi được sau này không?

Bạn có thể chọn khoảng thời gian khác để lấy log, nhưng **không sửa giờ trong
evidence gốc chỉ để làm khớp kết quả**. Parser hiện dùng duy nhất `systemTime`.
Không fallback sang thời gian Wazuh alert, `fields.timestamp`, `sort` hoặc giờ máy.
Thiếu event time → `missing_event_time`; thời gian sai → `invalid_event_time`.
V2 hỗ trợ 0..9 chữ số thập phân, không làm tròn/cắt, giữ cả số 0 cuối.
Thay chính sách chọn thời gian sau này phải có mapping version, thiết kế và test mới.
Nếu cần bù clock skew, đó là phép diễn giải riêng, không ghi đè raw evidence.

## Evidence ID và hash

- SHA-256 tính trên **toàn bộ byte file đầu vào**, gồm wrapper, BOM nếu có và newline.
- `raw_event_ref = source_ref + '#record=1'`; caller giữ file tương ứng với logical name.
- `source_ref` là tên logic ASCII 1..128 ký tự `[A-Za-z0-9][A-Za-z0-9._-]*`,
  không phải đường dẫn thật, không có `/` hoặc `\`.
- ID lấy SHA-256 của JSON array dưới đây, `ensure_ascii=True`, separators `(',', ':')`,
  encode UTF-8, không newline; tiền tố ID là `wazuh:evidence-v1:`.

```text
["wazuh-evidence-v1", environment_id, source_ref, 1, raw_event_hash]
```

Đổi byte, environment hoặc tên logic → đổi ID. Đổi ingest time hoặc collection
mode không đổi ID của evidence. Khi lưu nhiều cách diễn giải cùng evidence, khóa
diễn giải gồm `(event_id, mapping_version, collection_mode)`; không chỉ event ID.
Đây không phải cơ chế deduplicate sự kiện giữa nhiều bản export.
Unknown source fields còn nguyên trong file raw tham chiếu, không bị loại khỏi hash.
Parser không tự lưu trữ/copy file raw; caller chịu trách nhiệm giữ nó.

Mẫu trong Git có SHA-256:
`27813eae73a3276ab9bc61aeccf8572d0ba5309692ae4a888f7b8f7e55527571`.
Với context ví dụ, ID là:
`wazuh:evidence-v1:bf8783941ab703cf872f4fe04e9771a1e7b44c4ec00af62718fe8a5961a3f94a`.

## Phạm vi và lỗi an toàn

API: `parse_wazuh_document(raw: bytes, *, source_ref, environment_id, ingested_at,
collection_mode)` hoặc `load_wazuh_document(path, *, ...same context...)`.
Kết quả và metadata immutable qua API thông thường; không phải Python sandbox.

- Một JSON object UTF-8 có `_source`, không phải CSV/JSONL/array/bulk search response.
- Ba selector chuỗi bắt buộc: provider `Microsoft-Windows-Security-Auditing`,
  channel `Security`, event ID `4688`. Profile khác báo `unsupported_profile`.
- Tối đa 256 KiB, depth 20, 10.000 value nodes, numeric token 128 ký tự.
- PID chỉ chuỗi `0x`/`0X` cộng 1..126 chữ số hex, giá trị sau chuyển đổi tối đa
  128 chữ số thập phân để tương thích canonical reader. Không suy đoán decimal PID.
- Rule ID nhận string hoặc số nguyên không âm; severity chỉ số nguyên không âm.
- Từ chối duplicate keys, NaN/Infinity, UTF-8/surrogate không hợp lệ, kể cả unknown fields.
- Loader chỉ đọc tối đa limit+1 byte, không sửa file. Không cung cấp path sandbox;
  caller chọn file được phép đọc, ưu tiên regular file cục bộ.
- `WazuhParseError.diagnostic`: code, field path từ allowlist, record index và
  line/column khi có. Không nhúng message, command line, giá trị lỗi hoặc đường dẫn file.
  Đừng bật debugger locals/ghi raw input vào log; exception redaction không bảo vệ chúng.

CSV **có thể bổ sung sau**, nhưng phải có hợp đồng cột, kiểu, timezone và quy tắc
giữ raw riêng. CSV Export Formatted hiện tại không tự động tương đương JSON đầy đủ.
Linux, PowerShell 4104, Sysmon và nhiều record chưa được hỗ trợ trong mốc này.

## Bạn cần chuẩn bị gì tiếp theo?

1. Chạy test ở đúng worktree, gửi phần tổng kết test và `pip check`.
2. Đối chiếu các trường trong bảng với bản JSON gốc trên máy bạn. Không sửa fixture để
   làm test pass; báo lại nếu mapping khác ý nghĩa thực tế.
3. Nếu sẵn có, chuẩn bị 1–2 JSON đầy đủ của **loại event khác** bạn muốn dùng cho scenario
   tiếp theo, kèm máy phát sinh, thao tác đã làm, khoảng thời gian/timezone và direct/WEF.
   Không cần tạo hành vi tấn công hay tác động hệ thống chỉ để có mẫu.
4. Giữ log chưa ẩn danh ở máy bạn/ngoài Git, loại secrets/token/password; thống nhất
   cách ẩn danh trước khi đưa vào fixture công khai. Không gửi thông tin đăng nhập SIEM.

Sau đối chiếu: review phạm vi Issue #3 → PR nhỏ → merge khi được duyệt. Chọn profile
tiếp theo theo scenario thực tế; chưa nhảy sang live SIEM hoặc dashboard.

## Khung làm việc tối 08/09 đến 00:00

Đây là khung dự kiến, có thể hoàn thành sớm; không tự chạy lab hoặc chờ tới đúng giờ.

| Khoảng giờ (UTC+7) | Việc |
|---|---|
| 21:40–22:15 | Merge v2 đã duyệt, triển khai parser 4688 và kiểm thử |
| 22:15–22:45 | Review độc lập, kiểm tra wheel, sửa lỗi nếu có |
| 22:45–23:20 | Bạn chạy đối chiếu và kiểm tra mapping trên log gốc |
| 23:20–00:00 | Chốt review/PR nếu đủ bằng chứng; chọn mẫu/profile kế tiếp |

Nếu chưa có mẫu bổ sung vẫn hoàn thành mốc parser 4688 và tài liệu. Không tuyên bố
toàn bộ Issue #3/scenario end-to-end đã xong chỉ vì unit tests pass.
