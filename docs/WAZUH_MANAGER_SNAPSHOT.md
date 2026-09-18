# Wazuh manager snapshot — adapter bytes offline

Phần đầu của export/evaluation Issue #12. API này nhận **bytes snapshot đã thu**,
không tự đọc file trên manager, không gọi SSH/API và không chạy payload. Đầu ra
là canonical events từ hai parser Windows hiện có, documents dẫn xuất và ledger.

**Chưa phải công cụ hoàn chỉnh cho A/B/C:** chưa có file bundle writer, study
profile lab đã khóa, rule-state verification hoặc attestation workflow. Không
đổi nhãn rehearsal thành baseline và không dùng adapter để tuyên bố Regression
Passed. Snapshot chứa raw evidence phải giữ riêng ngoài Git.

## API

```python
from aegis_verify.connectors.wazuh.manager_snapshot import (
    ManagerSnapshot,
    ManagerSnapshotScope,
    ManagerSnapshotError,
    parse_manager_snapshots,
)
```

`ManagerSnapshot(source_label, raw, sha256)` chứa nhãn nguồn ổn định, bytes và
SHA-256 đã pin của toàn snapshot. `parse_manager_snapshots` chỉ nhận tuple gồm
những objects này, không tự đoán input là filename hoặc JSON string.

`ManagerSnapshotScope(agent_id, hostname, environment_id, start, end, ingested_at)`
chọn agent/host và cửa sổ Windows event time **đóng ở cả hai đầu**. Adapter này
chỉ dành cho collection trực tiếp trên endpoint; caller phải xác nhận mode đó.
Không dùng nó cho WEF/forwarded rồi xem agent ID là asset nguồn. Thời gian có
offset xác định và tối đa 9 chữ số thập phân; không fallback từ systemTime sang
received_at hoặc lấy giờ hiện tại.

Scope có thể dài khác 120 giây ở API vendor tổng quát. Quy tắc chính xác120s của
SCN-001 thuộc lớp study/run packaging tiếp theo, không được giả là adapter đã kiểm.

Các trường output:

- `result.documents`: `.raw` là bytes wrapper, `.source_ref`, `.parser` và
  `.telemetry` là `WindowsTelemetryResult` thực từ parser. Canonical ở
  `.telemetry.event`, provenance vendor ở `.telemetry.provenance`.
- `result.ledger`: mỗi dòng có nhãn/hash snapshot, `line`, `byte_offset` (0-based),
  `byte_length`, `line_sha256`, `bom_removed`, `disposition`, `reason`;
  selected entries có `document_source_ref`, `document_sha256` và source record ID
  nếu nguồn có. Blank/excluded không thành event.
- `result.snapshots`: metadata nhãn/hash/số bytes/số physical lines của từng file.
- `result.collection_assurance`: luôn `unknown`, kể cả khi không có lỗi và đã
  đọc đủ mọi file caller đưa vào.

Dataclasses bất biến, nhưng **input vẫn được kiểm lại tại API boundary**.
Không coi object tự dựng hoặc hash caller khai là xác thực nguồn.

## Ba lớp hash không được đánh đồng

1. Snapshot SHA-256: toàn bytes file, gồm BOM/newlines/whitespace.
2. Line SHA-256: toàn physical line, gồm LF/CRLF nếu có, BOM nếu ở dòng đầu.
3. Document SHA-256: bytes `{"_source":` + body gốc của dòng + `}`.

Chỉ tách line ending và BOM đầu file khỏi body khi wrapping. Không serialize
lại JSON object nên giữ nguyên numeric lexemes, unknown fields, whitespace
trong body và text escaped. Không tạo `_index`, `_id` hoặc metadata nguồn giả.

Canonical hash và evidence ID tính trên **document bytes**, không phải line
hash. Reference có dạng `source-label-line-N#record=1`; ledger nối về đúng
snapshot hash + line/byte range. Nhãn nguồn chỉ nhận ASCII safe label dài1–116
ký tự để còn chỗ suffix; phải giữ nhãn ổn định khi chuyển snapshot qua máy khác.
Đổi thứ tự input files không đổi evidence ID khi label/bytes/environment giữ nguyên.

Không tự chuẩn hóa decoded path hoặc script text. Các giới hạn mất thông tin
trong [native field profile](SCN001_EVENTCHANNEL_PROFILE.md) vẫn còn nguyên.

## Scope và từ chối dữ liệu

Không export-filter theo rule, severity, marker, filename, command line hoặc
PID. Generic alerts và PID khác vẫn được đưa vào nếu thuộc scope host/provider/
event/time. Vì vậy phần run-binding review tiếp theo vẫn cần phát hiện PID reuse,
scope chứa nhiều launch hoặc log không thuộc child của lượt chạy.

- Selected: native decoder `windows_eventchannel`, provider/channel/EventID phù
  hợp với parser Sysmon1 hoặc PowerShell4104 và thuộc cửa sổ nguồn.
- Excluded: đủ metadata hợp lệ chứng minh `outside_agent`, `outside_host`,
  `outside_event` hoặc `outside_window`; giữ tọa độ trong ledger.
- Bookkeeping: dòng whitespace-only, reason `blank_line`.
- Không phân loại chắc được: `unclassifiable_record`, không tự xem ngoài scope.

Non-Windows chỉ được bỏ khi decoder không phải windows_eventchannel và không có
data.win; nếu có data.win nhưng decoder mâu thuẫn thì dừng. Wrong channel trong
record được chọn khiến parser error, không trở thành successful skip.

JSON malformed, duplicate keys, root array/search-hit wrapper, NaN/Infinity,
UTF-8/Unicode sai, numeric/depth/node limits gây lỗi toàn snapshot set. BOM chỉ
cho phép ở đầu mỗi snapshot. Dòng cuối không newline được chấp nhận nếu JSON
hoàn chỉnh; điều đó không chứng minh export đã đầy đủ.

Không dedup âm thầm: labels/hashes snapshot trùng, body bytes trùng (bỏ line
ending/BOM) hoặc source record ID trùng trong cùng manager đều bị từ chối.
Manager name thiếu dùng cùng miền identity chưa xác định, không đoán tên máy.
Record ID thiếu vẫn null; nếu các record không có ID và khác bytes thì adapter
không thể tự chứng minh chúng là một event logic. Reviewer phải xử lý giới hạn đó.

4104 thiếu text/counters hoặc nhiều mảnh làm lỗi parser; không bỏ record để đạt
report. Các optional canonical fields khác vẫn null nếu thiếu, không điền từ
execution manifest/scope. Duplicate checks cũng áp dụng cho excluded records.

## Giới hạn và diagnostics

32 snapshots; 32 MiB/file; 64 MiB tổng; 20.000 physical lines tổng; 100 selected
documents. Wrapped document tối đa256KiB và giữ giới hạn decoder Wazuh depth20,
10.000 nodes, numeric token128. Wrapper tăng một tầng JSON; record ở giới hạn
depth gốc có thể bị parser từ chối sau wrapping. Không cắt input cho vừa limit.

Adapter không serialize ledger ra file. Bundle writer tiếp theo phải kiểm thêm
ledger/config 1MiB/32depth/50.000nodes, safe paths và snapshot consistency trên
filesystem. Một in-memory result không chứng minh đã qua các kiểm tra đó.

`ManagerSnapshotError.diagnostic` gồm code, snapshot_index (0-based), line
(1-based) và parser_code nếu có. Codes:

`invalid_input`, `invalid_context`, `hash_mismatch`, `invalid_record`,
`unclassifiable_record`, `parser_error`, `duplicate_snapshot`, `duplicate_record`,
`resource_limit`.

Không echo raw values, command/script text hoặc absolute paths trong exception.
API không trả result từng phần nếu record cuối bị lỗi; caller không nên bắt lỗi
rồi đánh giá những records tự giữ trước đó. Không dùng count để tự tạo
`complete_for_scope`.

## Kiểm chứng trên máy phát triển

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
$aegisTestTemp = 'build/pytest-snapshot-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_wazuh_manager_snapshot.py -q -p no:cacheprovider --basetemp $aegisTestTemp
```

Tests chỉ dùng synthetic: byte preservation, coordinates, strict scope, no
verdict filtering, unknown/null/errors, duplicate/limits và integration với
`python -m aegis_verify validate`. Integration chuyển hai wrapped documents vào
fixture bundle temporary, dùng profile synthetic đã có và nhận Inconclusive
do collection chưa xác nhận. Không có lab dependency hoặc payload execution.

Luôn dùng basetemp mới trong build để không đụng thư mục pytest tạm cũ của
Windows. Full checks, RED/GREEN và giới hạn review xem
[checkpoint](ISSUE_12_SAFE_DEMO_CHECKPOINT.md).
