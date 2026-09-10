# Cowrie Wazuh fixture parser — Issue #6, hướng A

Parser offline hướng A đã có trên nhánh `codex/issue-6-cowrie-fixture-parser`.
Nó nhận đúng một Wazuh search-hit chứa Cowrie data, phát một Canonical Event v2
và provenance bất biến. Không cần live Wazuh/Cowrie, không thực thi scenario,
command hoặc URL. Review kỹ thuật toàn nhánh `664880d..70477ee` đã hoàn tất,
không có finding cần hành động. Human/lab review vẫn còn chờ; chưa push, merge,
đóng Issue #6 hoặc kết luận pass/fail security.

## Chạy trên Windows

Mở PowerShell trong worktree đã có `.venv` editable:

```powershell
Set-Location 'I:/AEGIS-VERIFY/.worktrees/issue-6-cowrie-fixture-parser'
& '.venv/Scripts/python.exe' -c "import aegis_verify.connectors.cowrie as c; print(c.__file__)"
$aegisCowrieTemp = 'build/pytest-cowrie-' + [guid]::NewGuid().ToString('N')
& '.venv/Scripts/python.exe' -m pytest backend/tests/test_cowrie_fixtures.py -q -p no:cacheprovider --basetemp $aegisCowrieTemp
& '.venv/Scripts/python.exe' -m pytest backend/tests -q -p no:cacheprovider --basetemp ($aegisCowrieTemp + '-all')
& '.venv/Scripts/python.exe' -m pip check
git diff --check
```

Import đầu tiên phải trỏ tới `connectors/cowrie/__init__.py` trong worktree.
Các lệnh trên chỉ đọc fixture sanitized; không chạy nội dung event.

## API public và ví dụ an toàn

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

`CowrieParseResult` chứa `event: CanonicalEventV2` và
`provenance: CowrieProvenance`. Ví dụ sau lấy context/source_ref từ manifest,
kiểm hash rồi chỉ in các field audit an toàn. `ingested_at` là thời điểm replay
offline do manifest chọn, không phải thời điểm acquisition đã đo.

```powershell
@'
import json
from hashlib import sha256
from pathlib import Path
from aegis_verify.connectors.cowrie import load_cowrie_wazuh_document

folder = Path("tests/fixtures/cowrie")
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
entry = next(e for e in manifest["fixtures"]
             if e["file"] == "login-success-missing-user.sanitized.json")
path = folder / entry["file"]
raw = path.read_bytes()
assert sha256(raw).hexdigest() == entry["derivative_sha256"]
context = dict(manifest["parser_context"], source_ref=entry["source_ref"])
result = load_cowrie_wazuh_document(path, **context)
assert result.event.username is None
print(result.provenance.source_event_type, result.event.event_action)
print(result.event.timestamp.isoformat(), result.event.username)
print(result.provenance.authentication_outcome)
print(result.event.event_id)
print(result.event.raw_event_ref)
print(result.provenance.session_key)
'@ | & '.venv/Scripts/python.exe' -
```

Kết quả cho biết `cowrie.login.success login`, timestamp nguồn đủ sáu chữ số,
username `None`, outcome `success` ở provenance, event ID bắt đầu bằng
`cowrie:wazuh-evidence-v1:`, raw reference có `#L1-L58`, và session key bắt đầu
bằng `cowrie:session-v1:`. Không in `full_log`, command hay dữ liệu gốc.

Đường lỗi cũng có thể kiểm bằng payload nhân tạo không chứa dữ liệu riêng tư:

```powershell
@'
from aegis_verify.connectors.cowrie import CowrieParseError, parse_cowrie_wazuh_document

try:
    parse_cowrie_wazuh_document(
        b"[]", source_ref="synthetic-invalid.json", environment_id="fixture-lab",
        sensor_id="cowrie-fixture-01", ingested_at="2026-09-11T00:00:00Z",
    )
except CowrieParseError as error:
    print(error.code, error.record_index)
'@ | & '.venv/Scripts/python.exe' -
```

Kết quả là `invalid_root 1`; lỗi không echo input.

## Profile, mapping và null

Đầu vào phải là UTF-8 JSON object dạng Wazuh search-hit, có `_source.data`,
`_source.rule.groups` là array string chứa `cowrie`, và `data.eventid` thuộc sáu
loại sau:

| Cowrie event | canonical `event_action` | Provenance |
| --- | --- | --- |
| `cowrie.session.params` | `observed` | event type, arch, session |
| `cowrie.session.connect` | `observed` | event type, session |
| `cowrie.session.closed` | `observed` | event type, session |
| `cowrie.login.success` | `login` | `authentication_outcome=success`, session |
| `cowrie.login.failed` | `login` | `authentication_outcome=failure`, session |
| `cowrie.command.input` | `command` | event type, session |

Mapping chỉ lấy fact từ `_source.data`. Timestamp nguồn giữ 0–9 chữ số phần
giây và chuẩn hóa về UTC; không fallback timestamp Wazuh. Network fields map khi
có; protocol chỉ nhận `ssh`/`telnet`. Username chỉ map cho login, input chỉ map
cho command. Trường tùy chọn vắng hoặc JSON null giữ canonical `null`; present
sai kiểu vẫn là lỗi. Derivative `login-success-missing-user` chứng minh username
vắng trong data vẫn `null` dù bản sao `full_log` có chuỗi rỗng.

`source_record_id` là `_source.id`. Wazuh rule ID/level, collector metadata,
source sensor/uuid, arch, session và authentication outcome nằm trong provenance.
Không chuyển Wazuh alert level thành severity/verdict; asset/process/file/hash,
signature, technique và các field không có nguồn đều `null`.

## Giới hạn và lỗi an toàn

Mỗi API xử lý đúng một document, không nhận `hits.hits` array, CSV, payload Cowrie
trần hoặc JSONL native. Giới hạn là 256 KiB, nesting depth 20, 10.000 JSON nodes
và 128 ký tự cho numeric token. Loader đọc tối đa limit+1. `source_ref` và
`sensor_id` phải khớp `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`;
`environment_id` không trắng và tối đa 128 UTF-8 bytes; `ingested_at` bắt buộc có
timezone.

Lỗi raise `CowrieParseError` với vocabulary cố định như `invalid_json`,
`invalid_encoding`, `duplicate_key`, `input_too_large`, `invalid_field`,
`missing_field`, `unsupported_profile`, `invalid_event_time`, `invalid_context`
hoặc `io_error`. Diagnostic có `code`, `field_path`, `record_index`, `line` và
`column` khi xác định được, không echo raw value/path/credential. Không có partial
result: một document trả một result hoặc raise.

## Evidence và session identity

`raw_event_hash` là SHA-256 của toàn bộ bytes search-hit, kể BOM/newline.
`raw_event_ref = source_ref + #L1-L<n>` với `n` là số dòng vật lý. Fixture dùng
`source_ref = cowrie-` cộng derivative SHA-256, dài 71 ký tự.

Event ID là prefix `cowrie:wazuh-evidence-v1:` cộng SHA-256 của compact JSON array
(UTF-8, `ensure_ascii=True`):

```text
["cowrie-wazuh-evidence-v1", environment_id, sensor_id,
 source_ref, 1, raw_event_hash]
```

Session key là prefix `cowrie:session-v1:` cộng SHA-256 của:

```text
["cowrie-session-v1", environment_id, sensor_id, session]
```

Vì vậy `ingested_at` không đổi evidence/session identity. Session thiếu/null giữ
`session_key=null`; session rỗng bị từ chối. Key chỉ ổn định trong namespace
environment/sensor do caller xác nhận, không chứng minh session globally unique.

## Fixture và riêng tư

Manifest ghi 9 derivative thực tế, đủ sáu event types và tám session khác nhau.
Chỉ hai command (nguồn 5/6) là một cặp cùng session; không có full lifecycle
connect/login/command/closed cùng session trong evidence thực. Unit tests có
**một chuỗi synthetic bốn record** để kiểm contract correlation; đó không phải
lab validation. Không ghép tám session thật thành chuỗi giả.

Các derivative dùng alias `fixture-*`, dải tài liệu `192.0.2.0/24`, host URL
`example.invalid` và fixture-only path. Password/message trùng lặp đã bị loại ở
cả data/full_log; không lưu reverse map. Hai lexical token `full_log.duration`
được giữ nguyên và test bằng `Decimal`. Original SHA-256 và derivative SHA-256
được tách rõ; runtime hash luôn là derivative hash. Fixture preparation là bước
sanitize ngoài runtime — parser không tự redaction dữ liệu production.

## Đối chiếu acceptance Issue #6

| Acceptance | Bằng chứng hướng A | Giới hạn |
| --- | --- | --- |
| Canonical hợp lệ cho connection/login/command | Unit mapping và 9 fixture derivatives bao phủ sáu types | `session.params/closed` là `observed` |
| Giữ timestamp, peer, command, login result, session | Canonical giữ field có sẵn; provenance giữ outcome/session | Canonical hiện không có outcome/session |
| Cross-record session identity | ID/session tests; cặp command thật cùng key nhưng event ID khác | Full lifecycle chỉ là một sequence synthetic |
| Missing fields là null | Fixture login success thiếu username và unit boundary tests | Không fallback từ `full_log` |
| Stable evidence ID và line reference | Literal digest/hash/ref tests trên mọi derivative | `source_ref` là caller/manifest contract |
| Session sequence, missing, malformed tests | Fixture integration và unit decoder/mapping/error tests | Synthetic tests không phải lab evidence |
| Không live dependency; existing tests pass | File/bytes API offline và lệnh pytest/pip check ở trên | Human/lab comparison vẫn chờ |
| Native Cowrie input | Chưa có trong hướng A | Cần profile B JSONL riêng trước khi coi mục này hoàn tất |

## Bằng chứng kiểm tra hiện tại

Fixture/runtime handoff ở commit `8978ef5`. Focused Cowrie parser, mapping và
fixture tests: **193 passed in 0.61s**. Full suite editable: **1334 passed in
5.22s**; `pip check` sạch. Audit read-only đối chiếu đủ 9 nguồn/derivative xác
nhận hash nguồn không đổi, phép sanitize đúng allowlist, LF/duration lexical
token được giữ và không tạo reverse alias map.

Wheel cuối có SHA-256
`653f6c8228f8ba60fc426a708b710480b978c7d307454973bb24886eb6662fde`.
Sau khi cài wheel với test extra vào venv mới, `python -I` xác nhận package và
Cowrie import từ `venv-final/Lib/site-packages`; cả hai public APIs callable.
Full suite từ wheel: **1334 passed in 5.86s**; `pip check` sạch. Đây là kiểm tra
local/fixture, không thay cho human hoặc lab validation.

## Ranh giới kết luận

Validation engine hiện chỉ nhận canonical event, nên chưa đọc được
`provenance.authentication_outcome` hoặc `session_key`. Parser có thể nói log
nguồn ghi login success/failure và hai record chia sẻ source session; nó **không**
được tự kết luận scenario Detected/Prevented/Missing telemetry/False negative hay
Pass/Fail. Mọi kết luận security sau này phải do engine đánh giá theo ground truth
đã review và tham chiếu evidence ID.

Hướng A chỉ chứng minh offline Wazuh-exported search-hit, không chứng minh reader
native `cowrie.json` JSONL, coverage toàn session, live collection, scenario
execution hoặc detection correctness. Cần review code/evidence và human lab
validation trước quyết định merge hoặc trạng thái Issue #6.
