# pfSense filterlog fixture parser — Issue #5

Parser offline đã có trên nhánh `codex/issue-5-pfsense-fixture-parser`.
Profile V0 đọc BSD local filterlog, chuẩn hóa IPv4 TCP/UDP `pass`/`block` thành
Canonical Event v2. Không cần chạy lệnh nào trên pfSense lúc này.
Review cuối toàn nhánh và đối chiếu human/lab còn chờ; chưa push, PR, đóng issue
hoặc merge. Thiết kế đã duyệt nằm trong
[design](superpowers/specs/2026-09-10-pfsense-filterlog-design.md).

## Chạy trên Windows

Worktree đã có `.venv` riêng trỏ đúng code nhánh này; không cần Python/pip hệ
thống, activate venv hoặc cài lại. Mở PowerShell trên máy chứa AEGIS và chạy:

```powershell
Set-Location 'I:/AEGIS-VERIFY/.worktrees/issue-5-pfsense-fixture-parser'
& '.venv/Scripts/python.exe' -c "import aegis_verify.connectors.pfsense as p; print(p.__file__)"
New-Item -ItemType Directory -Force -Path build | Out-Null
$aegisTestTemp = 'build/pytest-issue5-' + [guid]::NewGuid().ToString('N')
& '.venv/Scripts/python.exe' -m pytest backend/tests -q -p no:cacheprovider --basetemp $aegisTestTemp
& '.venv/Scripts/python.exe' -m pip check
git diff --check
```

Import cần trỏ tới `connectors/pfsense/__init__.py` trong worktree trên. Dùng thư
mục test mới mỗi lượt; tạo `build` trước để tránh lỗi setup thư mục cha. Kết quả
hiện tại là 1.141 tests; hãy gửi phần tổng kết test và `pip check` để đối chiếu.

## API công khai

Import từ `aegis_verify.connectors.pfsense`:

```python
parse_pfsense_filterlog(
    raw: bytes, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp, source_year: int,
    source_utc_offset: str,
) -> tuple[PfSenseRecord, ...]

iter_pfsense_filterlog_file(
    path: str | Path, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp, source_year: int,
    source_utc_offset: str,
) -> Iterator[PfSenseRecord]
```

Đây là chữ ký API, không phải đoạn code để chạy. `PfSenseParseError`,
`PfSenseRecord`, `PfSenseProvenance`, `PfSenseContext`, `PfSenseDiagnostic`,
`make_context` và `source_timestamp` cũng được export. `datetime` thuộc datetime,
`Path` thuộc pathlib, `Iterator` thuộc collections.abc, `PreciseTimestamp` thuộc
`aegis_verify.models`.

Mọi context là bắt buộc, kể cả input rỗng. `source_ref` và `sensor_id` là nhãn
ASCII theo `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; chúng không phải URL/path.
`environment_id` là chuỗi UTF-8 tối đa 128 bytes, không trắng sau strip; giá trị
hợp lệ được giữ nguyên. `ingested_at` phải là timestamp có timezone hợp lệ;
caller cung cấp thời điểm ingest, parser không đọc đồng hồ để tự điền.

## Ví dụ có thể chạy: hai API trên cùng derivative

Chạy tiếp trong PowerShell tại worktree. Ví dụ đọc context và immutable
`source_ref` từ manifest, kiểm tra hash trước khi parse và chỉ in dữ liệu audit
an toàn. Timestamp ingest trong manifest là bối cảnh replay fixture.

```powershell
@'
import json
from hashlib import sha256
from pathlib import Path
from aegis_verify.connectors.pfsense import (
    iter_pfsense_filterlog_file, parse_pfsense_filterlog,
)

folder = Path("tests/fixtures/pfsense")
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
entry = next(e for e in manifest["fixtures"] if e["file"] == "udp-block.sanitized.log")
path = folder / entry["file"]
raw = path.read_bytes()
assert sha256(raw).hexdigest() == entry["derivative_sha256"]
context = dict(manifest["parser_context"], source_ref=entry["source_ref"])
records = parse_pfsense_filterlog(raw, **context)
assert records == tuple(iter_pfsense_filterlog_file(path, **context))
record, = records
assert record.status == "parsed" and record.event is not None
assert record.event.event_action == "blocked"
assert record.provenance.nat_context is None
print(record.status, record.event.event_action)
print(record.event.event_id)
print(record.event.raw_event_ref)
print(record.provenance.warnings)
'@ | & '.venv/Scripts/python.exe' -
```

Kết quả gồm `parsed blocked`, ID có prefix `pfsense:filterlog-evidence-v1:`,
reference kết thúc `#L1-L1` và warning `year_and_offset_supplied_by_caller`.
Derivative này có một dòng; dòng nguồn gốc là 2, chỉ được lưu trong manifest.
Chỉ `record.event` được truyền cho engine; provenance phục vụ audit.

## Kết quả, skip và import chưa hoàn tất

`PfSenseRecord` bất biến, từ chối trường dư và kiểm tra tổ hợp trường:

| Outcome | Ý nghĩa |
| --- | --- |
| `parsed` | Có event v2, `reason=None`, ID/hash/ref khớp provenance |
| `skipped` | `event=None`, provenance `event_id=None`, có reason và hash/ref/dòng |
| `PfSenseParseError` | Input/context/mapping/I/O không hợp lệ; không phải skip |

Bốn skip reasons là `blank_line`, `rotation_notice`, `unsupported_ip_version`,
`unsupported_protocol`. Skip ngoài profile chỉ phân loại sau khi header/common
fields hợp lệ; không xác nhận payload giao thức đó đúng. Input không nhận diện
hoặc TCP/UDP hỏng gây lỗi. File rỗng trả 0 outcomes; dòng trống vẫn được đếm.

Bytes API trả cả tuple hoặc raise, không trả phần thành công. File API đọc lazily;
lỗi có thể xảy ra khi bắt đầu hoặc sau nhiều lần yield. Chỉ khi iterator hết
bình thường mới được đánh dấu hoàn tất. Lỗi muộn hoặc consumer dừng sớm nghĩa là
toàn lần nhập **INCOMPLETE**; prefix đã nhận không đủ để kết luận coverage.
Nếu dừng sớm, gọi `close()` để giải phóng file; đóng file không có nghĩa import
thành công. Ví dụ sau kiểm tra đường lỗi bằng derivative giữ nguyên header hỏng:

```powershell
@'
import json
from collections import Counter
from pathlib import Path
from aegis_verify.connectors.pfsense import PfSenseParseError, iter_pfsense_filterlog_file

folder = Path("tests/fixtures/pfsense")
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
entry = next(e for e in manifest["fixtures"] if e["file"] == "malformed-header.sanitized.log")
context = dict(manifest["parser_context"], source_ref=entry["source_ref"])
stream = iter_pfsense_filterlog_file(folder / entry["file"], **context)
complete = False
counts = Counter()
try:
    for record in stream:
        counts[record.reason if record.status == "skipped" else "parsed"] += 1
    complete = True
except PfSenseParseError as error:
    print("INCOMPLETE", error.code, "line", error.line)
    assert error.code == "malformed_header" and error.line == 1
finally:
    stream.close()
assert not complete and not counts
'@ | & '.venv/Scripts/python.exe' -
```

Kết quả: `INCOMPLETE malformed_header line 1`. Lỗi an toàn cung cấp `code`,
`field_path`, `line`, `record_index` và `diagnostic`; lỗi trước đọc có thể chưa
có line. Không log raw input hay exception I/O gốc. Khi lưu kết quả ứng dụng,
cần giữ trạng thái lần nhập cùng outcomes và skip counts, chỉ công bố hoàn tất
sau exhaustion; parser không tự commit kết quả hay đưa ra security verdict.

## Profile, null và thời gian

Hỗ trợ UTF-8 strict, một bản ghi mỗi dòng LF/CRLF hoặc dòng cuối không newline;
BOM chỉ ở đầu file. Header BSD có hostname và `filterlog`/`filterlog[PID]`.
IPv4 TCP cần 29 cột, UDP 23 cột, protocol ID/text nhất quán, action `pass`/`block`,
direction `in`/`out`. CSV giữ cột rỗng nhưng không hỗ trợ quoting kiểu spreadsheet.
Không nhận RFC5424, payload trần, binary clog, dashboard CSV, live syslog/SSH.
IPv6 và giao thức khác như IGMP được skip khi đủ cấu trúc phân loại.

Giới hạn gồm 256 KiB mỗi dòng (kể BOM/newline), 32 MiB mỗi file, 100.000 dòng vật
lý tính cả skips và 128 ký tự mỗi token số trước đổi int. Dữ liệu UTF-8/BOM lỗi,
cột thiếu/thừa, action/direction lạ, IP/port/số sai hoặc vượt giới hạn bị từ chối.
Bytes API preflight kích thước/số dòng; file API kiểm tra tăng dần khi đọc.

`pass` → `allowed`, `block` → `blocked`; protocol → `tcp`/`udp`, tracker →
`rule_id` dạng chuỗi. Không fallback sang rule number; hostname là firewall ghi
log. Trường tùy chọn rỗng thành `null`, giữ port 0; thiếu cả cột là lỗi.
`source_record_id`, `asset_id`, username, severity, signature, techniques và
process/file fields không có trong nguồn đều `null`. PID không phải event ID.
Interface/direction/reason/rule number/subrule/anchor/tracker và protocol nguồn
nằm trong provenance. `nat_context=null`; không suy NAT/asset từ IP/interface.
Các trường nguồn còn lại được giữ trong artifact mà raw reference trỏ tới;
parser không nhúng raw payload vào canonical và không tự tải reference.

BSD timestamp thiếu năm/offset. `source_year` phải là int 1..9999 (không bool),
`source_utc_offset` là `+/-HH:MM` hợp lệ (00..23 giờ, 00..59 phút), cấm `-00:00`.
Parser dùng tháng tiếng Anh cố định, kiểm tra ngày và chuyển UTC với độ chính
xác giây; không suy năm từ máy chạy, tên file, mtime hoặc ingestion time.
File qua năm/đổi offset cần chia thành artifacts riêng có manifest bảo toàn
lineage, caller cung cấp context từng phần; parser không đoán rollover/DST.

Mẫu này dùng **giả định context tường minh 2026 / +07:00**. Căn cứ là đối chiếu
đồng hồ nguồn `2026-09-10T21:02:05+0700`, mtime nguồn `21:01:57` và log cuối
`Sep 10 21:01:41`. Đây không phải năm/offset có sẵn trong log, cũng không chứng
minh đồng hồ lịch sử đúng. Provenance giữ context,
`timestamp_basis="bsd_syslog_with_caller_context"` và warning
`year_and_offset_supplied_by_caller` cho outcomes có timestamp nguồn. Dòng trống
không có timestamp basis/warning giả.

## Identity và nguồn chứng cứ

`raw_event_hash` là SHA-256 của đúng bytes dòng, kể newline/BOM.
`raw_event_ref = source_ref + "#L<n>-L<n>"`, n là dòng vật lý bắt đầu từ 1,
kể cả skip. Caller gắn source_ref với artifact bất biến trong manifest.
Event ID có prefix `pfsense:filterlog-evidence-v1:` và digest SHA-256 của JSON
array UTF-8 (`ensure_ascii=True`, `separators=(",", ":")`):

```text
["pfsense-filterlog-evidence-v1", environment_id, sensor_id, source_ref,
 line_index, raw_line_hash, source_year, source_utc_offset]
```

Cùng bytes/context cho cùng ID. Đổi dòng, artifact, sensor, môi trường hoặc
context thời gian làm đổi ID; riêng `ingested_at` không đổi ID. Đổi năm/offset
cần lần nhập mới, không ghi đè evidence dưới ID cũ.

[Manifest](../tests/fixtures/pfsense/manifest.json) ghi 7 derivatives đã sanitize
từ các dòng gốc 1, 2, 38, 39, 45, 726 và 296. Review độc lập đã đối chiếu phép
thay alias, exact bytes, SHA-256 và Git object bytes. Hostname/PID/tracker,
4 interface aliases và địa chỉ được thay nhất quán; không lưu reverse map.
Alias không giữ nghĩa multicast, routing, scope hay NAT. Timestamp, action,
empty cells, TCP sequence range, IGMP trailing space và cả header hỏng được giữ.
Không đổi block thật thành pass. Hash runtime là hash derivative, không tráo hash
nguồn gốc. Log gốc ở ngoài Git và không bị sửa.

## Bằng chứng kiểm tra và việc còn chờ

Runtime cuối thay đổi tại `2b10121`; fixtures/tests tại `d4742ca`.
Task 4 full suite: **1.141 passed in 3.29s**. Task 5 kiểm tra lại trong `.venv`
với fresh basetemp và tắt pytest cache: **1.141 passed in 3.35s**, `pip check`
sạch. Hai ví dụ PowerShell ở trên đã chạy đúng kết quả mô tả; chữ ký API và
editable import path đã đối chiếu trực tiếp. Diff tài liệu được kiểm tra whitespace,
phạm vi và dữ liệu nhạy cảm trước commit; review cuối toàn nhánh vẫn còn chờ.
Task 5 đã build wheel bằng default
build isolation vào thư mục mới, cài `wheel[test]` noneditable trong fresh venv.
Wheel SHA-256:
`71ac4d147e779d5715af09e8918c86615ab60a030434310d080f5ab5d628e058`.
Kiểm tra `python -I` từ ngoài checkout xác nhận import ở site-packages và hai
API công khai tồn tại. Full suite trên wheel: **1.141 passed in 3.54s**;
`pip check` không có dependency hỏng. Runtime không đổi sau khi build.
Thư mục kiểm tra local: `build/verification-issue5-27b4bdb8ca22497f95ad8cfa1cc855a7/`
(wheel ở `wheels`, môi trường ở `venv`); đây là scratch ignored, không cần commit.

File nguồn có 245.311 bytes / 1.592 dòng; SHA-256 trước/sau audit không đổi:
`7c32779ba3825a2183b5eeae182af1ceb96d240b1f299cbb0d14f35f6de30f0c`.
Audit từng dòng độc lập cho **1.402 parsed (34 TCP, 1.368 UDP), 189 skipped
(69 protocol, 119 IPv6, 1 rotation), 1 malformed_header tại dòng 296**.
Atomic whole-file API raise tại dòng 296; stream yield 295 outcomes rồi cùng lỗi.
Prefix đó gồm 114 parsed, 1 rotation, 69 protocol, 111 IPv6 và là **INCOMPLETE**.
Không sửa/cắt header hỏng để nhập thành công; audit từng dòng không phải lần nhập
toàn file thành công.

Chưa có pass lab record; pass chỉ được kiểm thử synthetic. `blocked` là fact từ
firewall, chưa chứng minh scenario `Prevented`. Mọi kết luận security sau này
phải tham chiếu evidence IDs và do engine đánh giá theo ground truth đã review.
Lịch sử đồng hồ chưa được xác minh. Còn chờ review cuối toàn nhánh, người dùng
chạy đối chiếu Windows và human/lab validation trước quyết định merge;
không thay ground truth hoặc mở rộng protocol/syslog trong Issue #5.
