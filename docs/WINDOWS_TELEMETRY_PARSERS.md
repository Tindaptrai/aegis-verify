# Sysmon 1 và PowerShell 4104 qua Wazuh — hướng A

## Phạm vi và nơi chạy

Đây là phần mở rộng offline chuẩn bị cho Issue #12, **không phải hoàn thành demo
Gap → Fix → Re-test**. Không sửa SCN-001, canonical v1/v2, semantics engine hoặc
comparison. Parser 4688 của Issue #3 vẫn giữ nguyên API và giới hạn đã chốt.

| Thành phần | Nơi chạy | Việc thực hiện |
| --- | --- | --- |
| Parser, pytest, CLI AEGIS | Máy phát triển chứa repo, Python >=3.11 trong `.venv` | Đọc fixture, chuẩn hóa, đánh giá, so sánh offline |
| Sysmon/PowerShell/Wazuh agent | Máy Windows lab được phép kiểm thử | Ghi và chuyển telemetry; parser không tự cài/cấu hình chúng |
| Wazuh server/dashboard | Hệ thống Wazuh hiện có | Nhận log, áp dụng rule, xuất JSON theo quy trình thu thập |

Không có SSH, API live, dashboard mới, tải file hay thực thi PowerShell trong parser.
Kiểm thử triển khai hiện tại chạy trên Windows/Python 3.13; chưa xác nhận Linux
hoặc các phiên bản Python khác bằng lần chạy này.

## Hai API mới

```python
from aegis_verify.connectors.wazuh import (
    parse_wazuh_sysmon1_document,
    parse_wazuh_powershell4104_document,
    WazuhParseError,
)
```

Cả hai nhận `raw: bytes` là **một JSON Wazuh search-hit có `_source`**, cùng các
keyword bắt buộc `source_ref`, `environment_id`, `ingested_at`, `collection_mode`.
Trả `WindowsTelemetryResult(event=CanonicalEventV2, provenance=...)` bất biến.
Không có API tự đoán profile hoặc loader file riêng mới; CLI dùng bộ đọc file
an toàn hiện có để kiểm tra path, loại file, kích thước và hash trước dispatch.

| Khóa trong `inputs.json` | Provider bắt buộc | Channel bắt buộc | Event ID |
| --- | --- | --- | --- |
| `wazuh-sysmon1-v1` | `Microsoft-Windows-Sysmon` | `Microsoft-Windows-Sysmon/Operational` | chuỗi `1` |
| `wazuh-powershell4104-v1` | `Microsoft-Windows-PowerShell` | `Microsoft-Windows-PowerShell/Operational` | chuỗi `4104` |

Hai khóa dùng cùng context của Wazuh 4688: `ingested_at` có timezone và
`collection_mode` là `direct`, `forwarded` hoặc `unknown`. Không đoán mode từ tên
agent. Tên lớp context cũ `WazuhWin4688Context` được tái sử dụng để giữ API ổn định.

## Mapping đã chốt

Cả hai profile:

- `source_type=wazuh`; `event_provider` giữ provider nguồn, không đổi thành tên agent.
- `timestamp` lấy **chỉ** `data.win.system.systemTime`, tối đa 9 chữ số thập phân,
  chuẩn hóa UTC không cắt/làm tròn. Không fallback sang Wazuh `timestamp`, `fields`
  hoặc Sysmon `eventdata.utcTime`; không điều chỉnh clock skew để khớp kết luận.
- `source_record_id` lấy `_source.id`; Windows `eventRecordID` giữ riêng trong provenance.
- `hostname` lấy `system.computer`. `asset_id` lấy `agent.id` chỉ khi mode `direct`.
- `rule_id`/`severity` lấy `rule.id`/`rule.level`. Rule ID số nguyên không âm được
  chuyển thành text; severity phải là số nguyên không âm, không nhận bool.
- Thông tin collector agent/manager giữ trong provenance. Thiếu optional field
  vẫn `null`, không suy ra từ IP, tên agent hoặc nội dung message.

| Canonical | Sysmon 1 | PowerShell 4104 |
| --- | --- | --- |
| `process_id` | `eventdata.processId`, PID tiến trình mới | `system.processID`, PID tiến trình phát sự kiện |
| `process_name` | `eventdata.image` nguyên văn | `null` |
| `parent_process_name` | `eventdata.parentImage` nguyên văn | `null` |
| `command_line` | `eventdata.commandLine` nguyên văn, giữ khoảng trắng | **`null`, không gán scriptBlockText** |
| `username` | `eventdata.user` | `null`, không suy diễn SID thành username |
| `file_path` | `null` | `eventdata.path` nguyên văn, kể cả chuỗi rỗng |
| `file_hash`, network, `event_action`, ATT&CK | `null` | `null` |

PID nhận chuỗi chữ số ASCII thập phân dài 1–128 ký tự, giữ giá trị 0, cho phép
leading zero; thiếu/null thành null. Từ chối hex, dấu, khoảng trắng, Unicode digit,
JSON number và bool. Đây là profile cho định dạng Wazuh đã quan sát; không đoán
kiểu hoặc base khác. Sysmon tuyệt đối không dùng `system.processID` thay PID con.

Provenance mới giữ `windows_event_id`, `windows_record_id`, `process_guid`,
`parent_process_guid`, `parent_process_id`, `script_block_id`, `message_number`,
`message_total` khi áp dụng. GUID/ID text giữ nguyên, không tuyên bố đã xác thực
nguồn hoặc uniqueness toàn hệ thống. Các trường vendor khác, kể cả chuỗi nhiều
thuật toán `hashes`, vẫn trong evidence gốc, không tách/đoán vào canonical.

## PowerShell: chỉ hỗ trợ 1/1

Phải có **đúng chuỗi** `messageNumber="1"`, `messageTotal="1"` và
`scriptBlockText` là text không rỗng/không chỉ whitespace. Chuỗi `01`, JSON số `1`,
null hoặc thiếu không tự được chuẩn hóa thành `1/1`.

- Chia nhiều đoạn: `unsupported_fragmentation`.
- Thiếu counter hoặc script text rỗng: `incomplete_script`.
- Sai kiểu/định dạng: `invalid_field`.

Không ghép, cắt, thực thi hoặc in script. Script text chỉ nằm trong raw evidence;
không có trong canonical hay provenance đã serialize. `1/1` xác nhận metadata
đoạn của record được chọn, không chứng minh đã thu mọi script block của cả run,
không chứng minh toàn bộ script đã thực thi thành công.

CLI hiện chuẩn hóa lỗi parser thành `parser_error` tại stage `evidence` và chỉ
số file; không đưa text nguồn vào stderr. Khi lỗi, **không trả report một phần**.
Diagnostic chi tiết có thể lấy bằng byte API phía trên mà không in exception input.
Không xóa record lỗi khỏi bundle để tạo kết quả pass.

## Evidence và bảo mật

- Dùng decoder Wazuh hiện có: UTF-8 (cho phép BOM), tối đa 256 KiB/document,
  depth 20, nodes 10.000, numeric token 128; từ chối duplicate key, NaN/Infinity,
  malformed Unicode, root array và nhiều JSON nối tiếp.
- Hash SHA-256 tính trên **đúng toàn bộ bytes file** gồm wrapper, BOM, whitespace
  và newline. Thay bytes, environment hoặc source_ref làm đổi evidence ID.
- Identity giữ công thức `wazuh-evidence-v1` hiện có; không dùng Windows Event ID
  `1`/`4104` làm evidence ID. Thay ingestion time hoặc collection mode không đổi
  identity record, nhưng có thể đổi mapped context của run.
- `raw_event_ref=<source_ref>#record=1`; provenance/CLI ledger ghi dòng đầu 1,
  dòng cuối theo newline LF của toàn document; luôn có event ID và raw hash.
- CLI giữ ledger/inventory, không nhúng toàn bộ provenance. GUID và script metadata
  vẫn truy lại qua raw ref/hash; engine **không đọc raw hoặc join theo GUID** hiện tại.
- Correlation theo PID cần hostname/scope và time window đã review; PID có thể
  tái sử dụng, không được coi PID một mình là identity bền vững.
- Parser không làm sạch dữ liệu. Command line, file path và script vẫn có thể
  chứa thông tin nhạy cảm. Không commit export thật; làm sạch bản sao, giữ bản gốc
  riêng và hash lại bản đã làm sạch. Hash không phải chữ ký/xác thực nguồn.

## Chạy đối chiếu trên máy phát triển — PowerShell

Không chạy các lệnh này trên WIN-USER01 nếu repo không nằm ở đó.

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-windows-telemetry'
New-Item -ItemType Directory -Path 'build' -Force | Out-Null
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Mẫu CLI hoàn toàn synthetic, dùng SCN-001 **không chỉnh ground truth**:

```powershell
& '.\.venv\Scripts\python.exe' -m aegis_verify validate --scenario scenarios/SCN-001-powershell-execution.yaml --fixture tests/fixtures/wazuh/windows-telemetry
$LASTEXITCODE
```

Mong đợi: A01/A02 `satisfied`, A03 `inconclusive collection_not_confirmed`,
`parsed=2 referenced=2 skipped=0`, final **Inconclusive**, exit code **3**.
Đây là kết quả đúng của ví dụ có telemetry nhưng không có expected detection và
không có attestation đầy đủ. Không phải demo lab thành công hoặc Regression Passed.
Fixture profile có tên/ID synthetic và điều kiện minh họa; không dùng nó nguyên
xi làm profile lab cho ba lượt đổi tên file.

## Chưa làm và hướng nâng cấp

Chưa có multipart assembly, canonical script/GUID fields, PowerShell Core channel,
Sysmon event khác, EVTX/native XML, JSONL/bulk/CSV, live connector hoặc dashboard.
Muốn engine đánh giá script text/GUID cần thay đổi hợp đồng có version được duyệt;
không âm thầm đổi nghĩa `command_line` hoặc mở rộng whitelist engine.

Sau review parser và test đối chiếu, #12 còn cần: payload an toàn được duyệt,
profile lab cố định qua A/B/C, rule filename/behavior được version-control,
thu thập đầy đủ theo scope, mốc thời gian/đồng hồ, quy trình làm sạch và bằng chứng
cho từng run. Thiếu alert chỉ là false negative khi đáp ứng điều kiện collection
của engine; không tự khẳng định `complete_for_scope` từ vài mẫu export.
