# CLI validate — đánh giá evidence offline

Issue #8 cung cấp `aegis validate` và `python -m aegis_verify` tương đương.
Lệnh chỉ đọc snapshot local, chuẩn hóa qua connector và gọi Validation Engine.
Không cần lab/live API; lệnh không chạy scenario hoặc payload.

## Cài đặt và chạy mẫu trên Windows

Từ root repository, tạo venv mới với Python >=3.11:

```powershell
py -3.12 -m venv .venv-cli
.\.venv-cli\Scripts\python.exe -m pip install -e ".[test]"
.\.venv-cli\Scripts\aegis.exe validate --scenario tests/fixtures/cli/synthetic-detected/scenario.yaml --fixture tests/fixtures/cli/synthetic-detected
$LASTEXITCODE
.\.venv-cli\Scripts\python.exe -m aegis_verify validate --scenario tests/fixtures/cli/synthetic-detected/scenario.yaml --fixture tests/fixtures/cli/synthetic-detected --format json
$LASTEXITCODE
```

Mẫu trả `Detected`, exit `0`, parsed/referenced `2`, skipped `0`, cùng hai
evidence ID khác nhau trong witness pair của `SCN-999-A02`. Truy vết về
`synthetic-activity#record=1` và `synthetic-alert#record=1` bằng raw hash trong
`evaluation.evidence_index`. Đây là dữ liệu **synthetic test-only**, chỉ chứng
minh đường chạy phần mềm offline. Không chứng minh rule đang triển khai hay một
run lab thực đã phát hiện thành công. Xem [nguồn gốc và hash mẫu](../tests/fixtures/cli/synthetic-detected/README.md).

## Chuẩn bị snapshot

Một thư mục bundle gồm `inputs.json`, `profile.json`, `context.json` và các file
evidence liệt kê tường minh. Scenario YAML là file được chọn riêng (mẫu đặt trong
bundle cho tiện di chuyển). CLI không quét folder để đoán parser và không dùng
`expected_status` trong manifest audit cũ.

`inputs.json` là object đóng: `bundle_schema_version: "0.1.0"`, `environment_id`
khớp context đánh giá, và `files` chứa 0–100 mục. Mỗi mục bắt buộc có `path`
tương đối dùng `/`, `source_ref` duy nhất, `parser`, `sha256` lowercase 64 ký tự
của toàn bộ bytes file và `context` riêng của parser. Xem
[manifest mẫu](../tests/fixtures/cli/synthetic-detected/inputs.json).
`source_ref` là nhãn ASCII theo `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; giữ nhãn
ổn định khi di chuyển bundle để giữ evidence identity. Không sửa newline/BOM sau
khi tính hash. PowerShell: `(Get-FileHash -Algorithm SHA256 -LiteralPath <file>).Hash.ToLowerInvariant()`.

Mọi parser context cần `ingested_at` có timezone, do caller cung cấp. CLI không
lấy giờ hiện tại, không cho context khai báo lại environment/source_ref:

| Parser key | Input và context ngoài `ingested_at` |
| --- | --- |
| `wazuh-win4688-v2` | Một JSON search-hit/document Windows 4688; `collection_mode`: `direct`/`forwarded`/`unknown` |
| `wazuh-sysmon1-v1` | Một Wazuh JSON search-hit Sysmon Event 1; cùng context `collection_mode` như 4688 |
| `wazuh-powershell4104-v1` | Một Wazuh JSON search-hit PowerShell 4104, chỉ đoạn `1/1` có script text không rỗng; cùng context `collection_mode` |
| `suricata-wazuh-alert-v1` | Một Wazuh-exported Suricata alert; `deployment_mode`: `ids`/`ips`/`unknown` |
| `suricata-eve-jsonl-v1` | EVE JSONL alert/flow; `sensor_id`, `deployment_mode` |
| `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | BSD filterlog IPv4 TCP/UDP; `sensor_id`, `source_year`, `source_utc_offset` |
| `cowrie-wazuh-v1` | Một Wazuh-exported Cowrie document; `sensor_id` |
| `cowrie-jsonl-v1` | Native Cowrie JSONL; `sensor_id` |

Năm và UTC offset của BSD log phải có căn cứ thu thập; không suy từ đồng hồ máy.
Chi tiết định dạng vẫn theo các guide [Wazuh](WAZUH_FIXTURE_PARSER.md),
[Suricata A](SURICATA_WAZUH_ALERT.md), [Suricata B](SURICATA_EVE_JSONL.md),
[Cowrie](COWRIE_FIXTURE_PARSER.md) và [pfSense](PFSENSE_FIXTURE_PARSER.md).
Không hỗ trợ CSV, bulk-array wrapper, canonical JSONL import hay parser plugin động.

Hai profile Windows mới được mô tả trong [Windows telemetry parsers](WINDOWS_TELEMETRY_PARSERS.md).
PowerShell nhiều đoạn hoặc thiếu thông tin xác nhận `1/1` làm dừng bundle với
`parser_error`, không bỏ qua để tạo báo cáo thành công một phần.

Profile dùng [contract Validation Engine](VALIDATION_ENGINE.md) `EvaluationProfile`: ID/version, scenario binding và
fingerprint, rules theo assertion ID, role/capability/source, scope/match và
correlation. Context dùng `EvaluationContext`: run/environment, start/end,
bindings, declarations. Hai [file profile](../tests/fixtures/cli/synthetic-detected/profile.json)
và [context mẫu](../tests/fixtures/cli/synthetic-detected/context.json) là ví dụ
có thể đọc trực tiếp; phải review lại khi chuẩn bị dữ liệu khác. CLI không tự
sửa fingerprint để profile sai scenario trở nên hợp lệ.

## Chọn đúng file

`--scenario` và `--fixture` bắt buộc. Mặc định đọc `profile.json` và `context.json`
trong bundle; `--profile <file>` hoặc `--context <file>` chọn duy nhất file đó,
kể cả file local ngoài bundle. Không merge, không fallback khi file chọn bị lỗi.
`--format` nhận `text` (mặc định) hoặc `json`. Flag lặp, flag viết tắt và field
config lạ bị từ chối. Không đọc config từ environment hoặc home directory.

Dùng snapshot riêng, không có process khác ghi trong lúc đánh giá. Chỉ nhận
local regular files; không URL, UNC/device path, symlink/junction/reparse-point,
archive, glob hay path traversal. Entry không được có `..`, backslash, `:`,
thành phần rỗng, tên thiết bị Windows hoặc dấu chấm/space cuối thành phần.
Cùng physical file xuất hiện hai lần bị từ chối.

Hạn mức: config tối đa 1 MiB, 32 tầng, 50.000 nodes; không duplicate keys,
float/non-finite, surrogate hoặc integer token quá 128 ký tự. Evidence tối đa
32 MiB/file, 64 MiB tổng, 20.000 physical lines và 10.000 canonical events;
connector/scenario vẫn có giới hạn riêng nhỏ hơn. Output tối đa 32 MiB.
Vượt giới hạn hoặc file cuối hỏng làm lỗi toàn run, không trả verdict từng phần.

## Kết quả và mã thoát

Text in scenario/run, từng assertion, reason, evidence IDs/unevaluable IDs,
final status, counts, warnings và assurance. JSON có `cli_report_version`,
`kind`, `scenario`, `evaluation` nguyên kết quả engine, `counts`, `intake`
(inventory/ledger), `input_fingerprints` của bytes cấu hình đã chọn và, từ
Issue #10, `timeline` (version `0.1.0`): các event được `evidence_index` tham
chiếu, sắp theo `timestamp` rồi `event_id`, sao chép nguyên trường canonical
(`null` giữ `null`) để [dashboard](DASHBOARD.md) hiển thị. `evaluation`,
fingerprints và `compare` không đổi.
Parsed count không phải proof count; kết luận phải tham chiếu evidence IDs.

| Exit | Ý nghĩa |
| --- | --- |
| 0 | `Detected`, `Prevented`, hoặc help hợp lệ |
| 1 | `Missing telemetry` hoặc `False negative` |
| 2 | Flags/input/config, I/O, hash, parser, collection conflict hoặc resource limit |
| 3 | `Inconclusive`: CI không được coi là pass |
| 4 | Lỗi nội bộ hoặc output I/O thất bại |

Evaluation đi stdout, stderr bình thường trống. Error đi stderr với mã/hint
cố định và tọa độ sanitized; JSON có `kind: "error"`. Invalid argv chưa chọn
format rõ ràng dùng text. Không in traceback/raw exception. Consumer phải kiểm
tra exit code và JSON hoàn chỉnh: pipe ngắt có thể đã nhận một phần bytes.

## Skips và collection assurance

Ledger giữ parsed/skipped outcomes, ref/hash, line range, event ID nếu có,
reason và warning codes. `blank_line`/`rotation_notice` là bookkeeping;
`unsupported_event_type`, `unsupported_ip_version`, `unsupported_protocol` là
giới hạn dữ liệu. Skip không tạo canonical event. Unsupported skip cùng source
với detection assertion khai báo `complete_for_scope` gây `collection_conflict`.
CLI không đoán skipped record nằm ngoài scope hoặc âm thầm hạ assurance.

Thiếu alert với telemetry còn có và assurance unknown thường là `Inconclusive`.
`False negative` cần declaration `complete_for_scope` khớp profile/scope/event-set
fingerprints, coverage và các xác nhận sampling/gaps/clocks. Đây luôn là
`caller-attested`; hash đúng không chứng minh collection đầy đủ. Có thể chạy với
unknown để xem fingerprints, sau đó người có thẩm quyền review evidence và
collection trước khi tạo declaration. Run/window/profile thay đổi làm khai báo
cũ bị từ chối; không tự cập nhật hash để ép pass. `Missing telemetry` chỉ nói
thiếu evidence trong input đã đưa, không kết luận nguồn log hỏng.

Positive witness có thể đủ dù assurance unknown. `Prevented` cần blocked witness
riêng, tương quan với activity. Warning như `ids_blocked_action_requires_review`
phải được review về deployment/evidence; warning tự nó không chứng minh prevention.

## Privacy và đích output an toàn

Report không nhúng raw logs hoặc absolute input paths. Từ Issue #9, JSON thêm
`comparison_inputs` chứa snapshot scenario/profile/context đã validate để so sánh
hai run; snapshot có thể chứa điều kiện command line trong profile, target bindings
và thông tin attestation. Run ID, source labels, relative paths, hashes, evidence refs
cũng có thể nhạy cảm. Review trước khi
chia sẻ; giữ real exports riêng, sanitize theo [threat model](THREAT_MODEL.md).
Không đưa credentials, certificates, tokens hay unsanitized evidence lên Git.

Xem [hướng dẫn compare](CLI_COMPARE.md) cho compatibility policy, trạng thái
`Regression Passed`, giới hạn report và lệnh PowerShell chạy thử.

CLI chưa có `--output`. Shell redirection có thể ghi đè input trước khi CLI đọc:
chỉ ghi vào một đích mới ngoài snapshot. Ví dụ tạo thư mục kết quả duy nhất:

```powershell
$reportDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("aegis-report-" + [guid]::NewGuid()))
.\.venv-cli\Scripts\aegis.exe validate --scenario tests/fixtures/cli/synthetic-detected/scenario.yaml --fixture tests/fixtures/cli/synthetic-detected --format json > (Join-Path $reportDir.FullName "result.json")
$LASTEXITCODE
```

## Kiểm chứng và giới hạn bàn giao

Chạy full checks với thư mục tạm mới (tạo `build` trước):

```powershell
New-Item -ItemType Directory -Force build | Out-Null
$testBase = "build/issue8-final-" + [guid]::NewGuid()
.\.venv-cli\Scripts\python.exe -m pytest backend/tests -q -p no:cacheprovider --basetemp $testBase
.\.venv-cli\Scripts\python.exe -m pip check
git diff --check
```

Kiểm chứng đóng gói dùng `pip wheel . --no-deps`, cài wheel vào venv khác và gọi
cả console/module từ ngoài checkout; kiểm tra `aegis_verify.__file__` nằm trong
`site-packages`. Bộ fixture không nằm trong wheel: sao chép bundle mẫu riêng.

Kiểm chứng local ngày 2026-09-11: Python 3.13.14 đạt **1781 passed, 1 skipped**
(FIFO không có trên Windows), gồm 14 acceptance tests CLI và 9 regression cases
bổ sung sau final review (parser sai kiểu và lệnh mẫu README). `pip check` và
`git diff --check` đạt. Wheel cài riêng trên Python 3.12.1 chạy từ ngoài checkout,
import `site-packages`, console/module cho JSON và text giống nhau, exit 0.
Chưa kiểm chứng Python 3.11 hoặc lab thật.

SCN-001/002/003 vẫn draft; gaps Sysmon, PowerShell, session/NAT không được sửa
assertions cho pass. Không có live collection, scenario execution, UI hoặc run
comparison trong Issue #8. Bước tiếp theo là human review profile/evidence/clocks,
người dùng chạy thử local và lab validation; push/PR/merge cần phê duyệt riêng.
