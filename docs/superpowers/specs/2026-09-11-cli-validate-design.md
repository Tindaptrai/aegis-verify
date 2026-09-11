# Issue #8 — CLI validate: hồ sơ offline + tham số chọn cấu hình

Ngày: 2026-09-11. Nhánh: `codex/issue-8-cli-validate`.
Base: `bcc2579` (PR #22 đã merge).

Trạng thái: người dùng đã chốt hướng A + B giới hạn trong hội thoại. Bản chi
tiết này chờ người dùng duyệt trước khi lập kế hoạch implementation và viết code.
Không có phê duyệt push, PR hoặc merge Issue #8 trong bước thiết kế này.

## 1. Mục tiêu và ranh giới

Issue #8 nối các parser offline đang có với Validation Engine #7 thành một lệnh
`aegis validate`. Người dùng chọn scenario và bộ hồ sơ evidence; nhận kết quả
terminal hoặc JSON có thể truy vết. Cùng đầu vào và cùng phiên bản phần mềm phải
cho kết quả ổn định, không lấy thời gian máy chạy CLI để tự điền context.

Không thêm live access, SSH, API, UI, chạy payload, CSV parser, so sánh hai run,
adapter embedded-profile B của Issue #7, hoặc khả năng vendor parsing mới.
Không thay canonical v2, engine semantics, hay ground truth của SCN-001/002/003.
Tên A/B ở tài liệu này chỉ là cách cấp đầu vào CLI, không phải hướng A/B của
Cowrie, Suricata hoặc profile schema.

Acceptance criteria Issue #8:

- Nhận `--scenario` và `--fixture`.
- In scenario ID/name, run ID, từng assertion, final status và evidence count.
- Assertion chưa đạt vẫn giữ evidence IDs liên quan khi có.
- Input/fixture hỏng trả mã khác 0, với diagnostic có hướng khắc phục.
- Validation không đạt trả mã khác 0 được tài liệu hóa cho CI.
- Có JSON output ngay trong Issue #8.
- Integration test có cả đạt và không đạt; toàn bộ test cũ vẫn xanh.

## 2. Quyết định A + B giới hạn

**A là nền tảng:** một thư mục hồ sơ với các file cấu hình cố định và danh mục
evidence tường minh. **B là giao diện chọn:** flag chọn file profile/context khác
và định dạng output. Không có flag ghi đè từng target, rule ID, timestamp,
collection assurance hoặc điều kiện correlation.

Lựa chọn không triển khai:

- B đầy đủ: mọi điều kiện biểu diễn bằng flags. Nhiều trạng thái trùng/ghi đè,
  khó review và không cần thiết cho milestone CLI.
- C tự đoán: quét mọi file rồi suy parser, target hoặc completeness. Không đủ
  căn cứ, đặc biệt với Wazuh wrappers và timestamp BSD thiếu năm/timezone.

Lệnh dự kiến (chưa tồn tại tại thời điểm viết spec):

```text
aegis validate --scenario <scenario.yaml> --fixture <run-directory>
aegis validate --scenario <scenario.yaml> --fixture <run-directory> --profile <profile.json> --context <context.json> --format json
```

Đường dẫn trong dấu `<...>` là đối số do người sử dụng cung cấp, không phải
đường dẫn mặc định hoặc ví dụ lab thật.

Quy tắc chọn đúng một nguồn:

| Đầu vào | Không truyền flag chọn | Có flag chọn |
| --- | --- | --- |
| Scenario | Báo thiếu `--scenario` | Đọc đúng file chỉ định |
| Hồ sơ | Báo thiếu `--fixture` | Đọc `<root>/inputs.json` |
| Profile | Đọc `<root>/profile.json` | Chỉ đọc file `--profile` |
| Context | Đọc `<root>/context.json` | Chỉ đọc file `--context` |
| Format | `text` | `text` hoặc `json` |

Không deep-merge cấu hình, không đọc thêm file mặc định sau khi đã chọn file
tường minh, không fallback nếu file được chọn lỗi. Từ chối một flag xuất hiện
nhiều lần thay vì âm thầm lấy giá trị cuối. Không đọc cấu hình từ environment
variables, thư mục cá nhân hoặc nội dung log. Không hỗ trợ flag viết tắt.

## 3. Hợp đồng bộ hồ sơ

### 3.1 `inputs.json`

Object đóng, không chấp nhận field lạ:

- `bundle_schema_version`: literal `0.1.0`.
- `environment_id`: environment của toàn bộ evidence trong hồ sơ, phải bằng
  `EvaluationContext.environment_id` đã chọn. Giới hạn UTF-8 128 bytes, không trắng.
- `files`: array 0..100 mục. Danh sách rỗng được phép để đánh giá trường hợp không
  có evidence; không đồng nghĩa collection đầy đủ.

Mỗi mục có:

- `path`: đường dẫn tương đối bên trong root, dùng dấu `/`.
- `source_ref`: nhãn ASCII theo `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; duy nhất
  trong hồ sơ. Đây không phải đường dẫn thật và không tự sinh từ basename.
- `parser`: một trong sáu registry keys ở mục 4.
- `sha256`: SHA-256 lowercase 64 ký tự của toàn bộ file bytes.
- `context`: context riêng của parser theo mục 4; object đóng.

Không dùng lại các manifest sanitization hiện có làm cấu hình chạy tự động.
Các manifest đó chứa expected test outcomes và metadata audit khác nhau; CLI
không được đọc `expected_status` để quyết định verdict. Hồ sơ mới phải được
chuẩn bị tường minh; giữ nguyên fixtures/manifest audit cũ.

### 3.2 Profile và context

`profile.json` biểu diễn đúng `EvaluationProfile` của #7; `context.json` biểu
diễn đúng `EvaluationContext`. Chuyển JSON array thành các collection có kiểu
qua validation hiện có, không nới type bool/int/null hoặc sửa model để nhận input.
Scenario được đọc bằng loader YAML hiện có. Kiểm tra binding scenario/profile,
assertion IDs và fingerprints bằng API engine; không tự cập nhật fingerprint
để làm input không khớp trở thành hợp lệ.

Profile là tiêu chí đánh giá cần con người review. Collection declaration vẫn
là caller-attested. CLI không tạo hoặc điền `complete_for_scope`, không tự xác
nhận clocks, không tự bổ sung rule ID. Có thể chạy lần đầu với assurance unknown,
xem JSON fingerprints, review collection rồi chuẩn bị context được xác nhận.
Việc tính được hash không tự cấp quyền xác nhận collection.

### 3.3 Đọc JSON và file an toàn

Cấu hình dùng UTF-8 JSON object, cho phép một BOM đầu file. Từ chối duplicate
keys, non-finite numbers, floating-point numbers (các contract này không cần
float), token số nguyên quá 128 ký tự, surrogate không mã hóa UTF-8 được, quá
32 tầng nesting hoặc 50.000 nodes. Mỗi file cấu hình tối đa 1 MiB. Giữ nguyên
giới hạn nhỏ hơn của scenario YAML và các field/model hiện có.

Không shell expansion, template, `eval`, dynamic import hay code trong config.
Giới hạn CLI không nới hạn mức của connector/engine.

Các path bên trong bundle không được rỗng, absolute, drive-relative, chứa thành
phần `..`, backslash, `:`, NUL hoặc thành phần `.`; không glob, URL hay archive.
Từ chối thành phần rỗng, tên thiết bị Windows và thành phần kết thúc bằng dấu
chấm hoặc space để tránh alias/thiết bị được hệ điều hành diễn giải khác. Resolve
path và xác nhận ở trong root. Từ chối symlink/junction/reparse-point trong chuỗi
đường dẫn được duyệt, non-regular files và file trùng physical identity trong
bundle. Từ chối `source_ref` trùng; không tự deduplicate evidence.

CLI top-level paths có thể là đường dẫn local absolute hoặc relative từ CWD;
áp dụng kiểm tra regular-file/reparse-point và tên thiết bị trước khi đọc.
File profile/context được chọn tường minh có thể ở ngoài bundle. Không nhận
URL, UNC/device path. Không tự tải tài nguyên hay xin nâng quyền khi đọc lỗi.

Đây là công cụ local đọc snapshot do người dùng quản lý, không phải sandbox
chống process khác đồng thời tráo file/hardlink. Hướng dẫn yêu cầu dùng thư mục
snapshot riêng, không bị tiến trình khác ghi trong lúc đánh giá.

## 4. Registry parser cố định

`environment_id` luôn lấy từ bundle sau khi đối chiếu context đánh giá.
`source_ref` lấy từ file entry. Không cho khai báo lại hai giá trị này trong
parser context. `ingested_at` bắt buộc, có timezone, không tự lấy đồng hồ máy.

| Registry key mới của CLI | API bytes hiện có | Context thêm ngoài `ingested_at` |
| --- | --- | --- |
| `wazuh-win4688-v2` | `parse_wazuh_document` | `collection_mode`: direct/forwarded/unknown |
| `suricata-wazuh-alert-v1` | `parse_suricata_wazuh_document` | `deployment_mode`: ids/ips/unknown |
| `suricata-eve-jsonl-v1` | `parse_suricata_eve_jsonl` | `sensor_id`, `deployment_mode` |
| `pfsense-filterlog-bsd-ipv4-tcp-udp-v1` | `parse_pfsense_filterlog` | `sensor_id`, `source_year`, `source_utc_offset` |
| `cowrie-wazuh-v1` | `parse_cowrie_wazuh_document` | `sensor_id` |
| `cowrie-jsonl-v1` | `parse_cowrie_jsonl` | `sensor_id` |

Registry là danh sách cố định, không import từ string người dùng. Adapter chỉ
truyền context, gọi parser và đóng gói outcome; logic vendor vẫn ở `connectors/`.
Parser được chọn không phù hợp file thì báo lỗi, không thử parser thứ hai.
Wazuh-exported document là một search hit/file, không thêm bulk-array support.
Không thêm canonical JSONL import để lách các parser fixture trong issue này.

## 5. Pipeline và giới hạn

1. Parse flags, chọn đúng input paths, kiểm tra cấu trúc config và file inventory.
2. Đọc scenario/profile/context thành typed contracts, xác nhận environment.
3. Đọc từng evidence file một lần thành bounded bytes, so hash rồi truyền chính
   bytes đó vào parser. Không normalize newline/BOM, không đọc lần hai để parse.
4. Thu parsed events và intake ledger (cả skipped records). Không output verdict
   khi còn file chưa đọc xong. Không tạo một event cho dòng bị skip.
5. Kiểm tra policy completeness ở mục 6. Gọi `evaluate_scenario` một lần với
   toàn bộ canonical v2 events; engine tự áp dụng scope, không pre-filter/dedup.
6. Tạo report, serialize xong rồi in. Không viết lại evidence/config.

Hạn mức CLI mới: tối đa 100 files, 32 MiB/file và 64 MiB tổng evidence bytes;
tối đa 20.000 physical lines toàn bộ bundle, tính cả blank/unsupported lines;
tối đa 10.000 parsed canonical events (giữ hạn mức engine). Đếm physical line
theo LF và dòng cuối không có LF như connector hiện tại. Wrapper JSON nhiều
dòng vẫn tính physical lines dù chỉ sinh một event. Áp dụng giới hạn trước
parse khi có thể, và luôn trước khi gọi engine; vượt hạn mức thì lỗi toàn run.

Các parser wrapper/line vẫn giữ giới hạn riêng nhỏ hơn (ví dụ 256 KiB/document
hoặc line theo parser). Không truncation, sampling hoặc partial-result fallback.
Tổng encoded report tối đa 32 MiB; serialize có giới hạn trước khi phát stdout.
Vượt output budget báo lỗi, không cắt witness/evidence list để trả verdict thiếu.

## 6. Skips, warnings và collection assurance

CLI lưu từng outcome với `source_ref`, parser key, line range, raw reference,
raw hash, parsed event ID nếu có, status và reason/warning code. Không export
toàn bộ vendor provenance chứa username/password/command vào report mặc định.

- `blank_line`, `rotation_notice`: bookkeeping skips, vẫn ghi ledger/count.
- `unsupported_event_type`, `unsupported_ip_version`, `unsupported_protocol`:
  đánh dấu giới hạn dữ liệu rõ ràng; không coi là parse thành công đầy đủ.
- Parser errors (kể cả ở file cuối), hash mismatch hoặc duplicate event ID:
  dừng run, không có security verdict từ phần đã đọc trước đó.
- Parser warnings giữ nguyên mã cảnh báo trong report; không dùng warning như
  bằng chứng prevention/detection và không tự sửa canonical action.

Policy bảo thủ V0: nếu có unsupported skip của một source type mà profile có
detection assertion cùng source với declaration `complete_for_scope`, trả lỗi
`collection_conflict` trước evaluation. Không đoán skipped line thuộc ngoài
time/target scope, không hạ assurance hoặc sửa declaration ngầm. Caller phải
review và chọn context unknown để đánh giá trong giới hạn hiện có; muốn loại
trừ skip theo scope một cách có chứng cứ cần thiết kế riêng sau này.

Bookkeeping skips không tự phủ nhận declaration, cũng không chứng minh nó đúng.
Không có declaration complete thì engine vẫn xử lý theo #7. Positive witnesses
có thể đủ cho một assertion; unsupported requirement vẫn Inconclusive. Missing
telemetry chỉ nghĩa thiếu trong input đã đưa, không kết luận nguồn log hỏng.
IDS blocked-action warning và unknown deployment mode phải hiển thị rõ; review
profile và evidence vẫn là điều kiện trước khi tin verdict lab thật.

## 7. Output và mã thoát

CLI entry point: `aegis` qua packaging scripts; hỗ trợ tương đương
`python -m aegis_verify`. Dùng `argparse` của Python, không thêm runtime dependency.
Không prompt tương tác, không network, không tự sinh run ID hoặc giờ thu thập.

Report JSON có `cli_report_version: "0.1.0"`, `kind: "evaluation"`, scenario
ID/name/version, `evaluation` giữ nguyên `EvaluationResult`, intake ledger,
parsed/skipped/referenced evidence counts, và input fingerprints.

Input fingerprints gồm exact-byte SHA-256 của scenario, inputs, profile, context
đã chọn; inventory gồm source_ref, bundle-relative path, parser key, file hash
và parser-context fingerprint. Dùng serialization đóng và deterministic cho
fingerprint mới; không gọi `fingerprint()` #7 với kiểu model không được hỗ trợ.
Report không chứa absolute local paths, full command line, config bodies hoặc
raw logs. Relative paths/nhãn vẫn có thể nhạy cảm: phải review trước chia sẻ.

Text output bao gồm đủ metadata, mỗi assertion outcome/reason/evidence IDs và
unevaluable IDs, final status, parsed/referenced/skipped counts, warnings và
assurance. Unknown evidence không được trình bày là positive proof. Escape
control characters để log/config không chèn lệnh terminal hoặc dòng giả.
JSON luôn hợp lệ, không ANSI, không banner/progress text chen vào stdout.

| Exit code | Ý nghĩa |
| --- | --- |
| 0 | Evaluated Detected hoặc Prevented; hoặc yêu cầu help hợp lệ |
| 1 | Evaluated Missing telemetry hoặc False negative |
| 2 | Sai flags/input/config, I/O, hash, parser, collection conflict hoặc resource limit |
| 3 | Evaluated Inconclusive; chưa đủ căn cứ, CI không được coi là pass |
| 4 | Lỗi nội bộ không dự kiến hoặc output I/O thất bại; không claim pass |

Kết quả evaluated (0/1/3) đi stdout; stderr trống bình thường. Lỗi code 2/4
đi stderr, stdout trống nếu chưa phát output; JSON mode dùng object
`{cli_report_version, kind: "error", error: {code, stage, file_index, field, line,
hint}}` với các coordinate không có thì null. Invalid argv mà chưa chọn được
format rõ ràng dùng text error. Unknown exception không in traceback/locals.
Không cam kết thu hồi bytes nếu pipe bị ngắt giữa lúc ghi; consumer phải kiểm
tra exit code và JSON đầy đủ. Không bắt KeyboardInterrupt thành security verdict.

Diagnostic chỉ có mã allowlist, vị trí có cấu trúc và hướng khắc phục cố định,
không echo giá trị sai hoặc `str(exception)` có raw snippets. Text mặc định dùng
thuật ngữ status/code ổn định; guide và giải thích thao tác viết tiếng Việt.

Issue này chưa thêm `--output`, export bundle, database hoặc timeline UI. Người
dùng có thể redirect output bằng shell; shell có thể ghi đè file, nên hướng dẫn
chỉ dùng đích output mới bên ngoài input snapshot. CLI tự nó chỉ đọc input.

## 8. Chia module và khả năng tái sử dụng

- `backend/app/intake/`: bundle contracts, safe config/path reader, registry
  orchestration và intake ledger. Không phân tích field vendor ở đây.
- `backend/app/cli/`: argparse, orchestration gọi intake + engine, safe diagnostic
  translation, text/JSON reports, exit-code mapping.
- `backend/app/__main__.py`: entry point mỏng; update package list và console
  script trong `pyproject.toml`.
- Unit tests theo boundary; subprocess/installed-wheel tests cho command thật.
- `docs/CLI_VALIDATE.md`: cách dùng Windows, cấu trúc hồ sơ, exit codes, limitations.

Kết quả engine không bị CLI định nghĩa lại. UI/live adapter tương lai có thể
tái sử dụng intake/report boundary hoặc gọi engine trực tiếp bằng cùng contract;
không cần xây HTTP service hoặc plugin registry động trong Issue #8.

## 9. Kiểm thử và tiêu chí bàn giao

1. Config: duplicate keys/flags, unknown fields, type/null, Unicode, size/depth,
   default vs explicit selection, lỗi file tường minh không fallback.
2. Paths: traversal, absolute/drive-relative/UNC/device/ADS, symlink/junction,
   non-regular, cùng file nhiều path, path có space và Unicode; không mở file
   ngoài bundle qua entry và không sửa input bytes.
3. Hash: LF/CRLF/BOM exact bytes, hash mismatch và hash của bytes thực sự parse.
4. Intake: sáu parser keys, context thiếu/sai, không auto-detect, parsed + skip
   ledger, warnings, empty bundle, limits tại boundary và vượt một đơn vị.
5. Atomicity: file đầu tốt/file cuối hỏng không được gọi engine hoặc in verdict;
   không truncation, dedup hoặc mặc định completeness.
6. Assurance: complete declaration khớp hash/scope/profile, stale context,
   unsupported skip cùng source bị từ chối, unknown context không bị nâng cấp.
7. End to end: Detected, Prevented, Missing telemetry, False negative với
   synthetic attestation và Inconclusive; text/JSON counts/IDs/exit codes khớp.
8. Privacy/determinism: không raw secret/absolute path/traceback/ANSI từ input;
   output ổn định khi chạy lại cùng input; overflow/output failure không pass.
9. Packaging: console script và `python -m` chạy sau cài wheel từ ngoài checkout;
   `pip check`, toàn bộ backend tests, `git diff --check` sạch.

Fixtures positive/negative mới ghi rõ synthetic test-only, không lấy log các
tháng/máy khác nhau ghép thành một sự kiện lab thật. Dữ liệu làm mẫu phải qua
parser như production path; không mock engine cho test end-to-end chính.
Các real sanitized fixtures cũ chỉ dùng chứng minh compatibility trong scope.

Ba scenario thật vẫn draft; thiếu Sysmon/PowerShell/session/NAT support không
được sửa assertion cho pass. Human review profile, evidence, clocks và collection
assurance vẫn bắt buộc trước một kết luận thực tế.

## 10. Trình tự tiếp theo

1. Người dùng duyệt spec này, nhất là lựa chọn config, skip policy và exit codes.
2. Viết implementation plan, rồi TDD từng boundary; review và chạy full checks.
3. Người dùng chạy lệnh CLI minh họa + full tests trên Windows của mình.
4. Xin phê duyệt push/PR và merge riêng; không tự chuyển sang Issue #9.

### Ghi nhận chuẩn bị môi trường

Worktree mới có venv riêng, cài đúng dependency đã khai báo; không đổi dependency
trong repository. Lượt baseline đầu lỗi pytest tmp-path setup vì thiếu thư mục
`build` ở worktree mới. Cách xử lý chỉ là tạo `build` trước `--basetemp`, không
sửa test hoặc code. Chạy lại: **1631 passed in 12.87s**; `pip check` báo
`No broken requirements found.` Đây là baseline của code #7, không phải kết quả
kiểm thử CLI #8 (chưa được triển khai).
