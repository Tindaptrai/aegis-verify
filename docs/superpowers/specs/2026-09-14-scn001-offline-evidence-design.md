# Issue #12 — Snapshot alerts.json và đánh giá SCN-001 A/B/C

Ngày: 2026-09-14. Trạng thái: người dùng đã duyệt tiếp tục triển khai sau khi
nhận bản chi tiết và ước lượng. Bắt đầu kế hoạch adapter offline tuần tự;
không phải kết quả test hoặc bằng chứng A/B/C đã hoàn tất. Không tự commit/push/merge.

## 1. Mục tiêu, lựa chọn và ranh giới

Hoàn thiện phần tiếp theo của demo an toàn: đóng gói snapshot Wazuh manager
`alerts.json` thành evidence offline truy vết được, dùng nguyên parser Windows,
Validation Engine và comparison. Giữ SCN-001 phiên bản 0.1.0 và ba assertion.

Chọn snapshot manager JSONL vì phù hợp cách operator đang thu log. Export JSON
search-hit từ Dashboard là phương án thay thế nhưng không triển khai đồng thời.
Live API/Indexer, UI và tự điều phối SSH là nâng cấp sau, không thuộc bước này.

Thiết kế này thay riêng lựa chọn input ở mục 7 của thiết kế ngày 2026-09-12:
adapter manager JSONL được chọn tường minh, không giả đây là search result.
Không đưa `_source` vào engine, không tự nhận mọi định dạng hoặc tạo event từ
execution manifest. Không thay parser/canonical/engine/compare để đạt demo.

Không sửa payload, runner, rule revision, default Wazuh rules, policy hoặc
firewall. Lab do operator thực hiện từng bước. Không đọc credentials, không
đọc raw lab exports trong quá trình phát triển; tests chỉ dùng synthetic.

## 2. Luồng và trách nhiệm

1. Trước A: review và khóa study plan, profile, bindings và quy trình collection.
2. Operator chạy A/B/C bằng runner hiện có, giữ từng thư mục run riêng.
3. Operator tạo snapshot riêng tư và bằng chứng collection; không gửi raw lên Git.
4. Adapter offline kiểm snapshot, chọn records theo scope đã khóa, tạo documents
   dẫn xuất và ledger nối về từng dòng gốc. Không chọn theo kết quả detection.
5. Bộ chuẩn bị bundle kiểm kit/run/profile/provenance, tạo inputs/profile/context.
6. `aegis validate` chạy mặc định với collection unknown. Người review xác nhận
   riêng nếu có đủ căn cứ, rồi đánh giá lại với context attested mới.
7. `aegis compare` so sánh B/C; báo cáo giữ nguyên outcome do engine tính.

Source-specific decoding/classification ở `connectors/wazuh/`. Logic study,
execution binding và packaging ở module demo riêng, không vào validation engine.
Scripts là entry points offline mỏng. Không cần dependency mới.

## 3. Input được khóa

### Study plan riêng tư, version 0.1.0

Object đóng, có kind/version; chứa scenario/profile hashes và binding values
được review: environment, target host, agent ID, collection_mode=direct,
executable/command lines và hai script paths ở dạng canonical thực sự quan sát.
Không hard-code các binding lab trong source hoặc synthetic fixtures.

Giữ hash kit, runner, payload, hai rule revisions và field profile native.
Chỉ một rule ID được đánh giá cho cả A/B/C; đổi SIEM revision không đổi expected
rule ID. Ghi execution context đã duyệt (account/elevated) và yêu cầu giống nhau
qua các lượt; đây là operator evidence, không giả runner tự attests quyền.

Study plan cũng khóa cửa sổ 120 giây, correlation [-5,+15] giây, scope export,
các bước kiểm collection và nguồn thời gian. Không chứa expected verdict để
tool lấy làm kết quả. Không có secret/connector URL.

Executable và command-line literals phải đối chiếu trước A bằng metadata đã
review từ rehearsal. Không suy escape/case từ tên chương trình. Hai command
lines được review chỉ khác tên payload; cả hai dùng cùng hash payload đã khóa.
Đó là bước hoàn tất binding lab, không cho phép sửa tiêu chí giữa A/B/C.

### Input từng run

- Execution-start, execution-launched và execution.json; stdout/stderr của runner.
- Kit và artifact hashes được pin; rule-state receipt của operator trước/sau run.
- Danh sách snapshot files hữu hạn, chỉ định từng file, SHA-256 và nhãn nguồn ổn định.
- Collection receipt: run/study hashes, thời điểm thu, phạm vi, nguồn/rotation,
  các giới hạn và các tham chiếu review native events/manager health.
- Mặc định không có attestation complete_for_scope.

Snapshot phải là file local regular đã đóng băng, không đọc đường dẫn log đang
ghi trực tiếp làm bundle. Không glob/archive/URL/SSH. File thay đổi trong quá
trình đọc hoặc hash không đúng gây lỗi toàn bộ, không tự retry.

`execution.json` phải status executed, exit 0, timed_out false, không failure,
child PID hợp lệ, đúng host/run/label/kit/payload/rule revision. Kiểm tra liên kết
các manifest và đúng stdout/stderr đã định nghĩa trong runner; không tái tạo
manifest còn thiếu. Rule hash trong execution chỉ là khai báo, phải giữ receipt
riêng; công cụ không khẳng định đã xác minh manager từ xa.

Rehearsal có thể đóng gói để kiểm công cụ nhưng không đổi nhãn thành A/B/C.
Thất bại/incomplete giữ nguyên cho điều tra, không biến thành Detection Gap.

## 4. Adapter manager JSONL và evidence identity

Adapter profile tường minh `wazuh-manager-alerts-jsonl-v1`. Đầu vào mỗi record
là JSON object của manager, không phải root array/search-hit. Từ chối root có
wrapper `_source` để tránh double wrapping hoặc chọn nhầm adapter.

Với mỗi dòng không rỗng, kiểm UTF-8/JSON, duplicate keys, depth/nodes/numbers
theo decoder Wazuh hiện có. Không deserialize rồi serialize lại nội dung nguồn:
document dẫn xuất được tạo bằng bytes `{"_source":` + bytes JSON object của
dòng + `}`. Không chèn `_index`, `_id`, decoder hoặc field nguồn còn thiếu.
Không sửa LF trong script string hoặc backslashes để làm profile khớp.

Line separator LF/CRLF được tách khỏi body trước wrapping, nhưng hash dòng
nguồn bao gồm separator nếu có. UTF-8 BOM chỉ cho phép đầu snapshot; bỏ BOM
khi wrapping và ghi rõ trong ledger. BOM ở dòng khác là lỗi. Dòng cuối không
có newline vẫn được chấp nhận nếu là JSON object hoàn chỉnh; không suy từ đó
rằng snapshot đầy đủ. Whitespace-only lines có ledger bookkeeping riêng.

Ledger giữ cho mọi dòng: source label, snapshot SHA-256, line number 1-based,
byte offset/length, line SHA-256, disposition và reason; với dòng được chọn thêm
document path/hash/source_ref và source record ID nếu có. Không in raw values
trong diagnostic. Source labels và số dòng quyết định tên document/ref, không
phụ thuộc absolute path hoặc thứ tự chạy tool. Không âm thầm deduplicate.

Documents dùng hai parser keys hiện có `wazuh-sysmon1-v1` và
`wazuh-powershell4104-v1`. Canonical evidence ID/raw_event_hash vẫn do parser
tính trên đúng bytes document dẫn xuất. Snapshot hash/line hash là lớp khác:
không gán hash raw line vào canonical document hash.

Chuỗi truy vết: report evidence ID → document ref/hash → ledger entry →
snapshot hash + byte range/dòng. CLI không tự đọc ledger; có bước verify bundle
riêng đối chiếu lại toàn chuỗi trước bàn giao. Không tuyên bố generic compare
tự xác thực bytes nguồn hoặc độ tin cậy của receipt.

## 5. Scope, lỗi và tính đầy đủ

Chọn records của agent/host được review, provider+event ID Sysmon/1 và
PowerShell/4104, theo Windows `systemTime` thuộc cửa sổ đánh giá. Không lọc
theo rule ID, severity, marker, filename, command line hoặc child PID ở bước
export selection. Giữ cả records khác PID trong cùng scope để review.

Chỉ exclude khi field hợp lệ chứng minh record ngoài scope; ghi reason vào
ledger. Record malformed gây lỗi, kể cả chưa phân loại được. Thiếu dữ liệu
để chứng minh ngoài scope không được tự exclude. Record Windows có thể thuộc
scope nhưng sai/missing provider, EventID, host hoặc time làm dừng packaging
với diagnostic sanitized. Record không phải Windows chỉ được exclude khi có
metadata hợp lệ đủ phân biệt, không dựa vào text description.

Missing canonical optional field vẫn do parser biểu diễn null. PID/text/path
thiếu không được thay bằng manifest. Selected fragmented/incomplete 4104 hoặc
parser error dừng bundle, không lọc ra để chạy tiếp. Rule ID generic như 91816
không bị bỏ. Duplicate source record IDs trong cùng nguồn/manager, duplicate
snapshot hoặc overlapping duplicated lines gây lỗi để operator review; không
tạo witness giả bằng cách đóng gói cùng record hai lần.

Giới hạn ban đầu: tối đa 32 snapshot files, 32 MiB/file, 64 MiB tổng, 20.000
physical lines tổng, 256 KiB mỗi wrapped document theo parser hiện có, tối đa
100 selected documents theo CLI. Config/ledger dùng giới hạn 1 MiB, depth 32,
50.000 nodes của intake. Vượt bất kỳ giới hạn nào làm lỗi toàn bộ; không lấy
100 records đầu, không truncation, không nâng giới hạn engine âm thầm.

Giữ snapshot/receipt gốc để kiểm scope rộng hơn và record đến muộn. Mốc thu
snapshot không được dùng thay Windows event time. Đợi một khoảng cố định hoặc
query thấy hai alerts không đủ xác nhận ingestion đã hoàn tất. Nếu rotation,
retention, filter, sampling hoặc backlog chưa được giải quyết thì unknown.
Không bật archives toàn hệ thống hoặc dừng SIEM chỉ để tạo snapshot.

## 6. Profile chung và cửa sổ thời gian

Giữ nguyên scenario YAML. Profile mới là ground truth thực thi phải được review
và khóa trước A; không dùng profile synthetic hiện có nguyên xi cho lab.

| Assertion | Scope/match đã khóa |
| --- | --- |
| A01 | Wazuh/Sysmon provider, target host+asset; đúng executable và một trong hai command lines đã review |
| A02 | Wazuh/PowerShell provider, target host+asset; một trong hai decoded script paths đã review |
| A03 | Wazuh/PowerShell cùng scope paths; đúng rule ID demo; join tới A01 bằng hostname + asset_id + process_id, delta [-5,+15] giây |

A01/A02 là telemetry roots: contract hiện tại không cho telemetry correlation.
Không thêm correlation vào A02 để ép engine chấp nhận. Record 4104 có thể là
witness A02 và A03; anchor A01 phải là evidence ID khác, không nhân bản event.

Run-binding review riêng kiểm PID/ProcessGuid/ScriptBlockId và native record
metadata liên quan đến child trong execution manifest. Có telemetry phù hợp
nhưng PID khác child hoặc nhiều launch phù hợp trong scope là conflict, không
chọn record thuận lợi. PID null/thiếu native confirmation giữ trạng thái review
chưa đủ; không chứng nhận demo thành công chỉ vì generic CLI có positive witness.
Thiếu telemetry không tự là input giả: cho phép inspection với outcome gốc của
engine, nhưng không gắn nhãn lab verified. Không sửa canonical PID từ manifest.

Bindings cố định qua A/B/C, không đưa child PID từng run vào binding rồi bỏ qua
compatibility check. PID thay đổi được giữ trong execution/collection receipt,
và join canonical dùng PID thực tế. Chỉ một demo process/lượt, không chạy chồng.

Context start = window_start_utc; end = window_planned_end_utc. Kiểm chính xác
end-start = 120.000000000 giây bằng nanosecond, không round/truncate thời gian.
Runner đã ghi planned end; không đổi observed end hoặc sửa manifest.
Observed end phải >= planned end, launch/exit nằm trong window, thứ tự thời
gian hợp lệ. Clock jump/sleep chưa giải thích được chặn lab attestation.

Giữ scenario/profile fingerprints, environment, bindings và duration bằng
nhau. Study plan hash và execution-context review là điều kiện demo bổ sung,
không giả rằng generic compare đã biết chúng. Không thay semantics comparison.

## 7. Collection attestation và kết quả

Bundle ban đầu luôn declarations rỗng/unknown. Hash/count đọc đủ các file
được đưa vào chỉ chứng minh tính nhất quán của input, không chứng minh pipeline
đã thu đủ. Công cụ không tự bật ba cờ collection assurance.

Muốn attested context, operator phải review receipt riêng của run, xác nhận
coverage toàn 120 giây, no_sampling_or_truncation, no_parse_errors_or_gaps,
clocks_adequate và cung cấp confirmed_by/reference. Bằng chứng kiểm tra health,
threshold/filter/rotation/backlog, native-vs-manager mapping phải có tham chiếu.
Nếu không thể xác nhận thì giữ unknown; không buộc operator bấm yes cho đủ.

Tool tính profile/scope/event-set fingerprints từ bundle đã verify và đối
chiếu đúng request operator đã duyệt. Thay bytes/scope làm request cũ lỗi,
không tự cập nhật request để nó hợp lệ. Tạo context attested mới và report mới,
giữ unknown report/context cũ. Gắn metadata review riêng, không sửa verdict JSON.

Kỳ vọng có điều kiện, không phải output được đặt trước:

- A: telemetry và demo detection đủ → Detected.
- B: telemetry đủ, thiếu demo detection, collection unknown → Inconclusive.
- B chỉ có thể False negative khi mọi điều kiện engine/collection hợp lệ.
- C: telemetry và demo detection đủ → Detected.
- B unknown → C detected không được gọi Regression Passed.
- B false_negative → C tất cả satisfied, không unknown, compatible và review
  evidence/collection hợp lệ → compare có thể trả Regression Passed.

Kết luận chỉ về rule demo/nội dung thử nghiệm; generic alerts vẫn được báo.
Không tuyên bố toàn hệ thống không phát hiện hoặc phát hiện mọi malware.
Fixed native matching là decoded representation lossy, không proof source bytes.

## 8. Output, privacy và giao diện offline

Output mới ngoài Git gồm bundle documents, inputs.json/profile.json/context.json
theo contracts CLI hiện có; ledger.json, run/collection receipts và manifest hash
riêng cho packaging. Reports ở thư mục mới ngoài input bundle.

Paths là local regular, không URL/UNC/device/ADS/glob/traversal/symlink/junction/
reparse/hard-link alias; kiểm tổ tiên và output target. Không overwrite existing
output, không recursive cleanup. Validate input trước write; manifest hoàn tất
ghi cuối. Partial output khi I/O lỗi giữ riêng với trạng thái incomplete, không
được verify là bundle hoàn chỉnh. Snapshot gốc không sửa hoặc xóa.

Chỉ thao tác input operator chọn. Giữ unknown vendor fields nguyên bytes trong
document; tool không tự sanitize. Public bundle là bản dẫn xuất được sanitize
và hash lại, có provenance riêng; không giả đó là raw original hoặc giữ nguyên
evidence IDs sau khi bytes đã đổi. Runtime private reports có thể chứa bindings,
command lines/paths; không tự commit/share chúng.

Config không chứa float; execution manifest hiện có elapsed_seconds dạng float
phải dùng reader có contract riêng chấp nhận finite number cho trường này, không
nới JSON config reader chung. Không dùng elapsed_seconds để tính chính xác window.

Entry point dự kiến `scripts/prepare_scn001_bundle.py` có các thao tác tách biệt:
chuẩn bị bundle unknown, verify bundle, và tạo attested context từ request đã
được operator duyệt. Đây là giao diện mới dự kiến, không phải lệnh hiện đã có.
Không tự gọi SSH, restart, chạy payload hoặc thu hồi policy.

## 9. Files và tests dự kiến

- `connectors/wazuh/manager_snapshot.py`: vendor JSONL adapter + source coordinates.
- `backend/app/demo/`: contracts và SCN-001 study/bundle/run-binding verification.
- `scripts/prepare_scn001_bundle.py`: entry point offline.
- `backend/tests/test_wazuh_manager_snapshot.py`, `test_scn001_bundle.py`,
  `test_scn001_evaluation.py`: unit và CLI integration.
- `tests/fixtures/demo/scn-001/`: chỉ synthetic có nhãn rõ, không raw lab.
- `docs/SCN001_EVIDENCE_BUNDLE.md`, README demo và checkpoint: hướng dẫn tiếng Việt.

Viết test RED trước code. Ma trận gồm LF/CRLF/BOM/final-no-newline; preserving
unknown fields/number lexemes; duplicate keys/IDs/files; invalid/truncated/oversized
input; excludes có căn cứ và missing classification fields; hashes/line offsets;
fragments; sai host/PID/path/rule/time; overlapping launches; null PID; two-name
payload equality; clock/window nanosecond; partial output/path attacks; stale
attestation; changing profile/bindings; unknown/Missing telemetry/False negative;
A/B/C synthetic qua CLI thật; evidence trace và B/C compatibility.

Test parser/engine source-specific semantics không được thay đổi. Chạy tests
liên quan, full backend/tests, pip check và git diff --check trước bàn giao code.
TDD/local synthetic không thay thế PCRE2, native lab controls hoặc review độc lập.

## 10. Các mốc triển khai và điểm dừng

1. Review bản thiết kế này, sau đó lập kế hoạch phần nhỏ, tuần tự, không subagent.
2. Implement/test adapter và packaging unknown trước; dùng synthetic để kiểm trace.
3. Implement/test frozen profile/run checks và explicit attestation flow; chạy
   synthetic A/B/C bằng CLI, self-review và bàn giao cho reviewer độc lập.
4. Operator hoàn tất literal bindings và collection checklist trước A. Thu raw
   trên lab theo hướng dẫn từng máy, không dùng rehearsal làm baseline chính thức.
5. Chạy A/B, review evidence; đổi đúng rule sang fixed sau review; chạy C; verify,
   validate/compare và human review trước công bố kết luận.

Nếu input mới cần thay canonical/engine, phải dừng và xin thiết kế khác. Nếu
không đủ collection thì bàn giao trung thực Inconclusive, không sửa tiêu chí.
Chỉ đóng Issue #12 sau bằng chứng lab/review, không chỉ dựa vào test phần mềm.

## Căn cứ khảo sát

Đã đọc PRD, ARCHITECTURE, thiết kế demo ngày 2026-09-12, CLI_VALIDATE,
CLI_COMPARE, VALIDATION_ENGINE, WINDOWS_TELEMETRY_PARSERS và code contracts/
parser/runner/intake/compare tại worktree issue-12-safe-demo, HEAD fb05d3c cùng
pending native-profile changes. Root checkout cũ và thay đổi của user giữ nguyên.
Issue #12 online đã thử mở ở lượt khảo sát trước nhưng trả 404; không tuyên bố
đã xác minh acceptance criteria mới trên GitHub. Phạm vi theo thiết kế repo và
phê duyệt offline JSONL của user. Đây là thiết kế để review, chưa có code mới.
