# Issue #12 — Checkpoint demo vô hại

Ngày ghi nhận: 2026-09-12; cập nhật review/P3: 2026-09-13.
Giao tiếp/lab commands trong task này dùng tiếng Việt.

## Repository

- Worktree: `I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo`.
- Branch: `codex/issue-12-safe-demo`.
- Base PR #25: `bf4852979293a998e169b06d214486465678360e`.
- Design commit: `273fab6`.
- [Thiết kế](superpowers/specs/2026-09-12-safe-demo-design.md).
- [Kế hoạch phần 1 — kit lab](superpowers/plans/2026-09-12-safe-demo-lab-kit.md).
- Implementation phần 1: commit `92b412f` (generator, runner, 85 tests mới).
- [Hướng dẫn kit tiếng Việt](../demos/scn-001/README.md).
- Implementation làm inline/tuần tự; sau đó có subagent review độc lập theo
  phê duyệt của người dùng. Chưa push/merge/đóng Issue #12.
- Root checkout và dữ liệu chưa commit của người dùng không được reset/clean.

## Việc lab người dùng đã thực hiện và báo kết quả

Đây là **kết quả người dùng cung cấp**, không phải agent SSH vào manager hoặc
tự chạy kiểm chứng trên lab. Không có raw log/credential được lưu trong file này.

Wazuh manager: 4.14.4. Config test ban đầu exit 0 nhưng cảnh báo duplicate
IDs 120850, 120860, 120861 trong local_rules.xml. Người dùng đã duyệt:

1. Giữ ba định nghĩa đầu dùng if_group=suricata, bỏ ba bản sau cùng ID dùng
   if_sid=86601 và MITRE. Không sửa các rule khác.
2. Sau test phát hiện lệch field, người dùng duyệt đổi đúng ba field từ
   data.alert.signature_id sang alert.signature_id, PCRE2 exact anchors.

Mapping cuối đã được logtest synthetic kiểm tra:

| Input signature | Expected rule | Level | Kết quả người dùng |
| --- | --- | --- | --- |
| 1008502 | 120850 | 12 | PASS |
| 1008601 | 120860 | 10 | PASS |
| 1008602 | 120861 | 11 | PASS |
| 10085020 | 86601 | 3 | PASS |
| 10086010 | 86601 | 3 | PASS |
| 10086020 | 86601 | 3 | PASS |
| 2231000 | 86601 | 3 | PASS |

Lệnh kiểm tra dùng wazuh-logtest -q -U expected_id:level:json và đầy đủ timestamp.
Mẫu synthetic đầu tiên agent đưa thiếu timestamp nên không khớp parent 86600;
đã sửa mẫu và không dùng kết quả lỗi đó để kết luận lỗi production.

## Backup trên manager — không nhầm các phiên bản

- `/root/aegis-rule-review.REDACTED/original.xml`: bản **còn duplicate** ban đầu.
- `/root/aegis-rule-review.REDACTED/candidate.xml`: bản bỏ duplicate, **chưa sửa field**.
- `/root/aegis-field-review.REDACTED/before.xml`: bản bỏ duplicate, **chưa sửa field**.
- `/root/aegis-field-review.REDACTED/candidate.xml`: bản bỏ duplicate và **đã sửa ba field**.

Không tự rollback chỉ để đồng bộ tên file; mọi restore phải xác minh hash/diff
và trạng thái hiện tại, chỉ thực hiện theo yêu cầu người dùng.

## Sau restart

Active Response block người dùng gửi là placeholder bên trong XML comment;
không bật/tắt AR trong lượt sửa này. Không suy ra tất cả tích hợp tự động khác
đã được audit. Phải kiểm tra lại điều kiện liên quan khi thêm rule demo mới.

Người dùng chạy config test, systemctl restart wazuh-manager và kiểm tra status:
active (running), startup SUCCESS, từ 2026-09-12 20:21:16 +07 = 13:21:16 UTC.

Metadata alert sau restart do người dùng cung cấp:

| Wazuh record ID | Timestamp UTC | Rule | Decoder |
| --- | --- | --- | --- |
| 1789219285.6149942 | 2026-09-12T13:21:25.685+0000 | 5502 | pam |
| 1789219288.6150303 | 2026-09-12T13:21:28.973+0000 | 60642 | windows_eventchannel |
| 1789219291.6151883 | 2026-09-12T13:21:31.168+0000 | 19003 | sca |

Các ID trên là source record IDs do Wazuh cấp, **không phải canonical evidence
IDs của một AEGIS evaluation run**. Chúng hỗ trợ nhận định manager tiếp tục ghi
alert, không chứng minh custom Suricata detection, Sysmon/4104 của demo, hoặc
firewall blocked. Chưa có A/B/C evaluation reports hay Regression Passed.

## Bước tiếp theo

1. Review độc lập đã hoàn thành và P3 đã sửa; vẫn cần human review trước lab.
2. Người dùng đã đối chiếu bản trước P3 (2094 passed, 1 skipped); có thể chạy
   lại bản sửa theo lệnh bên dưới, không cần raw lab export để test kit.
3. Xác minh parent rule thực tế cho PS4104, custom ID trống, alert threshold
   và tác động tích hợp trước cài demo. Không dùng Suricata rule IDs cho demo PS.
4. Review kit rồi rehearsal trên Windows lab; không sửa policy/ground truth.
5. Lập kế hoạch export/attestation và evaluation A/B/C, tái sử dụng CLI hiện có.
6. Chỉ đóng Issue #12 sau human review và evidence lab hợp lệ.

## Implementation đã làm trong lượt tiếp tục

- Generator Python stdlib tạo hai tên cùng bytes/hash, hai revision cùng rule
  ID và level 5, manifest hash artifacts và 12 synthetic logtest cases.
- Không nhận arbitrary payload; bản chuẩn chỉ Write-Output marker và own PID.
- Validation chặt ID/host/path, từ chối overwrite/reparse/UNC và output trong
  Git checkout (ngoại lệ build của worktree này cho test). Đọc lại bytes đã ghi
  trước publish `kit.json`; output dang dở không được tự xóa hay dùng lại.
- Runner Windows PowerShell 5.1 x64 mặc định preflight không ghi run files hoặc
  launch. Kiểm tra host, bytes chuẩn độc lập với hash trong manifest, rule hash,
  services/log access và run selection. Chỉ `-Execute` mới tạo child.
- Execute path có window danh nghĩa 120 giây bằng Stopwatch, launch khoảng +10s,
  timeout child 30s, chỉ dừng child do runner tạo; kiểm tra stdout/PID/exit/stderr.
  Start/launched/final manifests tách biệt, không gán verdict hoặc assurance.
- README tiếng Việt phân máy/trách nhiệm, lệnh preflight, review/logtest/cài
  một revision, rollback guard hash, rehearsal và điểm dừng trước evaluation.
- Không thay scenario ground truth, canonical, connectors, engine, comparison
  hoặc dependencies. Không đọc/commit credential hoặc raw lab exports.

## Kiểm chứng mới đã chạy trên máy phát triển

Venv riêng của worktree: `.venv`, Python 3.13.14. Editable import đã kiểm tra
trỏ tới `issue-12-safe-demo/backend/app/__init__.py`, không phải root checkout.
Không sửa venv cũ/root của người dùng.

Baseline chạy lại trước thay đổi: **2009 passed, 1 skipped** (60.66s).
Targeted kit/runner trước guard cuối: **84 passed** (44.25s). Sau thêm guard
Git checkout khác, generator suite: **47 passed** (5.28s).

Full suite cuối trên implementation commit `92b412f`:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-handoff-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
git diff --cached --check
```

- **2094 passed, 1 skipped in 126.25s**; 85 test mới so với baseline.
- Skip: `backend/tests/test_intake_io.py:452`, FIFO không có trên Windows.
- `pip check`: `No broken requirements found.`
- Diff whitespace checks: exit 0. Git có thông báo chuyển LF/CRLF cho text
  thông thường; payload/runner/templates có `.gitattributes` giữ LF.
- Các relative file links trong README/DEMO đã được kiểm tra tồn tại.
- Cú pháp hashtable splatting tới PowerShell native exe trong README đã có test.

Đây là kết quả mới của agent trên máy phát triển, không phải test do người
dùng chạy trên endpoint lab. Không chạy `-Execute`, Wazuh config/logtest demo
mới hoặc cài rule trong lượt này.

## Review độc lập và bản sửa P3

Người dùng báo kiểm tra bản trước P3: **2094 passed, 1 skipped in 82.11s**,
`pip check` sạch và `git diff --check` không có output. Đây là kết quả người
dùng cung cấp, khác với kiểm chứng mới của agent bên dưới.

Reviewer độc lập đã xem `cac892f..9dc0898`: không phát hiện P1/P2, có một P3
về giới hạn đường dẫn. RunDirectory dài 208 ký tự vượt qua guard cũ; tên
`execution-start.json` vẫn vừa giới hạn 230 nhưng `execution-launched.json`
vượt giới hạn, có thể làm run dừng sau khi child đã khởi chạy.

Bản sửa kiểm tra đủ năm đường dẫn output trong `Assert-AegisRunDirectory`,
trước tạo thư mục hoặc chạy child. Giới hạn hiện tại của RunDirectory là
206 ký tự, suy ra từ giới hạn 230 của từng file và tên output dài nhất.
Không đổi payload, thời gian chạy, rule, ground truth hoặc semantics evaluation.

Kiểm chứng TDD ngày 2026-09-13:

- RED trên code cũ: **5 failed, 1 passed, 38 deselected in 6.38s**.
- GREEN kit/runner: **91 passed in 47.32s**.
- Sáu test mới kiểm tra các độ dài 206/207/208/218/230 và preflight thực tế
  từ chối đường dẫn trước khi kiểm tra telemetry hay tạo run directory.
- Reviewer độc lập kiểm tra lại diff và AST: 206 được chấp nhận;
  207/208/218/230 bị từ chối với `AEGIS_INVALID_LOCAL_PATH`. P3 đã giải quyết,
  không thấy regression cần xử lý trong diff bản sửa.

Lệnh kiểm chứng mới của agent trên bản sửa:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-p3-full-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Kết quả: **2100 passed, 1 skipped in 89.43s**; skip FIFO trên Windows tại
`backend/tests/test_intake_io.py:452`. `pip check`: `No broken requirements
found.`; diff check exit 0. Reviewer không chạy full pytest; các kết quả suite
này do agent chính chạy. Không chạy `-Execute`, cài rule hoặc truy cập lab.
Nếu đã tạo kit trước bản sửa, cần tạo kit mới để nhận runner đã sửa.

## Tự rà soát và giới hạn sau review

Tự rà soát đã bổ sung regression tests cho scalar fields bị thay bằng arrays
(PowerShell comparison có thể im lặng cho qua), generator output ở checkout
khác và readback mismatch. Không thay semantics engine để làm demo đạt.

Review độc lập đã đọc AGENTS, design/plan, README và kiểm tra các điểm sau;
human review và lab validation vẫn cần thiết:

1. Safety của payload/runner, no-overwrite/reparse, path/argument quoting,
   timeout/child lifecycle và partial manifests.
2. Hai payload cùng bytes, rule anchors/escaping, parent chain, host/counters,
   negative controls; fixed không được quảng bá là detector malware.
3. Manifest/hash chỉ là metadata/kết quả operator đối chiếu; không chứng thực
   remote, không là canonical evidence hoặc completeness attestation.
4. Hướng dẫn cài/rollback không đụng rule khác, Active Response/integrations
   cần được kiểm tra riêng trước lab.

Các giới hạn còn lại:

- Chưa kiểm chứng PCRE2, decoder và parent SID trên Wazuh 4.14.4 của lab.
  Python chỉ kiểm tra XML/pattern subset; `not_demo` không có nghĩa no alert.
- Runtime thành công/timeout, service/log access thực tế xuyên window, clock
  và thu log đầy đủ chưa được lab xác minh. Unit doubles không thay thế việc đó.
- Runner không phải sandbox chống operator độc hại hoặc concurrent writers;
  kit/output phải nằm trong thư mục riêng tin cậy, không sửa JSON/hash thủ công.
- Chưa có export packaging/attestation, frozen evaluation profile, reports A/B/C
  hoặc `Regression Passed`. Issue #12 chưa hoàn tất và chưa được đóng.

## Cập nhật lab và kit endpoint — 2026-09-13

Phần này cập nhật trạng thái lab cũ ở trên. Kết quả remote là do người dùng
gửi trong hội thoại; agent không SSH hoặc tự kiểm tra manager/endpoint.

### Synthetic trên clone riêng

- Người dùng dùng clone Wazuh 4.14.4 trên mạng Host-only. Chỉ trên clone,
  rule 60000 được đổi từ category ossec/decoder windows_eventchannel sang
  decoder json để kiểm tra raw synthetic JSON qua logtest. Không mang thay
  đổi này sang manager gốc; đây không phải kiểm chứng native Windows decoder.
- Bộ synthetic dùng host SYNTHETIC-ENDPOINT, custom ID 117001, parent 91816.
  Baseline: original khớp 117001:5; renamed khớp 91816:4. Comment-only khớp
  baseline filename là giới hạn đã dự kiến. Các controls còn lại không khớp
  demo ID; một số vẫn khớp rule cha, không có nghĩa không có alert.
- Fixed: người dùng báo đủ 12 controls PASS; original/renamed khớp 117001:5,
  mười controls còn lại không khớp demo ID. Kết quả được lưu trên clone tại
  `/root/aegis-fixed-controls.REDACTED`; baseline controls tại
  `/root/aegis-baseline-controls.REDACTED`.
- Clone đã được người dùng tắt trước khi mở lại hệ thống gốc. Không restart
  hoặc kết nối clone mang danh tính sao chép vào mạng lab gốc.

### Manager gốc và LAB-ENDPOINT-01

- Manager gốc: người dùng báo active, config test exit 0; agent AGENT-01
  LAB-ENDPOINT-01 Active. Tìm ID 117001 trong hai rule directories không thấy.
- log_alert_level=3, email_alert_level=12. XML inspection bỏ qua comment:
  không có active-response block trong ossec.conf; có custom-discord level 5,
  format json, không có filter rule_id/group/event_location được khai báo.
  Không suy ra trạng thái mọi automation hoặc nội dung custom script từ đây.
- Người dùng đã cho phép alert demo có thể gửi tới Discord hiện tại sau khi
  được giải thích về khả năng chia sẻ dữ liệu alert. Không đọc webhook/token,
  không đổi integration, firewall hoặc ngưỡng alert.
- LAB-ENDPOINT-01: user lab-endpoint-01\\<user>, Windows PowerShell 5.1.19041.6456 x64,
  Sysmon64 và WazuhSvc Running. Đây chưa phải chứng cứ thu đủ telemetry.
- Ngoại lệ được người dùng duyệt so với kế hoạch ban đầu: CurrentUser đổi
  từ Undefined (effective Restricted) sang RemoteSigned trên LAB-ENDPOINT-01.
  Không dùng Bypass; giữ cùng policy qua các lượt. Sau demo cần hướng dẫn
  người dùng khôi phục CurrentUser Undefined, không tự thay scope khác.
- Đường dẫn endpoint được người dùng xác nhận chưa tồn tại:
  `C:\Users\<user>\Downloads\AEGIS-SafeDemo`.

### Kit endpoint mới do agent tạo offline

- Nguồn: worktree issue-12-safe-demo, code commit fb05d3c.
- Output riêng ngoài Git:
  `C:\Users\<devuser>\Downloads\aegis-lab-endpoint-01-kit-20260913`.
- Bindings: LAB-ENDPOINT-01, đường dẫn endpoint ở trên, rule 117001, parent 91816.
  occupied_ids_declared là tập IDs đã biết từ output trước đó, không phải
  inventory toàn bộ ruleset. Cần kiểm tra lại ID trước khi cài.
- Baseline SHA-256:
  `81c39edb962243f95611ad6e64bdb8f51f1bb2e91c84618b93b4fe5446c71d6d`.
- Fixed SHA-256:
  `732fa1c4010991e67e8409161d8e454c1e76710e698d86be99d110eb51190d6e`.
- Hai payload cùng SHA-256:
  `0226fc3c28de6589d50bc2f7c17a49c5d5a546ed9cd42efad1f6c87f8071bd69`.
- Kiểm chứng mới: test_scn001_kit.py **47 passed in 0.52s**; generator trả
  prepared_not_executed; agent đọc lại và đối chiếu đủ 18 artifact hashes,
  hostname/path bindings và hai XML đã render. Không chạy lại full suite
  trong lượt tạo kit này; không sửa source code.

Chưa chuyển kit lên lab, chưa cài rule endpoint trên manager gốc, chưa chạy
preflight/Execute hoặc có evidence rehearsal. Parent 91816 đã được kiểm tra
trên clone với JSON adapter; native Windows event path còn cần kiểm chứng.
Bước kế: chuyển kit vào staging riêng ngoài rules, kiểm tra hash sau chuyển,
review/cài đúng một revision theo guard đã duyệt và xác minh native telemetry.
Không cài đồng thời baseline/fixed; không trộn synthetic cases vào evidence.
Export/attestation, frozen profile và A/B/C evaluation vẫn chưa hoàn thành.

### Rehearsal thực tế — kết quả người dùng gửi tiếp ngày 2026-09-13

- LAB-ENDPOINT-01 tải kit qua staging manager, báo KIT_VERIFIED=18/18 và
  PAYLOAD_NOT_EXECUTED trước khi chạy. Agent đối chiếu manifest gốc SHA-256:
  `322a91c291d565066cb0e911ba42d13cdb1a205edd409fd27553ca4891459c80`.
- Manager gốc đã cài baseline đúng hash ở
  `/var/ossec/etc/rules/117001-aegis-safe-demo.xml`; bản lưu root-owned:
  `/root/aegis-live-baseline.REDACTED/baseline.xml`. Config test không có
  warning/error; user restart manager và báo active lúc 14:41:30Z.
  Agent AGENT-01 LAB-ENDPOINT-01 sau đó kết nối lại Active, client 4.14.4.
- Preflight LAB-ENDPOINT-01 trả ready/executed=false, exit 0 và run directory
  chưa tồn tại. Không thay default rule 60000 trên manager gốc.
- Lượt `rehearsal-5b4cd73c37e74353a67fcd028f950018`: start
  14:44:20.5920273Z, child 5724 launch 14:44:30.8260273Z, runner 7652.
  Có stdout marker/PID nhưng không có execution.json; người dùng xác nhận
  đã bấm Ctrl+C. Hai lần retry cùng directory bị AEGIS_RUN_OUTPUT_EXISTS,
  exit 2 trước launch mới. Giữ lượt cũ là incomplete; không xóa, không dựng
  lại final manifest và không dùng nó làm detection/evaluation run hoàn tất.
- Đã sửa cách hướng dẫn console: gom guard/preflight/Execute trong cùng
  `& { ... }`, để throw dừng block. Chưa thay source code runner.
- Lượt mới `rehearsal-a516e556bc85410895b4d797ce0a930b` được người dùng
  báo executed_not_evaluated, REHEARSAL_EXIT=0; final manifest status executed,
  child_pid=7196, exit_code=0, timed_out=false, failure_code trống.
- Window start: `2026-09-13T14:49:59.2524181+00:00`;
  launch: `2026-09-13T14:50:09.4096364+00:00`;
  observed end: `2026-09-13T14:51:59.4557423+00:00`;
  elapsed_seconds=120.1913706.
- Output giữ riêng trên endpoint tại
  `C:\Users\<user>\Downloads\rehearsal-a516e556bc85410895b4d797ce0a930b`.

Đây là xác nhận thực thi từ output người dùng, chưa phải canonical evidence
hoặc telemetry completeness. Bước kế tiếp: tìm metadata Sysmon 1/PS4104
liên quan đúng host/PID/window trên manager và đối chiếu endpoint nếu cần.
Rehearsal dùng maintenance_check.ps1 với baseline nên không kỳ vọng demo ID
117001 khớp; vẫn có thể có parent/other-rule alerts. Chưa có kết luận Detection
Gap/Regression Passed. Chưa đổi fixed, chưa đóng Issue #12. CurrentUser
RemoteSigned vẫn đang là ngoại lệ lab được duyệt; còn bước khôi phục sau demo.

### Metadata Wazuh gốc khớp rehearsal mới

Người dùng lọc 20.000 dòng alerts.json gần nhất theo agent AGENT-01, provider,
Event ID và child PID 7196, gửi hai record metadata (không gửi full script):

| Loại | Wazuh source record ID | Event time UTC | Received UTC | Rule/level |
| --- | --- | --- | --- | --- |
| PowerShell 4104 | 1789311013.3580073 | 2026-09-13T14:50:09.6294732Z | 2026-09-13T14:50:13.977Z | 91816 / 4 |
| Sysmon 1 | 1789311015.3582304 | 2026-09-13T14:50:09.4364849Z | 2026-09-13T14:50:15.083Z | 92029 / 6 |

Cả hai có computer LAB-ENDPOINT-01 và decoder windows_eventchannel. PS4104 dùng
system.processID=7196, path maintenance_check.ps1 trong kit đã chọn,
scriptBlockId=a8a885f5-6ef1-41c9-bfce-63482fae3b72, counters 1/1 và có demo
marker. Sysmon dùng eventdata.processId=7196; system.processID=2852 là trường
khác, không được thay thế PID tiến trình mới. has_demo_marker=false ở Sysmon
là kết quả kiểm tra field scriptBlockText vốn không có, không phải mất marker.

Metadata này hỗ trợ xác nhận cả hai loại telemetry của rehearsal đã tới
manager và parent PS91816 hoạt động với native Windows decoding. Đây là
Wazuh source IDs, chưa phải canonical evidence IDs. Không suy ra collection
completeness hoặc không có alert khác từ truy vấn tail hữu hạn. PS record
được trả về khớp parent, không phải demo ID117001, phù hợp tên đã đổi trên
baseline. Chưa kết luận Detection Gap hoặc Regression Passed. Còn kiểm tra
script text exact-match (marker presence không đủ), export/attestation và
frozen evaluation profile trước A/B/C chính thức.

### Khác biệt biểu diễn PS4104 — đang chẩn đoán, chưa sửa rule

Người dùng đối chiếu Wazuh source record 1789311013.3580073 với Windows event
RecordId 5318, cùng ScriptBlockId a8a885f5-6ef1-41c9-bfce-63482fae3b72,
PID 7196 và event time 2026-09-13T14:50:09.6294732Z:

- Windows: script length 69, có 2 LF; ExactReviewedScript=true,
  EqualsFlattenedScript=false, ExactNativePath=true; counters 1/1.
- Wazuh sau json.loads: script length 68, không CR/LF/backslash;
  đúng bằng hai dòng reviewed script nối bằng một space, bỏ newline cuối.
  Đường dẫn length 66, có 10 backslash, đúng bằng native path với từng
  backslash nhân đôi. Không khớp native path literal.
- Đây không phải bằng chứng payload bị sửa. Không unescape hoặc khôi phục
  newline ngầm trong parser; biến đổi mất thông tin không đảo ngược duy nhất.
- Chưa xác định đầy đủ biểu diễn ở thời điểm rule matching so với thời điểm
  ghi alert. Cần pin nguồn/tái hiện trước thiết kế sửa templates; không sửa
  ngay bằng cách nới regex theo chuỗi trong alerts.json.
- Đã đọc mã nguồn Wazuh tag v4.14.4 winevtchannel.c: decoder dựng dữ liệu
  EventData và gọi JSON_Decoder_Exec; cần kiểm tra tiếp xử lý dynamic fields
  và alert serialization. Link:
  https://github.com/wazuh/wazuh/blob/v4.14.4/src/analysisd/decoders/winevtchannel.c

Baseline gốc vẫn giữ hash đã áp dụng. Fixed chưa cài; không chạy A/B/C mới,
không thay payload, runner, canonical, ground truth hoặc ruleset mặc định.

### Sửa tương thích offline sau khi người dùng duyệt — 2026-09-13

Phần này cập nhật trạng thái chẩn đoán ở trên; không thay lịch sử rehearsal.
Đã trace nguồn Wazuh v4.14.4: agent đổi CR/LF trước gửi, manager xử lý
EventData/trimming và dynamic fields trước rule matching. Chi tiết nguồn,
giới hạn lossy và kế hoạch lab nằm trong
[SCN001_EVENTCHANNEL_PROFILE.md](SCN001_EVENTCHANNEL_PROFILE.md).

- Thêm profile chọn rõ `wazuh-eventchannel-4.14.4-lf-v1`; mặc định cũ
  `decoded-json-v1` giữ nguyên rule bytes với cùng bindings.
- Native baseline khớp path field có backslash nhân đôi; fixed khớp exact
  flattened representation của payload LF đã review. Không nới whitespace
  tùy ý, không phục hồi source text ngầm. Giữ guards/parent/ID/level.
- Metadata profile nằm trong kit/catalog và comment XML. Kit format vẫn
  0.1.0 (additive metadata), không đổi scenario version hoặc runner.
- Test trước code: 14 failed / 47 passed do API/CLI chưa có profile;
  sau triển khai: 61 passed. Test literal regex không phải PCRE2/Wazuh thật.
- Full backend mới chạy bằng Python venv 3.13.14: **2114 passed, 1 skipped
  in 67.76s**. Skip `test_intake_io.py:452`: FIFO unavailable on Windows.
  `pip check`: No broken requirements found. `git diff --check`: exit 0;
  Git có cảnh báo chuyển LF/CRLF, không có lỗi whitespace.

Lệnh kiểm chứng (tại worktree issue-12-safe-demo):

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_kit.py -q -p no:cacheprovider --basetemp ('build/pytest-native-focused-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-native-full-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Đã tạo riêng kit **synthetic review-only**, đối chiếu 18/18 artifact hashes,
đọc cả hai XML render; không chạy payload hoặc chuyển/cài lên lab:
`build/scn001-native-review-f74ad4c9dc58497e860683238790ab40`.
Bindings synthetic, không dùng kit đó để cài trực tiếp trên LAB-ENDPOINT-01.
Payload hash vẫn `0226fc3c28de6589d50bc2f7c17a49c5d5a546ed9cd42efad1f6c87f8071bd69`.

Tự review diff: scope chỉ generator/template/tests/tài liệu; regex anchored,
profile unknown bị từ chối trước write; giữ evidence và mọi lượt cũ; không
đọc raw lab exports hoặc credential. Chưa review độc lập bản sửa mới, chưa
kiểm chứng PCRE2/native end-to-end của revision mới. Chưa commit/push/merge.

**Điểm kiểm soát kế tiếp:** ID 117001 đang có baseline, nên không dùng luồng
cài mới hoặc khai báo inventory `none`. Cần review quy trình đổi revision có
target/hash guard, chuẩn bị kit lab mới mà không overwrite kit cũ, rồi mới
test/restart/rehearsal. Không lách guard ID occupied trong generator. Chưa
triển khai cơ chế nâng cấp kit; chưa thay bất kỳ file nào trên manager hoặc
LAB-ENDPOINT-01. A/B/C và export/attestation vẫn là phần chưa hoàn tất.

### Tiếp tục review và chuẩn bị đổi revision — 2026-09-14

- Người dùng duyệt bản sửa và yêu cầu tiếp tục. Đã kiểm tra lại worktree
  `codex/issue-12-safe-demo`, HEAD fb05d3c; giữ các thay đổi chưa commit.
- Review tuần tự generator, template và test profile: chưa phát hiện lỗi mới
  trong phạm vi này; không gọi đây là review độc lập hay PCRE2 validation.
- Chạy lại test kit: **61 passed in 1.45s**. Không chạy lại full backend
  trong lượt chỉ-review này; kết quả 2114/1 ở trên thuộc lượt trước.
- Đối chiếu lại kit cũ trên máy phát triển: baseline 81c39e…c71d6d,
  fixed 732fa1…190d6e, manifest 322a91…91459c80 vẫn khớp hash lịch sử.
  Không sửa, di chuyển hoặc ghi đè kit cũ.
- Chờ người vận hành gửi trạng thái mới từ manager gốc: hash exact target,
  mọi chỗ tham chiếu 117001 trong rules, config test và service state. Lệnh
  kiểm tra không cài rule, không restart và không chạy payload. Chưa tạo
  kit nâng cấp cho lab, chưa thêm tùy chọn bỏ qua occupied-ID guard.

### Manager gốc xác nhận lại — output người dùng ngày 2026-09-14

Lúc `2026-09-14T12:05:17Z`, người vận hành gửi:

- Exact target `/var/ossec/etc/rules/117001-aegis-safe-demo.xml` khớp SHA-256
  baseline `81c39edb962243f95611ad6e64bdb8f51f1bb2e91c84618b93b4fe5446c71d6d`.
- `CONFIG_TEST_EXIT=0`, không có cảnh báo/lỗi trong output được gửi.
- Tìm chuỗi 117001 trong hai rule directories chỉ trả về target trên, dòng 3,
  rule level 5. Không suy rộng thành kiểm kê mọi include ngoài hai thư mục.
- `wazuh-manager` active. Chưa thay revision hoặc restart trong bước này.

Đã hướng dẫn tạo backup mới root-private ngoài rules, kiểm tra hash trước
và sau copy. Chờ đường dẫn backup từ người dùng; chưa tuyên bố backup đã
tạo. Mục tiêu tiếp tục là chuẩn bị revision riêng giữ nguyên ID/host/parent/
payload, có provenance bản cũ và không overwrite kit cũ hoặc bỏ qua kiểm
tra ID đang dùng. Chưa cài baseline native/fixed, chưa chạy rehearsal mới.

### Backup xác nhận và gói revision mới — 2026-09-14

Người dùng báo backup thành công tại
`/root/aegis-native-upgrade.REDACTED/baseline-before.xml`, hash baseline khớp,
live file chưa thay và service chưa restart trong bước backup.

Đã chuẩn bị gói nâng cấp offline ngoài repository:
`C:\Users\<devuser>\Downloads\aegis-native-upgrade-20260914`.
Đây là revision của kit đã hash, không phải tạo rule ID mới. Không gọi
`prepare_kit` với inventory giả; không sửa guard generator. Chi tiết quy trình
artifact và giới hạn metadata ở mục 6 `SCN001_EVENTCHANNEL_PROFILE.md`.

- Host LAB-ENDPOINT-01, rule 117001 level 5, parent 91816 giữ nguyên.
- Lab directory mới: `C:\Users\<user>\Downloads\AEGIS-SafeDemo-NativeV1`.
- Field profile: `wazuh-eventchannel-4.14.4-lf-v1`.
- Baseline SHA-256:
  `6b5b861532ac05fb9c993759a40434cfec9ecd3ed2fb400ccf4a5adf63a9d373`.
- Fixed SHA-256:
  `3e7fd335bb67f61fe72ff6db4b4860711dc4dcc018e88274dea5c26a84a47585`.
- Kit manifest SHA-256:
  `e3c8c4f023393a7e646f390cd4c86474c4d9d423fe74e61401444bd08da983df`.
- Payload và runner giữ nguyên bytes; kiểm tra 18/18 artifact hashes trước
  khi ghi manifest và lần nữa sau khi ghi. Không chạy payload.
- Test kit chạy mới trong lượt chuẩn bị: **61 passed in 1.03s**; full backend
  không chạy lại vì không thay source/tests trong lượt này. Đã đọc XML render
  và kiểm tra lại hash manifest kit cũ còn nguyên. Chưa kiểm thử PCRE2 hoặc
  preflight native trên lab với gói mới.

Chuẩn bị lệnh chuyển qua SSH/SCP do người dùng chạy trên Windows phát triển:
tạo mới `/home/soc/aegis-native-stage-20260914`, từ chối nếu đã tồn tại;
copy gói vào staging này, chưa vào rules. Chưa có output xác nhận chuyển
file, chưa tuyên bố đã staging/deploy. Trước thay baseline cần đối chiếu hash
candidate, diff, target/backup và config trên manager; không bỏ qua cảnh báo.

### User xác nhận chuyển gói nâng cấp vào staging

Người dùng gửi output SCP đủ kit và `TRANSFER_OK — chua cai rule, chua
restart, chua chay demo.` Đích theo lệnh đã cấp:
`/home/soc/aegis-native-stage-20260914/aegis-native-upgrade-20260914`.
Chưa có kết quả hash readback phía manager, nên chưa coi xác minh sau truyền
đã hoàn tất. Đang yêu cầu đối chiếu manifest/baseline/fixed cùng live/backup
và diff baseline, chỉ đọc; chưa cấp lệnh install hoặc restart.

Đã đối chiếu diff hai baseline ở máy phát triển: chỉ thêm comment profile và
đổi regex path sang biểu diễn doubled-backslash trong thư mục NativeV1 mới.
ID 117001, level 5, parent 91816 và các guards giữ nguyên. `git diff --no-index`
trả 1 vì có khác biệt, không phải lỗi kiểm thử. Không thay source/tests trong
lượt đối chiếu này, không chạy lại full suite hoặc tuyên bố live rule đã áp dụng.

### Hash/diff staging phía manager đã được người dùng xác nhận

Output người dùng: manifest, baseline mới, fixed mới, live baseline cũ và
backup L1FVC9 đều OK theo 5 hash đã pin. Diff baseline khớp chính xác diff
local: thêm comment field profile, đổi regex path sang doubled-backslash và
thư mục NativeV1; không đổi ID/level/parent/guards. Kết thúc
`READ_ONLY_CHECK_DONE — nothing installed.`

Bước đang hướng dẫn: chụp candidate/bản cũ vào thư mục root-private mới,
đối chiếu lại hash, thay đúng file demo rồi config test; warning/error hoặc
test fail thì khôi phục bản cũ và kiểm tra lại. Không restart tự động, không
cài fixed, không sửa default rules/agent/payload. Chưa nhận output thực hiện
bước này; không coi baseline native đã được ghi hoặc nạp vào manager.

### Người dùng xác nhận ghi baseline native, chưa restart

Output tiếp theo cho biết:

- `APPLY_DIRECTORY=/root/aegis-native-apply.REDACTED`.
- Live cũ, backup L1FVC9, staging candidate, root-private before/candidate
  và live sau install đều qua hash checks theo block đã cấp.
- Kết thúc `NATIVE_BASELINE_CONFIG_OK — service NOT restarted.`

Do đó đã có báo cáo ghi file baseline native và config test sạch; chưa có
xác nhận manager runtime nạp revision mới hoặc rule match thực tế. Bản gốc
giữ tại QEn5al/before.xml và L1FVC9/baseline-before.xml. Fixed chưa cài.
Bước kế: operator đối chiếu hash/config lại, restart manager có chủ đích,
kiểm tra active và agent AGENT-01. Chưa chuyển kit mới sang endpoint hoặc chạy
rehearsal mới. Các kết quả ở đây do người vận hành gửi, không phải agent
trực tiếp điều khiển/kiểm tra remote.

### Sau restart native baseline — cần xác nhận agent kết nối lại

Output người dùng tại `2026-09-14T12:18:42Z`: live baseline hash OK,
manager `active`, agent AGENT-01 LAB-ENDPOINT-01 `Disconnected`. Last keep alive
1789388310 đổi sang UTC là `2026-09-14T12:18:30Z` (12 giây trước thời điểm
kiểm tra). Chưa đủ dữ liệu kết luận lỗi lâu dài hoặc do rule; có thể đang
trong giai đoạn kết nối lại. Không restart liên tiếp hoặc sửa cấu hình.

Đang hướng dẫn kiểm tra lại agent sau 30–60 giây; nếu vẫn disconnected thì
đọc hostname/time và trạng thái WazuhSvc/Sysmon trên LAB-ENDPOINT-01. Tạm dừng
chạy demo; chưa có xác nhận active của endpoint hoặc rule match thực tế.

### Kết nối agent đã trở lại — 2026-09-14

User gửi manager status lúc `2026-09-14T12:21:06Z`: agent AGENT-01 LAB-ENDPOINT-01
Active, client 4.14.4, last keep alive 1789388450. Endpoint hostname
LAB-ENDPOINT-01, time `2026-09-14T19:22:19.4160113+07:00`, WazuhSvc và Sysmon64
Running. Không cần sửa service/firewall để giải quyết trạng thái disconnected
tạm thời này. Chưa suy ra telemetry completeness hoặc demo rule match.

Bước đang hướng dẫn: SCP từ staging manager tới thư mục mới
`C:\Users\<user>\Downloads\AEGIS-SafeDemo-NativeV1` trên LAB-ENDPOINT-01,
từ chối target tồn tại; pin kit manifest SHA-256 e3c8c4…da983df rồi xác minh
18 artifact hashes trước preflight. Chưa có output chuyển/verify từ endpoint,
chưa chạy payload hoặc preflight của kit mới. Hash kit manifest ở máy phát
triển vừa kiểm tra lại vẫn đúng giá trị đầy đủ ghi ở phần gói revision.

### Kit native đã xác minh trên LAB-ENDPOINT-01

Người dùng báo SCP hoàn tất, `KIT_VERIFIED=18/18`, kit directory đúng
`C:\Users\<user>\Downloads\AEGIS-SafeDemo-NativeV1`, `PAYLOAD_NOT_EXECUTED`.
Block đã cấp kiểm tra pinned manifest hash, host/path bindings và artifact
hashes/reparse guards. Đây là xác nhận từ output người dùng; chưa có run mới.

Bước kế là preflight với RunLabel Rehearsal, baseline hash
`6b5b861532ac05fb9c993759a40434cfec9ecd3ed2fb400ccf4a5adf63a9d373`,
RunId/thư mục mới. Không truyền -Execute. Chờ output ready/executed=false,
exit 0, run directory chưa tồn tại; chưa suy ra detection hoặc completeness.

### Preflight native chưa đạt — cần chẩn đoán quyền/kênh log

Người dùng chạy preflight mới và nhận `AEGIS_TELEMETRY_LOG_UNAVAILABLE`,
`PREFLIGHT_EXIT=2`, `RUN_DIRECTORY_EXISTS=False`. Không có -Execute; chưa
khởi chạy payload. Không được tiếp tục execution với kết quả này.

Đã đọc `Assert-AegisTelemetry` trong runner (dòng 78–96): thông báo chung
này gom lỗi ListLog, kênh disabled, đọc record thất bại hoặc không có record
Sysmon 1/PowerShell 4104. Chưa biết kênh nào và chưa kết luận thiếu quyền.
Đang hướng dẫn kiểm tra read-only ở cùng cửa sổ LAB-ENDPOINT-01: token elevated,
metadata kênh và metadata record gần nhất, giữ exception/ID lỗi gốc; không
in ScriptBlockText/Message event. Chưa nâng quyền, sửa ACL/logging, reset
service hoặc sửa runner để bỏ qua guard.

### Nguyên nhân preflight: quyền đọc Sysmon của phiên hiện tại

User gửi từ LAB-ENDPOINT-01: `IS_ELEVATED=False`; Sysmon ListLog trả
`LogInfoUnavailable` / `Attempted to perform an unauthorized operation`.
Kênh PowerShell Operational enabled, RecordCount 4477, đọc được 4104
RecordId 6297 lúc 19:28:45 theo đồng hồ endpoint. Không in nội dung event.

Đã xác định điểm chặn ở quyền đọc Sysmon của phiên PowerShell hiện tại,
không phải bằng chứng channel Sysmon mất hoặc rule Wazuh lỗi. Dừng trước
bước nâng quyền: hỏi người dùng có đồng ý mở Windows PowerShell bằng Run as
administrator qua UAC chỉ để kiểm tra đọc hai kênh hay không. Chưa nâng quyền,
đổi ACL/thành viên nhóm/policy, chưa chạy preflight hoặc payload bằng admin.
Nếu execution context thay đổi cho các lượt sau, cần ghi nhận và giữ nhất
quán khi so sánh; không trộn các lượt có quyền khác nhau như cùng điều kiện.

### Kiểm tra đọc log elevated đã được duyệt và thành công

Người dùng đồng ý mở Administrator chỉ để kiểm tra đọc kênh. Output mới:
LAB-ENDPOINT-01, cùng tài khoản `lab-endpoint-01\<user>`, `IS_ELEVATED=True`.
Sysmon Operational enabled, RecordCount 3204, đọc Event 1 RecordId 3204
lúc 19:30:29. PowerShell Operational enabled, RecordCount 4507, đọc 4104
RecordId 6320 lúc 19:30:31 (giờ endpoint ngày 2026-09-14).

Đối chiếu cùng tài khoản: phiên không elevated bị từ chối Sysmon, phiên
elevated đọc được. Không cần sửa ACL/logging hoặc cài lại Sysmon để giải
quyết kiểm tra đọc này. Bước kế là preflight read-only trong cửa sổ mới với
hash baseline native và RunId mới; không -Execute. Chưa có kết quả preflight
elevated và chưa thực thi payload bằng quyền Administrator; phải giữ rõ
execution context nếu tiếp tục sang các lượt lab so sánh.

### Preflight elevated của kit native đã đạt

User gửi `safe_demo_preflight`, status ready, executed=false,
PREFLIGHT_EXIT=0, RUN_DIRECTORY_EXISTS=False trong cửa sổ Administrator
đã kiểm tra ở trên. Đây là preflight thành công do người vận hành báo, chưa
phải execution, detection, collection completeness hoặc Regression Passed.

Trước -Execute: đang xin xác nhận riêng chạy rehearsal vô hại bằng quyền
Administrator (quyền đã duyệt trước đó chỉ là đọc log/preflight). Rehearsal
chọn maintenance_check.ps1 trên baseline, nên không kỳ vọng demo ID117001;
mục tiêu là kiểm tra runner và telemetry với kit native. Nếu được duyệt,
dùng RunId/thư mục mới, preflight lại cùng block trước Execute và giữ nguyên
các kiểm tra. Không trộn execution contexts cho A/B/C; chưa có approval hoặc
output execution elevated của lượt mới tại thời điểm ghi checkpoint này.

### Đã được phép thực thi rehearsal elevated trong lab

Người dùng trả lời đồng ý/toàn quyền trong lab cho câu hỏi chạy rehearsal
bằng Administrator trên LAB-ENDPOINT-01. Phạm vi thực hiện vẫn là demo vô hại
đã review; không mở rộng sang đổi firewall, policy, ACL hay kịch bản khác.

Đang cấp block duy nhất: xác nhận host/elevation và runner hash, tạo RunId
mới, preflight lại, kiểm tra output directory chưa tồn tại, rồi -Execute;
đọc final manifest metadata sau khi hoàn tất. Rehearsal dùng tên renamed
trên baseline nên chưa kỳ vọng demo ID117001. Chưa nhận output -Execute;
không tuyên bố run mới đã chạy hoặc pass. Giữ các lượt cũ nguyên vẹn.

### Rehearsal native elevated hoàn tất — chờ đối chiếu telemetry

Output người vận hành gửi: LAB-ENDPOINT-01, LAB-ENDPOINT-01\<user>,
IS_ELEVATED=True; preflight ready/exit 0; execution console
executed_not_evaluated, REHEARSAL_EXIT=0.

- Run ID: rehearsal-native-4980a0adcd694679af388d91dbcf4334.
- Thư mục endpoint: C:\Users\<user>\Downloads\rehearsal-native-4980a0adcd694679af388d91dbcf4334.
- Final manifest status executed, child_pid 7552, exit_code 0,
  timed_out False, failure_code trống.
- window_start_utc: 2026-09-14T12:37:49.4410929+00:00.
- launch_utc: 2026-09-14T12:37:59.5347186+00:00.
- window_observed_end_utc: 2026-09-14T12:39:49.5722037+00:00.
- elapsed_seconds: 120.10832429999999.

Đây là metadata người vận hành báo, chưa thu thập/kiểm hash final manifest
hoặc raw evidence. Bước tiếp chỉ đọc metadata alert agent AGENT-01 cho Sysmon 1
(eventdata.processId) và PowerShell 4104 (system.processID) của PID 7552,
đối chiếu thời gian nguồn với cửa sổ trên. Không suy ra detection gap từ
việc query không ra hoặc khẳng định collection completeness; chưa có
canonical evidence IDs, evaluation verdict hay Regression Passed. Không
thay rule, restart hoặc chạy thêm payload ở checkpoint này.

### Metadata Wazuh nhận được cho rehearsal native PID 7552

User gửi hai bản ghi agent AGENT-01, LAB-ENDPOINT-01, decoder windows_eventchannel:

- PowerShell 4104: source_record_id `1789389484.4343572`, rule 91816,
  level 4; source time 2026-09-14T12:37:59.7923604Z, received
  2026-09-14T12:38:04.891+0000. system.processID 7552;
  ScriptBlockId `14a515f9-2e6b-42e2-99b7-fc7db228c363`, counters 1/1,
  marker present, path hiển thị maintenance_check.ps1 trong kit NativeV1.
- Sysmon 1: source_record_id `1789389486.4345839`, rule 92029,
  level 6; source time 2026-09-14T12:37:59.5732995Z, received
  2026-09-14T12:38:06.003+0000. eventdata.processId 7552;
  system.processID 2804 không phải PID child để liên kết run này.

Hai source times sau launch và trong cửa sổ rehearsal, hỗ trợ đường đi
telemetry cho hai record này. ID trên là source record IDs, không phải
canonical evidence IDs. Chưa xác nhận exact decoded script/path bằng
so sánh sau JSON parse, chưa kiểm native event mới, chưa đóng băng export.
Không coi marker hoặc hai alerts là bằng chứng collection completeness,
baseline positive match hay Regression Passed. Bước tiếp đọc đúng PS source
record ID, chỉ xuất booleans cho profile đã pin, không in ScriptBlockText.

### Exact decoded profile đã đối chiếu với record rehearsal mới

Người vận hành đọc source record `1789389484.4343572` bằng json.loads:
agent_matches, pid_matches, script_block_id_matches, exact_decoded_script,
exact_decoded_path và counters_complete đều true; MATCHED_RECORDS=1.
Đây là phép so sánh chuỗi với profile native đã pin, không phải phép test
rule fixed bằng PCRE2 và không chứng minh raw source bytes từ chuỗi lossy.

Bước tiếp đối chiếu read-only Windows 4104 gốc trên LAB-ENDPOINT-01 bằng đúng
ScriptBlockId `14a515f9-2e6b-42e2-99b7-fc7db228c363`, PID 7552 và thời gian
2026-09-14T12:37:59.7923604Z. Chỉ xuất metadata/booleans; không in Message,
ScriptBlockText hay xuất raw logs. Chưa có kết quả native event mới tại
checkpoint này; không đổi rule/chạy payload thêm, chưa đánh giá A/B/C.

### Native Windows đối chiếu thành công — kết thúc kiểm tra rehearsal

Người vận hành gửi kết quả read-only Windows 4104: RecordId 7209,
EventTimeUtc 2026-09-14T12:37:59.7923604Z, ProcessId 7552;
PidMatches, ExactReviewedLFScript, ExactNativePath, CountersComplete đều
True và MATCHED_EVENTS=1. Query chọn chính xác ScriptBlockId
`14a515f9-2e6b-42e2-99b7-fc7db228c363`.

Đối chiếu với Wazuh source record `1789389484.4343572` cho thấy native
script/path đúng payload đã review trong event này, và decoded string/path
khớp profile native đã chọn. Sysmon source record `1789389486.4345839` hỗ
trợ process launch cùng PID/time. Đủ kết thúc các kiểm tra metadata/exact
representation của rehearsal này; không cần chạy lại rehearsal chỉ để lặp
lại cùng kiểm tra. Kết quả do người vận hành cung cấp, chưa phải bundle
evidence đã thu/kiểm hash độc lập hoặc canonical evaluation report.

Baseline native vẫn giữ nguyên, fixed chưa áp dụng. Theo README, bước còn
thiếu trước A/B/C chính thức là thiết kế export/scope/attestation, khóa
evaluation profile rồi mới thu các lượt A/B/C và dùng validate/compare.
Không suy ra toàn hệ thống không phát hiện từ việc thiếu demo ID 117001:
rehearsal đã có rules 91816 và 92029. Không tuyên bố Issue #12 hoàn tất hoặc
Regression Passed. Không đổi ground truth, policy, firewall hay rule ở bước này.

### Chốt hướng snapshot manager offline — bản thiết kế để review

User đã duyệt chọn alerts.json snapshot offline và giữ đường mở rộng API/UI
sau này. Đã khảo sát code parser/engine/compare/runner và viết bản chi tiết
`docs/superpowers/specs/2026-09-14-scn001-offline-evidence-design.md`.
Đây là phần kiến trúc export/evaluation, không phải tiếp tục sửa kit đơn lẻ.

Các điểm đã cụ thể hóa: adapter `_source` tường minh giữ bytes record; ledger
snapshot/line/document hashes; không export-filter theo rule/PID/marker;
planned window đúng 120 giây; profile/bindings cố định; run-binding review
riêng vì telemetry roots không hỗ trợ correlation; attestation unknown mặc định.
Runner hiện có window_planned_end_utc, không cần sửa thời gian manifest.

Tự đọc lại spec, kiểm scope/compatibility/lossy boundary và ma trận tests.
`git diff --check` exit 0 với cảnh báo LF/CRLF của các pending files trước đó.
Không chạy pytest/pip check vì lượt này chỉ thêm tài liệu; không nhận test cũ
là kiểm chứng mới. Chưa source implementation, chưa mở raw export/credential,
không commit/push/merge hoặc remote write. Bản chi tiết chờ user review theo
brainstorming trước khi chuyển writing-plans và TDD tuần tự.

### 2026-09-14 — Adapter snapshot offline đã triển khai và kiểm chứng

User đã duyệt triển khai bản thiết kế. Làm tuần tự trong worktree
`issue-12-safe-demo`, branch `codex/issue-12-safe-demo`, không subagent.
Kế hoạch phần đầu: `docs/superpowers/plans/2026-09-14-manager-snapshot-adapter.md`.
API và giới hạn: `docs/WAZUH_MANAGER_SNAPSHOT.md`.

Đã thêm adapter bytes-only trong `connectors/wazuh/manager_snapshot.py`,
contracts và scope helpers. Nhận snapshot bytes + hash + scope tường minh;
giữ hash snapshot, physical line với offset/length và wrapped document riêng.
Gọi parser Sysmon1/PowerShell4104 hiện có; không đổi canonical/engine/compare.
Scope dựa agent/host/provider/event/time chính xác nanosecond, không chọn theo
rule/PID/path/marker. Malformed/unknown classification, duplicates và vượt
giới hạn gây lỗi toàn bộ; absent fields giữ null; assurance luôn unknown.

Test mới dùng synthetic, không mở raw lab exports/credentials. RED ban đầu
60 cases chưa có module, sau stub có 60 failures vì NotImplementedError;
implement rồi 60 passed. Bổ sung edge cases và CLI integration thành 105 cases.
CLI integration thực sự gọi validate trên bundle synthetic tạm, kiểm canonical
IDs/raw references và Inconclusive khi collection chưa được xác nhận.

Kiểm chứng mới trên Windows, Python 3.13.14 của `.venv` trong worktree:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_wazuh_manager_snapshot.py -q --tb=short -p no:cacheprovider --basetemp ('build/pytest-snapshot-focused-' + [guid]::NewGuid().ToString('N'))
# 105 passed in 0.96s, exit 0
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-snapshot-final-' + [guid]::NewGuid().ToString('N'))
# 2219 passed, 1 skipped in 80.28s, exit 0
& '.\.venv\Scripts\python.exe' -m pip check
# No broken requirements found., exit 0
git diff --check
# exit 0; Git cảnh báo LF -> CRLF trên một số pending files.
```

Skip: `backend/tests/test_intake_io.py:452`, FIFO unavailable on Windows.
Fresh baseline trước adapter là 2114 passed, 1 skipped trong 61.62s.
Một lượt focused không có basetemp riêng thất bại ở pytest cleanup vì
PermissionError tại thư mục temp cũ `pytest-current`; không sửa ACL/xóa thư
mục đó. Chạy lại với basetemp mới trong build đạt kết quả phía trên.

Tự review byte preservation, scope, duplicates, unknown/error behavior và
traceability qua parser/CLI; chưa review độc lập hay mutation-test automation.
Không commit/push/merge, không đổi lab rule/service/payload/runner ở phần này.
Pending native-profile changes trước đó được giữ nguyên.

**Chưa xong Issue #12:** chưa có filesystem bundle writer, study/profile/run
contracts, collection attestation hoặc formal A/B/C reports. Adapter chỉ xác
nhận bytes được cung cấp, không chứng minh snapshot đầy đủ hoặc nguồn xác thực.
Chưa chạy live collection/lab test cho adapter. Bước tiếp là hợp đồng study/run
và đóng gói bundle an toàn, sau đó xác nhận collection và đánh giá A/B/C.
Reviewer độc lập cần kiểm scope/trace/limits trước merge; người vận hành còn
phải review evidence và lab validation. Chưa được gọi Regression Passed.

### 2026-09-14 — Snapshot transport writer/verify, tiếp nối adapter

User yêu cầu tiếp tục. Đã đọc lại AGENTS/PRD/ARCHITECTURE và bản thiết kế được
duyệt; xác minh worktree `issue-12-safe-demo`, branch `codex/issue-12-safe-demo`.
Dùng writing-plans, executing-plans và TDD tuần tự, không subagent; không đổi
root checkout hoặc pending native-profile changes. Kế hoạch:
`docs/superpowers/plans/2026-09-14-snapshot-bundle-transport.md`.

Đã tạo package `aegis_verify.demo` với API `prepare_snapshot_bundle` và
`verify_snapshot_bundle`, thêm package vào pyproject (không dependency mới).
Ghi snapshot copies, wrapped documents, inputs/profile/context, ledger và
completion manifest. Config/scope phải khớp, declarations rỗng. Validate trước
write, exclusive output ngoài Git, readback và completion ghi cuối. Partial
output giữ nguyên, không cleanup. Verify tái dựng toàn bộ bytes/trace từ
snapshot copies; không chỉ tin ledger hoặc hashes do ledger tự khai báo.

Guards: regular local files/ancestors, không traversal/ADS/device/UNC/glob,
symlink/reparse/hard-link alias; size/hash/identity checks và remaining read
budget. Scope/engine/compare/canonical/runner/rules/ground truth giữ nguyên.
Không đọc raw lab exports, credentials, không SSH/restart hoặc chạy payload.
Guide API và trust boundaries: `docs/SCN001_EVIDENCE_BUNDLE.md`.

TDD: 36 import errors khi package chưa có; tạo stub rồi 36 failures vì
NotImplementedError. Implement có 35 pass và một test so sánh sai Windows
short/long path; sửa assertion kiểm cùng file thực, được 36 pass. Edge tests
bổ sung bắt malformed constructed dataclass, giới hạn read khi file lớn lên
và inventory stat limit; từng lỗi đã được tái hiện RED rồi sửa GREEN. Tổng
focused cuối 54 passed trong 6.08s, exit 0. Một số edge cases đã pass ngay vì
guards nền đã có, không tuyên bố tất cả đều có RED riêng.

Integration thực sự gọi `evaluate_bundle` của CLI với synthetic SCN-001 và
đối chiếu evidence IDs; outcome Inconclusive vì collection chưa xác nhận.
Symlink tests thực thi được trên máy này (không skipped). Failure injection
chỉ thay IO biên để kiểm disk/read errors và budget; parser/engine chạy thật.

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_snapshot_bundle.py -q -rs -p no:cacheprovider --basetemp ('build/pytest-transport-final-focused-' + [guid]::NewGuid().ToString('N'))
# 54 passed in 6.08s, exit 0
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-transport-final-' + [guid]::NewGuid().ToString('N'))
# 2273 passed, 1 skipped in 82.39s, exit 0
& '.\.venv\Scripts\python.exe' -m pip check
# No broken requirements found., exit 0
git diff --check
# exit 0; LF -> CRLF warnings trên một số pending files.
```

Full suite trước inventory-limit fix đã đạt 2272 passed, 1 skipped trong
82.70s; không dùng kết quả đó thay verification cuối. Venv không có
setuptools/wheel (`pip show` báo package not found); chưa build/test wheel,
không tự cài thêm build tools. Editable imports và runtime tests đã chạy.

Final skip: `backend/tests/test_intake_io.py:452`, FIFO unavailable on Windows.
Ngoài tracked diff, đã kiểm `git diff --no-index --check` cho files mới của
transport; chỉ có LF/CRLF warnings, không có whitespace error được báo.

Tự review trace reconstruction, partial/write ordering, context unknown,
boundary inputs và resources. Đây không phải review độc lập hoặc cam kết chống
local admin thay ancestors đồng thời. Windows ACL cần operator review; hashes
không chứng minh authenticity/collection completeness nếu cả bundle được sửa
đồng bộ. Input phải giữ bất biến giữa verify và generic CLI.

Chưa có frozen study/profile/run contracts, kit/rule/collection receipts,
attestation flow, offline CLI entry point hoặc formal A/B/C lab reports.
Transport này không đủ để đóng Issue #12 hoặc gọi Regression Passed. Bước kế
tiếp là ràng buộc study/run trước khi đưa vào thu A/B/C. User chưa cần lấy log
mới hoặc chạy lại rehearsal. Giữ branch/worktree, không commit/push/merge;
còn cần review độc lập và human lab validation trước merge.

### 2026-09-14 — Frozen study/profile/kit và runner manifest chain

User tiếp tục duyệt triển khai. Giữ worktree/branch cũ, làm tuần tự, không
subagent/commit/push/merge. Dùng writing-plans/executing-plans/TDD; đã đọc lại
AGENTS, PRD, ARCHITECTURE và runner thực tế trước khi định nghĩa fields.
Plan: `docs/superpowers/plans/2026-09-14-scn001-study-run.md`.

Đã thêm `_study_contracts.py`, `study.py`, `_execution_json.py`, `run.py` trong
package demo; 86 tests synthetic và `docs/SCN001_STUDY_RUN.md`. Không thay
scenario/canonical/engine/compare/runner hoặc rule lab.

Study đóng có hash pin ngoài bytes study, pins scenario/profile/kit/runner/
payload/rule revisions; target và literal bindings cố định. Profile kiểm đúng
A01/A02/A03 với direct asset_id, providers, paths/commands và joins [-5,+15]s.
Native executable khác canonical_executable được review riêng; không suy
escaping. Kiểm đủ 18 kit artifacts và payload bytes an toàn đã duyệt.

verify_run kiểm lại toàn bộ study bytes, ba manifests từng stage, PID/hash/
host/revision/path/arguments, stdout/stderr và rule-state receipt operator.
Window planned-start đúng 120s nanosecond, không dùng elapsed float để sửa
window. Decoder Decimal riêng chỉ cho elapsed_seconds finite; intake config
decoder chung không đổi. Trả CheckedRun có context unknown, bindings cố định
target_host/target_agent, hash tham chiếu input riêng. Không tạo canonical
events từ manifest; không tự xác minh remote account/elevation/rule state.

TDD: 58 import errors trước module, sau stub 58 failures NotImplementedError;
implement rồi một assertion test nhầm engine empty-events là Inconclusive.
Đọc lại engine, sửa test đúng Missing telemetry (không sửa engine), đạt58.
Thêm regression test native/canonical executable riêng và hai Decimal exponent
vượt miền biểu diễn; đã quan sát RED rồi sửa GREEN. Các edge guards khác test
bổ sung pass sẵn, không tuyên bố mọi case có RED riêng.

Kiểm chứng mới:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_study_run.py -q -rs --tb=short -p no:cacheprovider --basetemp ('build/pytest-study-final-focused-' + [guid]::NewGuid().ToString('N'))
# 86 passed in 6.95s, exit 0
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-study-full-' + [guid]::NewGuid().ToString('N'))
# 2359 passed, 1 skipped in 89.87s, exit 0
& '.\.venv\Scripts\python.exe' -m pip check
# No broken requirements found., exit 0
git diff --check
# exit 0; LF -> CRLF warnings cho một số pending files.
```

Skip duy nhất: `backend/tests/test_intake_io.py:452`, FIFO unavailable trên
Windows. Tests đi qua Windows fixture parsers/engine thật: no events Missing
telemetry; telemetry đủ không demo detection + collection unknown Inconclusive;
có matching witness Detected. Không tự attests collection hoặc trả Regression
Passed. Generator chỉ tạo synthetic kit test, không thực thi payload/lab.

Tự review strict types (bool không phải PID/exit0), closed fields, duplicate
JSON keys, pins và stage relations, exact timestamps, profile drift, artifact
inventory/payload, receipt hash/account/rule coverage; chưa review độc lập.
Không mở credentials/raw lab exports hoặc sửa quyền/ACL/services. Wheel build
chưa được kiểm, build tools thiếu trong venv như checkpoint trước.

Các API study/run và transport vẫn tách biệt. Chưa final offline CLI kết nối
chúng, chưa native run-binding review (PID/ProcessGuid/ScriptBlockId), chưa
collection receipt/attestation fingerprints hoặc formal A/B/C trên lab. Hashes
và receipt chỉ chứng minh consistency của khai báo local, không authenticity.
Cần review độc lập trước merge và operator review canonical literals trước A.
User chưa cần chạy thêm rehearsal hay lấy raw log mới để test phần mềm này.

## 2026-09-14 — Explicit collection review API

Tiếp tục theo thiết kế offline đã duyệt; sequential, không subagent, không
commit/push/merge hoặc thay đổi lab. Worktree issue-12-safe-demo / branch
codex/issue-12-safe-demo vẫn được giữ nguyên; root checkout/user changes untouched.

Thêm `backend/app/demo/collection_review.py` và
`backend/tests/test_scn001_collection_review.py`, hướng dẫn
`docs/SCN001_COLLECTION_REVIEW.md`, kế hoạch
`docs/superpowers/plans/2026-09-14-collection-review.md`.

API `prepare_collection_request` kiểm lại toàn bộ study/run/kit, snapshot
transport và ràng buộc profile/context/scope agent-host. Request pin exact
completion bytes, run input hashes và fingerprints từ engine. Không điền cờ
collection hoặc verdict. `approve_collection_request` yêu cầu approval riêng,
closed bounded JSON, strict booleans và references health/filter/rotation/backlog/
native/time. Request được tái dựng nguyên bytes; thay input không được tự repin.
Coverage bao run; coverage_end <= collected_at <= reviewed_at.

Chỉ trả bytes context mới có caller-attested declaration cho SCN-001-A03;
không ghi đè bundle/context/report, không thay verdict hoặc evidence IDs.
Caller phải giữ request/approval gốc cùng context mới, ngoài Git/input bundle.
References chưa được mở/xác thực; chưa native run-binding verification.
**Không dùng API này để tự gắn nhãn lab verified.**

TDD: 47 tests RED ở stub, GREEN 47; thêm boundary tests GREEN 57.
Thời gian collection/review có một schema-positive RED và hai ordering RED
trước guard. Ban đầu một oversized pytest parameter ID gây setup errors Windows;
đã đổi sang IDs ngắn, không thay môi trường/ACL. Các edge tests đã pass sẵn
được ghi đúng, không tuyên bố tất cả có RED riêng.

Kiểm chứng mới trên Python của venv worktree:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_collection_review.py -q --tb=short -p no:cacheprovider --basetemp ('build/pytest-collection-final-' + [guid]::NewGuid().ToString('N'))
# 62 passed in 44.95s, exit 0
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-collection-full-' + [guid]::NewGuid().ToString('N'))
# 2421 passed, 1 skipped in 146.85s, exit 0
& '.\.venv\Scripts\python.exe' -m pip check
# No broken requirements found., exit 0
git diff --check
# exit 0; LF/CRLF warnings only
```

Skip: test_intake_io.py:452, FIFO unavailable trên Windows. Synthetic tests
kiểm Inconclusive -> False negative chỉ sau approval, empty evidence vẫn
Missing telemetry; stale receipts, valid-but-wrong scope/profile/context,
snapshot newline mutation, unknown approval fields và nanosecond coverage.
Không chạy runner payload, không đọc raw lab exports/credentials. Wheel build
vẫn chưa kiểm chứng; không cài dependency mới.

Tiếp theo: native run-binding/conflict review (PID/ProcessGuid/ScriptBlockId),
ghép API thành CLI offline và output hồ sơ review riêng, synthetic end-to-end
A/B/C, review độc lập, sau đó operator formal lab A/B/C. Chưa đóng Issue #12.
Reviewer độc lập cần chú ý trust boundary caller-attested vs lab-verified,
stale-request rejection, scope matching và lưu approval/provenance ngoài context.

## 2026-09-14 — Run binding và native review declaration

Thêm `backend/app/demo/run_binding.py`, tests
`backend/tests/test_scn001_run_binding.py` và hướng dẫn
`docs/SCN001_RUN_BINDING.md`. Kế hoạch ở
`docs/superpowers/plans/2026-09-14-run-binding.md`.

`review_run_binding(bundle, run_inputs=..., native_review=None)` kiểm lại run,
study/profile/context/scope và snapshot bytes, dùng canonical predicates A01/A02
để nhận diện candidates. Giữ cả unknown matches và records có child PID, không
lọc theo rule ID/detection outcome. PID khác, nhiều candidate, parent PID sai,
biến thể path/command sai hoặc ngoài launch..exit gây conflict. Metadata null/
blank và missing telemetry giữ unknown; không điền từ manifest/receipt.

Native review là JSON khai báo riêng do operator cung cấp, không phải EVTX
parser: request hash, reviewer/reference/time, payload path/hash, content review
boolean và cặp metadata native gồm hostname/provider/record/time/PID/GUID/
ScriptBlockId gắn evidence IDs. Khớp chỉ trả `caller_reviewed`, **không phải
lab_verified, Detected hoặc collection complete**. Không tạo native receipt
production tự động, không đọc raw lab/credentials hoặc thực thi payload.

Output giữ event_id/raw_event_ref/raw_event_hash, request hash và native review
hash. Generic engine/context/verdict không đổi. Collection review và binding
review còn tách biệt; CLI sau phải giữ hồ sơ từng bước, không dùng positive
witness để vượt conflict/unknown. Chưa push/merge/đóng issue hoặc đổi lab.

Baseline mới: 86 study/run tests passed in 7.45s. TDD: 34 failed ở stub rồi
34 passed in 31.03s. Edge suite 1 failed, 56 passed: GUID chỉ chứa khoảng trắng
được đánh missing ở candidate step nhưng native comparison lại coi là mismatch.
Sửa cùng định nghĩa blank, không normalize source: regression 1 passed in 1.07s.
Focused final: **60 passed in 52.19s**; extra edge guards pass sẵn được ghi đúng,
không tuyên bố tất cả test có RED riêng. Các label B/C/Rehearsal giữ nguyên
study/bindings và đúng renamed payload, không relabel rehearsal thành formal run.

Chưa review độc lập; cần reviewer kiểm conflict precedence, candidates không
lọc theo detection, nanosecond boundaries, stale native declaration và giới hạn
caller-reviewed vs bằng chứng native thật. Tiếp theo CLI orchestration/output
hồ sơ, synthetic end-to-end A/B/C, rồi human review và formal lab A/B/C.

Kiểm chứng cuối lượt run-binding:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_run_binding.py -q --tb=short -p no:cacheprovider --basetemp ('build/pytest-binding-final-' + [guid]::NewGuid().ToString('N'))
# 60 passed in 52.19s, exit 0
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-binding-full-' + [guid]::NewGuid().ToString('N'))
# 2481 passed, 1 skipped in 188.36s, exit 0
& '.\.venv\Scripts\python.exe' -m pip check
# No broken requirements found., exit 0
git diff --check
# exit 0, LF/CRLF warnings only
```

Skip duy nhất test_intake_io.py:452, FIFO unavailable trên Windows. Wheel build
chưa kiểm chứng, không cài dependency mới. Không truy cập SSH/lab, không mở
raw exports/credentials, không thay policy/ACL/services. Worktree và toàn bộ
pending changes trước lượt được giữ nguyên. User chưa cần chạy lại rehearsal.

## 2026-09-17 — Sanitize định danh nội bộ trong tài liệu

Tài liệu trên branch này dùng alias nhất quán thay cho định danh lab thật. Việc
thay chỉ áp dụng cho **văn bản tài liệu**; không sửa evidence, không sửa
fingerprint hay hash đã ghim ở bất kỳ đâu.

| Thật | Alias dùng trong tài liệu |
| --- | --- |
| Hostname endpoint lab | `LAB-ENDPOINT-01` |
| Agent ID | `AGENT-01` |
| Tài khoản Windows trên endpoint lab | `<user>` |
| Profile tài khoản trên máy phát triển | `<devuser>` |
| Hậu tố ngẫu nhiên của thư mục backup trên manager | `.REDACTED` |

Tài khoản được thay ở lượt rà soát cuối: bản đã commit trước đó **không** chứa
tên tài khoản nào, nên commit nguyên trạng sẽ là lần đầu đưa nó vào lịch sử Git.
Việc thay chỉ đụng token tên tài khoản; số lượng backslash và dấu nháy trong mọi
trích đoạn đo lường được giữ nguyên.

Tên thư mục backup vẫn giữ nguyên phần mô tả (`aegis-rule-review`,
`aegis-field-review`, `aegis-live-baseline`, `aegis-baseline-controls`,
`aegis-fixed-controls`, `aegis-native-apply`, `aegis-native-upgrade`) nên vẫn
phân biệt được từng bản; chỉ hậu tố ngẫu nhiên bị ẩn. Người vận hành tra cứu
đường dẫn thật trong ghi chép riêng, không đưa vào Git.

## 2026-09-17 — Orchestration đánh giá và synthetic A/B/C end to end

Lượt này làm đúng hai việc còn treo ở mục trước: "CLI orchestration/output hồ sơ"
và "synthetic end-to-end A/B/C". Không chạy lab, không nạp rule, không commit.

### Phần đã có, được tái sử dụng nguyên vẹn

Không sửa và không viết lại bất kỳ phần nào dưới đây: `study.py`, `run.py`,
`snapshot_bundle.py`, `collection_review.py`, `run_binding.py`, connector
`manager_snapshot`, kit generator, runner `Invoke-SafeDemo.ps1`, hai rule
template, và toàn bộ test có sẵn. Profile SCN-001 vẫn do `study._profile_rules`
sinh ra; không có profile hay context template nào được thêm vào repository.

### Phần mới bổ sung

| File | Nội dung |
| --- | --- |
| `backend/app/demo/evaluate.py` | `evaluate_demo_run`, cầu nối giữa run đã verify và report chuẩn |
| `backend/tests/test_scn001_demo_evaluation.py` | 15 test synthetic A/B/C end to end |

`evaluate_demo_run(bundle, run_inputs, scenario, context=None)` chỉ ghép các
kiểm tra đã có: `verify_run` ghim execution/receipt/stdout vào study, sau đó
`verify_snapshot_bundle` kiểm tra transport, rồi ràng buộc chéo ba thứ — profile
trong bundle phải đúng bytes của study, context trong bundle phải bằng context
mà run verification suy ra, và file scenario phải đúng bytes đã ghim. Cuối cùng
gọi thẳng `cli.service.evaluate_bundle` có sẵn. Không có logic đánh giá mới.

Context đã attested được truyền vào qua tham số `context`, và chỉ được chấp nhận
nếu nó bằng context của run ngoại trừ phần `declarations`, đồng thời mọi
declaration phải thuộc `SCN-001-A03`. Module không tự tạo attestation: thiếu
context thì run được đánh giá với assurance unknown, tức alert vắng mặt vẫn là
Inconclusive chứ không thành false negative.

So sánh B→C dùng `compare.compare_reports` có sẵn, không bọc thêm lớp nào.

### Kết quả thực tế

`backend/tests/test_scn001_demo_evaluation.py`: **15 passed in 7.84s**. Chạy lại
với `--basetemp` ngoài repository cũng **15 passed in 11.43s**, tức bộ test mới
không phụ thuộc vị trí basetemp.

Toàn bộ `backend/tests` sau khi thêm: **2496 passed, 1 skipped in 150.06s**,
exit 0, với `--basetemp` trong `build/`. Đúng bằng mốc 2481 cộng 15 test mới,
không có regression. `pip check` sạch, `git diff --check` sạch.

| Run | Kết quả | Ghi chú |
| --- | --- | --- |
| A | `Detected` | A01/A02/A03 satisfied, witness tương quan đúng process_id |
| B không declaration | `Inconclusive` | A03 `inconclusive`; đúng hợp đồng engine |
| B có declaration synthetic | `False negative` | A01/A02 satisfied, A03 `false_negative` |
| C | `Detected` | Dùng lại đúng script đã đổi tên của Run B |
| Compare B→C | **`Regression Passed`** | improvement=1, unchanged_pass=2, regression=0, unchanged_fail=0 |

Negative cases đã phủ: thiếu assurance thì comparison ra `Inconclusive` và
improvement=0; alert đúng `rule_id` nhưng lệch `process_id` thì A03 không
satisfied trong khi A02 vẫn satisfied; report lệch `scenario_version` hoặc
`profile_version` bị `compare` từ chối; context attested của run khác bị từ chối;
declaration chuyển sang assertion khác bị từ chối; scenario hoặc profile không
khớp study bị từ chối.

### Kiểm chứng wheel từ ngoài checkout

Mục trước ghi "Wheel build chưa được xác minh trong môi trường hiện tại vì
virtual environment không có `setuptools`/`wheel`". Lượt này đã xác minh xong mà
**không cài thêm gì vào venv của worktree**: dùng `pip wheel . --no-deps` với
build isolation, pip tự dựng môi trường build riêng theo `[build-system]`.

| Bước | Kết quả |
| --- | --- |
| Build wheel (build isolation) | `aegis_verify-0.1.0-py3-none-any.whl`, 114597 bytes, sha256 `6bd3bb0756408160695979b65d5aa4d2c1c075da3e01bf0e90247ed5fb18b685` |
| Nội dung wheel | 82 file; đủ **11 module** `aegis_verify/demo/` gồm `evaluate.py`; có `connectors/wazuh/manager_snapshot.py`; không lẫn `backend/`, `tests/`, `demos/`, `scripts/` |
| Cài vào venv sạch ngoài repository | Thành công, `pip check` sạch |
| Import ngoài checkout | `aegis_verify` và `demo.evaluate` nạp từ `site-packages`, không nằm dưới worktree |
| Console script `aegis --help` | Hiển thị `{validate,compare}` |
| `aegis validate` trên fixture repo | exit 3, `Inconclusive`, A01/A02 satisfied, A03 inconclusive |
| `aegis compare` hai report | exit 0, status `Inconclusive`, `unchanged_pass=2`, `unchanged_unknown=1` |
| **15 test E2E chạy với code trong wheel** | **15 passed in 8.89s** |

Lần chạy test cuối dùng `aegis-verify[test]` (pytest 9.1.1, đúng extra đã khai báo)
trong venv tạm ngoài repository; `aegis_verify` phân giải về `site-packages`, chỉ
helper test được nạp từ cây nguồn. Đây là bằng chứng packaging thực sự dùng được,
không chỉ import được.

Xác nhận packaging: việc WIP thêm `aegis_verify.demo` vào `[tool.setuptools]
packages` là đúng và đủ; không thêm runtime dependency nào.

### Hai phát hiện

1. `test_scn001_runner.py::test_repo_output_refused_before_execution` phụ thuộc
   ngầm vào vị trí `--basetemp`. Nó dựng `RunDirectory` từ `tmp_path`; guard
   `AEGIS_RUN_OUTPUT_IN_REPOSITORY` chỉ bắn khi `tmp_path` nằm trong repository.
   Chạy với basetemp ngoài repo trên máy không có Sysmon/WazuhSvc, preflight đi
   tiếp tới `Assert-AegisTelemetry` và trả `AEGIS_TELEMETRY_SERVICE_NOT_RUNNING`.
   Đã đo trực tiếp: basetemp ngoài repo cho 1 failed / 2480 passed / 1 skipped;
   basetemp trong `build/` cho **2481 passed, 1 skipped**, khớp mốc đã ghi.
   Thứ tự gọi trong runner vẫn đúng ý định (dòng 157 trước 158) và cả hai nhánh
   đều từ chối chạy với exit code 2, nên không có hành vi mất an toàn. Chưa sửa;
   đề xuất cho test tự dựng run directory trong `build/` thay vì dựa vào `tmp_path`.
2. Test mới cũng phải ghi bundle ra ngoài repository, vì `output_target` từ chối
   mọi đích nằm dưới `.git`. Đã dùng `tempfile.TemporaryDirectory` như test
   collection review đang làm, không hạ kiểm tra đó.

### Giới hạn, phải đọc trước khi trích dẫn kết quả

- Toàn bộ dữ liệu là synthetic sinh trong tiến trình test. **Không phải evidence lab.**
- Collection declaration trong test là hành động operator mô phỏng, chỉ dùng cho
  test phần mềm. Không được sao chép sang run thật dưới bất kỳ hình thức nào.
- `Regression Passed` ở đây chứng minh **đường đi phần mềm** chạy đúng đầu cuối,
  không chứng minh detection nào trong lab.
- Vẫn giữ exact script-content matching để kiểm chứng luồng, theo chỉ đạo lượt này.
- Chưa thêm subcommand CLI; orchestration hiện là API Python. Đây là lựa chọn có
  chủ đích để giữ bề mặt nhỏ và không đụng hợp đồng exit code đã tài liệu hóa.

### Acceptance criterion chưa đạt

Issue #12 ghi trong "Required runs": **"Run C: behavioral rule fix"**. Cách khớp
hiện tại là `win.eventdata.scriptBlockText` exact toàn văn có anchor, tức
**reviewed script-content matching**, không phải behavioral rule fix. Nó chứng
minh rule hết phụ thuộc tên file, nhưng không chứng minh năng lực phát hiện theo
hành vi và không tổng quát sang biến thể nội dung khác.

Ghi nhận là khoảng cách còn lại, **không** sửa acceptance criteria, không sửa
ground truth, không đóng issue. Bước sau cần một revision thực sự behavioral,
hoặc payload có hành vi đặc trưng để bắt, cùng bộ benign case chạy lại trên lab.

### Còn lại để đóng Issue #12

1. Sửa phụ thuộc basetemp của test runner.
2. Review độc lập `evaluate.py` và bộ test mới.
3. Revision behavioral cho Run C, kèm benign case chạy logtest trên manager gốc.
4. Nạp rule và chạy A/B/C thật, ký collection declaration thật cho Run B.
5. Khôi phục Execution Policy `CurrentUser` sau khi kết thúc.

## 2026-09-17 — Xử lý findings của review độc lập

Review độc lập nêu 6 finding CONFIRMED. Dưới đây là cách xử lý từng cái. Không
sửa scenario ground truth, không hạ kiểm tra nào để ép test pass.

### Finding 1 — biểu diễn field: **chưa sửa study, có chủ đích**

Profile khai "backslash nhân đôi trong giá trị field", nhưng kit chỉ nhân đôi
`eventdata.path`, trong khi `image`, `parentImage`, `commandLine` được map từ
**cùng** object `data.win.eventdata`. Nếu telemetry thật nhân đôi cả ba, predicate
của A01 sẽ trượt và cả ba run ra `Missing telemetry`.

Không sửa `study.py`, vì quan sát dẫn tới kết luận "nhân đôi" chỉ thực hiện trên
`path` của bản ghi 4104. Suy quy ước của một trường sang trường khác là phỏng
đoán, và study là dữ liệu được ghim làm ground truth cho lab.

Thay vào đó thêm fixture **viết tay, độc lập với kit generator** tại
`tests/fixtures/demo/scn-001/field-representation/` cùng
`backend/tests/test_scn001_field_representation.py` (6 test). Bộ test phân biệt
tường minh hai tầng — bytes JSON trên đĩa và giá trị sau `json.loads` — rồi khóa
lại cả hai khả năng, kèm một test bắt buộc ba trường dùng chung một object
`eventdata` không được lẫn quy ước.

**Còn chờ evidence lab:** một bản ghi Sysmon Event 1 thật đã sanitize, đối chiếu
đồng thời `image`, `commandLine` và `path` của bản ghi 4104 tương ứng. Có kết quả
rồi mới sửa study, trong một lượt có review riêng.

### Finding 2 — `ingested_at`: **đã sửa**

Làm rõ trước: `scope.ingested_at` là **thời điểm do caller khai** khi chụp snapshot
từ manager. Nó không được máy xác minh và **không** chứng minh alert đã được index.

Vì vậy nó chỉ được dùng để loại trường hợp chứng minh được là sai: snapshot chụp
trước khi cửa sổ run đóng thì không thể phủ cửa sổ đó, nên không bao giờ được
hỗ trợ `complete_for_scope`. Đây là điều kiện **cần**, không phải đủ; thiếu căn
cứ thì kết quả vẫn là Inconclusive.

Đã thêm: `_review_inputs` yêu cầu `ingested_at >= context.end`; `snapshot_ingested_at`
vào request bytes; `approve_collection_request` yêu cầu `collected_at >= ingested_at`.
Bốn test mới: snapshot chụp quá sớm, biên đúng bằng `context.end` vẫn hợp lệ,
approval bị mang sang snapshot khác cùng cửa sổ, và operator khai thu thập trước
thời điểm chụp.

### Finding 3 — đối chiếu fingerprint: **đã sửa**

`evaluate_demo_run` nay so `input_fingerprints` của report với digest của chính
bytes đã kiểm cho profile, scenario và context. Quan trọng nhất là context đã
attested: nó là input duy nhất lật A03 sang false negative và nằm ngoài thư mục
bundle bất biến. Hai test, gồm một ca fault injection.

### Finding 4 — nối run binding: **đã sửa, có đổi API**

`evaluate_demo_run` nay gọi `review_run_binding` và **không** truyền
`native_review` — cờ "đã review" do caller tự khai không phải bằng chứng, nên
status ở đường này không bao giờ đạt `caller_reviewed` và luôn kèm lý do.

- Status `conflict` → từ chối đánh giá.
- Ngược lại gắn kết quả vào `report['run_binding']` để không ai đọc verdict mà
  không thấy trạng thái binding bên cạnh.
- Đối chiếu thêm `request_sha256` của binding với request vừa dựng lại.

**Thay đổi API:** report trả về có thêm khoá `run_binding`. `validate_report` của
`compare` dùng `.get()` và không chốt tập khoá top-level, nên `compare` không bị
ảnh hưởng. Test mới: telemetry Run A dùng cho Run B bị từ chối với
`payload_variant_mismatch`; alert lệch PID bị từ chối với `child_pid_mismatch`.

### Finding 5 và 6 — binding metadata: **đã sửa**

`_NativeRecord` thêm `parent_process_id` (optional, mặc định `None`) và được so
cho bản ghi Sysmon. `_native_matches` nay trả `(consistent, unknown)` thay vì
bool: giá trị nguồn rỗng ghi `missing_binding_metadata` thay vì bỏ qua im lặng;
operator không khai parent PID ghi `native_parent_unconfirmed`. JSON phát ra thêm
`both_sides_caller_declared: true` để `caller_reviewed` không bị đọc nhầm thành
xác minh độc lập.

Không nới lỏng so sánh nào có trước: giá trị khai khác giá trị nguồn vẫn là
conflict. Ngược lại `caller_reviewed` nay **khó đạt hơn** — cần operator khai cả
parent PID. Bốn test mới.

### Sanitize

Định danh nội bộ trong tài liệu đã thay bằng alias nhất quán, xem mục riêng ở
trên. Không sửa evidence, không sửa fingerprint hay hash đã ghim.

### Trạng thái 6 findings — không phải tất cả đã đóng

| # | Nội dung | Trạng thái |
| --- | --- | --- |
| 1 | Biểu diễn field `image`/`commandLine` vs `path` | **CÒN CHỜ XÁC MINH LAB.** Đã rào bằng fixture và test độc lập; study giữ nguyên, chưa sửa theo phỏng đoán |
| 2 | `ingested_at` không ràng buộc với cửa sổ | Đã sửa, có test |
| 3 | Không đối chiếu fingerprint giữa hai lần đọc | Đã sửa, có test |
| 4 | Run binding không nối vào đường đánh giá | Đã sửa, đổi API, có test |
| 5 | `parent_process_id` không đối chiếu được | Đã sửa, có test |
| 6 | Giá trị nguồn rỗng bị bỏ qua im lặng | Đã sửa, có test |

Năm finding đã đóng bằng code và test. **Finding 1 chưa đóng**: nó chỉ được rào
lại để không âm thầm sai, và vẫn cần một bản ghi Sysmon Event 1 thật đã sanitize
để chốt. Không được ghi "đã giải quyết toàn bộ 6 findings".

### Vì sao chưa xác minh được finding 1 bằng công cụ của agent

Ngày 2026-09-17, agent thử kết nối read-only tới Windows target và Wazuh manager
bằng xác thực sẵn có trên máy phát triển. Không kết nối được, do thiếu cấu hình:

| Kiểm tra | Kết quả |
| --- | --- |
| `ssh` client | Có (`OpenSSH_10.3p1`, và `C:\Windows\System32\OpenSSH\ssh.exe`) |
| Private key trong `~/.ssh` | **Không có** (chỉ `known_hosts`, `known_hosts.old`) |
| Dịch vụ `ssh-agent` trên Windows | **Stopped, Disabled**; `ssh-add -l` báo không có agent |
| `SSH_AUTH_SOCK` | Không đặt |
| `~/.ssh/config` và `ProgramData\ssh\ssh_config` | **Không có** |
| Biến môi trường chứa thông tin kết nối | Không có |

Phiên SSH mà người dùng thực hiện diễn ra ngoài ngữ cảnh mà agent chạy. Agent
không yêu cầu password hay private key qua chat và không nhập được password.
Bước thu mẫu tối thiểu do người vận hành tự chạy được ghi ở mục kế tiếp.

### Bước thu mẫu tối thiểu cho finding 1 — chờ duyệt

Toàn bộ chỉ đọc. Không nạp rule, không restart service, không đổi cấu hình
logging, không chạy payload. Dùng bản ghi **đã có sẵn**, không tạo mới.

**1. Trên Windows endpoint — bối cảnh máy**

```powershell
hostname
[System.Environment]::OSVersion.VersionString
(Get-Item 'C:\Windows\Sysmon64.exe' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Get-Service Sysmon64, WazuhSvc | Select-Object Name, Status, StartType
(Get-Date).ToUniversalTime().ToString('o')
w32tm /query /status
```

**2. Trên Wazuh manager — giá trị SAU decode**

`jq -r` in ra chuỗi đã decode, tức đúng thứ parser nhìn thấy sau `json.loads`.
Thay `<HOST>` bằng `agent.name` thật.

```bash
sudo jq -r --arg h '<HOST>' 'select(.agent.name==$h and .data.win.system.eventID=="1")
  | "TIME=" + .data.win.system.systemTime,
    "PID=" + .data.win.eventdata.processId,
    "IMAGE=" + .data.win.eventdata.image,
    "COMMANDLINE=" + .data.win.eventdata.commandLine,
    "PARENTIMAGE=" + .data.win.eventdata.parentImage' \
  /var/ossec/logs/alerts/alerts.json | tail -5

sudo jq -r --arg h '<HOST>' 'select(.agent.name==$h and .data.win.system.eventID=="4104")
  | "TIME=" + .data.win.system.systemTime,
    "PID=" + .data.win.system.processID,
    "PATH=" + .data.win.eventdata.path' \
  /var/ossec/logs/alerts/alerts.json | tail -3
```

**3. Trên Wazuh manager — dạng ESCAPED trong JSON**

```bash
sudo jq -c --arg h '<HOST>' 'select(.agent.name==$h and .data.win.system.eventID=="1")
  | {image:.data.win.eventdata.image, commandLine:.data.win.eventdata.commandLine,
     parentImage:.data.win.eventdata.parentImage}' \
  /var/ossec/logs/alerts/alerts.json | tail -1

sudo grep -m1 '"eventID":"4104"' /var/ossec/logs/alerts/alerts.json | grep -o '"path":"[^"]*"'
```

**4. Điều kiện của cặp bản ghi hợp lệ**

Cùng `agent.name`; `eventdata.processId` của Sysmon 1 bằng `system.processID`
của 4104; hai `systemTime` cách nhau vài giây. Nếu không tìm được cặp như vậy
trong dữ liệu sẵn có thì báo thiếu evidence, **không** nới điều kiện tương quan.

**5. Sanitize trước khi đưa vào báo cáo**

Thay hostname bằng `LAB-ENDPOINT-01`, agent ID bằng `AGENT-01`, tên người dùng
bằng `SYNTHETIC\operator`, tên thư mục riêng bằng tên chung.

**Tuyệt đối giữ nguyên số lượng dấu backslash và ký tự phân cách.** Sanitize mà
đổi cách biểu diễn sẽ phá hỏng chính thứ đang cần đo. Giữ raw export ngoài Git.

**6. Câu hỏi mẫu này trả lời**

Với từng trường `image`, `commandLine`, `parentImage`, `path`: giá trị sau decode
có backslash đơn hay đôi? Bốn trường được đối chiếu **riêng rẽ**; không kết luận
trường này theo trường kia chỉ vì chung object `eventdata`.

## 2026-09-17 — Review độc lập lần hai và xử lý

Reviewer thứ hai kiểm lại sáu bản sửa. Reviewer tìm thấy bản build cũ tại
`build/lib/aegis_verify` (sinh ra khi dựng wheel) và dùng `diff -rq` để đối chiếu
trước/sau: chỉ ba module `collection_review.py`, `evaluate.py`, `run_binding.py`
khác biệt và **mọi khác biệt đều là thêm vào**. Đây là bằng chứng trực tiếp cho
câu hỏi "có hạ kiểm tra nào không", không chỉ đọc trạng thái cuối.

Kết luận của reviewer: finding 2, 3, 4, 5, 6 **Adequate**; finding 1 **Partial
(có chủ đích)**. Bảy mục CONFIRMED mức trung bình trở xuống, đã xử lý như sau.

### C1 — test field-representation chỉ rào một chiều: **đã sửa**

Reviewer đúng và đây là mục quan trọng nhất. Test cũ dùng literal cục bộ, không
nối với study nào, nên tên `..._matches_the_current_study_convention` nói quá
những gì nó kiểm. Một thay đổi âm thầm trong quy ước của study — đúng chiều mà
finding 1 nói tới — vẫn pass toàn bộ suite. Reviewer còn chạy probe read-only
cho thấy `verify_study` chấp nhận cả năm tổ hợp doubling.

Đã đổi tên test cũ thành `test_single_backslash_values_survive_parsing_unchanged`
và thêm `test_reference_study_pins_each_field_convention_separately`, đọc profile
của study tham chiếu rồi khóa **từng trường riêng**: A01 `process_name` đơn, A01
`command_line` đơn, A02 `file_path` đôi, cộng một assert nói thẳng rằng study
hiện **trộn quy ước** và đó là rủi ro mở chứ không phải thiết kế đã xác nhận.

### C5 — đối chiếu fingerprint thiếu một input: **đã sửa**

Thêm `input_fingerprints['inputs']` (bundle manifest) vào phép đối chiếu trong
`evaluate_demo_run`. Bytes của document evidence vẫn không có fingerprint riêng
trong report; phần đó nằm trong giả định "thư mục bất biến, không có writer song
song" đã ghi ở `SCN001_COLLECTION_REVIEW.md`.

### C6 — `_native_matches` thoát sớm làm mất lý do: **đã sửa**

Chuyển sang cờ `consistent` và tiếp tục quét, nên khi vừa có conflict vừa có
metadata thiếu ở record khác, `reasons` liệt kê đủ cả hai. Status không đổi:
conflict vẫn thắng.

### C2, C3, C4 — tài liệu lạc hậu so với code: **đã sửa**

- `SCN001_RUN_BINDING.md`: bổ sung `parent_process_id` vào danh sách field, nói
  rõ record PowerShell phải để null, giải thích vì sao bỏ trống không trung lập,
  thêm `both_sides_caller_declared`, liệt kê reason codes, và mô tả cách
  `evaluate_demo_run` gọi hàm này không kèm native review.
- `SCN001_COLLECTION_REVIEW.md`: thêm `snapshot_ingested_at` vào nội dung request,
  mục riêng về ràng buộc thời điểm chụp, và nêu rõ đây là điều kiện cần chứ
  không phải đủ. Cập nhật dòng thứ tự thời gian trong bảng approval.
- `SCN001_EVENTCHANNEL_PROFILE.md`: thêm cảnh báo ngay dưới bảng hợp đồng rằng
  quan sát "backslash nhân đôi" chỉ thực hiện trên `eventdata.path` của 4104,
  không được hiểu là mọi trường trong `eventdata` đều nhân đôi.

### C7, P1, P2 — ghi nhận, chưa sửa

- **C7:** phép đối chiếu `request_sha256` trong `evaluate_demo_run` gần như
  tautology vì hai vế cùng dẫn xuất từ một `bundle`/`run_inputs` trong cùng tiến
  trình; giá trị thật của nó chỉ là bắt writer song song. Cái giá là một lần
  `evaluate_demo_run` chạy `verify_run` khoảng 4 lần và `verify_snapshot_bundle`
  khoảng 5 lần. Giữ lại vì đúng, nhưng cần biết khi tối ưu sau này.
- **P1:** một context attested **viết tay** bỏ qua các gate mạch lạc của
  `_Approval`, vì `_attested` chỉ yêu cầu context trừ declarations bằng context
  đã verify và declaration thuộc A03. Vẫn còn nhiều lớp chặn: engine yêu cầu
  khớp ba fingerprint và phủ trọn cửa sổ, `CollectionDeclaration` yêu cầu cả ba
  confirmation là `True`, và gate `ingested_at >= context.end` vẫn áp dụng trên
  đường này nhờ `evaluate_demo_run` gọi `review_run_binding` và
  `prepare_collection_request`. Nhưng tính "gắn với đúng snapshot" của finding 2
  yếu hơn mức mà văn bản checkpoint gợi ý.
- **P2:** kết quả run binding không đi tiếp vào report của `compare`, nên mục
  tiêu "không ai đọc verdict mà không thấy binding" chỉ đúng ở report đánh giá,
  dừng lại một nhịp trước `Regression Passed` / `Inconclusive`.

### Vùng reviewer kết luận sạch

Tương thích `compare` khi thêm khoá `run_binding`; từ chối telemetry chéo run;
`caller_reviewed` không đạt được trên đường evaluate; biên `ingested_at` đúng;
không nới lỏng kiểm tra nào (chứng minh bằng diff build cũ); scenario ground
truth không đổi; error sanitization; không network/live-manager; và bản sửa test
basetemp là nâng chuẩn chứ không hạ.

## 2026-09-17 — SSH đã dùng được; thu mẫu finding 1 mới đi được nửa đường

Cập nhật thay thế mục "Vì sao chưa xác minh được finding 1" ở trên: cấu hình SSH
đã được người dùng thay đổi sau báo cáo đó. Agent kết nối được bằng Windows
OpenSSH (`C:\Windows\System32\OpenSSH\ssh.exe`) với `-o BatchMode=yes`, exit 0
tới cả hai máy. Agent không thấy và không xin private key hay password.

### Bối cảnh máy Windows — đã thu

| Mục | Giá trị |
| --- | --- |
| Hostname | `LAB-ENDPOINT-01` |
| OS | Microsoft Windows NT 10.0.19045.0 |
| Sysmon | 15.22, dịch vụ `Sysmon64` **Running** |
| Wazuh agent | dịch vụ `WazuhSvc` **Stopped** |
| Giờ UTC của máy | 2026-09-17T13:56:50.857Z |

**`WazuhSvc` đang dừng.** Agent không tự khởi động lại theo yêu cầu. Hệ quả cho
việc lấy mẫu: telemetry sinh ra trong lúc dịch vụ dừng có thể chưa tới manager,
nên kể cả khi mở được quyền đọc `alerts.json` thì chưa chắc có bản ghi tương ứng.

### Cặp bản ghi native tương quan — đã tìm được

Không chạy payload mới; đây là hoạt động có sẵn của Windows.

```text
SYSMON 1
  TimeCreatedUtc  = 2026-09-17T12:25:13.5836479Z
  ProcessId       = 7312
  ProcessGuid     = {4a2c592c-...}
  Image           = C:\Windows\System32\sdiagnhost.exe
  ParentImage     = C:\Windows\System32\svchost.exe
  ParentProcessId = 844
  CommandLine     = C:\Windows\System32\sdiagnhost.exe -Embedding

POWERSHELL 4104
  TimeCreatedUtc     = 2026-09-17T12:26:15.1419237Z
  ExecutionProcessId = 7312
  MessageNumber/Total= 1 / 1
  Path               = C:\Windows\TEMP\SDIAG_<redacted-guid>\TS_DiagnosticHistory.ps1
```

Cùng host, cùng PID 7312, cách nhau khoảng 62 giây. Đây là cặp hợp lệ theo tiêu
chí đã duyệt. Nội dung `ScriptBlockText` **không** được trích ra; chỉ ghi độ dài.

Ở tầng **native**, cả bốn trường `Image`, `ParentImage`, `CommandLine` và `Path`
đều dùng **backslash đơn** và nhất quán với nhau. Trong 200 bản ghi 4104 gần nhất
có 79 bản có `Path` khác rỗng.

### Vì sao finding 1 vẫn chưa kết luận được

Câu hỏi của finding 1 là giá trị **sau khi Wazuh decode** trông thế nào, không
phải giá trị native. Giá trị native là backslash đơn — điều này chưa bao giờ bị
nghi ngờ. Nửa còn thiếu là dữ liệu phía manager, và nó bị chặn bởi quyền:

| Lệnh | Kết quả chính xác |
| --- | --- |
| `id` (user `soc`) | `uid=1000(soc)` … `groups=…,27(sudo),…` — **không** có nhóm `wazuh` |
| `sudo -n true` | `sudo: a password is required`, exit 1 |
| `ls -ld /var/ossec` | `drwxr-x--- 20 root wazuh` |
| `ls -ld /var/ossec/logs` | `Permission denied` |
| `ls -l /var/ossec/logs/alerts/alerts.json` | `Permission denied` |
| `ls -l /var/ossec/logs/archives/` | `Permission denied` |
| `getent group wazuh` | `wazuh:x:110:` — danh sách thành viên rỗng |
| `command -v jq` | `/usr/bin/jq` (có sẵn) |

Traversal bị chặn ngay tại `/var/ossec`, nên toàn bộ cây bên dưới không đọc được.
Agent không dùng `sudo` vì cần password, và không xin password qua chat.

### Cần người dùng quyết một trong các phương án

1. **Cấp quyền đọc cho `soc`**: thêm vào nhóm `wazuh` rồi đăng nhập lại. Đây là
   thay đổi hệ thống, agent không tự làm. Cấp quyền đọc rộng cho toàn bộ log Wazuh.
2. **Người vận hành chạy một lần** các lệnh `jq` đã duyệt ở mục "Bước thu mẫu tối
   thiểu" rồi dán kết quả đã sanitize. Không đổi cấu hình gì.
3. **sudoers NOPASSWD giới hạn** cho đúng một lệnh đọc. Bề mặt lớn hơn phương án 2.

Dù chọn cách nào, phải tính tới việc `WazuhSvc` đang dừng: cần xác nhận manager
thực sự có bản ghi trong cửa sổ thời gian tương ứng trước khi kết luận.

### Không thay đổi kết luận của các khoảng trống khác

P1, P2 và "behavioral rule fix" của Run C vẫn là khoảng trống chưa giải quyết.
Finding 1 vẫn **chưa đóng**.

## 2026-09-17 — Finding 1 đã xác minh bằng evidence lab: là defect thật

Sau khi người dùng thêm `soc` vào nhóm `wazuh`, agent đọc được log manager và
đã đo trực tiếp. Finding 1 **được xác nhận là defect thật**, không còn là giả thuyết.

### Cặp bản ghi dùng để đo

Nguồn: `/var/ossec/logs/archives/2026/Sep/ossec-archive-14.json` (ngày rehearsal).
Không chạy payload mới; dùng bản ghi đã có.

| Trường | Sysmon 1 | PowerShell 4104 |
| --- | --- | --- |
| systemTime | 2026-09-14T12:37:59.5732995Z | 2026-09-14T12:37:59.7923604Z |
| computer | LAB-ENDPOINT-01 | LAB-ENDPOINT-01 |
| processId | 7552 | 7552 |
| parentProcessId | 8500 (runner) | — |
| messageNumber/Total | — | 1 / 1 |

Cùng host, cùng PID, cách nhau 0.219 giây. Đây là cặp hợp lệ theo tiêu chí đã duyệt.

### Kết quả đo — cả bốn trường đều nhân đôi

Giá trị **sau decode** (`jq -r`), đã sanitize username, giữ nguyên số backslash:

```text
image       = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
parentImage = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
commandLine = \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive -File \"C:\\Users\\<user>\\Downloads\\AEGIS-SafeDemo-NativeV1\\maintenance_check.ps1\"
path        = C:\\Users\\<user>\\Downloads\\AEGIS-SafeDemo-NativeV1\\maintenance_check.ps1
```

Dạng escaped trong JSON (`jq -c`) cho thấy bốn backslash, nhất quán với giá trị
nhân đôi sau decode. Kiểm tra bằng `test("\\\\\\\\")` trả `YES` cho cả
`image`, `commandLine` và `path`.

### Quy luật chính xác: không phải "nhân đôi backslash"

`commandLine` chứa `\"` — backslash **đơn** trước dấu nháy. Đối chiếu với giá trị
native đọc trực tiếp từ Windows Event Log của endpoint:

| Tầng | commandLine |
| --- | --- |
| Native | `"C:\Windows\...\powershell.exe" -NoLogo ... -File "C:\Users\...\maintenance_check.ps1"` |
| Wazuh decoded | `\"C:\\Windows\\...\\powershell.exe\" -NoLogo ... -File \"C:\\Users\\...\\maintenance_check.ps1\"` |

Quy luật thật: **giá trị sau decode bằng dạng JSON-escaped của giá trị native**.
Wazuh áp thêm một lớp escaping cho chuỗi trong `data.win.eventdata.*`.

Hệ quả cho việc sửa: một validator kiểu "mọi backslash phải nhân đôi" sẽ **sai**,
vì `\"` có backslash đơn. Quy tắc đúng phải là `decoded == json_escape(native)`,
áp dụng cho từng trường string, và nên được kiểm bằng chính phép escape đó chứ
không bằng đếm ký tự.

### Ảnh hưởng

Study hiện để `canonical_paths` nhân đôi nhưng `canonical_executable` và
`command_lines` giữ dạng native. Với dữ liệu thật, predicate của A01
(`process_name eq`, `command_line in`) sẽ **không khớp**, dẫn tới A01
`missing_telemetry`, A03 mất anchor, và cả ba run A/B/C ra `Missing telemetry`
thay vì chứng minh detection gap. Đây đúng là kịch bản review đã cảnh báo.

### Trạng thái

Finding 1 chuyển từ "chờ xác minh" sang **defect đã xác nhận, chưa sửa**. Việc
sửa study là một lượt riêng có review, theo đúng yêu cầu trước đó của người dùng:
cập nhật quy ước cho `canonical_executable` và `command_lines`, thêm validator
theo `json_escape`, cập nhật fixture field-representation và tài liệu profile,
rồi chạy lại toàn bộ kiểm chứng.

### Quan sát phụ cần biết khi lập kế hoạch lab

- `alerts.json` hiện tại và `archives.json` hiện tại **không có bản ghi Windows nào**
  (chỉ pfSense và manager). Khớp với việc `WazuhSvc` trên endpoint đang `Stopped`.
- Dữ liệu Windows chỉ còn trong các file đã xoay vòng, nhiều nhất ở
  `ossec-archive-14.json` (5004 bản ghi) và `ossec-alerts-14.json` (65).
- `/var/ossec/bin/agent_control` vẫn `Permission denied` với user `soc`.
- Có PID reuse trong dữ liệu thật: PID 7552 xuất hiện cho `wermgr.exe` lúc
  12:20:13 và cho `powershell.exe` lúc 12:37:59. Tương quan **chỉ theo PID là
  không đủ**; phải kèm ràng buộc thời gian, đúng như cửa sổ −5s..+15s của profile.

## 2026-09-17 — Lượt sửa study theo evidence lab

Finding 1 đã được sửa. Căn cứ là phép đo thật ở mục trên, không phải suy đoán.

### Quy tắc được chốt

`backend/app/demo/_study_contracts.py` có thêm hai hàm:

- `wire_text(value)` — trả về dạng Wazuh EventChannel đưa vào field đã decode,
  tức `json.dumps(value)[1:-1]`.
- `is_wire_text(value)` — đúng khi giá trị đã ở dạng escaped hợp lệ, kiểm bằng
  round-trip qua chính phép escape.

Docstring ghi rõ **không** được cài lại bằng cách đếm backslash: `\"` mang
backslash đơn, nên quy tắc "mọi backslash phải nhân đôi" sẽ từ chối nhầm command
line thật.

### Validator mới trong `Target`

`Target.consistent` nay bắt buộc:

- `canonical_executable`, mọi phần tử của `canonical_paths` và `command_lines`
  phải ở dạng wire.
- `canonical_executable` phải đúng bằng `wire_text(executable)`.

Study trộn dạng native với dạng wire bị từ chối ngay ở `Study.model_validate`,
trước cả bước so profile.

### Study tham chiếu đã sửa

`backend/tests/test_scn001_study_run.py` dựng mọi giá trị canonical qua
`wire_text` từ giá trị native tương ứng, thay vì `replace('\\', '\\\\')` chỉ áp cho
path. Nhờ đó `process_name`, `command_line` và `file_path` dùng chung một quy ước,
và command line mang `\"` đúng như telemetry thật.

### Test

| Test | Mục đích |
| --- | --- |
| `test_native_representation_in_canonical_values_is_refused` | 3 tham số: từ chối study để native ở `canonical_executable`, `canonical_paths`, `command_lines` |
| `test_canonical_executable_must_be_the_wire_form_of_the_native_one` | Wire form nhưng của đường dẫn khác vẫn bị từ chối |
| `test_escaped_quotes_survive_the_wire_round_trip` | Khóa lại chi tiết `\"` có backslash đơn |
| `test_reference_study_uses_one_wire_convention_for_every_field` | Thay test cũ pin trạng thái hỗn hợp; nay kiểm cả bốn trường cùng quy ước |
| `test_doubled_telemetry_is_what_the_corrected_study_matches` | Fixture doubled mô hình telemetry thật và khớp study |
| `test_native_telemetry_would_no_longer_match_the_study` | Chiều ngược lại, để parser normalise escaping cũng bị bắt |

Hàm `_historical_mixed_convention` còn sót sau khi đổi tên đã được **xóa hẳn**
thay vì để lại code chết mang khẳng định sai.

### Trạng thái finding 1

**Đã đóng.** Sáu finding của review độc lập nay đều đã xử lý bằng code và test.
P1, P2 và "behavioral rule fix" của Run C vẫn là khoảng trống chưa giải quyết.

## 2026-09-17 — Xử lý P1, P2 và giới hạn phạm vi quy ước wire

### Phạm vi của `wire_text` được khóa theo field profile

`wire_text` và validator không phải phát biểu chung về Wazuh. Docstring và
`Target.consistent` nay nêu rõ phạm vi: đo ngày 2026-09-17 trên Wazuh 4.14.4 với
field profile `wazuh-eventchannel-4.14.4-lf-v1`, trên các chuỗi thuộc
`data.win.eventdata` của Sysmon Event 1 và PowerShell 4104 (`image`,
`parentImage`, `commandLine`, `path`).

Validator kiểm `self.field_profile != MEASURED_WIRE_PROFILE` và từ chối trước khi
áp quy ước. Thêm một profile mới sẽ buộc phải đo lại, thay vì âm thầm thừa hưởng
quy ước của phiên bản khác. Phiên bản Wazuh khác, decoder khác, channel khác hoặc
source field ngoài object đó đều **chưa được đo** và không nằm trong phạm vi này.

### P1 — context attested viết tay: **đã sửa**

`evaluate_demo_run` nay nhận thêm `request` và `approval`. Khi có `context`,
`_attested` chạy lại `approve_collection_request` từ chính request và approval đó
và bắt buộc kết quả **bằng đúng bytes** của context được cung cấp. Đưa `context`
mà thiếu một trong hai, hoặc đưa hai cái đó mà không có `context`, đều bị từ chối.

Nhờ vậy collection assurance gắn với đúng run, đúng study và đúng snapshot. Một
declaration viết tay không còn đi vòng qua quy trình review được nữa.

Việc chạy lại review **không** biến approval thành bằng chứng thu thập đầy đủ.
Nó vẫn là caller attestation; phần thêm vào chỉ kiểm rằng nó thực sự đã được lập,
cho đúng bộ input này. Semantics của engine chung không đổi.

### P2 — comparison giữ run binding: **đã sửa**

`compare_demo_runs(before=..., after=...)` gọi `compare_reports` có sẵn và **không
đụng verdict**, sau đó gắn thêm `run_binding` cho cả before và after: `run_id`,
`status`, `reasons`, `both_sides_caller_declared`, `request_sha256`,
`native_review_sha256`. Report thiếu binding bị từ chối, nên một report chưa từng
được kiểm binding không đi qua đường này được.

Lý do: `Regression Passed` tự nó không nói gì về mức độ ràng buộc của từng run
với evidence, mà kết quả binding lại nằm ở report đánh giá, cách đó một nhịp.
Mang nó đi kèm nghĩa là giới hạn của từng run đi cùng kết luận.

### Test mới

| Test | Kiểm |
| --- | --- |
| `test_attested_context_without_its_approval_is_refused` | P1: bằng context đã verify là chưa đủ |
| `test_half_supplied_review_material_is_refused` | 2 tham số: thiếu `request` hoặc `approval` |
| `test_review_material_without_a_context_is_refused` | Đưa material mà không có context |
| `test_approval_from_another_snapshot_is_refused` | Cùng run và cửa sổ, snapshot chụp khác thời điểm |
| `test_approval_from_another_run_is_refused` | Approval của Run B dùng cho Run C |
| `test_declaration_for_another_assertion_is_refused` | Context bị sửa sau khi approve thì không tái dựng được |
| `test_demo_comparison_keeps_both_run_bindings` | P2: binding của cả hai run có trong output |
| `test_demo_comparison_does_not_change_the_engine_verdict` | So bằng với `compare_reports` thuần |
| `test_demo_comparison_refuses_a_report_without_a_binding` | Report thiếu binding bị từ chối |

Một ghi chú về thiết kế test: bản đầu của
`test_approval_from_another_snapshot_is_refused` **không** fail, vì hai bundle
dựng ra giống hệt nhau từng byte nên cùng snapshot hash — approval áp dụng hợp lệ,
và đó là hành vi đúng. Test đã được sửa để tạo một lần chụp thực sự khác
(`ingested_minute` khác), thay vì nới kiểm tra cho khớp kỳ vọng sai ban đầu.

### Trạng thái dịch vụ lab, kiểm lại read-only 2026-09-17T14:14:50Z

| Dịch vụ | Trạng thái |
| --- | --- |
| `Sysmon64` | Running |
| `WazuhSvc` | **Running** |

`WazuhSvc` **đã đổi** so với lần kiểm trước trong cùng ngày, lúc đó là `Stopped`.
Agent không khởi động dịch vụ; chỉ đọc trạng thái. Mọi kế hoạch lab phải kiểm lại
trạng thái tại thời điểm chạy, không dùng lại số liệu của báo cáo cũ.

## 2026-09-17 — Review độc lập lần ba và xử lý

Verdict của reviewer: A **partial**, B **adequate**, C **partial**. Mười ba mục
được nêu. Xử lý như sau.

### Đã sửa

| # | Nội dung | Cách sửa |
| --- | --- | --- |
| 2 | **Transcript evidence trong chính tài liệu này bị sai** | Đã sửa, xem mục riêng bên dưới |
| 1 | Fixture "doubled" có quote thô, vi phạm quy tắc nó minh hoạ | Sửa fixture sang dạng wire đúng; test nay cross-check `command_line`, không chỉ `process_name` |
| 3 | `compare_demo_runs` không ràng buộc binding với report | Bắt buộc `run_id` của binding khớp report và `both_sides_caller_declared is True` |
| 4 | `Target` chỉ neo `canonical_executable` | Neo thêm: `canonical_paths` phải nằm trực tiếp trong `native_directory`; mỗi `command_lines` phải chứa đúng path của nó |
| 6 | `SCN001_STUDY_RUN.md` nói canonical "không derive từ native" | Viết lại theo contract mới |
| 7 | Report không lưu tham chiếu approval | Thêm `report['collection_review']` với `request_sha256`, `approval_sha256`, `assurance` |
| 9 | `ensure_ascii` biến non-ASCII thành `\uXXXX` | `ensure_ascii=False`; `is_wire_text` từ chối non-ASCII vì chưa đo |
| 10 | Tài liệu suy rộng sang ký tự điều khiển | Viết lại: chỉ backslash và quote được đo. Việc agent đổi CR/LF thành space là suy ra từ truy vết mã nguồn ở mục 2 của `SCN001_EVENTCHANNEL_PROFILE.md`, **chưa đo trực tiếp**, nên không dùng làm cơ sở cho validator |
| 13 | Runner tests flaky khi tải nặng | `timeout=15` cứng đổi thành `RUNNER_TIMEOUT = 120` kèm giải thích; không test nào assert theo thời gian |

### Sửa quan trọng nhất: evidence bị sai trong chính tài liệu này

Reviewer phát hiện khối transcript "Giá trị sau decode" mâu thuẫn với quy tắc nó
dùng để biện minh. Kiểm bằng `repr()`: file chứa `C:\Windows\...` — **backslash
đơn**, trong khi phép đo thật cho `C:\\Windows\\...` — **nhân đôi**.

Nguyên nhân: khối đó được ghi bằng bash heredoc, và heredoc đã nuốt backslash.
Cùng lỗi này từng làm hỏng hai file test trước đó trong phiên.

Đã sửa bằng Edit thay vì heredoc, và xác minh lại bằng `repr()` cho từng dòng:
giá trị native (dòng 1488–1497) backslash đơn, giá trị Wazuh decoded (1568–1571,
1586) nhân đôi. Ba tuyên bố trong tài liệu nay nhất quán với nhau và với số đo.

**Bài học cho người viết tiếp:** không ghi evidence chứa backslash bằng heredoc.
Dùng Edit hoặc công cụ ghi file, rồi xác minh lại bằng `repr()` trước khi tin.

### Ghi nhận, chưa sửa

- **#5 Hai cách cài đặt cùng một quy ước.** `scripts/prepare_scn001_kit.py:94,166`
  dùng `.replace('\\', '\\\\')` (Python source) để dựng regex rule và synthetic controls, trong khi
  `wire_text` dùng JSON escape. Hai cách chỉ trùng nhau với path ASCII không có
  quote — đúng tập mà `_directory` hiện cho phép. Không sửa trong lượt này vì
  thay cách dựng regex sẽ đổi bytes rule đã được logtest kiểm trên clone; việc đó
  cần một lượt riêng có review và chạy lại controls.
- **#8 `aegis compare` bỏ qua `run_binding`.** `validate_report` dùng `.get()` nên
  khoá thừa bị lờ đi. Tính chất "không đọc verdict mà thiếu binding" chỉ đúng với
  `compare_demo_runs`. Sửa đúng cách là thêm subcommand CLI cho demo — nằm ngoài
  phạm vi đã thống nhất, và runbook đã được sửa để chỉ sang API.
- **#11 Tautology một phần.** `test_reference_study_uses_one_wire_convention_for_every_field`
  dựng kỳ vọng bằng chính `wire_text`. Phần độc lập là hai assert literal và
  cross-check với fixture viết tay ở `test_doubled_telemetry_is_what_the_corrected_study_matches`.
- **#12 Guard profile chưa với tới được.** `field_profile` là `Literal` một giá
  trị, nên guard chỉ kích hoạt khi thêm profile thứ hai. Giữ lại có chủ đích.

## 2026-09-17 — Đối chiếu lại transcript bằng chương trình, không bằng mắt

Mục trước sửa khối transcript theo quy tắc **dự đoán**. Đó là cách làm sai:
tài liệu được chỉnh cho khớp kết luận thay vì đọc lại bản ghi. Lượt này đọc lại
từ manager và đối chiếu bằng chương trình.

### Phương pháp

Mỗi giá trị được lấy ra bằng `jq -r ... | @base64` trên manager và bằng
`[Convert]::ToBase64String` trên endpoint, rồi giải mã tại chỗ. Base64 loại bỏ
mọi tầng escaping của shell, SSH và trình soạn thảo — chính những tầng đã hai
lần làm hỏng số liệu trong phiên này. Không giá trị nào được gõ lại bằng tay.

Cùng một event được đọc ở hai phía: Sysmon Event 1, PID 7552,
`2026-09-14T12:37:59.5732995Z`, khớp tới từng chữ số trên cả hai nguồn.

### Kết quả đo

| Field | backslash native | backslash decoded | quote native | `\"` trong decoded | `json_escape(native) == decoded` |
| --- | --- | --- | --- | --- | --- |
| `Image` | 5 | 10 | 0 | 0 | **True** |
| `ParentImage` | 5 | 10 | 0 | 0 | **True** |
| `CommandLine` | 10 | 24 | 4 | 4 | **True** |

Số học tự kiểm: `CommandLine` native có 10 backslash và 4 dấu nháy. Nhân đôi
backslash cho 20, cộng 4 backslash sinh ra khi escape dấu nháy, tổng 24 — đúng
bằng số đếm được ở cột decoded.

`path` của bản ghi 4104 tương ứng chỉ có ở phía manager trong lượt này; nó
round-trip qua phép escape: **True**. Không có giá trị native cùng event để so
trực tiếp, nên nó được ghi là nhất quán với quy ước, không phải đã đối chiếu hai phía.

### Trích đoạn đã sanitize

Chỉ tên tài khoản được thay bằng `<user>`. Backslash và dấu nháy giữ nguyên, vì
chính số lượng của chúng là thứ đang đo. Raw bytes không đưa vào Git.

```text
native  Image        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
decoded Image        C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
native  CommandLine  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -File "C:\Users\<user>\Downloads\AEGIS-SafeDemo-NativeV1\maintenance_check.ps1"
decoded CommandLine  \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive -File \"C:\\Users\\<user>\\Downloads\\AEGIS-SafeDemo-NativeV1\\maintenance_check.ps1\"
decoded path         C:\\Users\\<user>\\Downloads\\AEGIS-SafeDemo-NativeV1\\maintenance_check.ps1
```

### Kết luận, giới hạn đúng phạm vi

Với field profile `wazuh-eventchannel-4.14.4-lf-v1`, trên các trường đã đo của
Sysmon Event 1, giá trị decoded bằng dạng JSON-escaped của giá trị native. Đây
là kết quả đối chiếu hai phía trên cùng một event, không phải suy luận.

Chưa đo và **không kết luận**: ký tự non-ASCII, ký tự điều khiển, phiên bản
Wazuh khác, decoder khác, channel khác, và các source field ngoài
`data.win.eventdata` của hai loại bản ghi này. `is_wire_text` từ chối non-ASCII
thay vì đoán; không có phát biểu nào về việc Wazuh có hay không phát `\uXXXX`.
