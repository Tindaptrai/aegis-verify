# SCN-001 — frozen study và kiểm chứng runner manifests

API này kiểm tính nhất quán của **bytes được cung cấp** với study đã review.
Không chạy payload, không gọi Wazuh/SSH, không tự xác minh máy thật. Chưa phải
collection attestation, native event binding hoặc kết luận lab A/B/C hoàn chỉnh.

## Hai API bytes-only

`aegis_verify.demo.study.verify_study(study, *, study_sha256, scenario, profile,
kit, artifacts)`:

- study/scenario/profile/kit là bytes nguyên bản; artifacts là dict tên tương
  đối -> bytes cho đủ 18 artifacts kit hiện có.
- study_sha256 là hash đã pin riêng sau review, không tự tính lại để vượt lỗi.
- Trả model Study đã kiểm hợp đồng/pins. Không sử dụng model đó để bỏ qua kiểm
  bytes khi kiểm run; `verify_run` luôn tự kiểm lại study đầu vào.

`aegis_verify.demo.run.verify_run(*, study, study_sha256, scenario, profile, kit,
artifacts, execution_start, execution_launched, execution, stdout, stderr,
receipt)` nhận cùng study inputs và sáu byte inputs của run/receipt.

Trả `CheckedRun`: context EvaluationContext, child_pid, run_label,
study_sha256, mapping input_sha256 (read-only). Context có hai bindings cố
định `target_host`, `target_agent`; không đưa PID thay đổi từng run vào bindings.
Collection declarations luôn rỗng. Hashes trả riêng để tầng packaging tiếp
theo giữ liên kết về những manifests đã kiểm, không tạo canonical event từ chúng.

Public lỗi là StudyRunError với thông báo `invalid_study_run`, không echo
raw payload, account/path hoặc nội dung receipt sai.

## Study JSON 0.1.0

Object đóng, không bỏ qua unknown fields:

| Field | Giá trị / ý nghĩa |
| --- | --- |
| kind, version | scn001_study, 0.1.0 |
| study_id | ID riêng của study đã review |
| pins | SHA-256 lowercase của scenario, profile, kit, runner, payload, baseline, fixed |
| target | Các literal/context đã review theo bảng dưới |
| collection_reference | Tham chiếu quy trình collection đã khóa, không phải complete flag |
| time_reference | Tham chiếu nguồn/kiểm tra thời gian đã review |

Target gồm environment_id, hostname, agent_id, account, elevated (boolean),
executable **native**, canonical_executable, collection_mode=`direct`,
native_directory, canonical_paths, command_lines, rule_id, parent_sid,
field_profile=`wazuh-eventchannel-4.14.4-lf-v1`.

Hai arrays canonical_paths/command_lines phải đúng hai phần tử, thứ tự
original `lab_update.ps1`, renamed `maintenance_check.ps1`; chỉ khác tên đó.
**Cập nhật 2026-09-17.** Câu trước ở chỗ này ghi canonical literals "không derive
từ native path/escape/case". Điều đó **không còn đúng** sau khi đo telemetry thật:
canonical values phải ở dạng wire của field profile đã đo, và contract nay bắt buộc

- `canonical_executable == wire_text(executable)`;
- mỗi `canonical_paths` nằm trực tiếp trong `native_directory`, không thêm thư mục con;
- mỗi `command_lines` chứa đúng đường dẫn payload tương ứng của nó.

Người review vẫn đối chiếu metadata, nhưng đối chiếu ấy nay có ràng buộc máy kiểm
được. Điền tay giá trị dạng native sẽ bị `Target` từ chối. Executable native vẫn
dùng để kiểm runner; `canonical_executable` để match Sysmon. Hai biểu diễn khác
nhau, nhưng **không độc lập**: một cái là dạng wire của cái kia.

Quy ước wire chỉ áp cho field profile đã đo; xem
[SCN001_EVENTCHANNEL_PROFILE.md](SCN001_EVENTCHANNEL_PROFILE.md).

Rule ID thuộc 100000..120000, parent SID 1..999999, không trùng nhau. Không dùng
study để tự chọn ID còn trống hoặc cài rule. Pins ràng buộc hai revision khác
nội dung; tool kiểm hashes, **không chứng minh PCRE2 semantics hoặc trạng thái
remote**. Native rule controls và operator review vẫn bắt buộc.

Kit phải đúng schema/layout hiện có, đủ hashes/18 artifacts; từng artifact
tối đa 64 KiB. Hai payload phải đúng bytes payload 69-byte đã duyệt, không chỉ
cùng hash do caller vừa thay. Chưa có runtime export/sanitize tại API này.

## Profile không được đổi tiêu chí giữa các lượt

Scenario phải SCN-001 0.1.0 với ba assertion đã duyệt, expected_outcome detected;
hash bytes scenario và scenario_fingerprint phải cùng nguồn. Profile hash cũng
pin trong study. Profile được kiểm chính xác cấu trúc thực thi:

- A01: scope hostname/asset_id bằng bindings, provider Sysmon; match executable
  canonical và một trong hai command lines.
- A02: cùng host/asset, provider PowerShell; một trong hai canonical paths.
- A03: cùng PowerShell scope/paths và rule_id demo; join về A01 bằng hostname,
  asset_id, process_id; delta -5..+15 giây.

Không thêm telemetry correlation vào A02, không bind child PID để làm compare
mất tương thích. Profile phải theo thứ tự A01/A02/A03 và predicates đã mô tả;
đây là contract SCN-001 hẹp, không phải profile optimizer chấp nhận mọi cấu trúc
tương đương. Profile ID/version vẫn là metadata của profile đã review/pin.

## Kiểm run và receipt

Ba file bắt buộc execution-start.json, execution-launched.json, execution.json
đúng keys và trạng thái từng stage. Các fields chung không đổi. Start chưa có
child/launch; launched có PID và thời điểm launch nhưng chưa có exit. Final
phải executed, exit_code integer0 (không boolean), timed_out false,
failure_code null; child/runner PID là integer dương <= 2^32-1 và khác nhau.

- A dùng original/baseline; B dùng renamed/baseline; C dùng renamed/fixed.
- Rehearsal dùng renamed và giữ nguyên nhãn, không tự đổi thành A/B/C.
- Native path, executable, arguments, host, payload/rule hashes phải khớp study.
- start <= launch <= exit <= planned_end <= observed_end.
- planned_end - start **đúng 120.000000000 giây**; không round/truncate nanos.
- elapsed_seconds chỉ là sanity check finite number >=120, không dùng để tạo
  window hoặc tự kết luận clock accurate. Float được đọc Decimal chỉ trong
  field này; config decoder chung vẫn từ chối float. NaN/Infinity, exponent
  không biểu diễn được và numeric token dài quá 128 ký tự đều bị từ chối.
- stdout phải đúng marker và PID child, LF/CRLF được đối chiếu theo runner;
  stderr phải bytes rỗng. Không tái tạo stdout/manifests còn thiếu.

Receipt object đóng:

| Fields | Điều kiện |
| --- | --- |
| kind/version | scn001_rule_receipt / 0.1.0 |
| run_id, study_sha256, execution_sha256 | Đúng run và exact bytes đã review |
| account, elevated | Khớp execution context đã chốt trong study |
| before_rule_sha256, after_rule_sha256 | Cùng revision phù hợp A/B/C |
| before_utc, after_utc | Bao toàn run từ start tới observed end |
| confirmed_by, before_reference, after_reference | Không rỗng, operator cung cấp |

Receipt là **khai báo operator**, chưa có chữ ký/xác thực danh tính. Không suy
account/elevation thật từ runner vì runner hiện không ghi chúng; phải giữ
tham chiếu bằng chứng kiểm thủ công. `rule_state_verified_remotely` của runner
phải false: công cụ này không tự đổi thành true.

## Kết quả và giới hạn

Study/run consistency thành công không đồng nghĩa Detected. Test đi qua parser
và engine thật chứng minh: không có events -> Missing telemetry; có telemetry
nhưng chưa demo detection và collection unknown -> Inconclusive; có witness
detection phù hợp -> Detected. Không sửa outcome để đạt Regression Passed.

Chưa kiểm native record IDs/ProcessGuid/ScriptBlockId đối chiếu child, chưa
phát hiện run chồng nhau trên toàn study, chưa receipt collection/attestation,
chưa kết hợp API này với filesystem transport bằng final CLI. Vì vậy không
dùng riêng `verify_run` làm bằng chứng rằng lab đã thực thi đúng hoặc thu đủ log.

Trước formal A/B/C, operator còn phải review canonical executable/command-line
literals từ rehearsal, khóa study/profile và giữ hash pin bên ngoài bundle.
Không đổi pins/bindings giữa B và C để ép report tương thích. Chưa cần chạy
lại rehearsal chỉ để kiểm API phần mềm này.

## Lệnh kiểm tra trên máy phát triển

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
$aegisTestTemp = 'build/pytest-study-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_study_run.py -q -rs -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Tất cả fixtures của test là synthetic; generator chỉ tạo kit test, không chạy
payload, không SSH hoặc đọc exports lab. Kết quả test và giới hạn review xem
[checkpoint](ISSUE_12_SAFE_DEMO_CHECKPOINT.md).
