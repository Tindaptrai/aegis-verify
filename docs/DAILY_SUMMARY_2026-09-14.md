# AEGIS Verify — Phần việc phát sinh sau tổng kết ngày 11/09/2026

**Thời điểm chốt báo cáo:** 14/09/2026

**Phạm vi:** chỉ ghi những việc phát sinh sau `DAILY_SUMMARY_2026-09-11.md`.

## Nội dung không lặp lại

Báo cáo này không tổng kết lại các phần đã ghi ngày 11/09, gồm Cowrie Fixture
Parser (Issue #6), Validation Engine (Issue #7), CLI Validate (Issue #8), quá
trình thu thập Cowrie và mốc 1781 passed, 1 skipped. Các issue nền tảng trước đó
cũng không được kể lại.

## 1. Hoàn thành chức năng so sánh hai lần chạy — Issue #9

Issue #9 đã được triển khai, review, sửa các điểm còn thiếu và merge qua
[PR #24](https://github.com/Tindaptrai/aegis-verify/pull/24), merge commit
`d5f9779`.

Kết quả chính:

- Có thể so sánh hai validation run offline của cùng kịch bản tương thích.
- Hiển thị trạng thái assertion trước và sau, đồng thời giữ evidence ID của cả
  hai lần để truy vết.
- Phân biệt regression, improvement, unchanged pass và unchanged fail.
- Chỉ dùng nhãn `Regression Passed` khi detection gap đã được xác nhận ở lần
  trước và đã được khắc phục đầy đủ ở lần sau.
- Không biến trạng thái unknown, inconclusive hoặc thiếu telemetry thành
  pass/fail ngầm.
- Từ chối hai run không tương thích bằng lỗi có hướng xử lý.
- Không thay đổi scenario ground truth.

Tài liệu sử dụng đã được bổ sung tại `docs/CLI_COMPARE.md`.

## 2. Bổ sung Windows telemetry cho Wazuh — nền tảng của Issue #12

Phần parser Windows telemetry đã được triển khai và merge qua
[PR #25](https://github.com/Tindaptrai/aegis-verify/pull/25), merge commit
`bf48529`.

Những việc đã hoàn thành:

- Bổ sung đường đọc offline cho Wazuh Windows EventChannel.
- Chuẩn hóa Sysmon Event ID 1 và PowerShell Script Block Event ID 4104 về
  canonical event.
- Giữ giá trị không có dưới dạng `null`, không tự suy đoán dữ liệu.
- Giữ evidence ID và raw-event reference để truy vết về bản ghi nguồn.
- Không tạo phụ thuộc live vào Wazuh trong parser.
- Người dùng đã chạy bộ test đối chiếu: **2009 passed, 1 skipped**; `pip check`
  không phát hiện dependency hỏng.

## 3. Chuẩn bị telemetry thật trên LAB-ENDPOINT-01

Các bước lab đã trực tiếp thực hiện:

- Cài Sysmon 15.22 từ bộ Sysinternals có chữ ký Microsoft hợp lệ.
- Xác nhận dịch vụ `Sysmon64` hoạt động và kênh
  `Microsoft-Windows-Sysmon/Operational` sinh Event ID 1.
- Xác nhận kênh `Microsoft-Windows-PowerShell/Operational` sinh Event ID 4104.
- Xác nhận Wazuh agent có cấu hình thu thập cả hai kênh EventChannel.
- Khởi động lại `WazuhSvc` và xác nhận agent `LAB-ENDPOINT-01`/ID `AGENT-01` kết nối lại
  ở trạng thái Active.
- Đặt Execution Policy ở phạm vi `CurrentUser` thành `RemoteSigned` để chạy
  demo đã kiểm soát; không dùng `Bypass`.
- Thu thập các mẫu JSON đã làm sạch để kiểm tra parser, không đưa credential
  hoặc raw lab export chưa làm sạch vào Git.

## 4. Làm sạch rule Wazuh trong lab

Trên Wazuh Manager 4.14.4, đã phát hiện các rule ID `120850`, `120860` và
`120861` bị khai báo trùng trong `local_rules.xml`.

Đã thực hiện theo quy trình có backup và config test:

- Loại bỏ một bộ định nghĩa trùng, giữ lại đúng một định nghĩa cho mỗi rule ID.
- Sửa trường so khớp Suricata từ `data.alert.signature_id` sang
  `alert.signature_id` theo dữ liệu thực tế mà decoder JSON tạo ra.
- Dùng biểu thức exact-match để tránh SID dài hơn vô tình khớp tiền tố.
- Chạy bảy ca `wazuh-logtest`: ba positive case và bốn negative/control case;
  kết quả **ALL_7_TESTS_PASSED**.
- Xác nhận active response chỉ là khối ví dụ đang comment, nên demo không tự
  chặn IP hoặc thay đổi firewall.
- Chạy `wazuh-analysisd -t`, restart Wazuh Manager và xác nhận dịch vụ active.

Thử nghiệm thay decoder của rule nền `60000` chỉ được làm trên máy clone cô
lập. Máy clone sau đó đã tắt; thay đổi này không được áp dụng lên Wazuh Manager
chính.

## 5. Xây dựng safe demo không độc hại cho Issue #12

Một bộ demo PowerShell vô hại đã được xây dựng cho `LAB-ENDPOINT-01`. Payload chỉ
in marker và PID, không tải mã, không sửa registry, không tắt bảo vệ, không tạo
persistence và không thực hiện active response.

Bộ kit có các đặc điểm:

- Preflight kiểm tra hostname, quyền, log channels, đường dẫn và trạng thái đầu
  ra trước khi chạy.
- Mỗi lần chạy có run ID và thư mục kết quả mới; không ghi đè kết quả cũ.
- Ghi manifest thời gian, PID, exit code và timeout để ràng buộc execution với
  telemetry.
- Cửa sổ quan sát cố định 120 giây.
- Artifact được kiểm tra SHA-256 trước khi sử dụng.
- Baseline và fixed rule là hai revision riêng; chỉ cài revision đã duyệt.
- Safe execution tách biệt khỏi evidence evaluation và không tự tạo verdict.

Lần rehearsal đầu bị ngắt bằng `Ctrl+C`; kết quả dở dang được giữ lại và không
dùng làm bằng chứng đánh giá. Sau đó đã chạy lại thành công.

### Rehearsal native thành công

- Run ID: `rehearsal-native-4980a0adcd694679af388d91dbcf4334`
- Child PID: `7552`
- Exit code: `0`
- Timeout: `false`
- Khoảng chạy: `2026-09-14T12:37:49Z` đến `2026-09-14T12:39:49Z`
- PowerShell record: `1789389484.4343572`, Event ID 4104, rule `91816`
- Sysmon record: `1789389486.4345839`, Event ID 1, rule `92029`
- Native Windows Event Log xác nhận script, PID, path và bộ đếm message khớp
  chính xác.

Qua rehearsal, đã xác định Wazuh decoded field có thể làm phẳng newline thành
khoảng trắng và thể hiện path bằng backslash đã escape. Vì vậy profile
`wazuh-eventchannel-4.14.4-lf-v1` được đóng băng để phân biệt rõ:

- source-native value dùng cho kiểm chứng tại Windows;
- decoded value dùng cho rule/parser phía Wazuh;
- raw bytes, decoded field và giá trị hiển thị không được coi là giống nhau.

Rehearsal này mới chứng minh đường truyền telemetry và khả năng ràng buộc bản
ghi. Nó chưa phải kết quả A/B/C chính thức và chưa được gọi là
`Regression Passed`.

## 6. Các module offline mới đang được triển khai trên branch Issue #12

Các phần sau đã được viết và kiểm thử trong branch `codex/issue-12-safe-demo`,
nhưng tại thời điểm chốt báo cáo vẫn là thay đổi local chưa merge:

| Thành phần | Vai trò |
| --- | --- |
| Wazuh Manager snapshot adapter | Đọc `alerts.json` dưới dạng bytes/JSONL, lọc theo phạm vi nguồn và thời gian, tạo canonical evidence ổn định |
| Snapshot bundle transport | Đóng gói snapshot, hash, profile, context và ledger thành bundle bất biến để chuyển sang máy chạy AEGIS |
| Frozen study/run contract | Ghim scenario, profile, kit, runner, payload, baseline/fixed revision và cửa sổ 120 giây |
| Collection review | Tạo yêu cầu review và ghi nhận attestation tường minh của người vận hành; không tự nhận collection complete |
| Run binding | Đối chiếu PID, parent PID, timestamp, ProcessGuid và ScriptBlockId giữa manifest với evidence |

Các ranh giới an toàn được giữ:

- Không đọc live Wazuh từ core validation engine.
- Không lọc evidence theo nội dung detection đang cần chứng minh.
- Không cho phép symlink, reparse point, hardlink hoặc đường dẫn thoát khỏi
  bundle.
- Không ghi đè artifact đã tồn tại.
- `caller_reviewed` không đồng nghĩa `lab_verified`.
- Run binding chỉ báo `unknown`, `conflict` hoặc `caller_reviewed`; không tự kết
  luận Detected/Regression Passed.

## 7. Mốc kiểm thử mới nhất của branch đang làm

Mốc full-suite gần nhất đã ghi nhận:

```text
2481 passed, 1 skipped in 188.36s
pip check: No broken requirements found.
git diff --check: không có lỗi whitespace; chỉ có cảnh báo LF/CRLF của Git.
```

Test bị skip là kiểm tra FIFO tại `backend/tests/test_intake_io.py:452`, do FIFO
không khả dụng trên Windows; đây không phải test failure.

Các suite tập trung đã bao phủ manager snapshot, bundle transport, study/run
contract, collection review và run binding. Không thêm dependency bên ngoài.
Wheel build chưa được xác minh trong môi trường hiện tại vì virtual environment
không có `setuptools`/`wheel`; chưa tự ý cài thêm package.

## 8. Trạng thái hiện tại và phần chưa hoàn tất

Đã có đủ nền tảng để tạo một chuỗi offline có kiểm soát:

```text
safe execution
  -> Wazuh/Sysmon/PowerShell telemetry
  -> manager snapshot
  -> immutable evidence bundle
  -> collection review
  -> run binding
  -> canonical validation
  -> compare runs
```

Issue #12 **chưa hoàn tất**. Những phần còn lại là:

1. Ghép các module thành một CLI orchestration thống nhất.
2. Chạy A/B/C hoàn toàn bằng synthetic fixtures để kiểm tra toàn bộ đường đi.
3. Review độc lập code, error handling, evidence traceability và tài liệu vận
   hành.
4. Chỉ sau khi ba bước trên ổn định mới chạy A/B/C chính thức trên lab thật.
5. Đối chiếu evidence ID với bản ghi nguồn và chỉ công bố
   `Regression Passed` nếu đầy đủ điều kiện của Issue #9.
6. Khôi phục Execution Policy `CurrentUser` về trạng thái ban đầu sau khi kết
   thúc demo.
7. Chạy full test, `pip check`, `git diff --check`, rồi mới xin review, push/PR
   và merge.

## 9. Những điều báo cáo này không tuyên bố

- Chưa tuyên bố Issue #12 đã đóng hoặc production-ready.
- Chưa tuyên bố collection completeness chỉ từ một snapshot hoặc một
  attestation của người gọi.
- Chưa có kết luận Detection Gap hay Regression Passed cho lab A/B/C.
- Không coi rehearsal là một cuộc tấn công thật.
- Không có active response, thay đổi firewall hoặc payload độc hại trong demo.
- Không commit password, token, certificate, connector URL hay raw evidence
  chưa làm sạch.

**Tóm tắt để chia sẻ:** Sau bản tổng kết ngày 11/09, dự án đã hoàn thành và
merge chức năng so sánh hai validation runs (Issue #9), bổ sung parser Windows
telemetry từ Sysmon/PowerShell qua Wazuh (PR #25), đồng thời dựng được safe demo
không độc hại trên `LAB-ENDPOINT-01`. Lab đã xác nhận telemetry thật đi từ endpoint
đến Wazuh và đã sửa các lỗi rule trùng/field mapping. Branch Issue #12 hiện có
thêm chuỗi xử lý offline gồm snapshot, bundle, study contract, collection
review và run binding; full suite gần nhất đạt 2481 passed, 1 skipped. Phần còn
lại là ghép CLI, kiểm thử synthetic end-to-end, review độc lập và sau đó mới
chạy A/B/C chính thức trên lab.
