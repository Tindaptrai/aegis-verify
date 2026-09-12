# SCN-001 — Kit demo PowerShell vô hại

Phần 1 của Issue #12: **chuẩn bị kit và rehearsal**, chưa phải demo A/B/C hoàn
chỉnh. Chưa có bộ export/attestation và profile evaluation được khóa. Không
chạy A/B/C chính thức hoặc kết luận `Regression Passed` từ kit này.

## 1. Chạy ở máy nào?

| Nơi | Công việc |
| --- | --- |
| Windows phát triển có repository | Test Python, tạo kit offline, review file |
| Windows lab được duyệt, x64, Windows PowerShell 5.1 | Preflight và rehearsal với Sysmon/Wazuh agent |
| Linux Wazuh manager | Người vận hành kiểm tra/cài rule, chạy logtest, thu log |

Không cần Python trên Windows lab. Không chạy payload trên manager. Kit không
SSH, không gọi API SIEM, không đọc mật khẩu hoặc tự cấu hình hệ thống.

Payload chỉ có hai lệnh:

```powershell
Write-Output 'AEGIS_SAFE_DEMO_V1'
Write-Output ('AEGIS_PID=' + $PID)
```

Hai tên `lab_update.ps1` và `maintenance_check.ps1` có cùng bytes ASCII/LF và
SHA-256. Không thêm comment, BOM hoặc sửa bằng editor giữa hai lượt. Payload
không ghi file; runner ghi metadata/stdout/stderr vào **thư mục mới**.
Windows, Sysmon và agent vẫn có thể tự ghi telemetry như bình thường.

## 2. Những điều phải xác nhận trước

1. Có quyền thực hiện demo trên endpoint lab; biết hostname từ `hostname` và
   đường dẫn đích đầy đủ. Hostname/phần chữ hoa-thường phải trùng manifest.
2. Chọn custom rule ID chưa dùng trong dải 100000–120000, kiểm tra cả các file
   rule đang được nạp và cấu hình include/exclude; không chỉ xem một file.
3. Xác minh parent SID bằng ruleset và `wazuh-logtest -v` thực tế. ID `91816`
   trong test Python chỉ là input synthetic, không phải default cho lab.
4. Config test sạch; không bỏ qua duplicate warnings chỉ vì exit code bằng 0.
5. Sysmon Event 1 và PowerShell 4104 được đọc/thu thập; agent đang chạy.
   Record 4104 phải có `messageNumber=1`, `messageTotal=1`, script text đầy đủ.
6. Alert threshold không loại bỏ telemetry hoặc demo level 5. Kiểm tra Active
   Response, integration/webhook và rule kế thừa; demo không được gây block hay
   phản ứng tự động ngoài ý muốn. Không tự tắt phòng vệ để làm demo.

Giữ kit/output trong thư mục riêng, ACL chỉ cho người vận hành tin cậy ghi.
Runner từ chối UNC, đường dẫn tương đối, ADS, dot-segments, tên DOS đặc biệt,
symlink/reparse point; profile đường dẫn hiện tại chỉ nhận ASCII chữ/số,
space, `_`, `-`, `.` và dấu phân cách `\`. Dùng tên dài, không dùng alias 8.3
như `KUROH~1`. Thư mục lab tối đa 200 ký tự, không có dấu `\` cuối.

Đây là công cụ cho operator tin cậy, **không phải sandbox chống người có quyền
sửa runner/kit hoặc đồng thời thay file**. SHA-256 kiểm tra tính nhất quán,
không phải chữ ký hoặc chứng thực trạng thái remote. Không sửa `kit.json`
thủ công; nếu thay cấu hình, tạo kit mới và review lại.

## 3. Tạo kit trên máy phát triển

Chỉ làm sau khi có các thông tin ở mục 2. Các câu hỏi dưới đây không yêu cầu
mật khẩu/token. Dán nguyên block vào PowerShell, không dán ký hiệu prompt.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $aegisRepo = 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
    $aegisPython = Join-Path $aegisRepo '.venv\Scripts\python.exe'
    $aegisHost = Read-Host 'Hostname chinh xac cua Windows lab da duyet'
    $aegisLabDir = Read-Host 'Duong dan day du thu muc kit SE dat tren Windows lab'
    $aegisRuleId = Read-Host 'Custom rule ID da xac minh con trong'
    $aegisParent = Read-Host 'Parent SID da xac minh bang ruleset/logtest'
    $aegisOccupied = Read-Host 'IDs dang dung, cach bang dau phay; none CHI khi da xac minh rong'
    $aegisOutput = Join-Path (Join-Path $env:USERPROFILE 'Downloads') ('aegis-scn001-kit-' + [guid]::NewGuid().ToString('N'))
    $aegisArgs = @(
        (Join-Path $aegisRepo 'scripts\prepare_scn001_kit.py'),
        '--output-dir', $aegisOutput, '--lab-directory', $aegisLabDir,
        '--target-host', $aegisHost, '--rule-id', $aegisRuleId,
        '--parent-sid', $aegisParent, '--occupied-ids', $aegisOccupied
    )
    & $aegisPython @aegisArgs
    if ($LASTEXITCODE -ne 0) { throw 'Dung: tao kit that bai, khong dung output do.' }
    Write-Host ('KIT_DIRECTORY=' + $aegisOutput)
    Get-ChildItem -LiteralPath $aegisOutput | Select-Object Name, Length
}
```

Output gồm hai payload, runner, `baseline.xml`, `fixed.xml`, `kit.json` và
`logtest-cases/`. Manifest được ghi cuối; thiếu manifest là kit chưa hoàn thành.
Lỗi không tự xóa thư mục dang dở. Không chạy lại vào cùng output.

Review payload, runner và hai rule trước khi chuyển file bằng phương thức
được phép trong lab. Copy **nội dung** kit tới đúng đường dẫn `lab_directory`
trên endpoint, không tạo thêm một tầng thư mục. Không ghi đè thư mục có sẵn.
Chuyển riêng rule và synthetic cases tới thư mục staging mới trên manager,
ngoài `/var/ossec/etc/rules`; không gửi credential hay raw export lên Git.

## 4. Preflight trên Windows lab — chưa chạy payload

Mở Windows PowerShell 5.1 x64 theo quyền được quản trị viên cho phép. Không đổi
execution policy, không dùng Bypass, không tự nâng quyền để vượt lỗi.

```powershell
$aegisKitDir = Read-Host 'Duong dan kit tren Windows lab'
$aegisExpectedHost = Read-Host 'Hostname lab da duyet, dung chu hoa-thuong'
$aegisAppliedRevision = Read-Host 'Revision da duoc operator review: baseline hoac fixed'
$aegisAppliedHash = Read-Host 'SHA256 lowercase cua rule revision da doi chieu tren manager'
$aegisRunId = 'rehearsal-' + [guid]::NewGuid().ToString('N')
$aegisRunDir = Join-Path (Join-Path $env:USERPROFILE 'Downloads') $aegisRunId
$aegisParams = @{
    KitDirectory = $aegisKitDir
    RunDirectory = $aegisRunDir
    RunId = $aegisRunId
    RunLabel = 'Rehearsal'
    ExpectedComputerName = $aegisExpectedHost
    AppliedRuleRevision = $aegisAppliedRevision
    AppliedRuleSha256 = $aegisAppliedHash
}
$aegisPS = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $aegisPS -NoLogo -NoProfile -NonInteractive -File (Join-Path $aegisKitDir 'Invoke-SafeDemo.ps1') @aegisParams
$aegisPreflightExit = $LASTEXITCODE
Write-Host ('PREFLIGHT_EXIT=' + $aegisPreflightExit)
```

Kết quả tốt: `kind=safe_demo_preflight`, `status=ready`, `executed=false`,
exit 0. Không tạo thư mục run. Preflight đọc một event cũ mỗi kênh để kiểm tra
khả năng truy cập, **không xác nhận agent đã chuyển đủ log hay logging liên tục**.
Hash nhập là khai báo của operator, runner không truy vấn manager để xác thực.

## 5. Rule review/logtest — người vận hành trên manager

Hai revision dùng **cùng ID**; không nạp cùng lúc. Baseline khớp đường dẫn tên
gốc. Fixed khớp toàn bộ hai dòng script được duyệt, cho phép LF/CRLF và một
newline cuối; không khớp marker đơn độc, comment-only hoặc nội dung thêm.
Fixed là **rule nội dung chịu được đổi tên**, không phải detector malware hay
mô hình suy luận hành vi tổng quát. Không có kết luận `blocked` từ rule match.

Lệnh đọc trạng thái ban đầu trên Linux:

```bash
sudo /var/ossec/bin/wazuh-analysisd -V
sudo /var/ossec/bin/wazuh-analysisd -t
echo "CONFIG_TEST_EXIT=$?"
sudo grep -RnEo '<rule[[:space:]][^>]*>' /var/ossec/etc/rules
sudo grep -nE '<rule_(dir|include|exclude)' /var/ossec/etc/ossec.conf
```

Không cần gửi toàn bộ cấu hình. Sau khi xác nhận ID, parent và tác động tự
động, reviewer kiểm tra mapping sau với **mỗi revision riêng**:

| Synthetic case | Baseline demo ID | Fixed demo ID |
| --- | --- | --- |
| `original` | match | match |
| `renamed` | không match | match |
| `marker-only`, `comment-only`, `unrelated`, `missing-text` | phụ thuộc parent | không match |
| Sai host/provider/channel/EventID | không match | không match |
| `fragmented`, `missing-counter` | không match | không match |

Parent có thể yêu cầu nội dung như `$PID`; không buộc baseline khớp một mẫu
đã bị parent loại. `not_demo` nghĩa **không phải ID demo**, vẫn có thể xuất hiện
alert từ rule khác. Catalog chứa kỳ vọng, không phải kết quả đã chạy.

Với file synthetic đã chuyển lên manager, bắt đầu ở chế độ hiển thị đầy đủ:

```bash
read -r -p 'Duong dan tuyet doi original.synthetic.json da review: ' aegisCaseFile
test -f "$aegisCaseFile" && test ! -L "$aegisCaseFile" && sudo /var/ossec/bin/wazuh-logtest -v < "$aegisCaseFile"
```

Kiểm tra Phase 2 có đúng `win.*`, Phase 3 có đúng parent và các field guards.
Không đoán decoder là `json` hay `windows_eventchannel`: xác minh trên phiên
bản đang dùng; nếu không tới parent thì dừng, không cài thêm decoder để ép qua.
Sau khi review/cài **một** revision và biết decoder thực tế của mẫu dương:

```bash
read -r -p 'Demo rule ID da review: ' aegisDemoRuleId
read -r -p 'Decoder da xac minh o Phase 2: ' aegisDemoDecoder
sudo /var/ossec/bin/wazuh-logtest -q -U "${aegisDemoRuleId}:5:${aegisDemoDecoder}" < "$aegisCaseFile"
echo "POSITIVE_TEST_EXIT=$?"
```

Mỗi lần chỉ truyền một dòng JSON. Chạy từng negative với `-v`, xác nhận decoder
hoạt động và không khớp demo ID. **Exit khác 0 của `-U` đơn lẻ không chứng minh
negative đạt** vì cũng có thể là lỗi input/tool. Lưu output và hash vào staging
riêng; không đưa synthetic events vào index production hoặc bundle lab.

### Cài/đổi revision và rollback: điểm kiểm soát bắt buộc

Kit không tự thực hiện các bước sau. Trước cài, người vận hành tạo thư mục
backup mới bằng `mktemp -d` ngoài `etc/rules`, quyền riêng (`umask 077`), lưu
revision đã review, hash và cấu hình liên quan; không sửa bản backup sau đó.

1. Chọn một file demo riêng trong rule directory được nạp; xác minh file đích
   chưa tồn tại, không là symlink, không trùng ID. Không overwrite
   `local_rules.xml` hoặc default rules. Chỉ cài revision đã review với owner/
   permission giống policy rule hiện tại; xác minh hash sau copy.
2. Config test và toàn bộ logtest; nếu lỗi thì dừng, chưa restart. Gỡ khỏi
   rule directory **chỉ file demo vừa tạo, sau đối chiếu hash**; giữ bản sao
   trong staging. Config test lại. Không xóa log hoặc thư mục rules.
3. Khi tests và tác động tự động đã được duyệt, operator chủ động restart
   manager trong thời gian phù hợp, kiểm tra active và log mới. Logtest thành
   công không thay thế bước xác nhận manager áp dụng revision.
4. Khi chuyển baseline → fixed: chụp/hash bản đang nạp vào backup riêng,
   xác minh nó đúng baseline đã cài, rồi mới thay đúng file demo. Bất kỳ hash
   khác dự kiến: dừng để review; không overwrite mù. Test/restart như trên.
5. Rollback về baseline chỉ từ backup đã đối chiếu. Hoặc gỡ file demo khi
   hoàn tất lab, với guard hash tương tự, config test/restart có chủ đích.
   Không phục hồi toàn bộ cấu hình cũ để gỡ một rule demo.

Option `no_email_alert` trong template không tắt Active Response/integration;
phải review các cơ chế đó riêng. Hướng dẫn cài chi tiết theo file đích, quyền
và revision thực tế sẽ được chốt cùng người vận hành, không chạy tự động.

## 6. Rehearsal sau khi review và được phép chạy

Chỉ chạy khi preflight exit 0, rule đã test/applied và operator đồng ý. Giữ
nguyên `$aegisParams` ở mục 4; không đổi `RunLabel` sang A/B/C lúc này.

```powershell
& $aegisPS -NoLogo -NoProfile -NonInteractive -File (Join-Path $aegisKitDir 'Invoke-SafeDemo.ps1') @aegisParams -Execute
Write-Host ('REHEARSAL_EXIT=' + $LASTEXITCODE)
```

Rehearsal chọn `maintenance_check.ps1`. A chọn tên gốc, B/C chọn tên mới;
A/B chỉ nhận baseline, C chỉ nhận fixed. API đã có guards này để dùng về sau,
không có nghĩa đã sẵn sàng cho A/B/C evaluation chính thức.

Runner đợi khoảng 10 giây từ đầu window rồi tạo đúng một child PowerShell,
timeout child 30 giây. Nếu cần, chỉ dừng child do chính runner tạo. Window
danh nghĩa 120 giây được đếm bằng Stopwatch, timestamp UTC có 7 chữ số phần
thập phân; đây không phải cam kết đồng hồ chính xác tới 100 ns. Không chạy
các lượt chồng nhau; nếu máy sleep/clock jump, không dùng lượt đó để kết luận gap.

Output riêng tư:

- `execution-start.json`: đã bắt đầu chuẩn bị lượt, chưa chứng minh launch.
- `execution-launched.json`: PID child đã tạo; vẫn chưa chứng minh thành công.
- `stdout.txt`, `stderr.txt`: output child; phải đúng hai dòng và PID thực tế.
- `execution.json`: status `executed` hoặc `failed`, timestamps, timeout/exit,
  hashes và rule declaration. Nếu thiếu final manifest thì lượt chưa hoàn tất.

Exit 0 và `executed_not_evaluated` chỉ xác nhận runner quan sát child hoàn tất
đúng output. **Không phải Detected, Detection Gap, complete_for_scope hoặc
Regression Passed.** Không tái dùng run directory, không tự retry; thất bại
giữ lại để điều tra, lượt sau phải có RunId/thư mục mới.

Sau rehearsal, gửi metadata đã review: exit/status, hostname đã làm sạch khi
cần, các trường của Sysmon Event 1/4104 liên quan và decoder/parent logtest.
Giữ export JSON gốc riêng tư, chưa commit hoặc gửi toàn bộ script blocks/logs.
Chúng có thể chứa lệnh khác nhạy cảm. Mình sẽ hướng dẫn thu đúng scope và
sanitization trong phần export/attestation tiếp theo.

## 7. Khi gặp lỗi

| Mã/lỗi | Việc cần làm |
| --- | --- |
| `AEGIS_WRONG_HOST` | Dừng; xác nhận máy và hostname, không sửa để ép chạy trên máy khác |
| `AEGIS_INVALID_LOCAL_PATH`, `AEGIS_REPARSE_PATH` | Chọn đường dẫn local rõ ràng đúng profile; không vượt reparse guard |
| `AEGIS_INVALID_KIT_MANIFEST`, `AEGIS_*HASH_MISMATCH`, `AEGIS_UNREVIEWED_PAYLOAD` | Không Execute; đối chiếu kit gốc, tạo lại/review thay vì sửa hash |
| `AEGIS_RUN_OUTPUT_EXISTS` | Giữ output cũ; chọn RunId và thư mục mới |
| `AEGIS_RUN_OUTPUT_IN_REPOSITORY` | Chọn output riêng tư ngoài mọi Git checkout |
| `AEGIS_TELEMETRY_*` | Kiểm tra service/logging/quyền đọc cùng quản trị viên; runner không tự sửa |
| Policy/permission error | Dừng, xin hướng xử lý; không Bypass hoặc tự nâng quyền |
| `AEGIS_EXECUTION_*`, `AEGIS_CHILD_*`, thiếu final manifest | Lượt failed/incomplete, không phải Detection Gap; giữ metadata để review |

Preflight không chống tiến trình khác có quyền ghi thay file giữa kiểm tra và
launch. Runner không ký code, không xác thực remote, không kiểm chứng pipeline
đầy đủ. Luôn dùng kit từ commit được review trong thư mục riêng tin cậy.

## 8. Kiểm chứng trên máy phát triển

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path 'build' -Force | Out-Null
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Tests runner dùng PowerShell thật cho AST/preflight từ chối; unit test telemetry
và child-result dùng test doubles ghi nhãn rõ, không chạy payload hay giả rằng
máy dev có Sysmon. Không có Windows PowerShell hoặc policy chặn thì skip có lý
do. Runtime success/timeout, PCRE2 và parent chain phải kiểm chứng riêng trên lab.

## Nguồn và phần tiếp theo

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html): ID custom, nạp rules và restart.
- [Rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html): field PCRE2 và `no_email_alert`.
- [Wazuh logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html): một input/`-U` và các chế độ output.
- [Thiết kế](../../docs/superpowers/specs/2026-09-12-safe-demo-design.md) và [checkpoint](../../docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md).

Tiếp theo: review độc lập kit → parent/negative controls trên lab → rehearsal →
thiết kế export/scope/attestation → khóa profile → A/B/C và compare bằng CLI
hiện có. Chỉ đóng Issue #12 khi có evidence và human review, không chỉ test kit.
