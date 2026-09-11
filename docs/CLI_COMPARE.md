# Issue #9 — So sánh hai validation runs offline

`aegis compare` so sánh hai JSON report do `aegis validate --format json` tạo.
Comparison không chạy hành động lab, không parse log vendor, không sửa scenario
ground truth và không suy ra thất bại từ dữ liệu chưa đủ đánh giá.

## Hai API

```python
from aegis_verify.compare import compare_reports, compare_runs

# Đã có hai report dạng dictionary: không cần filesystem.
result = compare_reports(before=before_report, after=after_report)

# Adapter cho hai file JSON local, dùng đường dẫn tuyệt đối đã xác minh.
result = compare_runs(before=before_path, after=after_path)
```

CLI chỉ gọi adapter rồi render text/JSON. Các kết quả assertion và evidence refs
được giữ riêng cho `before` và `after`. Comparison không mở `raw_event_ref`.

## Điều kiện tương thích V0

Hai report phải có cùng scenario ID/version/fingerprint, profile ID/version/
fingerprint, tập assertion và role của từng assertion. V0 dùng version bằng nhau
chính xác, chưa có chính sách tự chấp nhận minor version khác nhau. Cùng ID nhưng
đổi nội dung ground truth vẫn bị từ chối. Chỉnh detection rule bên SIEM được phép;
đổi điều kiện đánh giá trong profile thì cần baseline mới theo profile đó.

Môi trường (`environment_id`), bindings theo tên/giá trị và độ dài cửa sổ đánh giá
phải bằng nhau. Thứ tự khai báo các binding không quan trọng; thứ tự phần tử của
binding dạng danh sách vẫn được so sánh chính xác. Khác host hoặc lab không được
ngầm xem là một retest cùng scope.

Run ID, thời điểm bắt đầu/kết thúc, evidence IDs, event-set fingerprint và
collection declarations được phép khác. Độ dài cửa sổ được tính chính xác bằng
nanosecond. Mỗi declaration được kiểm tra riêng với fingerprints, coverage và
assurance của chính run đó. `scope_fingerprint` bao gồm cả run ID và thời gian,
nên không thể dùng phép bằng nhau của hash này làm tiêu chí tương thích giữa runs.

`validate` thêm `comparison_inputs` version `0.1.0`, gồm snapshot scenario,
profile và context đã validate. Comparison tính lại fingerprints của snapshot,
kiểm tra IDs, counts, final status, role/reason, collection assurance, duplicate
assertions và witness references. Report cũ thiếu snapshot bị từ chối với hướng
dẫn chạy lại `validate`; không tự đoán context từ hash.

## Chuyển trạng thái assertion

| Trước / Sau | satisfied | false_negative | inconclusive | missing_telemetry |
| --- | --- | --- | --- | --- |
| satisfied | unchanged_pass | regression | became_unevaluable | became_unevaluable |
| false_negative | improvement | unchanged_fail | became_unevaluable | became_unevaluable |
| inconclusive | became_evaluable | became_evaluable | unchanged_unknown | unknown_changed |
| missing_telemetry | became_evaluable | became_evaluable | unknown_changed | unchanged_unknown |

`became_evaluable` chỉ nói sau này đã đủ điều kiện đánh giá; không chứng minh
trước đó có detection gap. Outcome và reason code gốc luôn được giữ lại.

## Khi nào hiện Regression Passed?

Phải có ít nhất một assertion `false_negative → satisfied`, tất cả assertion
của run sau đều `satisfied`, và cả hai run không có assertion unknown/missing.
`false_negative` phải là detection assertion có telemetry evidence và collection
declaration `complete_for_scope` hợp lệ. Vì vậy trước phải có gap đã xác nhận,
sau phải đạt toàn bộ; chỉ tìm được alert sau một run Inconclusive là chưa đủ.

Ưu tiên tổng hợp:

1. Có regression đã xác định: `Regression`; counts vẫn giữ các phần unknown.
2. Có chuyển trạng thái liên quan unknown/missing: `Inconclusive`.
3. Có improvement nhưng còn gap: `Improved with remaining gaps`.
4. Có improvement và đạt điều kiện trên: `Regression Passed`.
5. Không thay đổi: `Unchanged pass`, `Unchanged fail` hoặc `Unchanged mixed`.

## Evidence và giới hạn kết luận

Mỗi assertion giữ evidence IDs, raw refs/hashes, witness pairs, unevaluable IDs
và collection assurance của từng run. `evidence_changes` liệt kê IDs added,
removed, retained theo thứ tự ổn định. ID mới không tự chứng minh detector tốt
hơn; nó chỉ cho biết tập evidence đã khác. Hãy dùng cả outcome và reason code.

Hash kiểm tra sự nhất quán, không phải chữ ký số. Comparison không xác minh
nguồn report đáng tin, không tải raw bytes, không chạy lại predicates trên
canonical events và không tự xác nhận lời attestation của người thu thập log.
Người review phải kiểm tra nguồn evidence và collection trước kết luận lab.

Adapter file V0 dùng giới hạn intake hiện có: tối đa **1 MiB mỗi report**, độ sâu
JSON 32 và 50.000 nodes. UTF-8 có/không BOM được hỗ trợ, duplicate keys và số
NaN/Infinity bị từ chối. Report vượt giới hạn bị từ chối toàn bộ; không cắt evidence
để ép comparison chạy. Library in-memory tái kiểm tra contracts nhưng không áp
giới hạn byte của adapter file. Output CLI vẫn có giới hạn 32 MiB.

JSON có thêm snapshot cấu hình đã chọn, có thể chứa target bindings, điều kiện
profile, mô tả scenario và tên người attestation. Review/sanitize trước khi chia
sẻ; không đưa credentials, raw lab exports hoặc cấu hình chưa làm sạch lên Git.
Snapshot không nhúng raw logs. Ground truth trong repository không bị thay đổi.

## Chạy thử trên Windows PowerShell

Chạy nguyên khối sau. Đây là **smoke test synthetic**: đánh giá cùng một fixture
hai lần, kết quả mong đợi `Unchanged pass`, không phải demo sửa detection gap.
Không có thư mục `synthetic-detected-after` bắt buộc và không dùng placeholder.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $repo = 'I:\AEGIS-VERIFY'
    $py = Join-Path $repo '.venv\Scripts\python.exe'
    $scenario = Join-Path $repo 'tests\fixtures\cli\synthetic-detected\scenario.yaml'
    $fixture = Join-Path $repo 'tests\fixtures\cli\synthetic-detected'
    $out = Join-Path $repo ('build\compare-smoke-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $out | Out-Null
    $utf8 = [System.Text.UTF8Encoding]::new($false)

    foreach ($name in @('before', 'after')) {
        $lines = & $py -m aegis_verify validate --scenario $scenario --fixture $fixture --format json
        $code = $LASTEXITCODE
        if ($code -notin @(0, 1, 3)) { throw "Validate failed: exit $code" }
        $json = $lines -join [Environment]::NewLine
        if (($json | ConvertFrom-Json).kind -ne 'evaluation') { throw 'Missing evaluation report' }
        [System.IO.File]::WriteAllText((Join-Path $out ($name + '.json')), $json, $utf8)
    }

    $before = Join-Path $out 'before.json'
    $after = Join-Path $out 'after.json'
    & $py -m aegis_verify compare --before $before --after $after
    if ($LASTEXITCODE -ne 0) { throw 'Compare failed' }
    $lines = & $py -m aegis_verify compare --before $before --after $after --format json
    if ($LASTEXITCODE -ne 0) { throw 'Compare JSON failed' }
    [System.IO.File]::WriteAllText((Join-Path $out 'compare.json'), ($lines -join [Environment]::NewLine), $utf8)
    Write-Host "Ket qua nam tai: $out"
}
```

Với hai run thật, tạo `before.json` và `after.json` từ đúng snapshot tương ứng,
giữ cùng ground truth và scope theo quy tắc trên. Không sửa JSON verdict hoặc
copy attestation giữa các run để tạo `Regression Passed`.

Exit code `compare`: 0 = comparison đã tạo, **không đồng nghĩa security pass**;
2 = input không hợp lệ/không tương thích; 4 = lỗi nội bộ hoặc output. Đọc
`comparison.status` và từng assertion khi tích hợp CI. Lỗi xuất ra stderr,
không có partial report ở stdout.

## Kiểm chứng và review

```powershell
cd 'I:\AEGIS-VERIFY'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Test của Issue #9 dùng synthetic fixtures/attestations: 16 chuyển trạng thái,
full/partial gap fix, scope/profile compatibility, malformed reports, evidence
trace, text/JSON CLI, BOM và input limits. Các engine/canonical contracts giữ
nguyên semantics. Chưa kiểm chứng retest lab thật; cần reviewer độc lập xem
compatibility policy, unknown states, evidence traceability và disclosure của
snapshot cấu hình trước merge.

Kiểm chứng ngày 2026-09-11 trên Python 3.13.14/Windows: **1854 passed,
1 skipped** (FIFO không có trên Windows), `pip check` sạch và
`git diff --check` đạt. Đã chạy nguyên khối PowerShell smoke ở trên, xuất
`Unchanged pass` cùng evidence IDs nguyên vẹn. Wheel build thành công với build
isolation; cách build không isolation không chạy được vì venv thiếu setuptools.
Không thêm runtime dependency và không thay đổi venv để xử lý lỗi build này.
