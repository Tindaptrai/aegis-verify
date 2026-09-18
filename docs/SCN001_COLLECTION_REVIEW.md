# SCN-001 — Xác nhận collection tường minh

API offline thuộc Issue #12, triển khai ngày 2026-09-14. Đây là bước nối study/run
đã kiểm với snapshot transport unknown; chưa phải CLI hoàn chỉnh hoặc lab verification.
Không gọi SSH, chạy payload, đọc credentials, restart hay sửa rules trên hệ thống.

## API

```python
from aegis_verify.demo.collection_review import (
    prepare_collection_request, approve_collection_request,
)

request_bytes = prepare_collection_request(bundle_path, run_inputs=run_inputs)
# Người review đọc request và cung cấp approval_bytes riêng, không tự điền true.
context_bytes = approve_collection_request(
    bundle_path, run_inputs=run_inputs,
    request=request_bytes, approval=approval_bytes,
)
```

`run_inputs` là dictionary toàn bộ bytes/params của `verify_run` trong
[SCN001_STUDY_RUN.md](SCN001_STUDY_RUN.md). Không nhận một CheckedRun do caller
tự tạo. Snapshot transport được verify lại từ source copies theo
[SCN001_EVIDENCE_BUNDLE.md](SCN001_EVIDENCE_BUNDLE.md).

Profile bytes phải đúng study, context phải trùng run, scope agent/host phải
trùng bindings. Request chứa run/study/input hashes, hash completion manifest
của transport, profile/scope/event-set fingerprints, `snapshot_ingested_at` và
cửa sổ chính xác. Request không chứa verdict hoặc các cờ xác nhận được điền sẵn.

### Ràng buộc thời điểm chụp snapshot

`scope.ingested_at` là **thời điểm do caller khai** khi chụp snapshot từ manager.
Nó không được máy xác minh và **không** chứng minh alert nào đã được index.

Nó chỉ dùng để loại trường hợp chứng minh được là sai: một snapshot chụp trước
khi cửa sổ run đóng thì không thể phủ cửa sổ đó. Vì vậy
`prepare_collection_request` từ chối khi `ingested_at < context.end`, và
`approve_collection_request` từ chối khi `collected_at < snapshot_ingested_at`.
Biên bằng nhau được chấp nhận: `ingested_at == context.end` là hợp lệ.

Đây là điều kiện **cần, không phải đủ**. Timestamp hợp lệ không chứng minh
collection đầy đủ; thiếu căn cứ thì kết quả vẫn phải là Inconclusive. Vì
`snapshot_ingested_at` nằm trong request, một approval không thể mang sang
snapshot khác hoặc sang bản chụp lại của cùng cửa sổ.

## Approval riêng của người review

Object JSON đóng, UTF-8, tối đa 1 MiB; không duplicate keys, unknown fields,
NaN, float hoặc ép kiểu string/number thành boolean. Tất cả trường bắt buộc:

| Trường | Giá trị / ý nghĩa |
| --- | --- |
| kind / version | `scn001_collection_approval` / `0.1.0` |
| request_sha256 | SHA-256 chính xác bytes request đã review |
| confirmed_by / reference | Người xác nhận và tham chiếu hồ sơ review |
| coverage_start / coverage_end | Bao phủ toàn cửa sổ 120 giây của run |
| collected_at / reviewed_at | Timestamp có timezone; `snapshot_ingested_at <= collected_at`, `coverage_end <= collected_at <= reviewed_at` |
| no_sampling_or_truncation | Boolean true chỉ khi thực sự xác nhận được |
| no_parse_errors_or_gaps | Boolean true chỉ khi thực sự xác nhận được |
| clocks_adequate | Boolean true chỉ khi thực sự xác nhận được |
| health_reference | Kiểm manager/agent health |
| filter_reference | Threshold/filter/sampling đã được review |
| rotation_reference | Nguồn snapshot/rotation/retention đã được review |
| backlog_reference | Kiểm ingestion backlog/record đến muộn |
| native_reference | Tham chiếu đối chiếu native-vs-manager theo run |
| time_reference | Nguồn thời gian, clock jump/sleep và giới hạn |

Nếu không đủ căn cứ, **không tạo approval complete**, tiếp tục dùng context
unknown. Không sửa dấu thời gian hoặc điền true để đủ điều kiện.
References là chuỗi mô tả không rỗng: API không mở file/URL đó, không xác thực
danh tính reviewer, chữ ký hoặc tính đúng của nội dung review.

## Kết quả và lưu trữ

Approval hợp lệ trả bytes context mới, chỉ thêm một declaration cho
`SCN-001-A03`: `complete_for_scope`, **caller-attested**. Engine hiện có vẫn
quyết định outcome; thiếu telemetry vẫn là Missing telemetry, không tự thành pass.
Request được tái dựng và so bytes, không tự cập nhật request/approval khi input đổi.
Thay receipt/run, profile, scope, source bytes hoặc completion làm request cũ hết hiệu lực.

Hai API chỉ đọc bundle; không tự ghi context/report. Caller phải lưu request,
approval và context mới cùng hồ sơ riêng tư, bên ngoài bundle input/Git, giữ
context/report unknown ban đầu. Context chuẩn của engine không chứa đầy đủ
các health/native references; không được bỏ approval gốc khi bàn giao.
Chưa có lệnh CLI lưu các output này một cách nguyên tử; chưa hướng dẫn chạy lab bước này.

Lỗi public: `CollectionReviewError: invalid_collection_review`, không in raw values.

## Dùng context đã attested ở bước đánh giá

Context trả về từ `approve_collection_request` **không** được đưa thẳng vào
`evaluate_demo_run` một mình. Phải kèm chính `request` và `approval` đã tạo ra nó:

```python
from aegis_verify.demo.evaluate import evaluate_demo_run, compare_demo_runs

report = evaluate_demo_run(
    bundle_path,
    run_inputs=run_inputs,
    scenario=scenario_path,
    context=attested_context_path,   # bytes do approve_collection_request trả về
    request=request_bytes,
    approval=approval_bytes,
)
```

`evaluate_demo_run` chạy lại review từ `request` và `approval`, rồi bắt buộc kết
quả **bằng đúng bytes** của file context. Vì vậy một context viết tay không đi
vòng qua quy trình review được, và assurance gắn với đúng run, study và snapshot.

Các cách gọi bị từ chối: đưa `context` mà thiếu `request` hoặc `approval`; đưa
`request`/`approval` mà không có `context`; dùng approval của run khác hoặc của
một lần chụp snapshot khác.

Không truyền `context` là cách dùng đúng cho run **không** có attestation. Khi đó
assurance là unknown và alert vắng mặt vẫn là Inconclusive, không thành false negative.

Việc chạy lại review chỉ kiểm rằng approval đã thực sự được lập cho đúng bộ input.
Nó **không** biến approval thành bằng chứng thu thập đầy đủ.

## So sánh hai run của demo

```python
comparison = compare_demo_runs(before=report_b, after=report_c)
```

Hàm này gọi `compare_reports` có sẵn và **không đổi verdict**. Nó gắn thêm
`comparison['run_binding']` với `run_id`, `status`, `reasons`,
`both_sides_caller_declared`, `request_sha256` và `native_review_sha256` cho cả
hai phía, để người đọc `Regression Passed` thấy luôn giới hạn binding của từng
run. Report không mang `run_binding` bị từ chối.

## Giới hạn cần reviewer chú ý

- Hash là tính nhất quán, không xác thực nguồn hoặc chống người thay toàn bộ inputs.
- Yêu cầu thư mục riêng do operator kiểm soát, không có người sửa đồng thời;
  không tuyên bố chống privileged writer/TOCTOU toàn hệ thống.
- `native_reference` chưa thay thế bước đối chiếu PID/ProcessGuid/ScriptBlockId
  và launch conflict trong [SCN001_RUN_BINDING.md](SCN001_RUN_BINDING.md).
  Hai API còn tách biệt; **Caller-attested không đồng nghĩa lab verified.**
- Không kiểm PCRE2 thực tế, SIEM ingestion completeness hoặc snapshot rotation từ xa.
- Đã có orchestration ở mức API Python (`evaluate_demo_run`, `compare_demo_runs`),
  **chưa** có subcommand CLI. Chưa chạy formal A/B/C và chưa có kết luận
  `Regression Passed` nào trên lab thật; các kết quả hiện có đều là synthetic.

## Chạy đối chiếu trên máy phát triển

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_collection_review.py -q -p no:cacheprovider --basetemp ('build/pytest-review-user-' + [guid]::NewGuid().ToString('N'))
```

Tests chỉ dùng synthetic snapshots và kit, không thực thi payload hoặc chạm lab.
