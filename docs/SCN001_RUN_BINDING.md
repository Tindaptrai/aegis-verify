# SCN-001 — Đối chiếu bằng chứng với từng run

API offline thuộc Issue #12. Đây là kiểm tính nhất quán của canonical/provenance
và hồ sơ native do người review khai báo, **không đọc EVTX hoặc chứng thực máy từ xa**.
Không thay outcome của validation engine, không tự xác nhận collection đầy đủ.

## API và đầu vào

```python
from aegis_verify.demo.run_binding import review_run_binding

inspection_bytes = review_run_binding(bundle_path, run_inputs=run_inputs)
reviewed_bytes = review_run_binding(
    bundle_path, run_inputs=run_inputs, native_review=native_review_bytes,
)
```

`run_inputs` là bộ tham số của `verify_run` trong SCN001_STUDY_RUN.md.
Bundle phải là snapshot transport unknown đã đóng băng. Hàm kiểm lại study,
kit, manifest chain, context/profile/scope và source copies; không tin đối tượng
model do caller tự tạo. Yêu cầu thư mục riêng, không có writer đồng thời.

Candidate selection dùng conditions của A01/A02 qua predicates hiện có:
giữ true/unknown matches và records mang child PID. Definite nonmatch của PID
khác không là candidate, nhưng vẫn nằm nguyên trong bundle/ledger.
Không lọc theo rule ID hoặc chọn witness thuận lợi.

## Ý nghĩa kết quả

| status | Ý nghĩa |
| --- | --- |
| unknown | Thiếu telemetry, PID/provenance/match field hoặc chưa có native review/content confirmation |
| conflict | PID/parent PID sai, nhiều candidate, path/command sai biến thể, timestamp ngoài launch..exit hoặc native metadata mâu thuẫn |
| caller_reviewed | Một Sysmon và một PowerShell candidate khớp manifest và hồ sơ native do người review cung cấp |

Conflict ưu tiên hơn unknown. Null/chuỗi trống hoặc chỉ khoảng trắng không được
lấp từ manifest/native receipt. So timestamp chính xác nanosecond; không sửa
GUID, path, chữ hoa/thường hoặc source bytes để đạt khớp.

A phải dùng original; B/C/Rehearsal dùng renamed. Parent PID của Sysmon phải
bằng runner PID; cả hai process ID phải bằng child PID. Cần Windows record IDs,
ProcessGuid và ScriptBlockId, PowerShell counters 1/1. Các parser hiện có từ chối
fragmented/incomplete 4104 trước khi bước binding nhận input.

Output có kind/version/run_id, request_sha256, native_review_sha256 (null nếu
chưa có), status, `both_sides_caller_declared`, reason codes và danh sách evidence
event_id/raw_event_ref/raw_event_hash. Không có final_status, không sinh event
mới, không ghi file.

`both_sides_caller_declared` luôn là `true`. Nó có mặt để `caller_reviewed` không
bị đọc thành xác minh độc lập: cả hai phía được đem so đều là file do caller
soạn, nên "khớp" chỉ có nghĩa là hai tài liệu của chính caller nhất quán với nhau.

Reason codes có thể xuất hiện: `native_review_missing`, `native_content_unconfirmed`,
`native_parent_unconfirmed`, `missing_binding_metadata`, `missing_telemetry`,
`child_pid_mismatch`, `parent_pid_mismatch`, `outside_execution_interval`,
`payload_variant_mismatch`, `multiple_candidates`, `native_payload_mismatch`,
`native_metadata_mismatch`.

Đường đánh giá demo (`evaluate_demo_run`) gọi hàm này **không kèm** native review,
nên trên đường đó status không bao giờ đạt `caller_reviewed` và luôn kèm lý do.
Status `conflict` khiến việc đánh giá bị từ chối; các trạng thái khác được gắn
vào report tại khoá `run_binding`.

`compare_demo_runs(before=..., after=...)` mang binding của cả hai run sang output
so sánh tại `comparison['run_binding']`, gồm `run_id`, `status`, `reasons`,
`both_sides_caller_declared`, `request_sha256`, `native_review_sha256`. Verdict
so sánh do `compare_reports` quyết định và **không** bị hàm này thay đổi; phần
thêm chỉ để không ai đọc `Regression Passed` mà thiếu giới hạn binding của từng
run. Report không mang `run_binding` bị từ chối.

## Hồ sơ native tường minh

JSON đóng, UTF-8 tối đa 1 MiB; không duplicate keys, extra fields hoặc ép kiểu.
Các trường root bắt buộc:

- `kind`: `scn001_native_review`; `version`: `0.1.0`.
- `request_sha256`: hash chính xác collection request tạo từ cùng run/bundle
  bằng `prepare_collection_request`; không tự cập nhật receipt cũ.
- `confirmed_by`, `reference`: người review và tham chiếu hồ sơ native.
- `reviewed_at`: timestamp có timezone, không trước observed end của runner.
- `payload_path`: đường dẫn native chính xác của payload lượt đó.
- `payload_sha256`: hash payload đã khóa trong study.
- `full_script_reviewed`: boolean; chỉ true nếu người review đã đối chiếu toàn
  nội dung native với payload được duyệt, không chỉ tìm marker.
- `records`: đúng hai object, thứ tự không quan trọng, evidence IDs khác nhau.

Mỗi record gồm `evidence_id`, `hostname`, `provider`, `windows_record_id`,
`event_time`, `process_id`, `process_guid`, `script_block_id` và
`parent_process_id`. Process ID là integer 1..4294967295, không boolean.
Sysmon có script_block_id null; PowerShell có process_guid **và
`parent_process_id`** null — khai parent PID trên record PowerShell bị từ chối,
vì không có gì để đối chiếu.

`parent_process_id` là **optional**, mặc định null, để các receipt viết trước
thay đổi này vẫn hợp lệ. Nhưng bỏ trống không phải trung lập: khi record Sysmon
có parent PID ở nguồn mà operator không khai, kết quả ghi
`native_parent_unconfirmed` và status không thể đạt `caller_reviewed`. Đây là
quan hệ duy nhất mà người đọc EVTX có lợi thế xác nhận, nên nó được ghi nhận
tường minh thay vì mặc định coi như đã đối chiếu. Khai sai giá trị vẫn là conflict.

Những field native
phải được operator lấy từ record đã review, không copy giá trị mong muốn để
làm receipt khớp. Event time có thể khác cách viết timezone/precision nhưng phải
biểu diễn đúng cùng thời điểm.

Metadata không khớp trả conflict; receipt sai schema/stale hash trả
`RunBindingError: invalid_run_binding`. Trường native reference không được mở
tự động, hồ sơ không được ký/xác thực và công cụ không kiểm toàn bộ source text.

## Giới hạn quan trọng

**caller_reviewed không phải lab_verified, Detected hay Regression Passed.**
Hai hàm chỉ đối chiếu nội dung khai báo, không chứng minh bản khai đúng với EVTX.
Không gắn nhãn thành công chỉ vì generic CLI có witness. Các định danh source
được đối chiếu nguyên chuỗi, chưa thêm UUID normalization hoặc EVTX decoding.

Context collection vẫn giữ nguyên unknown; approval collection là bước riêng
trong SCN001_COLLECTION_REVIEW.md. Caller cần lưu request, native receipt,
binding report, collection approval và cả báo cáo unknown/attested riêng tư
ngoài Git, không ghi đè bundle input.

Chưa có CLI orchestration chung hoặc tự động thu hồ sơ native. Formal lab A/B/C,
review độc lập và quy trình lưu output hoàn chỉnh vẫn cần trước đóng Issue #12.

## Test trên máy phát triển

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_scn001_run_binding.py -q -p no:cacheprovider --basetemp ('build/pytest-binding-user-' + [guid]::NewGuid().ToString('N'))
```

Tests synthetic, không thực thi runner/payload, không kết nối lab.
