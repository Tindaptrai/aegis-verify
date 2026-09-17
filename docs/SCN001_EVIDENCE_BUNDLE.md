# Evidence bundle SCN-001 — snapshot transport offline

Trạng thái 2026-09-14: đã có API Python chuẩn bị và verify **transport unknown**.
Đã thêm API study/run/kit riêng trong [SCN001_STUDY_RUN.md](SCN001_STUDY_RUN.md),
và API xác nhận caller-attested trong [SCN001_COLLECTION_REVIEW.md](SCN001_COLLECTION_REVIEW.md).
Đã có đối chiếu run/provenance và khai báo native trong [SCN001_RUN_BINDING.md](SCN001_RUN_BINDING.md).
Chưa tích hợp thành CLI `prepare_scn001_bundle.py` hoặc tự đọc/xác thực EVTX.
Không dùng transport này một mình để công bố kết quả lab A/B/C.

## Phần đã có

Module `aegis_verify.demo.snapshot_bundle`:

```python
@dataclass(frozen=True, slots=True)
class SnapshotFile:
    path: str | Path
    source_label: str
    sha256: str

def prepare_snapshot_bundle(snapshots, *, scope, profile, context, destination):
    # Trả Path tuyệt đối của directory mới đã ghi và đọc lại.
    ...

def verify_snapshot_bundle(root):
    # Trả ManagerSnapshotResult đã tái dựng từ snapshot copies.
    ...
```

`snapshots` là tuple các SnapshotFile được caller chọn tường minh, không glob
hoặc SSH. `scope` là ManagerSnapshotScope của adapter, khai báo direct collection.
`profile` và `context` là bytes UTF-8 của configs đã được người vận hành review.
Đây không phải tool tự sanitize log hoặc tự tìm đường dẫn nguồn.

Caller phải đưa hash đã pin trước; không tính hash mới để vượt qua một lỗi
hash mismatch. Những configs đưa vào phải qua contracts hiện có. Context
environment/start/end phải trùng scope về giá trị (so sánh thời gian nanosecond);
declarations phải rỗng. Tool từ chối assurance có sẵn, không xóa nó để chạy tiếp.
Bytes configs vẫn giữ nguyên, không chuẩn hóa timestamp/whitespace trong file.

API không tự chứng minh profile phù hợp ground truth, bindings phản ánh child
process hoặc rule đã được áp dụng trên Wazuh. Những kiểm tra frozen study/run
là tầng kế tiếp; generic `validate` vẫn thực hiện các kiểm tra engine của nó.

## Nội dung directory mới

- `snapshots/<snapshot-sha256>.jsonl`: bản sao nguyên bytes input.
- `documents/<sha256-source-ref>.json`: `_source` wrapper từ adapter, không
  deserialize/serialize lại vendor record.
- `inputs.json`: manifest tương thích CLI; chỉ documents được adapter chọn.
- `profile.json`, `context.json`: configs caller cung cấp, unknown collection.
- `ledger.json`: tất cả physical lines, kể cả blank/excluded, kèm document_path
  khi selected. Các tầng hash/range theo [adapter guide](WAZUH_MANAGER_SNAPSHOT.md).
- `snapshot-bundle.json`: completion marker kind `snapshot_transport_unknown`,
  version `0.1.0`, scope, snapshot descriptors và hashes của toàn bộ payload.

Names không lấy trực tiếp từ hostname/path của lab. Source_ref ổn định theo
source_label/line; canonical IDs vẫn do parser hiện có tính. Không thay labels
chỉ để làm evidence mới hoặc tránh duplicate detection.

Verify không chỉ kiểm hashes được khai báo. Nó đọc snapshot copies bounded,
chạy lại adapter với scope đã ghi, tái tạo documents/ledger/inputs rồi so sánh
bytes và inventory. Sửa byte_offset trong ledger rồi cập nhật hash manifest
vẫn bị từ chối. Bước này nối canonical events về đúng bytes snapshot được đưa.

**Giới hạn trust:** hashes chỉ chứng minh tính nhất quán, không chứng minh nguồn
xác thực. Người sửa đồng bộ snapshot/scope/config và toàn bộ hashes có thể tạo
một transport nhất quán khác. Phải pin hash bundle/study bằng receipt riêng ở
tầng review; chưa có chữ ký số hoặc attestation tại đây. Generic CLI không đọc
completion/ledger, nên caller phải verify trước khi dùng validate và giữ input
không thay đổi giữa các bước. Không gọi verify transport là lab verification.

## Filesystem và lỗi

Destination phải mới, parent có sẵn và nằm ngoài cây có `.git`. Không ghi đè,
không xóa source hay tự dọn output. Local paths từ chối UNC/URL/device/ADS/glob,
`.`/`..` components, reparse/symlink ancestors và file có hard-link alias.
Đọc input có giới hạn, identity/size/time kiểm trước/sau và kiểm hash pin.
Tổng read budget còn lại được áp dụng cho mỗi file, kể cả file lớn lên sau
kiểm size ban đầu. Không retry nếu nguồn đang đổi.

Validate và render trước khi tạo output. Files ghi exclusive, flush/fsync và
đọc lại; completion ghi cuối. Lỗi giữa chừng giữ directory riêng cho điều tra,
không trả thành công. Thiếu/hỏng completion hoặc payload không đủ đều không
verify được. Nếu caller mất kết nối sau khi hoàn tất bytes, verify có thể xác
định directory đã nhất quán; không tự chạy lại/overwrite directory đó.

Input/destination cần nằm trong thư mục riêng operator kiểm soát. Mode 0700/0600
được yêu cầu khi tạo; trên Windows không thay thế việc review ACL thừa kế.
Các kiểm tra path/identity không phải cam kết chống admin hoặc local attacker
đổi ancestors đồng thời. Không dùng directory chia sẻ không tin cậy.

Giới hạn adapter vẫn giữ 32 snapshots, 32 MiB/file, 64 MiB tổng, 20.000 lines,
100 selected documents. Config và generated ledger/manifest phải qua giới hạn
intake 1 MiB, depth 32, 50.000 nodes. Vì ledger lớn, có thể đạt giới hạn 1 MiB
trước 20.000 lines; tool dừng, không cắt bớt records để vừa giới hạn.

Public error `SnapshotBundleError` chỉ có `invalid_snapshot_bundle`: không in
raw values, absolute paths hoặc command/script text. Không bypass checks chỉ
để được thông báo chi tiết hơn; giữ inputs và review offline.

## Kiểm chứng trên máy phát triển

Không chạy trên Wazuh hoặc LAB-ENDPOINT-01 ở bước phát triển này. Chỉ synthetic,
temporary output ngoài Git do test tạo và dọn; không mở raw lab exports.

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-12-safe-demo'
$aegisTestTemp = 'build/pytest-transport-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_snapshot_bundle.py backend/tests/test_wazuh_manager_snapshot.py -q -rs -p no:cacheprovider --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

## Còn cần trước formal A/B/C

1. Tích hợp API frozen study/profile/run đã có với transport; operator review
   literal bindings trước A. Không lấy profile synthetic làm lab.
2. Review run-binding/native evidence và collection receipt; unknown mặc định.
3. Explicit attestation request đúng fingerprints; giữ report/context cũ.
4. CLI entry point offline và synthetic A/B/C integration cho tầng đầy đủ.
5. Review độc lập rồi operator chạy/thu A/B/C, không lặp rehearsal chỉ để tạo
   thêm logs. Chưa được gọi Regression Passed hoặc đóng Issue #12.
