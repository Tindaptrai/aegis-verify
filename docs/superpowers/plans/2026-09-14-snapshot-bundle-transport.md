# Snapshot Bundle Transport Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans, tuần tự theo user; không subagent, commit/push/merge. Theo dõi checklist.

**Goal:** Ghi/verify một bundle transport unknown từ snapshot local được chỉ định, nối canonical evidence về bytes nguồn.

**Architecture:** `backend/app/demo/snapshot_bundle.py` orchestration; `_bundle_io.py` filesystem guards; `_bundle_render.py` in-memory rendering. Vendor parsing dùng adapter đã có. API transport không xác nhận study/run/kit, không phải entry point final SCN-001.

**Tech Stack:** Python >=3.11, stdlib và contracts hiện có; không dependencies mới.

**Spec:** ../specs/2026-09-14-scn001-offline-evidence-design.md, mục 4,5,7,8; study/run checks và attestation là mốc sau, không gắn nhãn lab verified tại đây.

## Kết quả thực hiện

Hoàn thành ba task transport: 54 focused passed (6.08s), 2273 full passed + 1 FIFO skipped (82.39s), pip check sạch, diff check đạt. 36 tests đầu đã fail với stub; edge tests có RED riêng cho malformed object, read budget và early inventory limit. Các guards có sẵn được test bổ sung GREEN, không giả mọi case có RED riêng. Windows short-path assertion đã sửa sang samefile. Không build wheel vì venv thiếu build tools; không tự cài. Chi tiết/giới hạn nằm trong checkpoint, chưa review độc lập hoặc lab A/B/C.

## Constraints

- Giữ scope/bytes, canonical/engine/compare/ground truth; collection declarations phải rỗng.
- Snapshot: 32 files, 32 MiB/file, 64 MiB tổng; adapter 20.000 lines/100 documents.
- Config/ledger: 1 MiB, depth32, 50.000 nodes; lỗi trước write nếu quá giới hạn.
- Chỉ regular local files, không traversal/reparse/symlink/hardlinks; kiểm ancestors và identity trước/sau đọc. Output mới ngoài Git, parent đã tồn tại.
- Không overwrite/cleanup/retry. Completion manifest ghi cuối; partial directory không verify được.
- Snapshot copies và configs giữ bytes; filename generated từ hash không dùng literal lab. Diagnostics không echo raw.
- Filesystem checks không chống admin/local attacker đổi ancestors đồng thời; dùng private directory operator kiểm soát.

## Interfaces và file map

Create `backend/app/demo/__init__.py`, `_bundle_io.py`, `_bundle_render.py`, `snapshot_bundle.py`; thêm package vào pyproject.

```python
@dataclass(frozen=True)
class SnapshotFile:
    path: str | Path
    source_label: str
    sha256: str

def prepare_snapshot_bundle(snapshots: tuple[SnapshotFile, ...], *,
    scope: ManagerSnapshotScope, profile: bytes, context: bytes,
    destination: str | Path) -> Path: ...

def verify_snapshot_bundle(root: str | Path) -> ManagerSnapshotResult: ...
```

Returned result chỉ canonical/ledger của snapshot, assurance unknown. Profile/context validate qua models hiện có, context.environment/start/end bằng adapter scope và declarations rỗng. Không thay profile bytes hoặc tự tạo bindings. Generated `inputs.json`, `ledger.json`, `snapshot-bundle.json`; copies `profile.json`, `context.json`, `snapshots/<sha>.jsonl`, `documents/<sha256(source_ref)>.json`. Completion manifest version0.1.0 kind snapshot_transport_unknown gồm scope, snapshot descriptors và file hashes. Verify reconstruct toàn bộ expected bytes bằng adapter, so sánh configs/ledger/inputs/document/inventory; không tin ledger chỉ vì hash khớp.

## Task 1 — Rendering và exclusive filesystem packaging

- [x] Tests synthetic trước implementation: wrapper giữ lexemes/newline, ledger hashes/ranges, scopes bằng context, declarations không được nâng lên, invalid input không tạo output, fresh destination/no overwrite.
- [x] Run test mới, xem RED vì implementation chưa có; minimal stub nếu cần để tách import error khỏi behavioral failures.
- [x] Implement bounded read + generated payload; validate tất cả trước mkdir; xb writes, fsync, readback; completion last. Không xóa partial.
- [x] GREEN và CLI validate integration trả Inconclusive unknown.

Example test expectations độc lập:

```python
assert (out / 'snapshots' / (sha256(raw).hexdigest() + '.jsonl')).read_bytes() == raw
assert json.loads((out / 'context.json').read_bytes())['declarations'] == []
assert ledger['lines'][0]['byte_offset'] == 0
```

## Task 2 — Verify trace và fail-closed inputs

- [x] Tests tamper snapshot/document/ledger/config/manifest; forged ledger với hashes cập nhật vẫn bị reject; thiếu completion/extra file; duplicates, path/device/traversal/aliases, hardlinks, symlink khi hỗ trợ, interrupted write.
- [x] Implement verify canonical reconstruction, inventory exact, all regular/unique identities. Error sanitized; partial giữ nguyên.
- [x] GREEN; verify roundtrip và real CLI/report IDs đúng adapter. Không cần SSH/raw lab.

```python
with pytest.raises(SnapshotBundleError):
    verify_snapshot_bundle(partial_output)
assert original_source.read_bytes() == original_bytes
```

## Task 3 — Docs, review và full verification

- [x] `docs/SCN001_EVIDENCE_BUNDLE.md`: API transport, unknown, privacy, owned-directory/race limit, chưa study/run/attestation. Ghi checkpoint phần còn thiếu.
- [x] Tự review missing guards, hash-vs-byte/reference integrity, partial/write order; không gọi là independent review.
- [x] Focused tests rồi full suite; pip check; git diff --check. Dùng fresh build basetemp. Tests output ngoài Git bằng test-only TemporaryDirectory.

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-transport-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

Không kết luận Issue #12 hoàn tất. Tiếp nối: frozen study/profile/run checks, receipts/attestation và operator A/B/C, review độc lập trước merge.
