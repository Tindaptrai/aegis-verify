# Manager Snapshot Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. User chọn triển khai tuần tự, không subagent; không tự commit/push/merge. Steps use checkbox syntax.

**Goal:** Hoàn thành adapter bytes-only của snapshot Wazuh manager, trả canonical events và provenance file/dòng cho phần packaging SCN-001.

**Architecture:** Vendor JSONL/framing/scope nằm trong connectors/wazuh; gọi hai parser Windows hiện có, không sửa semantics của chúng. Adapter không đọc filesystem/network, không kết luận collection completeness. Đây là phần độc lập đầu tiên của thiết kế export/evaluation, chưa phải bundle writer hoặc A/B/C.

**Tech Stack:** Python >=3.11, hashlib/dataclasses/re và decoder/PreciseTimestamp sẵn có; pytest, không dependency mới.

**Spec:** ../specs/2026-09-14-scn001-offline-evidence-design.md — các mục 4–5 và ranh giới source isolation của mục 2.

## Tiến độ thực tế

Đã hoàn thành Task 1–4: 105 focused tests; full suite 2219 passed, 1 skipped trong 80.28s; pip check sạch. Kết quả và giới hạn ghi trong checkpoint. Checklist bên dưới mô tả hành vi đã kiểm, không có nghĩa mỗi case bổ sung đều có một RED riêng: 60 cases đầu lỗi thiếu module, sau đó 60 failures với stub NotImplementedError rồi GREEN; 44 edge cases bổ sung và 1 CLI integration đều GREEN. Tự review đối chiếu test với các lỗi giả định; chưa chạy công cụ mutation testing hay review độc lập.

## Global Constraints

- Không đổi canonical, engine, compare, runner, payload hoặc rule.
- Chỉ synthetic trong tests. Không đọc raw lab exports/credentials.
- Giới hạn: 32 snapshots, 32 MiB/file, 64 MiB tổng, 20.000 physical lines tổng, 100 selected documents; wrapped document <=256 KiB theo decoder.
- Scope agent/host/provider/event ID/Windows time; không lọc rule/PID/path/marker.
- Bảo toàn bytes body; raw line hash gồm newline/BOM, document hash là lớp riêng.
- Malformed hoặc scope không xác định gây lỗi toàn bộ; không partial output.
- API chỉ xác nhận consistency của bytes được caller đưa, không tự complete_for_scope.
- Không làm thay đổi root checkout hoặc pending native-profile changes.

## File map và API

- Create `connectors/wazuh/manager_snapshot.py`: entry point `parse_manager_snapshots` và frozen input/output dataclasses.
- Create `connectors/wazuh/_snapshot_scope.py`: kiểm context + phân loại scope ba miền selected/excluded/error, nếu module chính cần tách để giữ ngắn.
- Create `connectors/wazuh/_snapshot_contracts.py`: contracts/diagnostics riêng của adapter.
- Create `backend/tests/test_wazuh_manager_snapshot.py`: framing/scope/trace/limits/integration.
- Create `docs/WAZUH_MANAGER_SNAPSHOT.md`: hướng dẫn API bytes-only và giới hạn.
- Update `docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md`: RED/GREEN/full verification và phần còn thiếu.

API được định nghĩa cho tasks kế tiếp:

```python
ManagerSnapshot(source_label: str, raw: bytes, sha256: str)
ManagerSnapshotScope(agent_id: str, hostname: str, environment_id: str,
                     start: str, end: str, ingested_at: str)
parse_manager_snapshots(snapshots: tuple[ManagerSnapshot, ...], *,
                        scope: ManagerSnapshotScope) -> ManagerSnapshotResult
```

Result có `.documents` (tuple), `.ledger` (tuple), `.snapshots` (tuple metadata).
Mỗi document có `.raw`, `.source_ref`, `.parser`, `.telemetry` (WindowsTelemetryResult).
Mỗi ledger entry có snapshot label/hash, line/offset/length/hash, BOM flag,
disposition/reason và optional document hash/ref/source_record_id.
Errors là `ManagerSnapshotError` có diagnostic allowlist code, snapshot_index và
line, optional parser_code; không echo raw values hoặc absolute paths.

## Task 1 — Byte framing và trace qua parser thật

- [x] Viết test API chưa tồn tại bằng importlib.find_spec assertion, rồi gọi thật sau khi module có; không mock parser.
- [x] Test selected Sysmon/4104 giữ exact wrapped bytes, số mũ/unknown fields không serialize lại; line offsets và canonical hash/ref đều kiểm độc lập bằng hashlib và literals.
- [x] Test LF/CRLF/BOM/blank/final-no-newline; chọn file labels ổn định, không dùng ordinal file để tạo identity.
- [x] Chạy RED:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests/test_wazuh_manager_snapshot.py -q -p no:cacheprovider --basetemp ('build/pytest-snapshot-focused-' + [guid]::NewGuid().ToString('N'))
```

- [x] Implement iterator chỉ split `b'\n'`; bỏ một LF và CR trước LF khỏi body, BOM chỉ tại offset0; wrapped = b'{"_source":' + body + b'}'. Decode validate trước khi phân loại. Ledger hash dùng original physical line, không body.
- [x] GREEN cùng lệnh; verify document bằng parser thật và `hashlib.sha256(document.raw).hexdigest()`.

Ví dụ assertion nền tảng trong test:

```python
assert result.documents[0].raw == b'{"_source":' + body + b'}'
assert result.ledger[0].byte_offset == 0
assert result.ledger[0].byte_length == len(body) + 2
assert result.ledger[0].line_sha256 == hashlib.sha256(body + b'\r\n').hexdigest()
assert result.documents[0].telemetry.event.raw_event_ref == 'synthetic-day-line-1#record=1'
```

## Task 2 — Scope không chọn theo kết quả

- [x] Tests bảng agent/host/provider/event/time đúng/sai/thiếu và 1 ns tại biên window đóng.
- [x] Tests generic rule, wrong PID/path/no marker vẫn được chọn nếu đúng export scope; selected fragmented/missing-text phải lỗi parser.
- [x] Implement validated metadata gates: sai agent có căn cứ → outside_agent; sai host → outside_host; Windows provider/EventID khác hợp lệ → outside_event; thời gian ngoài window → outside_window. Unknown required classification metadata → unclassifiable_record.
- [x] Non-Windows chỉ outside_event khi decoder hợp lệ không windows_eventchannel và không có data.win; decoder json/data.win mâu thuẫn không được che Windows record.
- [x] GREEN; metadata fields optional của canonical không lấy từ scope để điền vào event.

```python
assert [x.telemetry.event.rule_id for x in result.documents] == ['91816', '117001']
assert result.documents[0].telemetry.event.process_id is None
assert result.ledger[0].disposition == 'selected'
```

## Task 3 — Fail closed, duplicates và resource limits

- [x] Tests duplicate JSON keys, invalid encoding/Unicode/numbers, arrays/wrappers, malformed final line, over-depth/nodes; lỗi không chứa canary text.
- [x] Tests snapshot hash mismatch, duplicate labels/files/source record ID trong cùng manager, alias bytes across inputs, invalid context và resource limits (limit+1 bằng small controlled limit khi phù hợp).
- [x] Implement strict boundary revalidation; validate số lượng/bytes trước scan; kiểm hash trước parse; duplicate IDs toàn snapshot set có manager identity, không dedup; selected document count không quá100.
- [x] GREEN; test lỗi record cuối không trả result và input bytes không bị biến đổi.

```python
with pytest.raises(api.ManagerSnapshotError) as caught:
    api.parse_manager_snapshots(inputs, scope=scope)
assert caught.value.diagnostic.code == 'duplicate_record'
assert 'PRIVATE_CANARY' not in str(caught.value)
```

## Task 4 — Verification và bàn giao phần độc lập

- [x] Viết guide mô tả API và ví dụ synthetic executable, ba tầng hash, parser/context requirements; nói rõ chưa có file writer/attestation.
- [x] Tự review mutations: bỏ scopecheck, lọc generic alerts, tính hash body thay line, rounding nanos, serialize floats, swallowing parser error; mỗi hành vi phải có test bắt.
- [x] Chạy focused rồi full suite/pip/diff:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ('build/pytest-snapshot-final-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
git diff --check
```

- [x] Cập nhật checkpoint với lệnh/kết quả thực, limitations, không commit.

## Tiếp nối ngoài phạm vi adapter này

Adapter là đầu vào của phần study/profile/run contracts và bundle writer tiếp theo
trong thiết kế chính; các phần đó cần kế hoạch riêng với API filesystem/context cụ thể.
Attestation và real A/B/C chưa được adapter cung cấp. Không đóng Issue #12 khi chỉ
hoàn thành plan này. Human independent review và lab validation vẫn bắt buộc.
