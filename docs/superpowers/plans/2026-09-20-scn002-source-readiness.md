# SCN-002 Source Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xác định nguồn Sysmon 3/Wazuh và dữ liệu tương quan hiện có trước khi viết parser hoặc chạy SCN-002.

**Architecture:** Đây là phần đầu độc lập của thiết kế nhiều thành phần. Chỉ đọc
log có sẵn và tạo hồ sơ readiness riêng; không tạo event, sửa cấu hình hoặc
suy đoán shape nguồn. Parser, executable profile và sender/receiver có plan riêng
sau khi các đầu vào dưới đây được kiểm chứng.

**Tech Stack:** PowerShell Windows tích hợp, Wazuh Dashboard hiện có, Python
standard library của venv hiện có; không dependency mới.

**Spec:** `docs/superpowers/specs/2026-09-20-scn002-design.md` (đã duyệt).

## Global Constraints

- "Không hard-code vào mã, spec hoặc fixture lab" các địa chỉ, connector URLs và credentials.
- "Thiếu field giữ null."
- "Không dùng thời gian ingest để thay thời gian nguồn."
- "Không join chỉ theo timestamp hay hostname."
- "Collection declarations mặc định unknown."
- Không chạy sender, mở receiver, thay rule, bật thêm telemetry, thay ground truth hoặc tự merge P2.
- Giữ nguyên SCN-001 và allowlist của connector live/manager snapshot.
- Raw exports và hồ sơ lab nằm ngoài Git trong thư mục private đã kiểm tra ACL.
- Một issue triển khai riêng cho mỗi phần sau #48; #48 chỉ thiết kế/plan.

## Review Focus

1. Sysmon service chạy nhưng không có Event 3: báo thiếu bằng chứng, không coi nguồn đã sẵn sàng (Task 1).
2. Event Viewer có event nhưng Indexer không có: phân biệt nguồn endpoint và đường ingest (Task 2).
3. Wazuh document khác shape hoặc thiếu tuple: ghi rõ field/type, không tự đoán alias hay tạo giá trị (Task 2).
4. Bản sao Suricata tại Wazuh bị gọi nhầm là correlation: kiểm tra rule context riêng cho A04 (Task 3).
5. Export không đúng agent/run, NAT hoặc giờ lệch: chưa cấp quyền đánh giá live chỉ vì có log (Task 3).

## File structure và đầu ra

- Create khi thực thi: `docs/SCN002_SOURCE_READINESS.md`, chỉ chứa hướng dẫn tổng quát,
  mapping đã kiểm chứng và trạng thái capability; không chứa log hoặc topology riêng.
- Private artifacts: `endpoint-sysmon3.xml`, `indexer-sysmon3-hit.json`,
  `source-readiness.json` dưới thư mục owner-only được operator chọn.
- Không sửa `connectors/`, `scenarios/`, `detections/` hoặc runtime dashboard trong phần này.

## Task 1 — kiểm chứng endpoint, không phát sinh traffic thử

**Files:** Create `docs/SCN002_SOURCE_READINESS.md` section endpoint.

**Interfaces:** Consumes console trên Windows target do operator xác nhận;
produces local event candidate hoặc trạng thái `no_candidate`/`read_failed`.

- [ ] Đọc lại spec và kiểm tra branch sạch; mở issue chỉ cho source readiness
  nếu owner chọn thực thi phần này. Không gộp code với PR P2.
- [ ] Operator chạy khối chỉ đọc trên máy target. Không coi access denied là
  không có event. Không gửi Message/XML đầy đủ vào chat.

```powershell
$ErrorActionPreference = 'Stop'
$candidate = $null
try {
    $candidate = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 3
    } -MaxEvents 1 -ErrorAction Stop
    [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        EventId = $candidate.Id
        RecordId = $candidate.RecordId
        TimeUtc = $candidate.TimeCreated.ToUniversalTime().ToString('o')
    }
} catch {
    Write-Host 'Khong doc duoc Event 3. Giu nguyen cau hinh; doi chieu loi tai may.'
}
```

- [ ] Nếu đọc được, operator kiểm tra XML tại máy để biết đó là TCP hay UDP;
  ghi kết quả protocol, provider, field names/types và timestamp basis vào hồ sơ
  riêng. Không suy rằng một event TCP chứng minh UDP hoặc blocked-path logging.
- [ ] Nếu không có event hoặc không đọc được: ghi gate chưa đạt và yêu cầu
  owner chọn kiểm tra cấu hình hiện có. **Không tự bật network logging hoặc gửi
  packet để tạo mẫu.** Đây là kết quả hợp lệ của readiness, không phải test pass.
- [ ] Chỉ sau khi thư mục owner-only được xác nhận, export `$candidate.ToXml()`
  ra `endpoint-sysmon3.xml` bằng thao tác local; tính SHA-256. File không vào Git.

## Task 2 — đối chiếu một Wazuh search hit thực tế

**Files:** Update guide section Indexer; private `indexer-sysmon3-hit.json`.

**Interfaces:** Consumes event identity/time từ Task 1 và tài khoản đọc Indexer
đã có; produces một search hit nguyên vẹn hoặc `not_observed`/`query_failed`.

- [ ] Trong Wazuh Dashboard, dùng agent target đã xác nhận, provider
  `Microsoft-Windows-Sysmon`, Event ID `3`, và cửa sổ UTC hữu hạn bao quanh
  candidate. Không sửa quyền account, không query toàn bộ lịch sử không giới hạn.
- [ ] Export đúng một hit JSON hoàn chỉnh gồm `_source`; nếu dashboard export
  chỉ phần `_source`, giữ nguyên và ghi loại envelope, không tự bọc rồi nói đó
  là bytes gốc. Không sử dụng collector SCN-001 hiện tại vì allowlist không có ID 3.
- [ ] Đọc JSON local và in **chỉ tên trường, kiểu dữ liệu**, không in values.
  Khi chạy, truyền path private được operator chọn, không cố định path trong repo:

```python
import json
from pathlib import Path

def field_shape(value, prefix=''):
    if isinstance(value, dict):
        for name, child in value.items():
            yield from field_shape(child, f'{prefix}.{name}' if prefix else name)
    else:
        yield prefix, type(value).__name__

def inspect_local(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('sample_too_large')
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError('sample_not_object')
    return list(field_shape(document))
```

  Đây là inspection snippet, không phải production parser hay acceptance validator.
  Không coi `json.loads` là thay thế decoder strict của connector khi triển khai.
- [ ] So sánh local với XML: provider/channel/event code, event timestamp,
  host/agent identity, source/destination IP và port, protocol, process identity.
  Ghi từng đường dẫn JSON thật và quy tắc kiểu; port thiếu giữ absent, không tự
  ép về 0. Mapping chưa thống nhất thì dừng trước parser implementation.
- [ ] Nếu XML có nhưng search không có, ghi `not_observed`, không kết luận mất
  telemetry toàn hệ thống hoặc tự mở rộng index/đổi rule để ép có kết quả.
- [ ] Mẫu đưa vào repo sau này phải là derivative sanitized có manifest/hash,
  source lineage và human review. Phần này không commit raw hoặc derivative chưa duyệt.

## Task 3 — chốt readiness và bàn giao phần parser/profile

**Files:** Update guide section gates; private `source-readiness.json`.

**Interfaces:** Consumes candidates của Tasks 1/2 và cấu hình nguồn chỉ đọc;
produces readiness record với trạng thái quan sát được, không security verdict.

- [ ] Ghi riêng các thuộc tính có kiểu sau; mọi giá trị chưa kiểm chứng là
  `unverified`, không thay bằng true cho đủ checklist:

```json
{
  "schema_version": "1",
  "endpoint_sysmon3": "unverified",
  "indexer_sysmon3": "unverified",
  "udp_shape_reviewed": "unverified",
  "suricata_lan_eve": "unverified",
  "pfsense_lan_filterlog": "unverified",
  "wazuh_a04_rule_semantics": "unverified",
  "pre_nat_tuple_compatible": "unverified",
  "clock_alignment": "unverified",
  "private_storage": "unverified",
  "live_execution_authorized": false
}
```

  Các trường trạng thái chỉ dùng `verified`, `not_observed`, `read_failed`,
  `unverified`; references và hashes của artifacts bổ sung trong hồ sơ private.
- [ ] Đọc cấu hình/log sẵn có cho Suricata LAN EVE và pfSense LAN filterlog.
  Không thay chế độ IDS/IPS, rule, NAT, log settings hoặc restart dịch vụ.
  Nếu chưa có quyền truy cập, ghi unverified và yêu cầu operator export riêng.
- [ ] Kiểm tra ý nghĩa rule Wazuh A04 từ rule definition và mẫu thật. Nếu chỉ
  là bản sao alert Suricata thì ghi đúng là ingest/alert; chưa nhận là correlation.
- [ ] Gate parser: chỉ khi source shape/mapping được review mới viết plan cho
  `connectors/wazuh/network_telemetry.py`, export public entry point
  `parse_wazuh_sysmon3_document`, fixtures và tests riêng; giữ các parser cũ nguyên vẹn.
  Không thêm live dispatch hoặc sửa snapshot contracts trong issue parser offline.
- [ ] Gate profile: sau adapter offline, tạo plan riêng cho fixture-only SCN-002
  và profile review. Kiểm thử đủ/thiếu từng nguồn, null tuple, sai rule/time,
  NAT mismatch và evidence chéo hai lượt; không đổi draft manifest để né thiếu dữ liệu.
- [ ] Gate tools: plan sender/receiver riêng tuân giới hạn spec: một send,
  payload 128 bytes, sender 5 giây, receiver 60 giây/16 datagram/512 bytes,
  bind đúng interface. Chưa viết công cụ này trong phần readiness.
- [ ] Gate live: sau ba phần trên, owner duyệt IP/ports/SIDs/rule IDs thực tế,
  backup/rollback, clock check, storage và từng lượt. Không coi duyệt plan này
  là duyệt rule hoặc chạy live.
- [ ] Review tài liệu bằng đối chiếu references/mẫu, `git diff --check`, xác nhận
  không raw/credentials/IP lab trong staged files. Chỉ commit guide tổng quát;
  không chạy toàn bộ test suite cho thay đổi thuần tài liệu hoặc gọi đó là test parser.

## Coverage và giới hạn của plan này

Plan chỉ triển khai gate source readiness của spec, không tuyên bố bao phủ toàn
bộ SCN-002. Ba phần parser/profile/tools có thể bị review độc lập nên không ép
chúng vào một issue hoặc dự đoán interfaces khi chưa có mẫu nguồn. Live capture
và ground truth tiếp tục có approval riêng. Việc thiếu mẫu không cho phép dùng
fixture synthetic để tuyên bố lab đã hỗ trợ.

## Cách thực thi đề xuất

Native: main agent tự làm các bước tuần tự và chỉ gọi một reviewer khi có
deliverable cần review. Phù hợp vì các bước phụ thuộc mẫu của bước trước và
giúp tiết kiệm context; subagent-driven không mang lại song song hữu ích ở đây.
Chờ owner review plan và chọn cách thực thi trước khi bắt đầu Tasks 1–3.
