# SCN-001 Safe Lab Kit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chuẩn bị kit offline có thể review, tạo hai payload cùng bytes, render hai revision Wazuh rule và ghi manifest một lần chạy vô hại; chưa kết luận detection gap từ manifest.

**Architecture:** Kit lab tách khỏi parsing/evaluation. Python stdlib chuẩn bị artifacts, Windows PowerShell 5.1 thực hiện preflight và chạy đúng payload đã duyệt; người vận hành kiểm tra/cài rule Wazuh. Không kết nối từ kit tới SIEM hoặc endpoint khác.

**Tech Stack:** Python >=3.11, pytest hiện có, Windows PowerShell 5.1, Wazuh 4.14.4 XML/PCRE2 và wazuh-logtest trên lab.

**Spec:** `docs/superpowers/specs/2026-09-12-safe-demo-design.md`

## Global Constraints

- Chỉ Issue #12, không thay `SCN-001` version `0.1.0` hoặc fingerprint `729c4430e65269773334873a27819afde363638dfc93efa5519f5e28bba2ec25`.
- Không sửa canonical, parser registry, validation engine hoặc comparison semantics.
- Không thêm dependency, live connector, credential hoặc raw lab export vào Git.
- Không hard-code host lab, IP, rule ID được dùng trên lab hoặc connector URL.
- Payload không network, download, registry, persistence, xóa dữ liệu hoặc liệt kê process khác.
- Không `ExecutionPolicy Bypass`, không tự nâng quyền/tắt bảo vệ, không tự cài rule/restart manager.
- Chỉ tạo thư mục output mới; không overwrite user files hoặc đi qua symlink/reparse point.
- Config/test stdout không phải evidence thật. Unknown collection không được nâng thành complete tự động.
- Không tự push, merge hoặc đóng issue. Không mở subagent nếu chưa được người dùng chọn.

## Phân kỳ và coverage

Spec gồm ba deliverable; kế hoạch này chỉ triển khai **kit lab** (sections 3–5,
payload/run metadata của section 4, safety và kiểm chứng liên quan).

1. Kit lab: kế hoạch hiện tại; có thể test/render/dry-run độc lập.
2. Export intake offline: kế hoạch riêng trước khi thêm source-specific helper;
   chịu trách nhiệm snapshot/pagination, duplicate keys/hits, limits, hash chain.
3. Evaluation A/B/C: kế hoạch riêng cho profile/context/attestation và fixtures
   gọi CLI hiện có. Chịu trách nhiệm compatibility, missing/unknown, evidence
   trace và Regression Passed.

Các sections 6–8 của spec **không được xem là hoàn thành bởi kit**. Chưa chạy
A/B/C chính thức trước khi cả ba deliverable và preflight được kiểm chứng.
Rehearsal chỉ thu dữ liệu để khóa profile, không thay baseline.

## Cấu trúc file

| File | Trách nhiệm |
| --- | --- |
| `demos/scn-001/payload.ps1` | Nội dung chuẩn, ngắn, ASCII/LF |
| `scripts/prepare_scn001_kit.py` | Render offline hai tên cùng bytes, rule revisions và kit manifest |
| `detections/wazuh/scn-001/baseline.xml.template` | Rule theo đường dẫn tên gốc |
| `detections/wazuh/scn-001/fixed.xml.template` | Rule theo toàn bộ nội dung payload, không theo filename |
| `demos/scn-001/Invoke-SafeDemo.ps1` | Preflight mặc định; execute chỉ khi chỉ rõ và xác nhận target |
| `demos/scn-001/README.md` | Hướng dẫn tiếng Việt, máy nào chạy phần nào, failure/rollback |
| `backend/tests/test_scn001_kit.py` | Tests generator/validation/input/output safety |
| `backend/tests/test_scn001_runner.py` | Parse PowerShell AST, dry-run và manifest/input guards |
| `tests/fixtures/demo/scn-001/rule-cases/` | Logtest synthetic dương/âm có nhãn |
| `.gitattributes` | Giữ bytes payload/templates/fixtures ổn định |
| `docs/DEMO.md` | Trỏ tới kit; phân biệt rehearsal, synthetic và lab evaluation |

## Task 1: Bộ tạo payload và rule offline

**Files:** payload, Python generator, XML templates, test_scn001_kit.py,
rule-cases fixtures, .gitattributes như bảng trên.

**Interfaces:**

```python
def render_rule(*, revision: str, rule_id: int, parent_sid: int,
                target_host: str, baseline_path: str) -> str: ...

def prepare_kit(*, output_dir: Path, lab_directory: str, target_host: str,
                rule_id: int, parent_sid: int,
                occupied_ids: frozenset[int]) -> dict: ...
```

Generator đọc payload chuẩn từ repository, không nhận arbitrary script text
từ người dùng. Module được load trong test bằng importlib từ đường dẫn script;
không thay packaging/runtime API của `aegis_verify`.

- [x] Viết test red, kiểm tra hai tên giống bytes và không overwrite:

```python
def test_two_names_share_payload_bytes(kit_module, tmp_path):
    out = tmp_path / "kit"
    result = kit_module.prepare_kit(
        output_dir=out, lab_directory=r"C:\AEGIS-Synthetic",
        target_host="SYNTHETIC-ENDPOINT", rule_id=119901,
        parent_sid=91816, occupied_ids=frozenset())
    a = (out / "lab_update.ps1").read_bytes()
    b = (out / "maintenance_check.ps1").read_bytes()
    assert a == b
    assert result["payload_sha256"] == hashlib.sha256(a).hexdigest()
    assert result["kind"] == "safe_demo_kit"

def test_existing_output_refused(kit_module, tmp_path):
    out = tmp_path / "kit"
    out.mkdir()
    with pytest.raises(ValueError):
        kit_module.prepare_kit(
            output_dir=out, lab_directory=r"C:\AEGIS-Synthetic",
            target_host="SYNTHETIC-ENDPOINT", rule_id=119901,
            parent_sid=91816, occupied_ids=frozenset())
    assert list(out.iterdir()) == []
```

`kit_module` fixture loads `scripts/prepare_scn001_kit.py`; test-only names/IDs
ở trên không được trở thành default cấu hình lab. Reproduce red bằng venv của
worktree: `python -m pytest backend/tests/test_scn001_kit.py -q`.

- [x] Thêm table tests cho bool/string IDs, ID ngoài 100000..120000 hoặc occupied,
parent SID không phải int 1..999999 hoặc bằng rule ID; revision lạ; host trống,
control chars; đường dẫn relative/UNC/device/ADS/dot-segments; output symlink,
reparse ancestor, output nằm trong repository raw-data area không được chọn.
Giới hạn host 255 chars, directory 200 chars, không glob/quote/control chars
trong directory. Không sửa/chuẩn hóa input bất hợp lệ thành giá trị hợp lệ.

- [x] Implement payload chuẩn, không thêm header/comment thay bytes giữa hai tên:

```powershell
Write-Output 'AEGIS_SAFE_DEMO_V1'
Write-Output ('AEGIS_PID=' + $PID)
```

- [x] Render XML bằng escaping text/attributes đúng chuẩn; giá trị regex literal
phải escape trước khi escape XML. Cả hai rule có cùng ID và level 5, parent SID
do operator xác minh, exact provider/channel/EventID=4104/host, counters=1/1.
Baseline thêm exact `win.eventdata.path` của tên gốc. Fixed thêm exact
`win.eventdata.scriptBlockText` của payload (chấp nhận LF/CRLF và newline cuối
theo test, không chấp nhận comment-only/code khác); không dùng field path.
Tên fields không có tiền tố `data.`. Parent SID 91816 trong unit tests chỉ
là dữ liệu synthetic; không tự coi đây là parent đúng trên lab.

- [x] Rule templates phải ràng buộc đúng một revision, cùng field guards;
không dùng replacement tùy ý kiểu shell eval hoặc thay toàn bộ config SIEM.
Fixed là rule nội dung cho demo đổi tên, không quảng bá là detector malware
hoặc suy luận hành vi tổng quát. Không suy `blocked` từ match.

- [x] Kit manifest UTF-8 không BOM, kind/version, selected host/directory,
filenames/hash payload, rule IDs, revision hashes; không verdict/collection
assurance. Tính hash từ bytes artifacts đã ghi. Nếu lỗi giữa chừng, báo rõ
thư mục output chưa hoàn thành, không xóa đệ quy; thiếu manifest nghĩa kit
không hợp lệ. Dùng exclusive creation và từ chối reparse paths trước ghi.

- [x] Thêm synthetic positive/negative inputs: original/renamed, marker-only,
comment-only, unrelated script, wrong host/provider/channel/EventID, missing
text, messageTotal=2, missing counters. Nội dung đặt dưới rule-cases, không
coi là events production. Python kiểm tra cấu trúc XML và artifact integrity;
**chỉ Wazuh logtest mới kiểm chứng thực tế PCRE2 và parent rule chain**.

Expected matrix phải phân biệt hai revision, không tự yêu cầu baseline đã
được sửa hành vi trước khi demo gap:

| Case (các common guards khác hợp lệ) | Baseline demo ID | Fixed demo ID |
| --- | --- | --- |
| Payload chuẩn + tên gốc | match | match |
| Payload chuẩn + tên đổi | không match | match |
| Marker-only/comment-only/nội dung khác + tên gốc | match do giới hạn filename | không match |
| Sai host/provider/channel/EventID | không match | không match |
| Message total=2 hoặc counters thiếu | không match | không match |

Case thiếu script text với tên gốc cũng có thể khớp baseline filename nhưng
phải bị parser PS4104 từ chối khi đánh giá; không gọi đó là canonical detection
đạt. Fixed phải không khớp. Mọi "không match" nói về demo ID, không yêu cầu
Wazuh không có alert nào từ rule khác.

- [x] Run tests, kiểm tra diff; implementation lưu trong commit `92b412f`.

## Task 2: Runner có preflight, execute rõ ràng và manifest

**Files:** Invoke-SafeDemo.ps1, test_scn001_runner.py, README của kit.

**Interfaces:** PowerShell nhận `-KitDirectory`, `-RunDirectory`, `-RunId`,
`-RunLabel A|B|C|Rehearsal`, `-ExpectedComputerName`,
`-AppliedRuleRevision baseline|fixed`, `-AppliedRuleSha256`, và switch
`-Execute`. Không có `-Execute` thì chỉ validate/preflight; không ghi run files
hoặc khởi chạy payload. A/B phải baseline; C phải fixed; rehearsal khai báo
revision riêng. Applied rule hash là operator declaration, không xác minh
remote và không thay generation hash.

- [x] Red tests parse script bằng PowerShell AST (không dot-source). Sau đó
gọi default preflight với kit synthetic không đúng hostname hiện tại: phải
trả nonzero, không tạo RunDirectory hoặc launch payload. Test subprocess
timeout tối đa 15s; không thêm execution-policy override để test qua.

```python
def test_preflight_does_not_write_or_launch(run_runner, synthetic_kit, tmp_path):
    run_dir = tmp_path / "not-created"
    result = run_runner(synthetic_kit, run_dir, execute=False)
    assert result.returncode != 0  # synthetic hostname != local computer
    assert not run_dir.exists()
```

`run_runner` dùng subprocess argument list với executable Windows PowerShell
5.1 được xác minh; không `shell=True`. Nếu không có nền tảng/executable hoặc
policy chặn chạy thì báo skip/giới hạn thực tế; không giả test runtime đã pass.

- [x] Implement preflight fail-closed: hostname đúng, PowerShell executable
là Windows PowerShell của hệ thống, manifest/bytes/hash đúng, cả hai filenames
hợp lệ và cùng hash, không symlink/reparse, đủ quyền đọc Sysmon/4104, Sysmon
và WazuhSvc running. Không tự start/restart service hoặc sửa policy.

- [x] Execute chỉ sau preflight, tạo run directory mới bên ngoài repository.
Khóa hai tên/đường dẫn từ kit; không nhận arbitrary command. Launch bằng
ProcessStartInfo với `UseShellExecute=false`, argument string được quote và
kiểm tra chặt cho `-NoLogo -NoProfile -NonInteractive -File`.
Không `-Command`, `IEX`, `EncodedCommand` hoặc shell interpolation.

- [x] Capture own child PID, UTC nanosecond-compatible textual timestamps,
stdout/stderr, exit code, hash/revision declaration; window 120s, launch ở
start+10s. Đặt timeout child 30s, chỉ kết thúc đúng child do runner tạo nếu
hết thời gian; không kill bằng tên process. Không tự chạy lại lượt thất bại.
Không chặn agent commentary bằng gọi tool chờ >60s khi kiểm tra local.

- [x] Manifest có kind=`safe_demo_execution`, version, run ID/label, host,
payload SHA256, child PID, commandline, UTC launch/exit và window, exit code,
timed_out, rule revision/hash khai báo. Không tự tạo canonical events hoặc
Detected/FalseNegative. Kết quả execution phải ghi rõ failed nếu timeout hoặc
exit nonzero, không gọi đó là Detection Gap.

- [x] Tests bad manifests/hashes, wrong filename/revision/run label, existing
RunDirectory, path traversal/reparse, wrong host, missing service/log access,
dry-run no side effects. Runtime success/timeout được chạy riêng trên lab
được duyệt; tests portable không giả Sysmon/4104 hiện diện trên máy dev.

- [x] Run targeted checks; runner và generator đóng gói nó lưu cùng commit `92b412f`.

## Task 3: Operator rehearsal và bàn giao kit

**Files:** demos/scn-001/README.md, docs/DEMO.md,
docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md.

- [x] README có lệnh PowerShell từng dòng hoặc block dùng đúng cú pháp
PowerShell, không placeholder `<path>`, không redirection tạo UTF-16 report.
Input lab lấy bằng Read-Host và kiểm tra; output mới, không hardcode máy thật.

- [x] Chỉ dẫn thứ tự: review kit → preflight → xác minh custom ID/parent bằng
logtest trên Wazuh → kiểm tra alert threshold/AR → cài đúng một revision →
config test → restart có chủ đích → rehearsal → export thủ công.
Không chạy A/B/C chính thức trước deliverables 2/3 nêu ở đầu kế hoạch.

- [x] Ghi các test cases và expected rule mapping trong kit, để operator
chạy từng case qua wazuh-logtest `-U rule:level:decoder`; negative không được
khớp demo ID, expected parent chỉ chốt sau rehearsal. Không lấy numeric
exit=0 của logtest thông thường làm chứng cứ đúng rule.

- [x] Hướng dẫn backup vào thư mục mới ngoài `etc/rules`, không overwrite
local_rules/default rules; cài file demo riêng chỉ khi target chưa tồn tại.
Rollback kiểm tra file hash đúng revision vừa cài trước gỡ file demo; nếu
khác thì dừng. Backup người dùng là bất biến; không sửa hoặc xóa logs.

- [x] Full checks trong worktree: tạo build folder; dùng GUID basetemp,
`python -m pytest backend/tests -q -rs -p no:cacheprovider --basetemp ...`,
`python -m pip check`, `git diff --check`. Xác minh Python import lấy code
worktree, không dùng editable install của root checkout. Không sửa venv cũ.

- [ ] Review độc lập bởi người dùng/reviewer trước chạy lab: payload effects,
same-byte filenames, exact regex/content controls, no-overwrite/rollback,
không trộn manifest với evidence, và giới hạn assertion chưa kết nối.

## Checkpoint thực thi

Đã thực hiện inline/tuần tự, không mở subagent. Generator và runner được viết
theo red → green: generator chưa tồn tại; synthetic catalog chưa có; runner
chưa tồn tại; child-result guard chưa có; test manifest scalar-array và readback
mismatch từng thất bại trước khi triển khai phần tương ứng.

Targeted kit/runner checks: 84 passed, gồm PowerShell AST và subprocess preflight
thật trên Windows. Unit tests telemetry/child-result dùng doubles rõ ràng,
không chạy Execute hoặc giả trạng thái lab. Test external output dùng tên dài
thay 8.3 alias của TEMP để thực sự tới guard existing-directory.

Bổ sung trong phạm vi safety: kiểm tra output marker/PID cùng exit code, đọc
lại bytes đã ghi trước publish manifest, dùng Stopwatch để clock correction
không kéo dài window vô hạn. Thêm test output ở Git checkout khác; full suite
cuối **2094 passed, 1 skipped** (85 test mới), pip check sạch. Không thay payload,
scenario hoặc engine. Chưa có human review hoặc runtime lab validation.

Checkbox implementation không chứng nhận runtime lab/PCRE2. Commit, full-suite
và giới hạn bàn giao được cập nhật tại `docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md`.
