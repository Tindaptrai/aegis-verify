# SCN-001 v2 — Bản ghi duyệt payload và manifest pins (đã sanitize)

Tài liệu này cho reviewer kiểm được hai AC của Issue #12 mà không cần evidence
private: **AC 1** "All payloads and targets are approved and non-destructive" và
**AC 4** "Before/after detection rule revisions are version controlled". Nó
cũng liệt kê evidence ID và raw-event reference cho mọi kết luận của bộ A/B/C v2
(AC 3), và ghi nhận trung thực mọi cảnh báo 4104 quan sát được trên engine thật.

Bản máy đọc: [`docs/evidence/scn001-v2-pins.json`](evidence/scn001-v2-pins.json)
(sinh trực tiếp từ artifact private, có kiểm rò rỉ hostname/tài khoản trước khi ghi).

Quy ước sanitize: hostname endpoint lab thay bằng `<lab-endpoint>`; tài khoản
Windows bị lược; evidence thô (archives, manifests, stdout) **không** công bố.
Issue #12 không đòi artifact ký riêng cho payload; tài liệu này không tạo ra
yêu cầu đó và **không** ký thay ai.

## 1. Bản ghi duyệt payload và target (AC 1)

| Mục | Nội dung |
| --- | --- |
| Quyết định | Chủ dự án chọn **Phương án B** (payload làm giàu + revision `behavioral`, parent 91802) ngày 2026-09-18, trong chat, sau khi xem hai phương án A/B nguyên văn |
| Nơi ghi nhận | `docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md`, mục "Bước tiếp Issue #12: đề xuất behavioral rule fix" (đề xuất) và "Phương án B được duyệt" (áp dụng) |
| Bản chất tài liệu này | bản ghi quyết định đã cho, do agent soạn; **không phải chữ ký**. Chủ dự án xác nhận bằng cách duyệt PR chứa file này |
| Cũng đã duyệt trong chat | chạy ba control lành tính qua agent thật (mục 4); approval thu thập Run B (mục 3.4) do chủ dự án cung cấp `confirmed_by`/`reviewed_at` |

### 1.1 Payload 0.2.0 — nguyên văn và phân tích phá hủy

`demos/scn-001/payload.ps1`, SHA-256
`e8a5ebee1cb2dc303035bf7f31a55fc97092966ad5626fb61d23cdb662e45f21`:

```powershell
$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }
Write-Output 'AEGIS_SAFE_DEMO_V1'
Write-Output ('AEGIS_PID=' + $facts.Pid)
```

- Đọc ba giá trị có sẵn trong tiến trình (tên máy, tên người dùng, PID); ghi hai
  dòng ra stdout. Không ghi file, registry, mạng; không tạo tiến trình con; không
  nhận tham số; không dùng quyền nào ngoài quyền của người chạy.
- Hợp đồng stdout **không đổi** so với payload 0.1.x (`AEGIS_SAFE_DEMO_V1`,
  `AEGIS_PID=<pid>`); runner vẫn đối chiếu PID in ra với PID child.
- Hai tên file trong kit (`lab_update.ps1`, `maintenance_check.ps1`) cùng bytes;
  runner từ chối chạy nếu bytes khác hằng đã review (`Invoke-SafeDemo.ps1`, test
  `test_two_names_share_reviewed_bytes`).
- Scenario `SCN-001` version `0.1.0` không đổi
  (`scenarios/SCN-001-powershell-execution.yaml`, SHA-256 `18df07e0…`, mục 2).

### 1.2 Target

| Mục | Giá trị |
| --- | --- |
| Endpoint | `<lab-endpoint>` (Windows, Sysmon 15.22, Wazuh agent id `012`), lab riêng |
| Manager | Wazuh 4.14.4, lab riêng; `archives.json` với `logall_json` |
| Thư mục lab | `C:\AEGIS-Lab\SCN001-v2` (bộ v2 dùng thư mục mới, không ghi đè bộ v1) |
| Rule demo | id `118001`, group `aegis_safe_demo`, parent `91802`; id `117001` khai báo occupied và **không đụng** |
| Trạng thái sau lab | 118001 khôi phục nội dung pre-lab (`0ddd7bc0…`), 117001 `6b5b8615…`, analysisd restart do chủ dự án, xác minh 2026-09-18T06:25:03Z |

## 2. Manifest pins (AC 4)

Template ba revision nằm trong Git (`detections/wazuh/scn-001/*.xml.template`).
Rule đã nạp lên manager là bản **render** từ template với `host_pattern` của
endpoint, nên bytes render chứa hostname và không đưa vào Git; hash của chúng
được pin ở đây và trong study.

### 2.1 Pins của study v2 (`study_id` `aegis-lab-scn001-v2-20260918`)

| Pin | SHA-256 | Kiểm bằng gì |
| --- | --- | --- |
| scenario | `18df07e0b5e03c344a8306194db8466d985b65950e0cbf1f3a28ef5af7a01feb` | `sha256sum scenarios/SCN-001-powershell-execution.yaml` |
| payload | `e8a5ebee1cb2dc303035bf7f31a55fc97092966ad5626fb61d23cdb662e45f21` | `sha256sum demos/scn-001/payload.ps1` |
| runner | `49e5f9759e402be06fb3b44e2e403ab1bed2443c48c7d5e61960e54135f0a82d` | `sha256sum demos/scn-001/Invoke-SafeDemo.ps1` |
| baseline (render) | `8dcb4020f9d1422c3b370ff987d42c2d2f7c1b532bf4a627259233816549a5d3` | tái sinh kit (2.3) |
| fixed (render) | `420a0cfe4a162d15e3c23d8a8ea7cbf31c014023c55964886340ae85a7795466` | tái sinh kit (2.3) |
| behavioral (render) | `351ddc13ad4a0807e31d6a66b8a9c10426d008ea2d04f40f7873c825fda4629a` | tái sinh kit (2.3) |
| kit (`kit.json`) | `6811fce418d72315805132d22f8948303e0dc361e73b47111eec98d52460b156` | tái sinh kit (2.3); file chứa hostname |
| profile | `08a8fc0b83a400fc22f0394ea9c2986f43753ede05b9554452fa53ee264aa29d` | profile đánh giá sinh từ study; fingerprint khi chạy `4f140927…` (mục 3) |

`study.json` (SHA-256 `d3889018bee85c2cbf9e3cd3045fa4674536d4e4ebfc4d6b470d5151cfa6c6ff`)
chứa hostname và tài khoản nên giữ private; tám pin trên là toàn bộ `pins` của nó.

### 2.2 Hash file trong repo tại commit này

| File | SHA-256 |
| --- | --- |
| `detections/wazuh/scn-001/baseline.xml.template` | `551c4cc7273344ff1570039e24afd71944093b3548bff33c4f066382a6e995f2` |
| `detections/wazuh/scn-001/fixed.xml.template` | `ca9311d0de8b8864c2b54a3fef3cce33b2f2108363d25c483e29ea70491905df` |
| `detections/wazuh/scn-001/behavioral.xml.template` | `562cbcfb8e604cf392ffd3aef8c5b33f4fb5597cd2bed606c2ccb61702b9b3ac` |
| `scripts/prepare_scn001_kit.py` | `f1ebe779e4dcd0676315215ed99c99979a442e42399db31b7774e4fcc696c9d6` |
| `demos/scn-001/payload.ps1` | `e8a5ebee1cb2dc303035bf7f31a55fc97092966ad5626fb61d23cdb662e45f21` |
| `demos/scn-001/Invoke-SafeDemo.ps1` | `49e5f9759e402be06fb3b44e2e403ab1bed2443c48c7d5e61960e54135f0a82d` |

### 2.3 Tái sinh kit để đối chiếu hash render

Người có hostname lab chạy (cùng tham số kit đã dùng):

```bash
python scripts/prepare_scn001_kit.py --output-dir <thư-mục-mới> --lab-directory "C:\AEGIS-Lab\SCN001-v2" --target-host <lab-endpoint> --rule-id 118001 --parent-sid 91802 --occupied-ids 117001 --field-profile wazuh-eventchannel-4.14.4-lf-v1
```

rồi so `artifact_sha256` trong `kit.json` sinh ra với `kit.artifact_sha256`
trong `docs/evidence/scn001-v2-pins.json` (gồm ba rule render, runner, 15 case
logtest và catalog). Kit generator là hàm thuần của tham số, nên khớp hash là
khớp bytes đã nạp. Không có hostname thì chỉ kiểm được payload, runner, template
và generator (2.2).

## 3. Bộ A/B/C v2 — kết luận và evidence (AC 3, AC 5)

Scenario `SCN-001` 0.1.0; profile fingerprint
`4f140927e428b790909d0cc95766276de34c4db37b3be81762aad55784a749dc` cho cả ba run;
kit 0.2.0; cùng payload bytes; A/B nạp `baseline` (`8dcb4020…`), C nạp
`behavioral` (`351ddc13…`).

### 3.1 Run

| Run | run_id | Payload | runner → child PID | launch → exit (UTC) | evaluate_demo_run | Run binding |
| --- | --- | --- | --- | --- | --- | --- |
| A | `scn001v2-a-20260918T0523Z` | `lab_update.ps1` | 6984 → 6692 | 05:23:27.007 → 05:23:27.257 | **Detected** | unknown (`companion_record_unmatched`, `native_review_missing`) |
| B | `scn001v2-b-20260918T0525Z` | `maintenance_check.ps1` | 2184 → 7036 | 05:25:45.519 → 05:25:45.746 | **False negative**, caller-attested | unknown (+`companion_after_exit`) |
| C | `scn001v2-c-20260918T0537Z` | `maintenance_check.ps1` | 1104 → 5584 | 05:37:55.212 → 05:37:55.525 | **Detected** | unknown (`companion_record_unmatched`, `native_review_missing`) |

Cửa sổ thu thập 120 s từ trước launch (`window_start_utc`/`window_end_utc` trong
JSON), cộng 300 s buffer nhận trước khi trích snapshot.

### 3.2 Evidence theo assertion

`raw_event_ref` trỏ vào snapshot private của run tương ứng; `raw_event_hash` là
SHA-256 của bản ghi thô; Windows `eventRecordID` cho phép đối chiếu với EVTX nếu
được đọc sau này. Evidence ID đầy đủ nằm trong JSON.

| Run | Assertion | Kết quả | Evidence (rút gọn) | raw_event_ref | Windows recID → rule đã nổ |
| --- | --- | --- | --- | --- | --- |
| A | A01 telemetry | satisfied | `…b13eec50` | part1 line 25 | Sysmon 1 recID 8280 (child 6692) |
| A | A02 telemetry | satisfied | `…dbd4038892` | part1 line 22 | 4104 recID 11513 → **118001** L5 |
| A | A03 detection | satisfied (witness pair) | `…dbd4038892` + `…b13eec50` | line 22 + 25 | 11513 + 8280 |
| B | A01 telemetry | satisfied | `…b063b1f095d` | part1 line 20 | Sysmon 1 recID 8296 (child 7036) |
| B | A02 telemetry | satisfied | `…a61bf42216b1` | part1 line 17 | 4104 recID 12313 → **91816** L4 (không 118001) |
| B | A03 detection | **false_negative** (`expected_detection_absent`, caller-attested) | `…b063b1f095d` | part1 line 20 | 8296 |
| C | A01 telemetry | satisfied | `…0537eb4a0cfe` | part1 line 20 | Sysmon 1 recID 8385 (child 5584) |
| C | A02 telemetry | satisfied | `…27f61f274a8a` | part1 line 17 | 4104 recID 13166 → **118001** L5 "behavior matched" |
| C | A03 detection | satisfied (witness pair) | `…27f61f274a8a` + `…0537eb4a0cfe` | line 17 + 20 | 13166 + 8385 |

Mỗi run còn một script block companion của chính child (`$global:?`, không
`path`; recID 11517 / 12317 / 13170) được ghi nhận là `unevaluable` cho A02 và
là lý do `companion_record_unmatched` của run binding; nó không phải witness.

### 3.3 Comparison B → C

`compare_demo_runs`: **Regression Passed** — A01 `unchanged_pass`, A02
`unchanged_pass`, A03 `improvement` (`expected_detection_absent` →
`witness_found`); 0 regression; cùng profile fingerprint; `scenarios/` không đổi.
SHA-256 comparison `8c2a718ad225f15eea1d5650a663b3c9859d9efb66dcc62b0596f7c5745bb816`.

### 3.4 Attestation thu thập cho Run B

| Trường | Giá trị |
| --- | --- |
| request | `65b50de1ac2e5454849e101421bc2e51ddd6b1f25e134ddd91ec66f88fddf7ca` |
| approval | `b941d40bb962b1dcd20c4374443e2604f4eb1964df039789ee7f9d305b75ddde` |
| context attested | `c31d030494f0776f24ca0faf8af7d6b135071b6fba16e9ef18f0b6ae09434f14` |
| `confirmed_by` / `reviewed_at` | Nguyen Le Trong Tin / 2026-09-18T06:24:42Z (chủ dự án cung cấp trong chat) |
| coverage | 05:25:35.424Z → 05:27:35.424Z; `collected_at` 05:32:44Z |
| ba cờ | `no_sampling_or_truncation`, `no_parse_errors_or_gaps`, `clocks_adequate` = true, căn cứ ghi trong approval (references sức khỏe, filter, rotation, backlog, native, thời gian) |

Assurance là **caller-attested**: manager↔snapshot cùng tập 10 = 10 sự kiện trong
scope, không đọc EVTX native. Không phải "lab-verified".

### 3.5 Hash snapshot và report (private)

| Artifact | SHA-256 |
| --- | --- |
| snapshot A / B / C (`*-part1.jsonl`) | `b8f8a35b2e1a6b674331306eeb2cd173fab3b37206120859d24b19947af65f90` / `540285ca8ace32b3de86038f1d902367f2ad44e2ae665d9b46b4dd553ffed4b1` / `a348cbbc631aeb995a00c9ef957d129fd51a87432fcb78048ffaf4420863a691` |
| report A / B / C | `44cd23fe0d1d5c3e608345aca1ee4a590b13ef2e0d2898f32aadf1e6bdbeea87` / `030f86b94242af47175b52bb5a6dcbe2e60b2213e37844a567fb2887b277e8f3` / `e21eb2d0da8038005cc4df32c1d51423158043572d2980ee37e246502c30749f` |

## 4. Engine thật: mọi cảnh báo 4104 quan sát được, kể cả ngoài scope

Bảng này liệt kê **mọi** bản ghi 4104 trong snapshot có rule nổ, không chỉ
witness. Rule stock của Wazuh: 91815 "Powershell executing process discovery"
(T1057, L4), 91816 "Powershell script querying system environment variables"
(T1082, L4). Hai rule này và 118001 đều là con của 91802; Wazuh báo rule có
level cao nhất trong các anh em cùng khớp.

| Run (rule nạp) | recID | Script block | Rule nổ |
| --- | --- | --- | --- |
| A (baseline) | 11268 | runner `Invoke-SafeDemo.ps1`, hàm `Get-AegisPreflight` | 91815 L4 |
| A (baseline) | 11413 | runner, hàm `Invoke-AegisExecution` | 91816 L4 |
| A (baseline) | 11513 | payload `lab_update.ps1` | **118001** L5 (filename) |
| B (baseline) | 12068 | runner, `Get-AegisPreflight` | 91815 L4 |
| B (baseline) | 12213 | runner, `Invoke-AegisExecution` | 91816 L4 |
| B (baseline) | 12313 | payload `maintenance_check.ps1` | 91816 L4 — **không 118001** |
| C (behavioral) | 12921 | runner, `Get-AegisPreflight` | **118001** L5 — khớp ngoài dự kiến, xem mục 5 |
| C (behavioral) | 13066 | runner, `Invoke-AegisExecution` | 91816 L4 |
| C (behavioral) | 13166 | payload `maintenance_check.ps1` | **118001** L5 "behavior matched" |

### 4.1 Controls lành tính chạy qua agent thật (behavioral nạp, run `scn001v2-controls-20260918T060503Z`)

| Script | SHA-256 | Nội dung | recID | Rule nổ | Kỳ vọng |
| --- | --- | --- | --- | --- | --- |
| `env-only.ps1` | `9cc01be3df0dfe31aa97792020645abba84f34b4f846c0140ed31b6bce8cfb37` | `Write-Output $env:COMPUTERNAME` | 13736 | 91816 L4 | không 118001 ✓ |
| `pid-only.ps1` (payload 0.1.x) | `0226fc3c28de6589d50bc2f7c17a49c5d5a546ed9cd42efad1f6c87f8071bd69` | `Write-Output 'AEGIS_SAFE_DEMO_V1'` / `Write-Output ('AEGIS_PID=' + $PID)` | 13752 | 91816 L4 | không 118001 ✓ — rule hẹp hơn parent |
| `reworded.ps1` | `a813f41e7d6dc58f26ccdce1479361a3a7b75bc79a459f14b24203c21e659107` | `[Environment]::MachineName` + `[Environment]::UserName` + `GetCurrentProcess().Id` | 13769 | **118001** L5 | 118001 ✓ — chịu viết lại |

Tổng kết engine thật: 5/15 case catalog (`original`, `renamed`, `reworded`,
`env-only`, `pid-only`) đã qua analysisd; 10/15 chỉ có pytest Python `re`, không
phải PCRE2. `wazuh-logtest` trên 4.14.4 không tái tạo decoder
`windows_eventchannel` (probe 10/10 ra `json`), nên không có đường tắt.

## 5. Đánh giá riêng: rule `behavioral` khớp block preflight của runner

### 5.1 Sự kiện

Hàm `Get-AegisPreflight` của `Invoke-SafeDemo.ps1` được PowerShell ghi thành một
script block 4104 riêng (`messageTotal` 1, `path` = runner). Hàm này đọc
`[Environment]::MachineName` (kiểm đúng host) và `$PID` (kiểm host process), tức
đúng hai hành vi mà rule `behavioral` mô tả. Trên engine thật, Run C recID 12921
→ 118001 L5. Bản ghi này không thành witness chỉ vì scope A03 giới hạn
`file_path` vào hai đường dẫn payload.

### 5.2 Vì sao scope A03 không xoá được vấn đề

Scope là thuộc tính của **profile đánh giá**, không phải của rule. Rule đã nạp
vẫn sinh cảnh báo level 5 cho một script lành tính. Nói đúng: trong bộ v2 có
**một control lành tính không dự kiến bị khớp** (block preflight của runner),
bên cạnh ba control dự kiến đúng như kỳ vọng. Đây là hạn chế precision của rule,
không phải lỗi của comparison (profile giống hệt ở A/B/C nên verdict và
comparison vẫn đúng).

### 5.3 Căn cứ để cân nhắc

1. **Không có lớp cảnh báo mới.** Trên baseline (A/B), block preflight đã nổ rule
   stock 91815 L4 và block `Invoke-AegisExecution` nổ 91816 L4 trong **mọi** run.
   `behavioral` chỉ nâng block preflight từ 91815 L4 lên 118001 L5; số bản ghi
   runner sinh cảnh báo không đổi (2/run).
2. **Rule hẹp hơn parent nó thay thế** ở mức cao nhất: hai control live
   (`env-only`, `pid-only`) chỉ nổ 91816, không nổ 118001.
3. **Mọi cách thu hẹp có sẵn đều đổi bytes đã pin.** Thêm `negate` theo
   `win.eventdata.path` của runner là allowlist theo tên file, đúng loại điểm yếu
   mà demo này tồn tại để phơi bày. Sửa runner để tránh cùng lúc hai lần đọc là
   chỉnh tooling cho né rule của chính mình, và đổi hash runner `49e5f975…`. Cả
   hai làm pins của Run C v2 và controls không còn khớp template/runner trong
   repo, tức phải chạy lại lab, điều chủ dự án đã quyết định không làm ở vòng này.
4. **Cách sửa đúng là rule ngoại lệ tường minh**, ví dụ rule con `if_sid 118001`
   level 0 cho tooling đã biết theo `path` + hash, hoặc yêu cầu tín hiệu thứ ba
   (gom giá trị đọc được vào một cấu trúc rồi xuất ra). Cả hai cần bộ run mới để
   có bằng chứng engine thật; chưa có bằng chứng thì không được tuyên bố.
5. AC của Issue #12 yêu cầu "reviewed behavioral rule fix" và Run C "detection
   found, regression passed"; không yêu cầu rule không có false positive. Mô tả
   rule đã ghi "not a malware verdict"; group `aegis_safe_demo` chỉ nạp trên
   manager lab và đã rollback.

### 5.4 Khuyến nghị

**Chấp nhận giới hạn cho phạm vi demo của Issue #12, công bố rõ, và mở follow-up
trước khi dùng rule ngoài lab.** Không thu hẹp trước merge, vì mọi cách thu hẹp
hiện có hoặc lặp lại anti-pattern theo tên file, hoặc làm mất tính nhất quán
giữa evidence đã thu và bytes trong repo. Follow-up (đề xuất trong PR): rule
ngoại lệ tường minh cho tooling + bộ run mới để chứng minh runner không còn nổ
118001 và payload vẫn nổ; ghi rõ rule hiện tại **không được triển khai ngoài
lab** khi chưa có ngoại lệ đó.

## 6. Artifact private (không công bố) và lý do

| Artifact | Lý do giữ private |
| --- | --- |
| `snapshots-v2/*.jsonl`, `controls-v2/raw-evidence.jsonl` | archives thô chứa hostname, IP, tài khoản, đường dẫn hồ sơ người dùng |
| `runs-v2/*/execution*.json`, stdout/stderr | chứa hostname/đường dẫn; hash và trường cần thiết đã ghi ở mục 3 |
| `study.json`, `kit.json`, rule render | chứa hostname/tài khoản; hash pin ở mục 2 |
| `collection-request-B-v2.json`, `collection-approval-B-v2.json`, `context-B-v2-attested.json` | references mô tả manager/endpoint chi tiết; hash và trường quyết định ở mục 3.4 |
| `evidence-v2-raw/` (probe logtest, log manager/endpoint) | log hệ thống thô |

Bản sao còn trên endpoint (`C:\AEGIS-Lab\…`) và staging/backup trên manager
(`~/aegis-v2/`, `~/aegis-rule-backup-v2/`) giữ nguyên; xoá là quyết định của chủ
dự án sau khi xác nhận evidence đã lưu đủ.
