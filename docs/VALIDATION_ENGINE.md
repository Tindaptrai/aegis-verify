# Validation Engine offline

Validation Engine của AEGIS Verify là thư viện Python offline. Engine nhận các
contract đã có kiểu, đánh giá canonical evidence và trả kết quả có thể truy vết.
Nó không chạy scenario, không gọi mạng, không đọc `raw_event_ref`, không parse
YAML và không tự xác nhận rằng collection đã đầy đủ.

Issue #7 triển khai hướng A: `ScenarioManifest` và `EvaluationProfile` là hai đầu
vào riêng. Profile là ground truth thực thi nên mọi rule ID, selector, binding và
khoảng tương quan phải được con người review. Ba scenario hiện có trong repository
chưa có profile thật được phê duyệt bởi thay đổi này.

## API public và bốn đầu vào

Import từ `aegis_verify.validation`:

- Contract đầu vào: `AssertionRule`, `Binding`, `CollectionDeclaration`,
  `Correlation`, `EvaluationContext`, `EvaluationProfile`, `JoinPair`, `Predicate`.
- Kết quả: `AssertionResult`, `EvaluationResult`, `EvidenceEntry`, `OutcomeCounts`,
  `WitnessPair`.
- Hàm: `evaluate_scenario`, `fingerprint`, `scenario_fingerprint`,
  `profile_fingerprint`, `scope_fingerprint`, `event_set_fingerprint`.
- Lỗi public: `ValidationEngineError`.

Chữ ký evaluator:

```python
evaluate_scenario(
    manifest: ScenarioManifest,
    events: list[CanonicalEventV2] | tuple[CanonicalEventV2, ...],
    *,
    profile: EvaluationProfile,
    context: EvaluationContext,
) -> EvaluationResult
```

Bốn đầu vào có trách nhiệm khác nhau:

1. `manifest` mô tả scenario đã review và assertion IDs.
2. `events` là danh sách/tuple hữu hạn chỉ gồm `CanonicalEventV2`. V1 phải được
   caller nâng cấp tường minh trước khi gọi; engine không đoán version.
3. `profile` gắn rule có kiểu với từng assertion ID. Detection phải dùng
   `rule_id` hoặc `signature_id` literal đã review; prevention phải yêu cầu
   `event_action == "blocked"`.
4. `context` chốt `run_id`, `environment_id`, cửa sổ thời gian, target bindings
   và collection declarations. Binding là giá trị có kiểu, không nội suy text.

## Ví dụ chạy độc lập, hoàn toàn synthetic

Ví dụ dưới đây không chạy hành động, không phải profile lab được duyệt và không
đưa ra verdict về hệ thống thật. Phần attestation thứ hai cũng là dữ liệu synthetic:
caller giả lập việc đã review collection chỉ để minh họa API.

<!-- runnable-example:start -->
```python
from aegis_verify.models import CanonicalEventV2
from aegis_verify.models.scenario import ScenarioManifest
from aegis_verify.validation import (
    AssertionRule,
    Binding,
    CollectionDeclaration,
    Correlation,
    EvaluationContext,
    EvaluationProfile,
    JoinPair,
    Predicate,
    evaluate_scenario,
    event_set_fingerprint,
    profile_fingerprint,
    scenario_fingerprint,
    scope_fingerprint,
)

manifest = ScenarioManifest(
    id="SCN-999",
    name="Synthetic API demonstration",
    version="0.1.0",
    status="draft",
    description="Synthetic demonstration, not a lab verdict.",
    safety={
        "destructive": False,
        "authorization_required": True,
        "notes": "Does not execute any action.",
    },
    expected_sources=["wazuh"],
    expected_outcome="detected",
    assertions=[
        {"id": "SCN-999-A01", "description": "Synthetic activity", "source": "wazuh"},
        {"id": "SCN-999-A02", "description": "Synthetic detection", "source": "wazuh"},
    ],
)

scope = (Predicate(field="hostname", op="eq", binding="target_host"),)
profile = EvaluationProfile(
    profile_id="synthetic-example",
    profile_version="0.1.0",
    scenario_id=manifest.id,
    scenario_version=manifest.version,
    scenario_fingerprint=scenario_fingerprint(manifest),
    rules=(
        AssertionRule(
            assertion_id="SCN-999-A01",
            role="telemetry",
            capability="supported",
            source_type="wazuh",
            scope=scope,
            match=(Predicate(field="event_action", op="eq", value="command"),),
        ),
        AssertionRule(
            assertion_id="SCN-999-A02",
            role="detection",
            capability="supported",
            source_type="wazuh",
            scope=scope,
            match=(Predicate(field="rule_id", op="eq", value="synthetic-rule"),),
            correlation=Correlation(
                anchor_assertion_id="SCN-999-A01",
                join_pairs=(
                    JoinPair(target_field="hostname", anchor_field="hostname"),
                ),
                min_delta_ns=0,
                max_delta_ns=1_000_000_000,
            ),
        ),
    ),
)

base_context = EvaluationContext(
    run_id="synthetic-run",
    environment_id="synthetic-env",
    start="2026-01-01T00:00:00Z",
    end="2026-01-01T00:00:10Z",
    bindings=(Binding(name="target_host", value="synthetic-host"),),
)

activity = CanonicalEventV2(
    event_id="synthetic-activity",
    source_type="wazuh",
    environment_id="synthetic-env",
    timestamp="2026-01-01T00:00:01.000000001Z",
    ingested_at="2026-01-01T00:00:03Z",
    hostname="synthetic-host",
    event_action="command",
    raw_event_ref="synthetic-only/activity:1",
    raw_event_hash="a" * 64,
)
alert = CanonicalEventV2(
    event_id="synthetic-alert",
    source_type="wazuh",
    environment_id="synthetic-env",
    timestamp="2026-01-01T00:00:02.000000001Z",
    ingested_at="2026-01-01T00:00:03Z",
    hostname="synthetic-host",
    event_action="observed",
    rule_id="synthetic-rule",
    raw_event_ref="synthetic-only/alert:1",
    raw_event_hash="b" * 64,
)

detected = evaluate_scenario(
    manifest, [activity, alert], profile=profile, context=base_context
)
print(detected.final_status)
print(detected.assertions[1].witness_pairs)

# Synthetic-only absence demonstration. These three hashes bind the caller's
# declaration to this exact reviewed profile, scope and supplied event set.
missing_alert_events = [activity]
declaration = CollectionDeclaration(
    assertion_id="SCN-999-A02",
    status="complete_for_scope",
    confirmed_by="synthetic-reviewer",
    reference="synthetic-only/collection-attestation",
    coverage_start=base_context.start,
    coverage_end=base_context.end,
    no_sampling_or_truncation=True,
    no_parse_errors_or_gaps=True,
    clocks_adequate=True,
    profile_fingerprint=profile_fingerprint(profile),
    scope_fingerprint=scope_fingerprint(base_context),
    event_set_fingerprint=event_set_fingerprint(missing_alert_events),
)
attested_context = base_context.model_copy(update={"declarations": (declaration,)})
absent = evaluate_scenario(
    manifest, missing_alert_events, profile=profile, context=attested_context
)
print(absent.final_status)
print(absent.assertions[1].collection_assurance)
```
<!-- runnable-example:end -->

Output chính xác:

```text
Detected
(WitnessPair(target_event_id='synthetic-alert', anchor_event_id='synthetic-activity'),)
False negative
caller-attested
```

`False negative` ở đây chỉ hợp lệ vì caller đã khai báo collection synthetic là
`complete_for_scope` và gắn khai báo với đúng profile/scope/event set. Hash là dấu
vân tay ổn định, không phải chữ ký số và không chứng minh nguồn đáng tin. Engine
không thể tự biết caller đã xác nhận đúng hay chưa.

## Trạng thái và reason code

`final_status` chỉ có đúng năm giá trị sau:

| Trạng thái | Ý nghĩa giới hạn |
| --- | --- |
| `Detected` | Mọi assertion đạt và manifest mong đợi `detected`. |
| `Prevented` | Mọi assertion đạt và manifest mong đợi `prevented`; witness phải có action literal `blocked`. |
| `Missing telemetry` | Input không có activity telemetry cần thiết; không khẳng định agent hoặc nguồn log bị hỏng. |
| `False negative` | Có activity, không có detection phù hợp và caller đã attestation collection đầy đủ cho đúng scope. Không nói prevention thất bại. |
| `Inconclusive` | Evidence/field/window/assurance chưa đủ hoặc requirement không được hỗ trợ. |

Mỗi assertion dùng `outcome` (`satisfied`, `missing_telemetry`, `false_negative`,
`inconclusive`) và một `reason_code` chính xác:

| `reason_code` | Khi nào xuất hiện |
| --- | --- |
| `witness_found` | Có witness đầy đủ; target và anchor của correlation là hai event khác nhau. |
| `activity_not_found_in_input` | Telemetry root không có witness và không còn candidate unknown. |
| `missing_activity_anchor` | Target phụ thuộc vào telemetry root đang thiếu. |
| `uncertain_activity_anchor` | Telemetry root chưa thể kết luận do field thiếu. |
| `insufficient_fields` | Còn candidate có thể liên quan nhưng canonical field cần thiết là `null`. |
| `collection_not_confirmed` | Detection vắng nhưng chưa có attestation `complete_for_scope`. |
| `expected_detection_absent` | Detection vắng và attestation hợp lệ; outcome là `false_negative`. |
| `incomplete_detection_window` | Khoảng correlation của ít nhất một activity witness bị cắt bởi evaluation window hoặc vượt range timestamp. |
| `prevention_not_demonstrated` | Không có witness `blocked`; không suy ra traffic đã được phép. |
| `unsupported_requirement` | Profile ghi rõ requirement hiện chưa biểu diễn được. |

Ưu tiên tổng hợp cố định là `Inconclusive` > `Missing telemetry` >
`False negative` > success. Một alert không che assertion khác còn thiếu.
`Failed` không phải trạng thái kết quả của engine. Input/config sai làm
`evaluate_scenario` raise `ValidationEngineError`, không biến lỗi hợp đồng thành
security verdict.

## Lỗi public và giới hạn tài nguyên

`ValidationEngineError.code` chỉ có các mã ổn định:

- `invalid_input`
- `unsupported_version`
- `profile_binding`
- `assertion_binding`
- `invalid_predicate`
- `invalid_correlation`
- `missing_binding`
- `duplicate_evidence_id`
- `invalid_collection_declaration`
- `resource_limit`

Diagnostic chỉ chứa field path đã allowlist và index không âm; raw values, username,
command, secret-looking key hoặc exception locals không được echo. Boundary public
revalidate cả model tạo bằng `model_construct`/`model_copy`. Duplicate event ID bị
từ chối toàn bộ, kể cả event nằm ngoài environment/time scope.

Giới hạn V0:

| Tài nguyên | Giới hạn |
| --- | ---: |
| Canonical events | 10.000 |
| Assertion rules / scenario assertions | 100 |
| Scope conditions mỗi rule | 16 |
| Match conditions mỗi rule | 16 |
| Phần tử của `in` hoặc binding list | 100 |
| Join pairs mỗi target | 8 |
| Bindings | 100 |
| Collection declarations | 100 |
| Tổng candidate/pair comparisons | 1.000.000 |
| Mỗi chuỗi trong evaluation profile/context (gồm predicate literal và binding value) | 4 KiB UTF-8 |

Vượt giới hạn làm toàn bộ evaluation raise `resource_limit`; engine không trả
partial verdict. List/tuple ở đúng giới hạn được chấp nhận nếu mọi invariant khác
cũng hợp lệ; phần tử kế tiếp bị từ chối. Giới hạn 4 KiB này không áp dụng cho
chuỗi trong canonical event hoặc scenario manifest; các đầu vào đó giữ nguyên
giới hạn schema riêng. Caller không được cắt ngắn evidence để đáp ứng budget của
profile/context.

## Thời gian, correlation và nguyên tắc không suy đoán

- Evaluation window `[start, end]` và delta interval `[min_delta_ns,
  max_delta_ns]` đều đóng, chính xác tới 1 ns.
- `delta_ns = target.timestamp - anchor.timestamp`; delta âm được phép khi profile
  khai báo. Engine không tự bù clock skew và không dùng `ingested_at` thay event time.
- Mọi join field phải đúng trên cùng một target/anchor pair. Không lấy IP từ một
  pair và port từ pair khác; `null` không bao giờ tự join với `null`.
- Một positive witness làm phép tồn tại đạt dù còn candidate unknown. Candidate
  unknown vẫn được giữ riêng trong `unevaluable_evidence_ids`, không trở thành proof.
- Trước absent-detection conclusion, toàn bộ correlation interval của mọi positive
  activity witness phải nằm trong evaluation window.
- Engine không suy NAT, session, provider từ description, completion từ việc đã đọc
  hết file, hoặc provenance/vendor field ngoài Canonical Event V2.

`evidence_ids` và `witness_pairs` chỉ tham chiếu event có thật trong input;
`evidence_index` giữ `raw_event_ref`, `raw_event_hash` và canonical schema version.
Engine không mở reference, không kiểm tra raw bytes và không xác minh chữ ký nguồn.

## Trách nhiệm collection attestation

Chỉ caller có thể khai báo `complete_for_scope`. Một declaration hợp lệ phải:

- gắn với assertion detection được hỗ trợ;
- có `confirmed_by` và `reference` là nhãn review, không phải secret/URL kết nối;
- phủ toàn bộ evaluation window;
- xác nhận không sampling/truncation, không parse error/gap đã biết và clock đủ tin cậy;
- khớp chính xác `profile_fingerprint(profile)`, `scope_fingerprint(context)` và
  `event_set_fingerprint(events)`.

`scope_fingerprint` loại declarations để tránh hash vòng; `fingerprint(context)`
vẫn chứa declarations. Thay run, environment, window, bindings, profile hoặc event
set làm attestation cũ không dùng lại được. `status="unknown"` luôn giữ assurance
`unknown`, kể cả khi có một phần metadata. Xác nhận sai có thể tạo kết luận sai;
human review và lab collection assurance vẫn là bước bắt buộc.

## Cowrie và giới hạn session

Engine nhận trực tiếp các `CanonicalEventV2` do connector Cowrie offline trả về và
giữ evidence coordinates. Điều này chỉ chứng minh compatibility của contract.
Session key, authentication outcome và các provenance field khác không thuộc
Canonical Event V2 nên engine không được đọc chúng. Requirement cần chứng minh
cùng session/login outcome phải dùng rule `capability="unsupported"` với reason rõ
ràng như `requires_session_identity`; kết quả là `Inconclusive`, không phải một
scenario pass thật.

## Hướng A đến B trong tương lai

Hướng A hiện tại truyền `ScenarioManifest` và sidecar `EvaluationProfile` riêng.
Hướng B có thể thêm một manifest schema version mới chứa profile, sau đó adapter
chuyển thành đúng cùng cặp contract đã validate trước khi gọi evaluator. Issue #7
chưa triển khai adapter B và không thêm field vào YAML v0.1. Nếu tương lai caller
cung cấp cả embedded profile lẫn sidecar, boundary nên từ chối đầu vào kép; caller
phải chọn một nguồn ground truth, không merge hoặc chọn bản mới nhất ngầm.

## Kiểm tra local và bàn giao lab

Từ worktree repository trên Windows PowerShell:

```powershell
.venv/Scripts/python.exe -m pytest backend/tests/test_validation_acceptance.py -q --tb=short -p no:cacheprovider --basetemp build/pytest-validation-acceptance
.venv/Scripts/python.exe -m pytest backend/tests -q --tb=short -p no:cacheprovider --basetemp build/pytest-validation-full
.venv/Scripts/python.exe -m pip check
.venv/Scripts/python.exe -m pip wheel . --no-deps --no-build-isolation --wheel-dir build/issue7-wheel
git diff --check
git status --short
```

Trước khi tạo profile lab thật, người review cần cung cấp và duyệt:

1. Scenario/hành động được cho phép và assertion IDs giữ nguyên.
2. `run_id`, environment, mục tiêu, start/end cùng timezone.
3. Rule/signature IDs kỳ vọng và logical provider literal nếu manifest dùng
   `sysmon` hoặc `powershell` qua Wazuh.
4. Join fields thực sự có trong canonical output; không dựa vào provenance.
5. Collection report cho đúng cửa sổ, cùng mọi gap/sampling/parse/clock caveat.
6. Actual sanitized evidence để reviewer đối chiếu evidence IDs/hash/ref.

Sau test tự động vẫn phải request human code review và lab validation. Chỉ merge
sau khi profile ground truth, evidence và collection attestation đã được review;
guide này không thay thế sự phê duyệt đó.
