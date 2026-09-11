# Issue #7 — Validation Engine: hướng A, sẵn đường mở rộng B

Trạng thái: người dùng đã duyệt thiết kế và cho phép implementation ngày 2026-09-11.
Người dùng đã chốt hướng A; chưa phê duyệt các profile ground truth cụ thể.
Mốc nền: main `836cd2d`, sau khi merge Cowrie A+B qua PR #21.

## 1. Quyết định kiến trúc và phạm vi

Giữ nguyên Scenario YAML v0.1 và Canonical Event v2. Thêm EvaluationProfile
riêng để biểu diễn điều kiện đánh giá có kiểu, gắn từng assertion ID của scenario.
Engine là thư viện offline thuần: không chạy scenario, không gọi mạng, không mở
raw_event_ref, không đọc trường vendor hoặc provenance của connector.

Issue #7 gồm model profile/context/result, evaluator, tests và hướng dẫn sử dụng.
Không thêm UI, CLI hoàn chỉnh, live connector, ngôn ngữ truy vấn tổng quát,
session/NAT inference, schema migration hoặc sửa ba scenario hiện tại.
Không thêm runtime dependency; dùng Pydantic và thư viện chuẩn đang có.

### A và B có thể phát triển song song

- A hiện tại: ScenarioManifest và EvaluationProfile là hai đầu vào riêng.
- B tương lai: phiên bản manifest mới có thể chứa profile ở bên trong.
- Cả hai chuyển thành cùng cặp contract đã validate trước khi vào evaluator.
- Engine không cần biết profile đến từ file riêng, manifest, CLI hay UI.
- B cần phiên bản schema mới và kiểm thử tương đương A/B; không tự thêm field
  vào YAML v0.1 vốn đang từ chối field lạ.
- Nếu sau này nhận cả embedded profile và sidecar: mặc định từ chối đầu vào
  kép; không merge ngầm, không chọn bên mới nhất. Caller chọn một đầu vào rõ ràng.
- Tính tương đương A/B được so trên các contract bên trong, không trên whitespace
  hay cách đóng gói file. Không có adapter B được triển khai trong Issue #7.

## 2. Đầu vào và ranh giới tin cậy

API đề xuất: evaluate_scenario(manifest, events, *, profile, context).
Đây là API Python nhận contract có kiểu; không nhận đường dẫn hoặc tự parse YAML.
Đầu vào list/tuple hữu hạn; không nhận arbitrary iterator, callback hoặc mã thực thi.
Tất cả contract phải revalidate ở ranh giới public, kể cả model đã được dựng bằng
model_construct hoặc model_copy; dữ liệu lỗi không trở thành kết luận an ninh.

Events chỉ nhận CanonicalEventV2. V1 phải được caller nâng cấp chủ động bằng API
đang có; không đoán version hoặc hạ độ chính xác. Canonical source_type và
event_provider được dùng tường minh: sysmon/powershell trong manifest là nguồn
logic, không phải các giá trị SourceType mới. Profile phải khai báo selector
canonical thích hợp, không có bảng đoán provider từ description trong engine.

Context gồm run_id, environment_id, cửa sổ thời gian và bindings cho mục tiêu.
Bindings là giá trị có kiểu được profile tham chiếu theo tên, không nội suy text.
Thiếu binding hoặc sai kiểu là input error. Không nhận secret/connector URL.
Mỗi assertion hỗ trợ phải có ít nhất một điều kiện eq/in trong scope dùng binding
với asset_id, hostname, username, src_ip, dst_ip, src_port, dst_port hoặc process_id
để tránh cấu hình chỉ chọn mọi log cùng nguồn trong cửa sổ.
Việc binding có thực sự định danh đúng lần chạy vẫn cần con người review.

Context có collection declaration theo assertion ID để đánh giá việc thiếu
detection: trạng thái unknown hoặc complete_for_scope, người xác nhận, nhãn
tài liệu xác nhận và khoảng thời gian coverage. Complete đòi hỏi coverage bao
trùm cửa sổ đánh giá, xác nhận không bị cắt mẫu/lỗi parse/gap đã biết và đồng hồ
đủ tin cậy cho cửa sổ này. Declaration gắn với fingerprint profile, evaluation
scope (run_id, environment_id, start/end, bindings) và tập event
đã cung cấp. Không tự coi input hết file, ingested_at mới, hoặc có vài log là đủ.

Đây là xác nhận của caller, không phải bằng chứng engine tự kiểm chứng được.
Engine ghi rõ mức bảo đảm caller-attested trong kết quả; sai xác nhận có thể
dẫn đến sai kết luận. Lab validation và live collection assurance là việc sau.

## 3. EvaluationProfile v0.1

Metadata: profile_schema_version, profile_id, profile_version, scenario_id,
scenario_version, scenario_fingerprint và danh sách assertion rules.
Version dùng dạng X.Y.Z; không tự chọn profile dựa trên ngày sửa file.
Rules phải khớp một-một với toàn bộ assertion IDs của manifest, giữ thứ tự
manifest khi xuất kết quả; thiếu, thừa, trùng ID hoặc binding scenario sai là lỗi.

Mỗi rule có role telemetry, detection hoặc prevention và capability supported
hoặc unsupported. Unsupported giữ role dự định cùng một reason_code rõ ràng
(ví dụ requires_session_identity) và
không được kèm predicate giả để làm đạt yêu cầu. Với rule hỗ trợ:

- Scope: canonical source_type, các điều kiện định danh nguồn/provider và mục tiêu.
  Manifest source wazuh/suricata/pfsense/cowrie phải khớp source_type cùng tên;
  sysmon/powershell phải dùng source_type wazuh và event_provider eq tường minh
  trong profile. Tính đúng của provider literal cho nguồn logic cần review;
  engine không tự chọn literal hoặc mở raw log để xác minh nguồn.
- Match: các điều kiện chứng minh hoạt động hoặc kết quả mong đợi.
- Detection/prevention: tham chiếu đúng một telemetry assertion được hỗ trợ
  làm activity anchor, cùng các cặp trường tương quan và khoảng thời gian.
- Prevention phải yêu cầu event_action bằng blocked. Redirected, allowed,
  có alert hoặc không có lưu lượng không tự chứng minh đã chặn.
- Detection phải yêu cầu rule_id hoặc signature_id thuộc tập ID được review;
  có ID bất kỳ hoặc severity cao không đủ. ID và nội dung rule vẫn phải do chủ
  profile kiểm tra; engine không chứng minh chất lượng detection rule.
- Manifest expected_outcome detected cần ít nhất một rule role detection;
  prevented cần ít nhất một rule role prevention. Các rule này có thể unsupported
  để biểu diễn đúng giới hạn hiện tại, nhưng khi đó không thể tạo kết quả success.

Profile là ground truth thực thi. Thay profile phải review, kể cả khi không sửa
YAML. Trạng thái draft của manifest chỉ cho phép offline evaluation, không cấp
quyền thực hiện hành động lab. Issue #7 không tự tạo profile thật cho SCN-001/002/003.

### Predicate nhỏ, có kiểu và không suy đoán

V0 chỉ có all-of các điều kiện; mỗi điều kiện dùng eq, in, exists hoặc contains.
eq/in dùng scalar cùng kiểu; in là danh sách hữu hạn, không ép số thành chuỗi,
không coi bool là số. contains chỉ kiểm tra phần tử chính xác của technique_ids,
không tìm substring trong command_line. exists kiểm tra khác null.
Không có regex, eval, negation, OR tùy ý, template, scoring hoặc fuzzy matching.

Allowlist trường lọc: source_type, event_provider, asset_id, hostname, username,
src_ip, dst_ip, src_port, dst_port, protocol, process_name, parent_process_name,
process_id, command_line, file_path, file_hash, rule_id, signature_id,
event_action, severity và technique_ids. Timestamp do cửa sổ quản lý;
environment_id lấy từ context. Evidence coordinates không dùng làm predicate
để tránh viết điều kiện theo ID của một mẫu đã biết.

So sánh text chính xác, phân biệt hoa/thường, không trim; IP so bằng giá trị địa
chỉ canonical đã validate. Null với eq/in/contains cho unknown, không cho match;
exists(null) là false. Với all-of: có false thì false, nếu không false nhưng có
unknown thì unknown, còn lại true. Unknown ở trường không được dùng không tác động.

## 4. Thời gian, tương quan và cardinality

Lọc environment chính xác và cửa sổ đóng [start, end] theo event.timestamp;
start <= end. Dùng epoch_nanoseconds nguyên, giữ đủ 9 chữ số; ingested_at không
thay thời gian sự kiện. Ngoài phạm vi là excluded, không dùng làm evidence.
Không tự nới cửa sổ, suy clock skew hoặc cộng thời gian chờ bằng đồng hồ hiện tại.

Detection/prevention tương quan với telemetry anchor qua ít nhất một cặp trường
canonical khác thời gian, cộng khoảng delta_ns khai báo tường minh. Delta là
target.timestamp - anchor.timestamp; min/max là số nguyên có dấu và min <= max,
cho phép profile diễn đạt độ lệch đã được review, không sửa timestamp nguồn.
Cặp join dùng scalar allowlist, không dùng rule/signature/evidence IDs làm khóa
nhận diện hoạt động. Null ở bất kỳ vế join nào là unknown, không bao giờ null=null.
V0 không có correlation chain hoặc cycle: anchor luôn là telemetry root.
Trước khi kết luận detection vắng mặt, khoảng [anchor.timestamp + min_delta,
anchor.timestamp + max_delta] của mọi anchor witness phải nằm trong cửa sổ đã
đánh giá và coverage được xác nhận. Nếu cửa sổ bị cắt hoặc vượt timestamp range,
trả Inconclusive / incomplete_detection_window, không kết luận false negative.

Mỗi assertion là phép tồn tại ít nhất một witness trong phạm vi, không phải
mọi lần thử đều thành công. Join là tồn tại cặp cùng thỏa toàn bộ điều kiện;
không được lấy IP từ một cặp và port từ cặp khác. Tập evidence phải giữ các cặp
witness cụ thể, không chỉ hai danh sách ID độc lập làm mất liên hệ.
Một event không thể tự làm cả target và anchor trong cùng một cặp.
Không deduplicate theo raw hash hoặc đoán native/Wazuh là cùng một sự kiện.

Nếu một witness đầy đủ tồn tại thì phép tồn tại đạt, dù còn candidate unknown;
nếu không witness nhưng còn candidate có thể liên quan mà thiếu field thì
Inconclusive. Các positive được giới hạn đúng nghĩa tồn tại trong tập evidence,
không tuyên bố toàn bộ hoạt động của hệ thống đều được bảo vệ.

## 5. Trạng thái assertion và kết quả tổng

Phân biệt outcome của assertion (satisfied, missing_telemetry, false_negative,
inconclusive) với kết quả tổng scenario (năm giá trị của Issue #7).
Input/config malformed được trả bằng ValidationEngineError, không gắn Failed
hay Inconclusive để che lỗi hợp đồng.

| Tình huống assertion | Outcome và lý do |
| --- | --- |
| Rule unsupported | inconclusive / unsupported_requirement |
| Có witness scope + match (+ join nếu cần) đầy đủ | satisfied |
| Không witness, còn candidate unknown | inconclusive / insufficient_fields |
| Telemetry không witness và không candidate unknown | missing_telemetry / activity_not_found_in_input |
| Target có anchor missing | missing_telemetry / missing_activity_anchor |
| Target có anchor inconclusive | inconclusive / uncertain_activity_anchor |
| Detection có anchor đạt, không witness/unknown, collection đủ | false_negative / expected_detection_absent |
| Detection có anchor đạt, không witness/unknown nhưng collection chưa đủ | inconclusive / collection_not_confirmed |
| Prevention có anchor đạt nhưng không witness/unknown | inconclusive / prevention_not_demonstrated |

Không có block không đồng nghĩa đã allowed hoặc exfiltration thành công, kể cả
collection complete. False negative trong V0 chỉ nói thiếu detection, không nói
prevention failure. Missing telemetry chỉ nói tập input thiếu telemetry yêu cầu,
không khẳng định agent hỏng hoặc hoạt động không xảy ra.
Với target, xét trạng thái anchor trước; chỉ tìm witness/unknown và áp dụng quy
tắc thiếu detection/prevention khi anchor satisfied. Scope false loại candidate;
scope unknown vẫn phải được theo dõi nếu các điều kiện còn lại không loại được nó.

Đánh giá tất cả assertions, không dừng ở lỗi chứng cứ đầu tiên. Tổng hợp theo
ưu tiên cố định: inconclusive > missing_telemetry > false_negative > success.
Success chỉ khi mọi assertion satisfied: expected_outcome detected -> Detected;
expected_outcome prevented -> Prevented. Một alert hoặc một block không che
được assertion chưa đạt. Summary luôn kèm số lượng mỗi outcome và mọi kết quả
chi tiết, kể cả khi nhãn tổng che một false_negative đã chứng minh ở nhánh khác.

## 6. Evidence, tính ổn định và kết quả xuất

Result frozen, có result_schema_version, engine_semantics_version, run_id,
scenario/profile identities và fingerprints, context fingerprint, event-set
fingerprint, final status và assertion results theo thứ tự manifest.
Mỗi assertion result có assertion_id, role, outcome, reason_code, evidence_ids,
witness_pairs, unevaluable_evidence_ids và collection declaration reference.

- evidence_ids chỉ là ID thật trong input hỗ trợ kết luận; negative detection
  dùng activity anchor IDs. Không bịa ID cho detection bị thiếu.
- Missing telemetry có thể evidence_ids=[]; lý do và phạm vi được ghi rõ.
- Candidate thiếu field nằm ở unevaluable_evidence_ids, không bị gọi là bằng
  chứng chứng minh detection. Witness pairs là target ID + anchor ID.
- Evidence index ánh xạ mỗi ID được tham chiếu tới raw_event_ref/hash và phiên
  bản canonical. Engine không kiểm chứng bytes tại ref hoặc chữ ký nguồn.
- Không in command, username, input snippets hay exception locals trong diagnostics.
- ID trùng trong input bị từ chối toàn bộ, kể cả nội dung giống; caller phải xử lý
  nhập trùng tường minh. Không chọn bản ghi cuối để ghi đè evidence.
- Evidence ID và witness pairs sắp xếp từ điển ổn định; assertions theo manifest.
  Không dùng set iteration, thời gian hiện tại, random hoặc input order làm tie-break.

Fingerprint dùng SHA-256 của JSON UTF-8 xuất từ validated model với mọi defaults,
null được giữ, object keys sort, separators compact, ensure_ascii=true, không
NaN. Array contract giữ thứ tự; riêng event set sort theo event_id trước khi hash.
Canonical timestamp dùng dạng xuất hiện tại; không đổi định dạng/chữ số nguồn.
Đổi thứ tự input events không đổi result; thay profile/context/evidence làm đổi
fingerprint tương ứng. Đây không phải chữ ký số hay chứng minh nguồn đáng tin.
Collection declaration tham chiếu event-set/profile/evaluation-scope fingerprint; context
fingerprint tính sau declarations, không tạo phụ thuộc hash vòng tròn.

## 7. Giới hạn tài nguyên và lỗi

Giới hạn V0 đề xuất: 10.000 events, 100 assertions, 16 scope conditions và
16 match conditions mỗi rule, 100 phần tử cho in, 8 join pairs mỗi target,
100 bindings, tổng 1.000.000 lượt so sánh candidate/pair cho một evaluation.
Điều kiện text/literal và binding tối đa 4 KiB UTF-8 mỗi giá trị.
Vượt budget -> controlled input/resource error, không trả partial security result.
Đây là giới hạn evaluator trên dữ liệu trong bộ nhớ, không thay budget ingress
của canonical reader hoặc chứng minh chống mọi DoS.

Mã lỗi ổn định theo nhóm: invalid_input, unsupported_version, profile_binding,
assertion_binding, invalid_predicate, invalid_correlation, missing_binding,
duplicate_evidence_id, invalid_collection_declaration, resource_limit.
Diagnostic chỉ field path allowlist/chỉ số, không raw values/khóa lạ.

## 8. Tổ chức code dự kiến, không triển khai trong lượt thiết kế

- backend/app/validation/contracts.py: profile, context, result và invariants.
- backend/app/validation/predicates.py: phép so sánh có kiểu và ba giá trị.
- backend/app/validation/engine.py: scope, witnesses, dependency và budgets.
- backend/app/validation/results.py: tổng hợp, fingerprints, evidence index.
- backend/app/validation/errors.py và __init__.py: public API/diagnostics.
- backend/tests/test_validation_*.py: contract, matching, status, safety tests.
- pyproject.toml: đăng ký package validation khi implementation, không đổi deps.

Không refactor connector, canonical hoặc scenario loader chỉ để thuận tiện cho
engine. Nếu thực thi spec phát hiện cần thay hợp đồng nền, dừng và xin duyệt.

## 9. Kiểm thử và acceptance của Issue #7

Unit tests synthetic có nhãn rõ, tách khỏi evidence lab. Bao phủ:

1. Đủ telemetry/detection -> Detected; đủ yêu cầu prevention -> Prevented.
2. Activity có/không; detection thiếu với coverage unknown/complete; prevention
   không chứng minh; rule unsupported; candidate thiếu join/predicate fields.
3. Block/alert không liên quan không làm đạt; nhiều candidates phải dùng cùng
   một witness pair; một event không tự làm hai vai; không suy NAT/session.
4. Scope sai environment/host/provider; Sysmon/PowerShell qua Wazuh không tự map.
5. Timestamp sát biên 1 ns, timezone tương đương, âm delta được khai báo;
   input đảo thứ tự kết quả không đổi; null không tự match.
6. Duplicate IDs, invalid model qua construct/copy, sai version, literal sai
   kiểu, profile/manifest lệch, bindings thiếu và mọi budget boundary.
7. Hash/ref giữ nguyên, mọi result ID tồn tại trong input, empty evidence list
   không được điền giả; lỗi không lộ raw values.
8. Mọi tổ hợp ưu tiên trạng thái tổng, positive không che requirement thiếu.
9. Full regression suite và kiểm thử wheel độc lập; không live dependencies.

API profile được chứng minh bằng synthetic scenarios cho unit tests, không
ngầm phê duyệt điều kiện thật của ba scenario repo. Fixture thật có thể dùng để
kiểm chứng engine nhận canonical và giữ evidence, nhưng không dùng mẫu rời rạc
để tuyên bố một run lab đã pass. Yêu cầu Cowrie cùng session/login outcome hoặc
NAT proof chưa được canonical biểu diễn phải unsupported, không đọc provenance.

## 10. Người dùng cần duyệt và chuẩn bị

Lượt này chỉ tạo spec. Duyệt spec nghĩa là chốt hợp đồng engine và phạm vi tests,
không đồng nghĩa chấp thuận rule IDs, collection completeness hoặc ba profile lab.
Sau duyệt mới viết implementation plan và code theo TDD; trước merge vẫn cần
review và người dùng chạy đối chiếu. Không push/merge Issue #7 trong lượt này.

Chưa cần log mới để làm engine offline. Khi thiết lập profile thực tế, cần:
scenario và hành động được phê duyệt, môi trường/mục tiêu, thời gian/múi giờ,
rule/signature kỳ vọng, khóa tương quan thực sự có trong canonical, nguồn log
đã thu thập và xác nhận giới hạn collection. Không xin password hoặc token.

Lộ trình sau lõi offline: hồ sơ lab được review -> CLI end-to-end -> timeline/
run comparison -> UI -> live adapters. Đây là hướng phát triển, không mở thêm
phạm vi Issue #7. B có thể thêm khi cần đóng gói scenario tiện dụng mà không
thay evaluator; không cam kết chuyển đổi không tốn công hoặc tự tương thích.
