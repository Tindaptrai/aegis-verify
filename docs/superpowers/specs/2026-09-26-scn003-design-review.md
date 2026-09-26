# SCN-003 — review thiết kế và kế hoạch, 2026-09-26

Issue: #76. Đối tượng review: spec `2026-09-23-scn003-safe-cowrie-design.md` và
plan `2026-09-24-scn003-offline-foundation.md`, cả hai viết trước khi SCN-002
hoàn tất. Review này đối chiếu chúng với mã trên `main` tại `9a672f0` và với
những gì SCN-002 đã dạy. Nó **không** thay hai tài liệu trên; nó liệt kê điểm
đã xác minh, điểm phải sửa, và quyết định còn cần chủ dự án. Chưa có code, chưa
có lưu lượng lab, chưa đổi ground truth.

## 1. Đã xác minh đúng với mã hiện tại

| Giả định của plan | Kiểm | Kết quả |
| --- | --- | --- |
| Fingerprint manifest SCN-003 `d84ec3db…1550` | `scenario_fingerprint(load_scenario(...))` | khớp |
| SID `1000012` và rule Wazuh `120003` chưa bị dùng | grep toàn repo | chưa dùng |
| `session_key` đã có ở connector Cowrie, prefix `cowrie:session-v1:` | `connectors/cowrie/_context.py` | có, tính từ `environment_id`, `sensor_id`, `session` |
| Context intake của hai parser Cowrie có `sensor_id` | `CowrieWazuhContext`, `CowrieJsonlContext` | có, nên parser alert Wazuh mới dùng cùng `sensor_id` là hợp lý |
| Engine cho phép nhiều telemetry root, detection neo vào root bất kỳ | `engine.py` `_target` | đúng; SCN-002 đã dùng một root, cấu trúc hai root không cần đổi engine |
| Binding được phép trên `rule_id` của rule telemetry | validator `AssertionRule` | đúng; SCN-002 A03 đã dùng cho tracker |
| Parser Cowrie giữ `protocol` là `ssh`/`telnet`, Suricata giữ `TCP`, pfSense `tcp` | mapping của ba connector | đúng; plan đã pin `protocol` riêng từng rule, giữ nguyên cách này |
| Rule cha Wazuh cho Cowrie trong lab | fixture thật đã sanitize | rule `100300` "Cowrie JSON event detected", group `cowrie, honeypot`; `parent_group` khi render là `cowrie` |

## 2. Phải sửa trong plan trước khi thực thi

1. **`False negative` cần declaration.** Plan Task 3, test 4 kỳ vọng "sai
   SID/rule ID cho `False negative` khi telemetry root còn". Engine chỉ trả
   `false_negative` khi context có `CollectionDeclaration` với
   `status: complete_for_scope`, đủ ba xác nhận và ba fingerprint; nếu không
   nó trả `inconclusive` với `collection_not_confirmed`. Test phải dựng
   declaration hợp lệ cho ca này, hoặc đổi kỳ vọng thành `Inconclusive` và thêm
   một ca riêng có declaration. Đây là quy tắc đúng của engine, không nới.
2. **Cửa sổ tương quan.** Plan đặt ±5 s "hợp đồng tổng hợp". SCN-002 đo được
   lệch dưới 0,7 s và đã siết xuống ±2 s (PR #72). Với SCN-003, Cowrie là nguồn
   thứ tư, chưa đo. Giữ ±5 s trong profile công khai cho tới khi lượt đối chứng
   thật đo được cả bốn nguồn, rồi siết bằng PR riêng như đã làm. Không đặt hẹp
   trước khi đo.
3. **Cầu nối trước và sau NAT là bindings, không phải join.** Spec mục 4 nói
   "tương quan qua NAT"; trong profile của plan, A01 chỉ neo A02 và A04 chỉ neo
   A03, engine không join giữa hai miền. Thứ nối hai miền là hai binding
   `initiator_ip` và `initiator_port` cùng xuất hiện trong scope của cả hai
   root. Nghĩa là verdict phụ thuộc vào việc receipt phía client ghi đúng cổng
   nguồn và pfSense không viết lại cổng nguồn. Plan và README profile phải nói
   thẳng điều này, và test phải có ca "cổng nguồn ở miền sau NAT khác miền
   trước NAT" cho kết quả không `Detected` (plan đã có mục "source port
   rewrite", giữ).
4. **Từ ngữ `TARGET_FIELDS`.** Plan thêm `session_key` vào `FILTER_FIELDS` và
   `JOIN_FIELDS` nhưng không vào `TARGET_FIELDS`. Đồng ý. Ghi thêm: thêm
   trường canonical mới là thay đổi `CanonicalEventV2` và tài liệu v2, cần test
   ở cả hai phiên bản, đúng như plan Task 2 đã liệt kê.
5. **Parser alert Wazuh cho Cowrie.** Kể từ 24/9, `connectors/wazuh/suricata_alert.py`
   (PR #66) đã có cùng chính sách identity `wazuh:evidence-v1` và cách re-root
   diagnostic của connector con dưới `data.`. Parser Cowrie mới nên sao chép
   đúng mẫu đó, kể cả việc thêm đường dẫn `data.*` của Cowrie vào `_FIELDS`
   của `connectors/wazuh/errors.py`, nếu không diagnostic sẽ mất `field_path`.
6. **Hình dạng alert Wazuh thật.** Plan tự nhận là "cần mẫu Wazuh thật trước khi
   chốt parser". Fixture thật hiện có là search-hit của Indexer (có `_source`),
   không phải dòng `alerts.json` của manager. Với SCN-002, hai hình dạng này
   khác nhau ở chỗ manager stringify số. Trước Task 2, lấy một dòng
   `alerts.json` thật của rule `100300` (chỉ đọc, đã có sẵn trên manager), xác
   nhận `data.src_port` là chuỗi hay số, rồi mới viết fixture synthetic.

## 3. Bài học từ SCN-002 áp vào SCN-003

- **Điều kiện vào phải kiểm agent.** Ngày 2026-09-22 danh sách agent trên manager
  cho thấy agent Cowrie (`004`) ở trạng thái `Disconnected`, cùng lúc agent
  Windows cũng đã tự dừng và làm mất A01 của một lượt. Preflight SCN-003 phải có
  `agent_control -lc` với agent Cowrie `Active` và một dòng Cowrie mới lên
  archive manager trong ngày, trước khi tạo bất kỳ kết nối nào.
- **Thao tác theo runbook có [DUYỆT] từng bước**, cùng mẫu với
  `SCN002_BLOCK_RUN_RUNBOOK.md`: sao lưu cấu hình và hash, kiểm chỉ đọc
  (`pfctl -sr`, `pfctl -sn` cho NAT), một kết nối, thu evidence theo bảng, hoàn
  tác có kiểm chứng.
- **Ráp bundle bằng công cụ**, không tay: `assemble_scn002_bundle.py` (ngoài
  Git) chỉ cần thêm hai parser key Cowrie là dùng lại được, và nó đo lệch giờ
  từng nguồn so với root.
- **Fixture sanitized từ lượt thật** với lineage hash, như
  `tests/fixtures/cli/scn002-lab-sanitized/`, là bước đóng kịch bản.

## 4. Quyết định cần chủ dự án, theo thứ tự cần

| # | Câu hỏi | Khuyến nghị |
| --- | --- | --- |
| 1 | Manifest SCN-003 ghi "approved internal scan" ở mô tả và A01, trong khi #76 loại quét cổng khỏi milestone. Sửa ground truth hay giữ? | Sửa A01 thành "Suricata records the approved decoy connection" và mô tả tương ứng, bằng PR riêng như A04 của SCN-002, **sau** khi spec được duyệt. Fingerprint và profile pin lại cùng lúc. |
| 2 | Tương tác Cowrie: `login.failed` (không mở shell) hay `login.success` rồi đóng ngay? | `login.failed`, đúng spec. |
| 3 | Giao thức decoy: `ssh` hay `telnet`? | `ssh` (cổng 2222 mặc định của Cowrie); fixture thật hiện có đủ cả hai. |
| 4 | Topology: máy khởi tạo ở LAN hay MGMT, decoy VIP ở interface nào, DNAT do pfSense làm? | Cần anh xác nhận bằng lệnh chỉ đọc trên pfSense trước khi viết runbook; spec chọn hướng DNAT nhưng chưa ai kiểm. |
| 5 | Hai ID `1000012` và `120003` | Giữ như plan; chưa bị dùng. |
| 6 | Đưa spec, plan và review này vào `main` trước khi code | Có; đúng yêu cầu của #76 "reviewed design before code". |

## 5. Thứ tự việc sau khi duyệt

1. Merge tài liệu (PR này).
2. PR ground truth cho A01 và mô tả, nếu anh chọn (quyết định 1).
3. Plan Task 1: hai template rule và test nội dung.
4. Đọc một dòng `alerts.json` thật của rule `100300` trên manager (chỉ đọc) để
   chốt hình dạng; rồi plan Task 2: `session_key` canonical và parser
   `wazuh-cowrie-alert-v1`.
5. Plan Task 3 và 4 với các sửa ở mục 2: profile hai root, bundle CLI tổng hợp,
   test âm tính có declaration.
6. Runbook lượt đối chứng và preflight (điều kiện vào có agent Cowrie).
7. Live: một kết nối, một login failed, thu evidence, `aegis validate`, đo lệch
   giờ, siết cửa sổ nếu số đo cho phép, fixture sanitized, tài liệu kết quả.

Mỗi bước là một PR, CI xanh, anh duyệt merge; không bước nào chạm lab trước
bước 6.
