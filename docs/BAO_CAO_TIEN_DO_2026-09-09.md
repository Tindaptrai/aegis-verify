# AEGIS Verify — Báo cáo tiến độ ngày 09/09/2026

## 1. Tóm tắt điều đã đạt được

Hôm nay dự án đã hoàn thành mốc kỹ thuật **Suricata A** trên một nhánh riêng:
đọc một alert Suricata nằm trong JSON export của Wazuh, chuyển dữ liệu sang
`CanonicalEventV2`, giữ bằng chứng có thể truy vết và kiểm tra chặt dữ liệu sai.

Mốc A hiện **sẵn sàng để chủ dự án chạy đối chiếu và review**, nhưng chưa push,
chưa tạo/merge PR và chưa đóng Issue #4. Issue #4 vẫn còn bước B: direct EVE JSONL
và flow record. Test xanh không đồng nghĩa alert đã được xác thực là một sự cố thật
hoặc IDS/firewall đã ngăn chặn lưu lượng.

Trạng thái nền trước khi bắt đầu A:

- Canonical Event v1 và Scenario YAML đã merge.
- Canonical Event v2 giữ timestamp chính xác đã merge qua PR #16.
- Wazuh Windows 4688 fixture parser đã merge qua PR #17 lúc 23:04 ngày 08/09/2026.
- `main` dùng làm nền cho A là commit `4869b52`.

## 2. Công việc cụ thể đã thực hiện hôm nay

### 2.1. Phân loại đúng mẫu log

Mẫu `pfense_sample.json` ban đầu được xem xét về cấu trúc. Kết luận kỹ thuật:

- Đây không phải pfSense firewall `filterlog`.
- Đây là một Wazuh search-hit có `_source.data` chứa Suricata EVE alert.
- Event là Suricata alert về QUIC failed decrypt; lab được người dùng xác nhận đang
  chạy IDS-only.
- Vì vậy mẫu phù hợp với hướng A của Issue #4, không dùng để tuyên bố Issue #5
  pfSense firewall parser đã có dữ liệu đầu vào.

Điểm này quan trọng vì cùng xuất hiện trên máy pfSense nhưng log Suricata và log
firewall pfSense là hai nguồn/ý nghĩa khác nhau. Connector không được gắn nhãn sai.

### 2.2. Chuẩn bị fixture an toàn

Tạo derivative đã sanitize để kiểm thử và chỉ commit derivative này:

`tests/fixtures/suricata/suricata-wazuh-alert-001.sanitized.json`

- Kích thước: 2.137 byte.
- Số dòng vật lý: 92.
- SHA-256: `9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c`.
- 14 giá trị định danh được thay thế nhất quán: document/source ID, collector,
  địa chỉ mạng, flow ID, interface và location.
- Loại bỏ `packet`, `payload`, `payload_printable` vì có thể chứa raw packet hoặc
  nội dung nhạy cảm được mã hóa.
- Thêm `.gitattributes` để Git không tự chuyển newline của fixture.
- So sánh bản trong working tree với blob đã commit: khớp byte-for-byte.
- File export gốc vẫn nằm ngoài Git và không bị sửa.

Fixture này dùng để chứng minh parser xử lý đúng định dạng đã review; hash chỉ chứng
minh bytes không đổi, không tự chứng minh tính xác thực của sự kiện.

### 2.3. Chốt hợp đồng và kế hoạch trước khi code

Đã viết specification và implementation plan riêng:

- `docs/superpowers/specs/2026-09-09-suricata-a-design.md`
- `docs/superpowers/plans/2026-09-09-suricata-a.md`

Phạm vi được khóa rõ:

- Chỉ đọc một Wazuh JSON object chứa Suricata alert.
- Không làm direct EVE/JSONL, flow record, CSV hoặc live connector trong A.
- Không sửa Canonical Event schema hay scenario ground truth.
- Không thêm dependency.
- Không suy diễn dữ liệu vắng mặt và không tạo security conclusion.
- Mọi context quan trọng phải do caller khai báo: source label, environment,
  ingestion time và chế độ `ids`/`ips`/`unknown`.

### 2.4. Triển khai theo test-first

Baseline trước thay đổi: **650 tests passed**.

Test đầu tiên được chạy khi API chưa tồn tại và thất bại đúng nguyên nhân
`ImportError`. Sau đó mới triển khai production code. Thành phần mới:

- `connectors/suricata/parser.py`: chọn profile Wazuh, context, evidence identity,
  line reference và file loader có giới hạn.
- `connectors/suricata/_mapping.py`: chỉ map trường Suricata, không biết wrapper Wazuh.
- `connectors/suricata/_fields.py`: validator chặt cho text, IP, port, decimal ID,
  severity và flow ID.
- `connectors/suricata/errors.py`: diagnostic theo vocabulary cố định, không làm lộ
  nội dung log hoặc đường dẫn máy.
- `connectors/suricata/models.py`: kết quả và provenance immutable.
- Public API:
  - `parse_suricata_wazuh_document(...)`
  - `load_suricata_wazuh_document(...)`

Parser tái sử dụng bộ giải mã JSON có giới hạn của Wazuh, nhưng không gọi Windows
4688 mapper. Nhờ tách `_mapping.py`, bước B có thể thêm adapter direct EVE mà không
phải bỏ A hoặc bắt EVE gốc mang metadata của Wazuh.

### 2.5. Mapping và độ chính xác đã bảo vệ

Các quyết định chính:

| Canonical/provenance | Nguồn | Ý nghĩa |
|---|---|---|
| `timestamp` | `data.timestamp` | Giờ sự kiện Suricata, không lấy giờ Wazuh nhận |
| `src/dst_ip`, `src/dst_port` | trường top-level Suricata | Không tự bù từ `flow` hoặc agent |
| `protocol` | `data.proto` | Network protocol, ví dụ `UDP` |
| `app_proto` | `data.app_proto` | Lưu provenance, ví dụ `quic` |
| `signature_id` | `alert.signature_id` | Suricata SID |
| `rule_id` | `_source.rule.id` | Wazuh rule ID, không trộn với SID |
| `severity` | `alert.severity` | Giữ thang severity của nguồn |
| `event_action` | `alert.action` | Action ở phạm vi alert rule |
| `flow_id_raw` | `data.flow_id` | Giữ chính xác trong provenance |
| collector | `_source.agent/manager` | Metadata thu thập, không giả làm asset nguồn |

Timestamp mẫu `2026-04-30T00:18:09.338512+0700` được chuẩn hóa đúng thành
`2026-04-29T17:18:09.338512Z`, giữ đủ 6 chữ số thập phân. Parser hỗ trợ 0–9 chữ số
và không fallback sang Wazuh timestamp, `fields.timestamp`, `sort` hay `flow.start`.

Nếu nguồn thiếu trường tùy chọn thì canonical giữ `null`. Nếu trường tồn tại nhưng
sai kiểu/range thì parser báo lỗi thay vì đoán. Flow ID không đi qua float để tránh
mất độ chính xác. Hiện flow ID nằm trong provenance vì Canonical v2 chưa có trường
đó; thay đổi canonical phải là một quyết định hợp đồng/version riêng.

`allowed`/`blocked` được giữ đúng như nguồn. Trong IDS-only, `blocked` tạo warning
`ids_blocked_action_requires_review`, không tự nâng lab thành IPS và không kết luận
firewall đã chặn.

### 2.6. Evidence và giới hạn an toàn

- Hash trên toàn bộ input bytes, bao gồm BOM/newline/trường không được map.
- `raw_event_ref` trỏ đến cả wrapper: `...#L1-L92`.
- Evidence ID phụ thuộc bytes, environment, source label và record index.
- Đổi ingestion time hoặc deployment mode không đổi identity của cùng evidence.
- A chưa deduplicate cùng một event giữa Wazuh export và direct EVE tương lai.
- Một document tối đa 256 KiB, depth 20, 10.000 node, numeric token 128 ký tự.
- Chỉ nhận một JSON object; chưa nhận JSON array, search response, JSONL hoặc CSV.
- File loader chỉ đọc, không ghi và không kết nối hệ thống.

### 2.7. Review và kiểm thử

Kết quả cuối cùng trên commit hiện tại:

- **826 passed in 2.05s**.
- `pip check`: **No broken requirements found**.
- Có 176 test mới so với baseline 650.
- Build wheel thành công.
- Cài wheel vào một virtual environment mới thành công.
- Import được xác nhận đến từ `site-packages`, không vô tình dùng source checkout.
- Chạy lại 826 test bằng wheel và `--import-mode=importlib`: tất cả đều pass.
- Ví dụ tài liệu chạy thật và kiểm tra timestamp, SID, rule ID, flow ID, hash và
  evidence ID cố định: pass.

Một lượt review độc lập đã kiểm tra production diff:

- 152 focused tests: pass.
- 802 full-suite tests tại thời điểm review: pass.
- 24 boundary probes bổ sung: pass.
- Không có finding Critical hoặc Important.
- Reviewer đề nghị giữ regression test cho metadata null, số 128 chữ số và giới
  hạn flow fraction; các test đó đã được đưa vào suite, nâng tổng lên 826.

Trong quá trình test, pytest từng vượt giới hạn 32.767 ký tự của environment variable
trên Windows do tên parameter chứa nguyên input 256 KiB. Đã xác định nguyên nhân ở
tên test do pytest tạo, không phải parser. Tên được thay bằng SHA-256 rút gọn; dữ liệu
kiểm thử và assertion không bị thay đổi.

### 2.8. Tài liệu bàn giao

Đã viết:

- `docs/SURICATA_WAZUH_ALERT.md`: giải thích A bằng tiếng Việt, cách đọc mapping,
  ý nghĩa IDS/action, cách chạy PowerShell, lỗi/giới hạn và checklist B.
- `docs/superpowers/plans/2026-09-09-suricata-a-verification.md`: bằng chứng test,
  hash, review limits và phạm vi chưa làm.
- Cập nhật README root và README connector đúng trạng thái thực tế.

Nhánh/commit cục bộ:

```text
branch: codex/issue-4-suricata-wazuh-alert

5efed1c docs: define approved Suricata A scope and test plan (#4)
403b29c feat: parse Suricata alerts from Wazuh fixtures (#4)
2d06ce0 docs: explain Suricata A and prepare direction B (#4)
```

## 3. Việc chủ dự án cần làm tiếp theo

### Bước gần nhất: đối chiếu A

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-4-suricata-wazuh-alert'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
```

Sau đó chạy ví dụ đầy đủ tại mục 3 của `docs/SURICATA_WAZUH_ALERT.md` và xác nhận:

- Timestamp UTC khớp log.
- SID `2231000` và Wazuh rule `86601` đúng vai trò.
- Lab là IDS-only.
- `allowed` được hiểu là source alert action, không phải verdict an toàn.
- Fixture derivative không còn thông tin nhạy cảm mà chủ dự án nhận ra.

Nếu đối chiếu đạt, bước tiếp theo là yêu cầu push nhánh, mở PR cho Suricata A, review
PR và merge vào main. Không đóng Issue #4 ở PR A vì B chưa xong.

### Chuẩn bị cho B ngày mai

Nếu có quyền lấy dữ liệu, chuẩn bị:

1. 1–3 dòng EVE JSON `event_type=alert` trực tiếp từ Suricata.
2. 1–3 dòng `event_type=flow` liên quan, ưu tiên cùng `flow_id`.
3. Phiên bản Suricata, interface theo dõi, múi giờ và xác nhận IDS/IPS nếu biết.
4. Giữ bản gốc riêng; chia sẻ derivative đã xem xét. Đặc biệt kiểm tra/bỏ
   `packet`, `payload`, `payload_printable` khi chúng chứa dữ liệu nhạy cảm.

Không cần cung cấp password, token, certificate, toàn bộ PCAP hoặc quyền truy cập
hệ thống. Nếu không lấy được flow, cung cấp alert trước và ghi rõ flow chưa có;
không tạo log giả. Wazuh JSON hiện tại vẫn tiếp tục dùng được cho A nhưng không
thay thế được bằng chứng về định dạng direct EVE cho B.

Trình tự B đề xuất:

1. Review và sanitize direct EVE sample.
2. Chốt input contract cho JSONL, alert/flow và hành vi với event không liên quan.
3. Chốt flow identity: tiếp tục provenance hay mở issue thay đổi canonical.
4. Viết test RED trước, sau đó thêm direct EVE adapter dùng lại mapping Suricata.
5. Test line-level evidence, malformed lines, missing fields và hồi quy A.
6. Review độc lập, chủ dự án đối chiếu lab, rồi mới push/merge phần B.

## 4. Có thể chia dự án thành 4 nhánh cho 4 người không?

**Có.** Kiến trúc fixture-first và source isolation phù hợp để chia việc. Tuy nhiên,
không nên cho bốn người tùy ý sửa cùng model hoặc cùng scenario. Mỗi người phải có
Issue, nhánh, thư mục sở hữu và acceptance criteria riêng.

### Phương án phân công đề xuất

| Người | Nhánh đề xuất | Phạm vi chính | Đầu vào cần |
|---|---|---|---|
| 1 | `codex/issue-4-suricata-direct-eve` | Hoàn thiện B: direct EVE alert + flow, giữ A tương thích | EVE alert/flow đã sanitize |
| 2 | `codex/issue-5-pfsense-filterlog` | Parser pfSense firewall/filterlog | Mẫu filterlog thật đã sanitize; mẫu Suricata hiện tại không dùng thay thế |
| 3 | `codex/issue-6-cowrie-json` | Parser Cowrie JSON và các profile được chốt | Mẫu Cowrie đã rà soát IP, session, command, payload |
| 4 | `codex/issue-7-validation-engine` | Engine thuần canonical: assertion/status/evidence IDs | Canonical v2 + Scenario model; dùng canonical test objects |

Người 4 có thể làm song song engine vì engine **chỉ nhận canonical events**, không
đọc field Suricata/pfSense/Cowrie. Phần integration fixture thực tế của engine nên
chờ các connector tương ứng merge. Người 4 không được đưa logic vendor-specific
vào engine để đi trước connector.

### Thứ tự khởi động an toàn

1. Chủ dự án review A; push/merge A vào main.
2. Cập nhật main và tạo cả bốn nhánh từ cùng main mới nhất.
3. Mỗi người dùng worktree/clone và `.venv` riêng; không dùng chung editable install.
4. Mỗi nhánh đọc Issue/PRD/ARCHITECTURE, viết spec nhỏ và test trước code.
5. Chỉ thay đổi đúng file thuộc phạm vi; không sửa ground truth hoặc canonical schema
   nếu chưa có issue/approval riêng.
6. Mỗi PR ghi test result, fixture provenance, giới hạn và phần chưa hỗ trợ.

Không nên cho nhánh B của Suricata bắt đầu từ một feature branch chưa review nếu mục
tiêu là làm việc nhóm lâu dài. Merge A trước giúp cả nhóm có một base commit rõ ràng.
Nếu cần khởi động gấp, chỉ người 1 có thể tạm branch từ A; trước PR vẫn phải rebase
theo main sau khi A được merge.

### Quy tắc để gộp không vỡ

- Một Issue = một branch = một PR nhỏ.
- Không merge cả bốn PR cùng lúc. Merge lần lượt; sau mỗi merge, các nhánh còn lại
  rebase/update từ main rồi chạy toàn bộ test.
- `CanonicalEventV2`, scenario files và evidence-ID contract là shared contracts;
  không ai tự đổi. Nếu thiếu field như flow ID, mở issue/schema version riêng.
- `README.md`, `pyproject.toml` và package list là điểm dễ conflict. Hạn chế sửa README
  ở mỗi nhánh; rebase ngay trước merge. Conflict ở package list phải được giải bằng
  cách giữ entry của tất cả connector đã merge, không chọn một phía rồi làm mất entry.
- Người 1 chỉ sửa `connectors/suricata/` và test/docs Suricata.
- Người 2 chỉ sửa `connectors/pfsense/` và test/docs pfSense.
- Người 3 chỉ sửa `connectors/cowrie/` và test/docs Cowrie.
- Người 4 chủ yếu sửa module validation trong `backend/app/` và test engine; không
  import trực tiếp module connector.
- Fixture phải sanitize và có manifest/hash; không commit credential/raw production.
- Mọi security conclusion của engine phải mang evidence ID.
- Chạy focused tests, full suite, `pip check`, wheel/package import và human review
  trước khi merge.

### Thứ tự merge đề xuất

```text
main sau Suricata A
  ├─ PR Issue #4B — direct EVE/flow
  ├─ PR Issue #5  — pfSense filterlog
  ├─ PR Issue #6  — Cowrie JSON
  └─ PR Issue #7  — validation engine core
                  ↓
       integration PR: fixture → canonical → assertion → evidence result
                  ↓
       CLI / timeline / run comparison
                  ↓
       dashboard sau khi luồng CLI end-to-end ổn định
```

Ba connector có thể merge theo thứ tự nhánh nào review xong trước. Engine core có
thể merge khi hợp đồng assertion/evidence ổn định, nhưng integration end-to-end nên
được làm bằng PR riêng sau khi các connector cần thiết đã có trên main.

## 5. Những rủi ro cần nhớ

- Mẫu đang có cho pfSense thực chất là Suricata qua Wazuh; Issue #5 vẫn cần filterlog.
- Cowrie sample phải kiểm tra lại dữ liệu nhạy cảm trước khi commit.
- Direct EVE và Wazuh wrapper có thể là cùng event nhưng bytes khác; chưa được tự
  deduplicate nếu chưa có identity design.
- IDS alert action không đủ để kết luận prevented.
- Timestamp độ phân giải cao không chứng minh clock chính xác; cần xác minh clock lab.
- Nếu bốn nhánh cùng sửa canonical/schema/scenario, xung đột sẽ không chỉ là Git mà
  còn là sai hợp đồng. Shared contract phải do một issue riêng quản lý.
- Dashboard chưa nên chạy trước CLI fixture-driven end-to-end theo PRD.

## 6. Trạng thái kết thúc ngày

- Suricata A: triển khai, test, package check, tài liệu và independent review hoàn tất.
- Sẵn sàng cho human/lab comparison.
- Chưa push/merge A; Issue #4 chưa đóng.
- B đã có checklist, chưa triển khai và không có automation tự chạy ngày mai.
- Mô hình 4 người khả thi khi chia theo Issue #4B/#5/#6/#7 và giữ contract chung.
