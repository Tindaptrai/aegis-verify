# Issue #2 — Thiết kế Scenario YAML v0.1

## Phạm vi và trạng thái phê duyệt

Người dùng đã duyệt hướng: giữ nguyên kỳ vọng của ba scenario, bổ sung bộ đọc và
kiểm tra cấu trúc trước; chưa triển khai engine đối chiếu bằng chứng. Tài liệu
này cụ thể hóa hướng đó để người dùng review trước kế hoạch triển khai và code.

Cơ sở: Issue #2 đã đọc trên GitHub, AGENTS.md, PRD, ARCHITECTURE, THREAT_MODEL,
CANONICAL_EVENT và ba manifest đã commit. Nhánh bắt đầu từ main tại dc09897.

Không sửa bất kỳ byte nào của ba manifest hiện tại. Không thêm rule ID, điều kiện
khớp log, cửa sổ tương quan, payload hoặc kết quả kỳ vọng mới. Không có live I/O,
thực thi scenario, CLI sản phẩm, parser log hay kết luận detection trong issue này.

## Các cách tiếp cận

1. **Chọn: model Pydantic + bộ đọc YAML giới hạn.** Tái sử dụng cách tổ chức domain
   model của Issue #1; YAML là định dạng đầu vào, model là hợp đồng đã kiểm tra.
   Giữ assertion.description làm kỳ vọng bằng câu chữ, chưa diễn dịch nó thành mã.
2. JSON Schema độc lập: phù hợp khi nhiều ngôn ngữ cùng tiêu thụ, nhưng hiện tại
   cần thêm một tầng validator và chuyển đổi domain model trong backend Python.
3. Thêm ngôn ngữ assertion thực thi được ngay: có thể phục vụ engine trực tiếp,
   nhưng cần duyệt ground truth chi tiết và vượt hướng người dùng vừa chọn.

## Thành phần và luồng dữ liệu

- `backend/app/models/scenario.py`: enum và model thuần, không đọc file.
- `backend/app/scenario_loader.py`: đọc đường dẫn do bên gọi chỉ định hoặc text,
  kiểm tra YAML, tạo model; không ghi file hoặc tìm file khác theo nội dung YAML.
- `backend/tests/test_scenario.py`, `backend/tests/test_scenario_loader.py`:
  test hợp đồng, lỗi đầu vào, immutability và ba manifest thật của repo.
- `docs/SCENARIO_SCHEMA.md`: tài liệu trường, ví dụ cách đọc và giới hạn.
- Cập nhật exports, metadata dependency và README khi triển khai; không sửa
  canonical event behavior hay scenario ground truth.

Luồng: file/text YAML → kiểm tra cú pháp và cấu trúc YAML → validate model và
quan hệ giữa các trường → trả ScenarioManifest bất biến. Không trả Pass/Fail.

## Hợp đồng dữ liệu

Các tên trường hiện có được giữ nguyên. Không thêm trường bắt buộc vào manifest.

| Trường | Quy tắc dự kiến |
| --- | --- |
| id | Chuỗi ASCII dạng SCN- và ba chữ số, ví dụ SCN-001 |
| name, description | Chuỗi chứa ký tự không phải khoảng trắng, UTF-8 hợp lệ |
| version | Chuỗi phiên bản dạng X.Y.Z, mỗi phần là số nguyên không âm không có số 0 dẫn đầu ngoài giá trị 0; phạm vi này chưa hỗ trợ hậu tố prerelease/build |
| status | Giá trị duy nhất được hỗ trợ ở V0 là draft; không tự nâng lên approved |
| safety | Model bắt buộc gồm destructive, authorization_required, notes |
| safety.destructive | Boolean thực sự và phải false trong profile an toàn V0 |
| safety.authorization_required | Boolean thực sự và phải true; không phải bằng chứng đã được cấp phép |
| safety.notes | Chuỗi không trắng, UTF-8 hợp lệ; ghi chú không thay thế cơ chế thực thi an toàn |
| expected_sources | Danh sách không rỗng các tên nguồn hợp lệ, không trùng |
| expected_outcome | detected hoặc prevented; đây là mục tiêu, không phải kết quả đo |
| assertions | Danh sách không rỗng các ScenarioAssertion |
| tags | Danh sách chuỗi không trắng, UTF-8 hợp lệ; tùy chọn, thiếu thì null; [] được giữ nguyên |

ScenarioAssertion yêu cầu `id`, `description`, `source`. ID dạng
`<scenario-id>-A<hai chữ số>`, duy nhất trong scenario và phải khớp ID scenario cha.
`description` là kỳ vọng về bằng chứng do tác giả viết, không trắng và UTF-8 hợp lệ.
Validator không thể chứng minh một câu văn có ý nghĩa đúng: human review vẫn phải
xác nhận nó thực sự mô tả bằng chứng cần có. Không suy diễn câu văn thành predicate.

Nguồn hợp lệ: sysmon, powershell, wazuh, suricata, pfsense, cowrie. Đây là enum
ScenarioSource riêng, không sửa enum SourceType của CanonicalEvent. Sysmon và
PowerShell là nguồn telemetry logic, có thể được thu qua Wazuh. Bộ đọc không tạo
mapping provider, không suy đoán source_type, không tạo event từ tên nguồn.

Mỗi assertion.source phải thuộc expected_sources. Mỗi nguồn trong expected_sources
phải được ít nhất một assertion tham chiếu, tránh khai báo kỳ vọng không có điều
kiện kiểm tra. Không tự sắp xếp, loại trùng, trim hay đổi chữ hoa/thường để sửa input.

Model từ chối trường lạ ở mọi tầng và từ chối ép kiểu số/bool thành chuỗi. Tất cả
model lồng nhau frozen; danh sách được lưu thành tuple, JSON xuất thành array.
Không nhận set hoặc container không có thứ tự khi validate dữ liệu Python.

## Quy tắc đọc YAML và chẩn đoán

API dự kiến:

- `parse_scenario_yaml(text: str, *, source_name: str) -> ScenarioManifest`.
- `load_scenario(path: str | Path) -> ScenarioManifest`, chỉ đọc file được chỉ định.
- `ScenarioLoadError`: lỗi công khai chứa định danh nguồn, scenario ID hợp lệ nếu
  đọc được, vị trí trường và mã lỗi; có dòng/cột khi parser cung cấp được.

Nếu thiếu hoặc sai scenario ID, dùng source_name/tên file làm định danh để người
dùng vẫn biết manifest nào lỗi. Không in toàn bộ YAML, giá trị input lỗi hoặc
traceback thư viện trong thông báo công khai. Lỗi IO và encoding cũng được chuyển
thành lỗi có ngữ cảnh file. Không tuyên bố đường dẫn hay tên scenario là dữ liệu
đã được làm sạch; bên gọi cần chọn nhãn phù hợp khi xuất log.
Đường dẫn trường trong lỗi chỉ dùng tên trường hợp đồng và chỉ số danh sách;
tên khóa lạ do input cung cấp được thay bằng nhãn cố định, không echo vào lỗi.

Chỉ nhận một tài liệu YAML có root là mapping. Từ chối file rỗng, nhiều tài liệu,
duplicate mapping keys ở mọi tầng, non-string keys, custom tags/object tags,
anchors/aliases và merge keys. Không cho duplicate key âm thầm ghi đè ground truth.
Boolean safety dùng literal YAML true/false; không chấp nhận yes/no/on/off hay 0/1
như boolean. Phiên bản/ID/tên nguồn phải là chuỗi, không ép kiểu scalar để hợp lệ.

File đọc UTF-8 nghiêm ngặt, chấp nhận BOM đầu file; malformed Unicode bị từ chối.
Giới hạn V0: 256 KiB đầu vào, độ sâu collection tối đa 20, tối đa 10.000 YAML nodes.
Kích thước text tính bằng UTF-8 bytes, gồm BOM nếu có. Root mapping có độ sâu 1;
chỉ mapping/sequence tăng độ sâu. Node budget đếm scalar, mapping và sequence,
bao gồm các scalar dùng làm mapping key.
Kiểm tra kích thước bằng bounded read; kiểm tra nesting/node budget và aliases
trước khi dựng toàn bộ object graph, không chỉ bắt lỗi sau recursive construction.
Đây là giới hạn cho file cấu hình nhỏ, không phải bộ parser cho log lớn hoặc bảo
đảm chống mọi hình thức DoS trong môi trường đối kháng.

Thêm PyYAML làm dependency runtime là có lý do: Python standard library không có
YAML parser và Pydantic chỉ validate dữ liệu sau parse. Khi triển khai sẽ xác minh
phiên bản và API bằng nguồn chính thức rồi pin phiên bản được kiểm chứng, theo cách
repo đang dùng. Không cài dependency ở bước thiết kế này. SafeLoader chỉ là nền
tảng; cần bổ sung chính sách duplicate keys, scalar và giới hạn nêu trên.

## Giữ nguyên ground truth

Loader không có API save/update, không render template, không thay biến môi trường,
không dùng eval, không thực thi YAML tag, không tự thêm assertion hoặc outcome.
Model và các phần tử lồng nhau không thể bị gán lại qua API thông thường; dữ liệu
đầu vào mutable được tách khỏi model khi validate.

Frozen model không phải ranh giới bảo mật với mã Python có toàn quyền. Không dùng
model_construct/model_copy(update=...) để nhận dữ liệu không tin cậy. Tính bất biến
không ngăn người có quyền sửa file ngoài chương trình; Git và review vẫn là cơ chế
kiểm soát thay đổi ground truth. Không thêm cơ chế chữ ký hoặc storage mới ở đây.

## Kiểm thử và nghiệm thu

1. Ba manifest trong repo validate thành công, giữ đúng ID, phiên bản, thứ tự
   assertions, nội dung description và outcome hiện tại; không ghi lại file.
2. Từ chối thiếu/sai ID, phiên bản, outcome, nguồn; duplicate assertion IDs,
   assertion ID sai scenario; nguồn không khai báo hoặc không được tham chiếu.
3. Từ chối kiểu sai, trường lạ, text trắng, Unicode không hợp lệ và safety sai.
4. Từ chối YAML duplicate keys, multi-document, tag nguy hiểm, anchors/aliases,
   merge keys, root không phải mapping, encoding sai và vượt các giới hạn.
5. Lỗi có source/scenario, đường dẫn trường hoặc dòng/cột thích hợp; marker nhạy
   cảm đặt trong input lỗi không xuất hiện trong thông báo công khai.
6. Gán lại trường, sửa collection/nested model bị ngăn; sửa dict/list input sau
   validate không làm thay đổi model; serialization round-trip giữ dữ liệu.
7. Toàn bộ 180 test Issue #1 giữ xanh; pytest và pip check chạy trong đúng venv.
   Xác minh import trỏ tới checkout Issue #2, không dùng nhầm editable Issue #1.
8. So sánh Git xác nhận ba manifest không thay đổi; tự review, rồi bàn giao cho
   người dùng chạy đối chiếu. Không push/merge hoặc lấy log thật trong bước code
   nếu chưa được người dùng yêu cầu tiếp.

## Giới hạn thành phẩm

Issue #2 hoàn tất sẽ chứng minh manifest hợp cấu trúc, không chứng minh detection
hay prevention hoạt động. Các kỳ vọng bằng câu chữ chưa đủ cho engine thực thi:
predicate, mapping provider và tương quan bằng chứng cần thiết kế/review ở bước
sau trước khi engine sử dụng. Không tự động đưa draft scenario vào chạy live.
