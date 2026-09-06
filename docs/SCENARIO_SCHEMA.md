# Scenario YAML v0.1 — đề bài kiểm thử, không phải kết quả

Issue #2 kiểm tra cấu trúc ba manifest đã có, không sửa ground truth, không chạy
scenario và không đối chiếu log. `expected_outcome: prevented` là mục tiêu cần
chứng minh ở bước engine, không có nghĩa firewall đã chặn thành công.

Hợp đồng v0.1 được mô tả trong tài liệu này và JSON Schema sinh từ
`ScenarioManifest.model_json_schema()`. `version` bên trong YAML là phiên bản của
kịch bản, không phải `schema_version` của Canonical Event. V0 chưa có bộ chọn
nhiều phiên bản schema và không tự migrate manifest.
JSON Schema mô tả kiểu và cấu trúc cơ bản, không thay thế các validator Python:
các quan hệ ID/nguồn, cờ an toàn V0 và chính sách YAML vẫn cần đi qua API ở đây.

## Cài đặt và chạy test

Chạy trong checkout chứa Issue #2, với venv thuộc chính checkout đó:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e ".[test]"
& .\.venv\Scripts\python.exe -m pytest backend/tests -q
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -c "import aegis_verify; print(aegis_verify.__file__)"
```

Đường dẫn import cần trỏ tới backend/app của checkout đang test. Venv cũ của
Issue #1 có thể đang dùng editable package ở worktree khác; không dùng nhầm nó.

## Các trường

Trừ `tags`, mọi trường bên dưới đều bắt buộc và không nhận null. Text không ép
kiểu từ số/bytes/bool; không trim, chuẩn hóa Unicode hoặc tự sửa nội dung.

| Trường | Quy tắc |
| --- | --- |
| id | Chuỗi SCN- và đúng ba chữ số ASCII, ví dụ SCN-001 |
| name | Chuỗi không trắng, UTF-8 hợp lệ |
| version | Chuỗi X.Y.Z, mỗi phần không âm, không thêm số 0 đầu; không hậu tố prerelease/build |
| status | Chỉ draft ở V0; không có bước tự phê duyệt |
| description | Mô tả kịch bản, chuỗi không trắng và UTF-8 hợp lệ |
| safety | Object ba trường bên dưới, từ chối field lạ |
| safety.destructive | Boolean false; không nhận 0, "false", no, off |
| safety.authorization_required | Boolean true; không nhận 1, "true", yes, on |
| safety.notes | Ghi chú an toàn, chuỗi không trắng, UTF-8 hợp lệ |
| expected_sources | Danh sách nguồn không rỗng, không trùng |
| expected_outcome | detected hoặc prevented; không phải trạng thái kết quả chạy |
| assertions | Danh sách điều kiện không rỗng; quy tắc bên dưới |
| tags | Danh sách text không trắng, UTF-8 hợp lệ hoặc null; thiếu → null; [] vẫn là [] |

Assertion bắt buộc có `id`, `description`, `source`:

- ID là `<scenario-id>-A<hai chữ số ASCII>`, thuộc đúng scenario cha và không trùng
  assertion khác. Đây là ID do tác giả giữ ổn định, không tự sinh hoặc đánh lại số.
- Description mô tả kỳ vọng về bằng chứng bằng câu chữ. Model chỉ kiểm tra text
  hợp lệ, không đánh giá câu văn đúng/sai và không chuyển nó thành lệnh/predicate.
- Source phải nằm trong expected_sources; mọi expected_source phải được ít nhất
  một assertion tham chiếu.

Nguồn hợp lệ: sysmon, powershell, wazuh, suricata, pfsense, cowrie. ScenarioSource
là enum riêng. Sysmon/PowerShell là nguồn telemetry logic có thể đi qua Wazuh;
không sửa SourceType của CanonicalEvent và không tự map tên provider khi đọc YAML.

Các collection giữ nguyên thứ tự, lưu bằng tuple bất biến trong Python và xuất
array trong JSON. Dữ liệu Python chỉ nhận list/tuple, không nhận set/generator.
Tags trùng được giữ nguyên vì đây không phải định danh assertion/nguồn.

## Cách dùng

Chạy ví dụ Python này từ gốc checkout. Các file dưới scenarios/ là manifest thật
của repo, không phải bản ghi sự kiện hoặc bằng chứng detection:

```python
from pathlib import Path
from aegis_verify.scenario_loader import load_scenario, ScenarioLoadError

for path in sorted(Path("scenarios").glob("*.yaml")):
    try:
        manifest = load_scenario(path)
    except ScenarioLoadError as error:
        print(str(error))
        raise SystemExit(1)
    print(manifest.id, manifest.expected_outcome.value, len(manifest.assertions))
```

Kết quả:

```text
SCN-001 detected 3
SCN-002 prevented 4
SCN-003 detected 4
```

Các giá trị detected/prevented ở đây chỉ được đọc lại từ đề bài.

Có sẵn `parse_scenario_yaml(text: str, *, source_name: str)` khi bên gọi đã có
text. Chỉ dùng `ScenarioManifest.model_validate(data)` cho dữ liệu đã giải mã;
không dùng `yaml.safe_load()` bên ngoài rồi kỳ vọng model phát hiện khóa bị ghi
đè: sau khi YAML biến thành dict, thông tin duplicate keys có thể đã mất.

## YAML được nhận và bị từ chối

- UTF-8 nghiêm ngặt, chấp nhận BOM đầu file; không tự đoán UTF-16/encoding khác.
- Đúng một document, root mapping; không nhận file rỗng, scalar root hoặc list root.
- Từ chối khóa trùng mọi tầng, kể cả dạng quoted/unquoted giải mã ra cùng tên.
- Khóa mapping phải là chuỗi; merge key `<<` bị từ chối kể cả khi được quote.
- Từ chối anchors/aliases, custom tags, Python object tags, binary, timestamp và set.
- Chỉ hỗ trợ standard tags str/bool/int/float/null/seq/map và phải đúng loại node.
  Numeric scalar được giữ là số và bị strict model từ chối nếu trường cần text;
  lỗi chuyển đổi scalar được báo có kiểm soát. Boolean chỉ true/false viết thường.
- Ngày không quote có thể được YAML nhận dạng timestamp và bị từ chối; muốn giữ
  ngày như text, viết chuỗi có dấu nháy. Đây là một profile YAML giới hạn, không
  tuyên bố hỗ trợ trọn vẹn mọi tính năng YAML 1.1 hoặc 1.2.
- Không nội suy biến môi trường, không template, không eval, không đọc file theo
  nội dung manifest và không thực thi bất kỳ lệnh nào.

Giới hạn: 256 KiB UTF-8 bao gồm BOM, độ sâu collection 20 (root mapping = 1),
10.000 nodes tính cả key scalar. Bộ đọc file chỉ đọc tối đa giới hạn + 1 byte;
event stream được kiểm tra trước khi dựng object graph đệ quy. Đây là giới hạn
file cấu hình, không phải chứng minh chống mọi DoS trong môi trường đối kháng.

## Lỗi và dữ liệu nhạy cảm

`ScenarioLoadError` có:

- `source_name`: nhãn truyền vào hoặc đường dẫn file.
- `scenario_id`: ID hợp lệ nếu đã giải mã được root, ngược lại None.
- `diagnostics`: tuple bất biến các ScenarioDiagnostic gồm code, field, line, column.
  Field là tuple tên trường/chỉ số; line/column là vị trí một-based nếu parser có
  cung cấp, ngược lại None. Lỗi model dùng field; lỗi YAML thường dùng dòng/cột.

Mã lỗi chính: input_type, input_size, input_encoding, input_io; yaml_root,
yaml_documents, yaml_duplicate_key, yaml_key, yaml_merge, yaml_alias, yaml_tag,
yaml_tag_shape, yaml_scalar, yaml_depth, yaml_nodes, yaml_syntax; và mã validation
như missing, extra_forbidden, duplicate_assertion_id, assertion_parent,
duplicate_source, undeclared_source, unreferenced_source.

Thông báo công khai không chứa giá trị input, snippet YAML hoặc tên khóa lạ;
khóa lạ thành `<unknown>`. Exception chaining được ẩn khi format traceback.
Không log exception locals, __context__ hay raw ValidationError.errors()/json()
để tránh lộ input. source_name/đường dẫn vẫn có thể nhạy cảm: bên gọi phải chọn
nhãn phù hợp. Bộ đọc không phải bộ làm sạch log hoặc dữ liệu cá nhân.

## Tính bất biến và giới hạn

Manifest, safety và assertion đều frozen, không có API writer. Sửa dict/list đã
đưa vào không làm đổi model; muốn đổi phải tạo dữ liệu mới và validate lại, sau
đó review thay đổi ground truth bằng Git. Không tự ghi đè file nguồn.

Frozen không chống lại mã Python có toàn quyền: model_construct,
model_copy(update=...), object.__setattr__ hoặc chỉnh nội bộ có thể bỏ qua hợp
đồng. Không dùng các đường đó cho input không tin cậy. Bộ đọc không sandbox đường
dẫn: bên gọi quyết định file được phép đọc, tránh thiết bị/pipe/đường dẫn mạng nếu
cần kiểm soát I/O. authorization_required không chứng minh người dùng đã cấp phép.

Chưa có engine, predicate, tương quan log, kết quả Pass/Fail hay live execution.
Các kiểm tra an toàn ở đây không thay thế allowlist và phê duyệt chạy lab.

## Dependency và nguồn tham khảo

Tái sử dụng Pydantic 2.13.5. Thêm PyYAML 6.0.3 để giải mã YAML, vì model không
thực hiện công việc parse đó. PyYAML được subclass trong module riêng; không sửa
resolver toàn cục. SafeLoader là nền tảng, chính sách nghiêm ngặt do AEGIS bổ sung.

- [PyYAML documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [PyYAML 6.0.3](https://pypi.org/project/PyYAML/6.0.3/)
- [PyYAML constructors](https://github.com/yaml/pyyaml/blob/6.0.3/lib/yaml/constructor.py)
