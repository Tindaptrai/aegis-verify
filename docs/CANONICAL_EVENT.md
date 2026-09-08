# Canonical Event v1.0 — dữ liệu chung của AEGIS

V1 vẫn giữ nguyên API microsecond. Xem [Canonical Event v2.0](CANONICAL_EVENT_V2.md)
cho thời gian tối đa 9 chữ số, reader có version và nâng cấp chủ động v1 -> v2.

Canonical Event là hợp đồng dữ liệu dùng chung cho bốn connector. Model kiểm tra
cấu trúc và kiểu dữ liệu; việc kết luận một scenario được phát hiện hay ngăn chặn
thuộc validation engine ở Issue #7.

## Cài đặt và chạy test

Chạy tại thư mục checkout của nhánh chứa Issue #1:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest backend/tests -q
.\.venv\Scripts\python.exe -m pip check
```

Python yêu cầu >=3.11; phiên bản kiểm chứng trong buổi này là 3.13.14.
Pydantic 2.13.5 là dependency runtime để validate, serialize và xuất JSON Schema.
pytest 9.1.1 chỉ dùng để test. setuptools hỗ trợ cài package từ backend/app;
SHA-256 dùng hashlib có sẵn. Hai dependency trực tiếp được pin phiên bản;
đây chưa phải lockfile toàn bộ dependency bắc cầu.

Package Python tên `aegis_verify`, source nằm trong `backend/app/`. Cài editable
giúp Python tìm đúng package mà không chỉnh PYTHONPATH thủ công.

## Trường bắt buộc

| Trường | Kiểu và ý nghĩa |
| --- | --- |
| `schema_version` | Chuỗi `1.0`, có giá trị mặc định; từ chối phiên bản khác |
| `event_id` | Chuỗi không rỗng, ID được future result `evidence_ids` tham chiếu |
| `timestamp` | Thời điểm sự kiện, có múi giờ, chuẩn hóa UTC |
| `source_type` | `wazuh`, `suricata`, `pfsense` hoặc `cowrie` |
| `environment_id` | Chuỗi không rỗng, định danh môi trường do bên gọi cung cấp |
| `raw_event_ref` | Chuỗi không rỗng, tham chiếu dòng/bản ghi đã làm sạch |
| `raw_event_hash` | SHA-256 của đúng bytes bản ghi đã làm sạch, 64 ký tự hex thường |
| `ingested_at` | Thời điểm thu nhận do bên gọi cung cấp, có múi giờ, chuẩn hóa UTC |

Ngoài schema_version, model không tự tạo các trường này. Connector phải cung cấp
ID ổn định khi đọc lại cùng nguồn, phân biệt được môi trường và vị trí record.
Hash không thay thế event_id: hai dòng trùng nội dung có thể cùng hash.

## Trường tùy chọn

Các trường bị thiếu hoặc được truyền `None` sẽ xuất JSON là `null`.

| Nhóm | Trường | Quy tắc |
| --- | --- | --- |
| Nguồn gốc | `source_record_id`, `event_provider` | Chuỗi nguồn cung cấp; provider là công cụ tạo event gốc |
| Tài sản/người dùng | `asset_id`, `hostname`, `username` | Chuỗi, không suy đoán từ IP hoặc nguồn khác |
| Địa chỉ | `src_ip`, `dst_ip` | IPv4/IPv6 dạng text hoặc đối tượng ipaddress; từ chối số, hostname và CIDR |
| Cổng | `src_port`, `dst_port` | Số nguyên 0–65535; từ chối bool, số thực và chuỗi số |
| Giao thức | `protocol` | Chuỗi nguồn đã chuẩn hóa, không đoán từ cổng |
| Tiến trình | `process_name`, `parent_process_name`, `command_line` | Chuỗi; giữ nguyên nội dung và khoảng trắng |
| Process ID | `process_id` | Số nguyên không âm; giá trị 0 được giữ nguyên |
| File | `file_path`, `file_hash` | Chuỗi nguồn cung cấp; không giả định thuật toán file_hash |
| Rule/signature | `rule_id`, `signature_id` | Chuỗi; parser chuyển ID số tường minh trước khi tạo model |
| Hành động | `event_action` | Enum bên dưới hoặc null; không có mặc định observed |
| Mức độ | `severity` | Số nguyên không âm theo nguồn; chưa phải thang điểm chung giữa công cụ |
| ATT&CK | `technique_ids` | Danh sách chuỗi không rỗng do nguồn/mapping đã review cung cấp; không tự map |

`event_action` nhận: `observed`, `allowed`, `blocked`, `redirected`, `login`,
`command`, `other`. `detected` và `prevented` là kết luận của engine, không phải
giá trị thay thế cho hành động nguồn trong model này.

Ví dụ Sysmon đi qua Wazuh: source_type là `wazuh`, event_provider có thể là
`Microsoft-Windows-Sysmon`. Model không giới hạn provider thành một danh sách cố định.

technique_ids lưu bằng tuple bất biến trong Python, xuất thành array trong JSON.
`null` nghĩa là chưa có thông tin mapping; `[]` giữ một danh sách trống được bên gọi
cung cấp. Không nhận set hoặc tự sắp xếp/deduplicate làm thay đổi thứ tự nguồn.

## Quy tắc xử lý

- Từ chối field lạ: connector giữ trường riêng của vendor trong raw evidence.
- Text tùy chọn và scope ID của IPv6 phải mã hóa được thành UTF-8. Surrogate
  đơn lẻ (ví dụ `\ud800` được `json.loads()` chấp nhận) bị báo ValidationError
  ngay khi tạo model, trước bước xuất JSON. Không tự xóa/thay ký tự lỗi; tiếng Việt,
  emoji, dấu tổ hợp, khoảng trắng và chuỗi rỗng hợp lệ được giữ nguyên.
- Nhận RFC 3339 dạng `2026-09-05T22:30:00+07:00` hoặc aware datetime; xuất UTC.
- Text timestamp phải có giây, `T`, `Z` hoặc offset `+/-HH:MM`, tối đa 6 chữ số
  thập phân. Từ chối epoch số, ngày không có giờ, giờ không có múi giờ, offset
  `-00:00` không xác định và giá trị vượt phạm vi UTC biểu diễn được.
- Nguồn có timestamp khác định dạng phải được parser chuyển đổi tường minh;
  timestamp gốc luôn còn trong raw evidence. Chưa hỗ trợ độ chính xác nanosecond.
- Model không so sánh timestamp với ingested_at để suy diễn clock skew.
- Model frozen: không gán lại trường sau validation. Muốn đổi, validate một bộ
  dữ liệu mới. Pydantic `model_construct()` và `model_copy(update=...)` có thể bỏ
  qua validation; không dùng chúng cho dữ liệu không tin cậy.
- Không đọc file theo raw_event_ref. Kiểm tra đường dẫn, quyền truy cập, sự tồn tại
  của record và đối chiếu hash thực tế thuộc tầng lưu/đọc evidence sau này.
- Không có trường password hoặc toàn bộ raw payload trong canonical model.
  Tuy vậy command_line/username/file_path vẫn có thể nhạy cảm: model không phải
  bộ làm sạch dữ liệu. Bên thu thập phải làm sạch trước và UI phải escape khi hiển thị.
- ValidationError dạng text không in lại input lỗi. Không log `errors()`/`json()`
  trực tiếp; khi cần diagnostic có cấu trúc, bỏ input/context và review dữ liệu.

## Ví dụ chạy được — dữ liệu nhân tạo, không phải log INC-002

```python
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEvent

raw = b"abc"  # Byte mẫu kiểm thử, KHÔNG phải log từ công cụ an ninh.
event = CanonicalEvent(
    event_id="unit-event-001",
    timestamp="2026-09-05T22:30:00+07:00",
    source_type="pfsense",
    environment_id="unit-environment",
    raw_event_ref="unit-only/record.txt:1",  # Vị trí minh họa; không có file thật.
    raw_event_hash=hash_raw_event(raw),
    ingested_at="2026-09-05T22:31:00+07:00",
)
print(event.timestamp.isoformat())  # 2026-09-05T15:30:00+00:00
print(event.process_name)  # None: không tự thêm tên tiến trình.
print(event.model_dump_json(indent=2))
restored = CanonicalEvent.model_validate_json(event.model_dump_json())
assert restored == event
schema = CanonicalEvent.model_json_schema()
```

Đầu vào như `dst_port=70000` bị từ chối bằng ValidationError có vị trí `dst_port`.
Event hợp lệ chỉ chứng minh hợp đồng dữ liệu được đáp ứng; ví dụ này không chứng
minh firewall đã chặn hay detection nào đã hoạt động.

## Hash tính trên cái gì?

`hash_raw_event(raw_record: bytes) -> str` tính SHA-256 trên đúng bytes được truyền.
Hàm không parse JSON, không bỏ khoảng trắng, không đổi encoding hay newline.
`b"abc"`, `b"abc\n"` và `b"abc\r\n"` có hash khác nhau.

Parser tương lai phải lưu đúng slice bản ghi dùng để tính hash; newline được giữ
trong slice cũng được tính. Giữ nguyên encoding và byte range/record index trong
hồ sơ provenance khi cần. Hash kiểm tra nội dung thay đổi, không chứng minh nguồn
đáng tin hoặc nội dung là sự kiện thật. Schema chỉ kiểm tra định dạng hash.

## Phạm vi bàn giao

Issue #1 có model versioned, enum, kiểm tra đầu vào, serialize/deserialize, xuất
JSON Schema và helper hash. Test hoàn toàn offline, dùng dữ liệu nhân tạo trong
backend/tests, không thêm fixture INC-002. Schema chỉ là data layer đầu tiên;
scenario schema, bốn parser và detection engine còn ở các issue sau.

Tham khảo thư viện: [Pydantic Models](https://docs.pydantic.dev/latest/concepts/models/).
