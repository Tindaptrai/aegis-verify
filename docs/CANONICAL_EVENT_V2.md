# Canonical Event v2.0 — thời gian không mất chữ số

Issue #15. Đã triển khai trên nhánh riêng; cần người dùng review trước merge.

## Đọc nhanh: thay đổi này giúp gì?

V1 dùng `datetime`, giữ tối đa 6 chữ số sau dấu chấm (microsecond).
V2 dùng `PreciseTimestamp`, giữ tối đa 9 chữ số (nanosecond). Cả `timestamp`
và `ingested_at` đều được chuẩn hóa UTC mà không cắt hoặc làm tròn phần dư.
JSON vẫn là chuỗi, không phải số lớn có thể mất độ chính xác trong JavaScript.

Ví dụ nhân tạo: `2026-01-02T03:04:05.123456789+07:00` trở thành
`2026-01-01T20:04:05.123456789Z`, giữ đủ `123456789`.

Đây là hợp đồng dữ liệu, **chưa phải Wazuh parser, CSV importer hoặc engine**.
Chưa cần lấy thêm log hoặc chạy tác vụ trên SIEM để test Issue #15.

## V1 vẫn dùng được

`CanonicalEvent` vẫn là v1.0, vẫn dùng aware `datetime`, vẫn mặc định version
`1.0` khi gọi constructor. Không đổi alias sang v2 và không nới regex v1.
`CanonicalEventV2` là API mới, mặc định version `2.0` khi caller chọn nó.
Mỗi model từ chối version của model còn lại.

Các field ngoài thời gian dùng chung validation: required evidence ID/reference/
SHA-256, enum, IP, port, các optional field mặc định `null`, frozen, extra forbid.
Xem [hợp đồng v1](CANONICAL_EVENT.md) cho ý nghĩa các field không đổi.
Thứ tự key JSON không phải hợp đồng; không dùng JSON canonical làm raw evidence.

## API thời gian chính xác

```python
from aegis_verify.models import PreciseTimestamp

a = PreciseTimestamp.parse("2026-01-01T00:00:00.123456788Z")
b = PreciseTimestamp.parse("2026-01-01T00:00:00.123456789Z")
assert b.difference_ns(a) == 1
assert a < b
assert b.isoformat() == "2026-01-01T00:00:00.123456789Z"
assert b.fractional_digits == 9
assert b.nanosecond == 123456789
```

- `parse(str | datetime | PreciseTimestamp)` là cách tạo value; không tạo bằng components.
- `epoch_nanoseconds` trả số nguyên Python chính xác, kể cả trước epoch hoặc ngoài int64.
- `isoformat()` xuất UTC `Z`, giữ số chữ số ban đầu, kể cả số 0 ở cuối.
- Equality, ordering, hash so **thời điểm**: `.1Z` bằng `.100Z`, nhưng chuỗi xuất khác.
- Không tự so sánh thứ tự với `datetime`, chuỗi hoặc số; hãy parse rõ ràng trước.
- `to_datetime_exact()` chỉ chuyển nếu phần nanosecond chia hết cho 1000;
  nếu không, báo `ValueError`, tuyệt đối không cắt/làm tròn.
- Aware `datetime` đầu vào giữ phần microsecond sẵn có và xuất 6 chữ số;
  không thể phục hồi chữ số đã mất trước lúc truyền vào.
- Value bất biến và hỗ trợ copy/deepcopy. Python reflection không phải ranh giới bảo mật.

Định dạng nhận: ASCII `YYYY-MM-DDTHH:MM:SS[.1..9 chữ số](Z|+/-HH:MM)`.
Năm local và UTC đều trong 0001..9999; kiểm tra lịch thật và chuyển ngày khi đổi UTC.
Không nhận `-00:00`, naive datetime, epoch number, Unicode digits, khoảng trắng dư,
chữ thường t/z, leap second, 24:00 hoặc quá 9 chữ số. Offset tối đa 23:59.
JSON Schema có `type: string`, `format: date-time`, pattern; pattern không thay thế
kiểm tra lịch/range ở runtime. Consumer dùng format checker riêng có thể chặt hơn.

**Giữ 9 chữ số không chứng minh đồng hồ nguồn chính xác tới nanosecond.** Nó chỉ
không làm mất dữ liệu đã nhận. Không sửa thời gian nguồn để khớp một kết luận.

## Đọc dữ liệu có version

```python
from aegis_verify.canonical_io import (
    parse_canonical_event, parse_canonical_event_json, upgrade_canonical_event,
    CanonicalReadError,
)

# Dữ liệu unit-test nhân tạo, không phải incident evidence.
data = {
    "schema_version": "2.0",
    "event_id": "unit-event",
    "timestamp": "2026-01-01T00:00:00.123456789Z",
    "ingested_at": "2026-01-01T00:00:01Z",
    "source_type": "wazuh",
    "environment_id": "unit-lab",
    "raw_event_ref": "unit-only/record:1",
    "raw_event_hash": "a" * 64,
}
event = parse_canonical_event(data)
wire = event.model_dump_json()
assert parse_canonical_event_json(wire).timestamp.nanosecond == 123456789
assert event.model_dump()["timestamp"] is event.timestamp  # Python mode
assert event.model_dump(mode="json")["timestamp"] == data["timestamp"]
```

Reader bắt buộc `schema_version` là chuỗi `1.0` hoặc `2.0`; thiếu, null hoặc lạ
đều lỗi. Không đoán version theo độ dài timestamp, không tự upgrade. Dict reader
chỉ nhận JSON-like: không datetime, IP object, tuple/set hoặc custom object.
Các kiểu Python tương thích đó dùng trực tiếp model constructor phù hợp.

Policy reader (không thay đổi constructor v1):

- JSON UTF-8 strict, root object, không duplicate key (kể cả key escape tương đương).
- Wire tối đa 1 MiB; dict cũng giới hạn kích thước JSON UTF-8 compact tương đương.
- Tối đa 32 container, tính root là 1; ngoặc trong chuỗi không tính.
- Numeric token tối đa 128 ký tự, không NaN/Infinity hoặc float overflow.
- UTF-8 kiểm tra cả key/value, từ chối cycle; shared subtree được duyệt với budget
  tính mỗi lần xuất hiện để không cho phép payload mở rộng vô hạn.
- Không đọc/ghi file, không mutate dữ liệu input.

Lỗi `CanonicalReadError` cung cấp `code` và `field_path` là tên field cho phép hoặc
`None`. Các code: `invalid_json`, `input_too_large`, `input_too_deep`,
`invalid_number`, `unsupported_version`, `invalid_event`, `invalid_upgrade`.
Không có raw value, key lạ hoặc exception gốc trong thông báo lỗi công khai.
Không log Pydantic `errors()`/`json()` kèm input; không bật traceback locals cho
evidence nhạy cảm. Giới hạn reader không áp dụng khi gọi thẳng model_validate_json;
dùng reader cho ranh giới nhận dữ liệu không tin cậy.

## Nâng cấp v1 chủ động

`upgrade_canonical_event(old_v1)` revalidate v1 trước khi serialize, kể cả object
tạo qua `model_copy`/`model_construct`. Hàm trả v2 mới, giữ non-time fields,
evidence ID/reference/hash và null; không sửa object/file gốc.

Hàm chỉ giữ biểu diễn còn có trong v1, không lấy lại được độ rộng/chữ số đã mất.
Đây là chuyển đổi model-to-model, không áp dụng budget dành riêng cho reader;
v1 không serialize/validate hợp lệ sẽ bị từ chối. Không có API downgrade v2 -> v1.

## Trường thêm sau v2.0: `session_key`

Từ SCN-003 (#76), cả v1 và v2 có thêm trường tuỳ chọn `session_key`: khoá tương
quan mờ do connector sinh từ namespace phiên của chính nó, hiện chỉ Cowrie dùng
(`cowrie:session-v1:` cộng SHA-256 hex). Giá trị mặc định `null`, không đổi
`schema_version`, không tham gia evidence ID, và không bao giờ chứa định danh
phiên gốc. Engine có thể lọc và join theo trường này nhưng không dùng nó làm
target binding. Xem [CANONICAL_EVENT.md](CANONICAL_EVENT.md).

## Bước tiếp theo

1. Người dùng chạy đối chiếu và review Issue #15; chỉ merge khi được duyệt.
2. Cập nhật thiết kế Issue #3, dùng v2 cho parser fixture Wazuh, giữ systemTime gốc.
3. Kiểm tra fixture đã ẩn danh và evidence hash; sau đó mới đi tiếp engine.

CSV có thể thêm sau bằng adapter nguồn khi cột đủ dữ liệu; CSV thiếu command line,
timestamp gốc hoặc provenance không tự khôi phục được bằng schema mới.
