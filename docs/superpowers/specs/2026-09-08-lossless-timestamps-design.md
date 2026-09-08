# Issue #15 — Canonical Event v2 với thời gian không mất độ chính xác

Ngày: 2026-09-08. Trạng thái: thiết kế chi tiết chờ người dùng duyệt trước code.
Issue: https://github.com/Tindaptrai/aegis-verify/issues/15

## 1. Tóm tắt dành cho người dùng

Người dùng chọn mở rộng canonical thay vì cắt phần thời gian của Windows.
Mục tiêu là giữ đủ tối đa 9 chữ số thập phân, chuẩn hóa UTC, đọc/ghi lại không
mất dữ liệu và so sánh được hai thời điểm cách nhau 1 nanosecond.

Đề xuất giữ API CanonicalEvent v1.0 hiện có và thêm CanonicalEventV2 với
schema_version="2.0". V2 dùng kiểu PreciseTimestamp cho cả timestamp và ingested_at.
Đây là phiên bản mới vì kiểu dữ liệu Python của hai trường đổi, dù JSON vẫn dùng
chuỗi thời gian. Không âm thầm làm v1 chấp nhận dữ liệu v2.

Issue #3 chờ hợp đồng này được duyệt/kiểm chứng rồi chuyển sang dùng v2.
CSV là adapter đầu vào khác có thể làm sau khi có mẫu/cột đủ dữ liệu, không cần
thay thiết kế thời gian lần nữa chỉ vì đổi JSON thành CSV.

## 2. Hiện trạng và các lựa chọn

CanonicalEvent hiện dùng AwareDatetime và chỉ nhận timestamp text tối đa 6 chữ số.
Các validator khác, enum, required evidence fields và optional null đã có tests.
Chưa có parser/engine/CLI đang dùng timestamp để correlation; thay đổi được giới
hạn ở model, reader/migration, docs và tests, không phải di chuyển kho dữ liệu live.

Các lựa chọn:

- Chỉ nới regex: loại, vì datetime microsecond vẫn có thể làm mất phần dư.
- Thêm trường timestamp phụ bên cạnh datetime cũ: có thể làm nhưng tạo hai giá trị
  cần đồng bộ và dễ khiến consumer tiếp tục so sánh trường đã giảm precision.
- Một kiểu thời gian chính xác trong model v2, giữ v1 riêng: lựa chọn đề xuất.

Không xóa hỗ trợ v1; không sửa fixtures gốc, ground truth, evidence ID hoặc hash.
Không thêm thư viện thời gian mới. Python >=3.11, Pydantic 2.13.5 giữ nguyên.

## 3. Kiểu PreciseTimestamp

Value object bất biến, không phải datetime subclass. Biểu diễn bên trong:

- epoch_seconds: số nguyên giây theo UTC kể từ Unix epoch, theo floor.
- nanosecond: số nguyên 0..999999999 trong giây đó.
- fractional_digits: số chữ số thập phân của biểu diễn input, 0..9.

Hai trường số nguyên xác định thời điểm. fractional_digits giữ độ rộng biểu diễn,
không khẳng định độ chính xác vật lý, độ tin cậy hoặc đồng bộ của đồng hồ nguồn.

### Public interface

- `PreciseTimestamp.parse(value: str | datetime | PreciseTimestamp) -> PreciseTimestamp`.
- `isoformat() -> str`: chuỗi UTC kết thúc Z, giữ số chữ số thập phân đã nhận.
- `epoch_nanoseconds -> int`: epoch_seconds * 1000000000 + nanosecond, số nguyên
  Python, không bị giới hạn int64 và không xuất thành JSON number mặc định.
- `fractional_digits -> int`, `nanosecond -> int`: thuộc tính read-only.
- `difference_ns(other: PreciseTimestamp) -> int`: chênh lệch chính xác có dấu.
- `to_datetime_exact() -> datetime`: chỉ cho phép khi nanosecond chia hết cho
  1000; nếu có phần dư thì ValueError cố định. Không có mode truncate/round.
- Equality, ordering và hash chỉ dựa trên thời điểm, không dựa vào số chữ số.
  So sánh ordering với datetime/str/int không được chuyển đổi ngầm.

Không cho public constructor nhận components chưa validate để tạo object lỗi.
Các factory nội bộ cũng kiểm tra range, kiểu int không bool và tương thích giữa
nanosecond với fractional_digits. Frozen là chống sửa vô ý, không phải sandbox
chống Python reflection hoặc object.__setattr__.

### Nhận input text

- Chỉ chuỗi ASCII theo cấu trúc `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+/-HH:MM)`.
- Year 0001..9999; leap year/calendar kiểm tra thật, không chỉ regex.
- Fraction vắng hoặc 1..9 chữ số; không dấu chấm rỗng, không hơn 9 chữ số.
- Hour 00..23, minute/second 00..59; không leap second, không 24:00.
- Offset hour 00..23, minute 00..59; từ chối -00:00 không xác định.
- Từ chối số epoch, float, bool, bytes, dict/list, naive datetime, timezone không
  xác định, whitespace dư, chữ thường t/z, Unicode digits và năm mở rộng.
- Chuẩn hóa offset sang UTC không mất nanosecond; cả input local date và UTC
  result đều phải trong range năm 0001..9999.
- Không đoán múi giờ, không tự lấy giờ hiện tại.

Dùng datetime/date chỉ cho calendar và phần giây nguyên/offset. Phần nanosecond
được tách trước và xử lý bằng integer; không đưa chuỗi 7..9 chữ số qua parser
datetime rồi kỳ vọng lấy lại phần dư. Không dùng timestamp()/float/total_seconds()
cho phép tính giữ độ chính xác. Các ngày trước epoch cần floor nhất quán.

### Nhận aware datetime

Đây là đường tương thích cho caller đã có datetime, không phải đường đọc log
high precision. Chuẩn hóa UTC bằng arithmetic chính xác của datetime, chuyển
microsecond thành nanosecond bằng nhân 1000, fractional_digits=6.
Không thể phục hồi dữ liệu đã mất trước khi caller truyền datetime.
Naive/utcoffset=None hoặc normalization ngoài range bị từ chối.

### Serialize và so sánh

Ví dụ dưới đây là dữ liệu unit-test nhân tạo, không phải log lab:

- `2026-01-02T03:04:05.123456789+07:00` -> `2026-01-01T20:04:05.123456789Z`.
- `.1Z` vẫn là `.1Z`, `.100Z` vẫn là `.100Z`; hai biểu diễn cùng thời điểm nên
  bằng nhau khi so sánh và có cùng hash, nhưng giữ khác biệt độ rộng khi serialize.
- `.123456789Z` và `.123456788Z` khác nhau đúng 1 ns.
- `1969-12-31T23:59:59.999999999Z` có epoch_nanoseconds=-1.

Consumer muốn so sánh representation phải so isoformat/fractional_digits,
không dùng equality theo thời điểm để chứng minh hai raw payload giống nhau.
Object equality/hash không thay thế evidence hash SHA-256.

## 4. Canonical Event v1 và v2

- `CanonicalEvent` tiếp tục là model v1.0 với tên import và hành vi cũ.
- `CanonicalEventV2` có schema_version Literal "2.0" mặc định khi caller chọn
  constructor v2 một cách tường minh; timestamp/ingested_at là PreciseTimestamp.
- Các field khác giữ nguyên tên, kiểu, nullable rules, required evidence và
  validation; extra forbid, frozen và hide_input_in_errors giữ nguyên.
- V1 không nhận version 2.0; v2 không nhận version 1.0. Không đổi alias mặc định
  CanonicalEvent sang v2 trong issue này.
- Tách phần fields/validators không liên quan thời gian thành private base dùng
  chung; không copy hai bộ logic rồi để chúng lệch nhau. Regression test v1 là
  cổng kiểm chứng bắt buộc cho refactor này.
- Pydantic python mode trả PreciseTimestamp object; JSON mode trả string UTC.
- Cả model_validate và model_validate_json phải đi qua cùng validation exact,
  không có đường JSON thành datetime để mất precision trước validator.
- PreciseTimestamp được tích hợp Pydantic bằng schema/serializer riêng, không
  bật arbitrary_types_allowed chỉ để bỏ qua kiểm tra kiểu.

JSON Schema cho hai trường: type string, format date-time, pattern ASCII mô tả
cấu trúc và tối đa 9 fractional digits. Ghi rõ range calendar/known timezone và
phạm vi không leap-second; regex không được quảng cáo thay thế calendar validation.
Không xuất epoch nanoseconds thành JSON number để tránh mất số ở JavaScript.

## 5. Reader có version và nâng cấp dữ liệu cũ

Public API dự kiến trong `aegis_verify.canonical_io`:

- `parse_canonical_event(data: dict) -> CanonicalEvent | CanonicalEventV2`.
- `parse_canonical_event_json(raw: str | bytes) -> CanonicalEvent | CanonicalEventV2`.
- `upgrade_canonical_event(event: CanonicalEvent) -> CanonicalEventV2`.

Reader mới yêu cầu schema_version tường minh, chỉ nhận chuỗi 1.0 hoặc 2.0;
missing/null/sai kiểu/version lạ báo lỗi. Không đoán version theo số chữ số thời
gian và không tự upgrade. JSON do model v1 hiện xuất đã có schema_version, nên
đọc được qua reader mới mà vẫn trả model v1.

Code cũ tạo CanonicalEvent từ dict chưa có schema_version vẫn giữ hành vi mặc
định 1.0 như trước; đây là API v1, không phải reader dispatch mới.

JSON reader dùng UTF-8 strict, từ chối duplicate keys, NaN/Infinity và JSON root
không phải object; không đọc file hoặc nguồn vendor. Giới hạn wire input 1 MiB,
độ sâu 32 container, numeric token 128 ký tự; ghi rõ đây là policy reader mới,
không sửa hành vi của các public constructor v1. Preflight depth nhận biết
string/escape trước parse; không đếm dấu ngoặc bên trong text. Kiểm tra finite
number và UTF-8 string/key toàn bộ tree trước dispatch. Dict reader kiểm tra
cấu trúc JSON-like bằng duyệt giới hạn depth, từ chối cycle và không mutate input;
date objects chỉ được dùng qua constructor model, không qua reader wire-data.

Upgrade tường minh:

1. Revalidate model v1 đầu vào để không tin dữ liệu tạo qua bypass API.
2. Dùng representation JSON hiện có của v1, đổi version sang 2.0, validate v2.
3. Giữ nguyên non-time fields, IDs và evidence reference/hash; không sửa file cũ.
4. Chỉ giữ độ chính xác/biểu diễn còn có trong v1. Không thể phục hồi chữ số
   nguồn đã mất trước đây; không thêm số 0 rồi gọi đó là đo chính xác nanosecond.

Không triển khai downgrade v2->v1 trong issue này. Muốn lấy datetime dùng
to_datetime_exact và nhận lỗi nếu giá trị không biểu diễn chính xác được.

CanonicalReadError có code cố định và field path allowlisted, không chứa raw
payload, arbitrary unknown keys, original exception text hoặc input value.
Pydantic model validation giữ định dạng lỗi ẩn input như v1. Không log trực tiếp
errors()/json() có input; caller không được bật traceback locals cho dữ liệu nhạy cảm.

## 6. File và ranh giới thay đổi

- Tạo `backend/app/models/precise_timestamp.py`: exact value, validation,
  serialization, comparisons và Pydantic integration.
- Tạo `backend/app/models/_canonical_fields.py`: fields và validators chung.
- Sửa `backend/app/models/canonical_event.py`: v1 dùng base chung, giữ logic time v1.
- Tạo `backend/app/models/canonical_event_v2.py`: v2 dùng exact time và base chung.
- Tạo `backend/app/canonical_io.py`: dispatch/migration/public reader errors.
- Cập nhật `backend/app/models/__init__.py`: thêm exports, không đổi alias v1.
- Tests: test_precise_timestamp.py, test_canonical_event_v2.py, test_canonical_io.py;
  giữ toàn bộ test_canonical_event.py và tests của Issue #2.
- Docs: CANONICAL_EVENT.md và tài liệu migration v2; README chỉ đổi phần cần thiết.
- Không thay connectors, scenario YAML, evidence bytes/helper hash, engine hoặc CSV.

## 7. Kiểm chứng và acceptance coverage

1. Precision: 0..9 fractional digits, trailing zeros, 1 ns difference, exact
   delta/hash/equality/order, boundary giây/ngày/năm và epoch âm.
2. Calendar/offset: leap day, offset day rollover, min/max year, UTC overflow,
   unknown offset, local naive, leap second và invalid syntax/Unicode digits.
3. Hai trường timestamp/ingested_at: dict/JSON validation, serializer/round-trip,
   JSON Schema, frozen values, invalid constructed components bị từ chối.
4. V1 regression không đổi, unknown versions không lách được reader, v1->v2
   giữ IDs/hash/null/Unicode/IP/process context; không mutate input hay file gốc.
5. Marker nhạy cảm không xuất hiện trong public errors; duplicate/depth/size/
   numeric/Unicode/cycle của reader có lỗi kiểm thử được, không exception leak.
6. Wheel install/import ở môi trường riêng, toàn bộ backend tests và pip check;
   không chỉ chạy các test mới. Human review kết quả trước merge.

Giới hạn: representation chính xác không chứng minh đồng hồ nguồn đúng. Dữ liệu
độ chính xác thấp không thể tạo ra thứ tự chắc chắn ở cấp nanosecond. Engine phải
xử lý ambiguity riêng, không thuộc Issue #15.

## 8. Bàn giao và thứ tự tiếp theo

Người dùng duyệt spec này trước implementation plan/TDD. Sau khi Issue #15 được
kiểm chứng và review, cập nhật spec Issue #3 bỏ toàn bộ floor-microsecond policy,
dùng CanonicalEventV2 và systemTime nguyên độ chính xác. Không tự push/merge.

Đầu ra trong bước này là thiết kế và issue tracking, chưa có implementation hoặc
kết quả test mới. Khi triển khai sẽ chuẩn bị nhánh/môi trường tách biệt với baseline
test, không dùng nhầm editable install đang trỏ tới worktree Issue #1/#2.

Nguồn: AGENTS.md, PRD, ARCHITECTURE, CANONICAL_EVENT và model/tests hiện tại.
[Python datetime](https://docs.python.org/3/library/datetime.html) giải thích giới
hạn microsecond; đây là lý do không chỉ mở regex của model cũ.
