# SCN-001 — Profile biểu diễn EventChannel, sửa tương thích kit

Ngày 2026-09-13. Phạm vi: kit/rehearsal của Issue #12, chưa phải hoàn thành
Issue #12 hoặc đánh giá A/B/C. Không thay parser, canonical schema, ground
truth, payload, runner hay cấu hình lab bằng bản sửa này.

## 1. Vì sao cần sửa cả baseline và fixed?

Đối chiếu do người vận hành thực hiện cho cùng ScriptBlockId/PID/time:

| Nơi quan sát | Nội dung script | Đường dẫn |
| --- | --- | --- |
| Windows Event 4104 XML | 69 ký tự, 2 LF, đúng payload đã review | Dấu phân cách đơn |
| Wazuh alert sau JSON parse | 68 ký tự, hai lệnh nối bằng một space, không LF cuối | Mỗi dấu phân cách bị nhân đôi |

Tham chiếu: Windows RecordId 5318; Wazuh source record ID
`1789311013.3580073`, ScriptBlockId `a8a885f5-6ef1-41c9-bfce-63482fae3b72`.
Đây là source identifiers người dùng cung cấp, **không phải canonical evidence
IDs** hoặc bundle đã được xác minh đầy đủ. Không đưa raw export vào repository.

Baseline cũ đòi đường dẫn đơn; fixed cũ đòi xuống dòng thực. Synthetic tests
cũ chỉ kiểm tra dạng decoded JSON đã chọn, không bao phủ đường truyền native.
Vì vậy việc chúng pass trên clone không chứng minh tương thích EventChannel.

## 2. Xác minh biến đổi xảy ra trước rule matching

Đã đọc mã nguồn chính thức, pin tag **v4.14.4**, không suy luận chỉ từ ảnh
hiển thị hoặc JSON escape trên dashboard:

1. Agent gọi `win_format_event_string(xml_event)` trước khi gửi Event XML.
   [read_win_event_channel.c](https://github.com/wazuh/wazuh/blob/v4.14.4/src/logcollector/read_win_event_channel.c)
2. Hàm đó đổi từng CR/LF thành space. Với payload LF của kit, hai lệnh trở
   thành cách nhau đúng một space.
   [logcollector.c](https://github.com/wazuh/wazuh/blob/v4.14.4/src/logcollector/logcollector.c)
3. Manager lấy Event XML qua JSON serialization; EventData dùng
   `replace_win_format(..., 0)`, giữ escape và bỏ whitespace cuối, rồi chuyển
   vào JSON decoder. Cách đọc XML giữ backslash trong content.
   [winevtchannel.c](https://github.com/wazuh/wazuh/blob/v4.14.4/src/analysisd/decoders/winevtchannel.c),
   [os_xml.c](https://github.com/wazuh/wazuh/blob/v4.14.4/src/os_xml/os_xml.c)
4. JSON decoder đưa string values vào dynamic fields dùng cho rule; đây
   không chỉ là thao tác trình bày của dashboard.
   [json_decoder.c](https://github.com/wazuh/wazuh/blob/v4.14.4/src/analysisd/decoders/plugins/json_decoder.c)

Code tracing và đối chiếu lab hỗ trợ profile bên dưới; **không thay thế
positive/negative tests của revision mới trên Wazuh thật**.

## 3. Hợp đồng của bản sửa

| Profile | Baseline exact path | Fixed exact text |
| --- | --- | --- |
| `decoded-json-v1` (mặc định cũ) | Native backslash đơn | Hai dòng LF/CRLF, newline cuối tùy chọn |
| `wazuh-eventchannel-4.14.4-lf-v1` (chọn rõ) | Backslash nhân đôi trong giá trị field | Hai lệnh nối một space, không whitespace cuối |

**Cập nhật 2026-09-17 — đã đo trên Wazuh 4.14.4 thật.** Dòng trên đúng nhưng
chưa đủ chính xác; đọc tiếp trước khi dựa vào nó.

Đo trên cặp bản ghi cùng host, cùng PID 7552, cách nhau 0.219 giây trong
`ossec-archive-14.json`: **cả bốn trường** `image`, `parentImage`, `commandLine`
(Sysmon 1) và `path` (4104) đều mang backslash nhân đôi sau decode. Không chỉ
riêng `path`.

Nhưng quy luật **không phải** "nhân đôi mọi backslash". `commandLine` chứa `\"`
— backslash đơn trước dấu nháy. So với giá trị native đọc trực tiếp từ Windows
Event Log, quy luật thật là:

> Giá trị sau decode của một trường string trong `data.win.eventdata.*` bằng
> **dạng JSON-escaped** của giá trị native. Wazuh áp thêm một lớp escaping.

Điều này giải thích đồng thời backslash nhân đôi và quote bị escape. Mọi validator
hoặc rule pattern phải xây theo phép escape này, **không** theo việc đếm backslash:
một quy tắc "mọi backslash phải nhân đôi" sẽ từ chối nhầm `\"`.

**Không suy rộng ra ký tự điều khiển hay non-ASCII.** Chỉ backslash và quote được
đo, trên các trường và profile nêu trên.

Với newline, mục 2 của tài liệu này truy vết rằng agent chuyển CR/LF thành khoảng
trắng trước khi gửi; nếu đúng thì dạng escaped `\n` sẽ không tới nơi. Đó là suy ra
từ truy vết cũ, **chưa đo trực tiếp** ở lượt này, nên không dùng làm cơ sở cho
validator. Ký tự non-ASCII cũng chưa đo: `is_wire_text` từ chối chúng thay vì
chọn giữa dạng UTF-8 nguyên bản và `\uXXXX`, và việc từ chối đó **không** phải
phát biểu về những gì Wazuh phát ra.

Ai cần các trường hợp đó phải đo trước, theo đúng cách đã đo backslash và quote:
đọc lại bản ghi ở cả hai phía, chuyển qua base64, đối chiếu bằng chương trình.

Hệ quả, **đã xử lý**: trước 2026-09-17 study để `canonical_paths` nhân đôi nhưng
`canonical_executable` và `command_lines` giữ dạng native, nên assertion A01 sẽ
không khớp telemetry thật. Study đã được sửa và `Target` nay **từ chối** đúng
trạng thái đó: mọi canonical value phải ở dạng wire, `canonical_executable` phải
bằng `wire_text(executable)`, `canonical_paths` phải nằm trực tiếp trong
`native_directory`, và mỗi `command_lines` phải chứa đúng path của nó.

Số liệu đầy đủ ở `ISSUE_12_SAFE_DEMO_CHECKPOINT.md`, mục "Đối chiếu lại transcript
bằng chương trình"; fixture đối chiếu ở
[field-representation](../tests/fixtures/demo/scn-001/field-representation/README.md).

Profile native chỉ dành cho payload ASCII/LF 69 bytes đã khóa. Không hỗ trợ
mọi script/Unicode/CRLF/phiên bản Wazuh. Không dùng `.*`, `\s+`, optional
escaping hoặc tự dò profile để che mất khác biệt. Path regex vẫn escape toàn
bộ ký tự; nội dung dùng `\A...\z`, không chấp nhận suffix hoặc khoảng trắng
bất kỳ. Guard host/provider/channel/4104/counters 1/1, ID, parent và level 5
được giữ nguyên. Fixed không phụ thuộc tên file.

**Giới hạn mất thông tin:** nhiều source text khác nhau có thể cho cùng chuỗi
đã flatten. Khớp fixed mới chỉ xác nhận **decoded representation**, không
chứng minh bytes nguồn giống nhau hoặc script vô hại. Không đảo ngược chuỗi
để tạo lại evidence. Hash payload, native event, scope và liên kết run vẫn
cần giữ riêng trước khi đưa ra kết luận an ninh. Rule description mới nói
rõ giới hạn này; không tuyên bố malware verdict.

`field_profile` được ghi trong kit manifest và catalog; XML native có comment
profile để review. Đây là metadata bổ sung trong định dạng kit `0.1.0`, không
đổi schema/version của scenario. Runner giữ nguyên và đối chiếu hashes rule;
runner **không tự kiểm tra phiên bản Wazuh hoặc xác nhận profile đang được
nạp**. Giữ kit.json/hash cùng execution manifests để truy lại profile.

## 4. Tests và synthetic fixtures

- Test mới được viết và chạy RED trước khi triển khai profile.
- Hai tên script vẫn cùng bytes/hash; runner không đổi; profile cũ giữ bytes
  rule cũ khi render với cùng bindings.
- Native baseline từ chối single/mixed backslashes, tên khác, regex-like
  path và suffix; fixed từ chối multiline gốc, marker-only, comments, text
  thêm, whitespace thừa, NUL và thay biến.
- Common guards từ chối sai/missing values; unknown/auto profile bị từ chối
  trước khi tạo thư mục. CLI nhận profile rõ ràng.
- 12 synthetic cases dùng đúng biểu diễn profile; catalog ghi
  `decoded_fields_json_not_native_transport`. Chỉ mô phỏng field layer của
  các controls ASCII/LF đã commit, **không phải trình giả lập agent/decoder**.
- Python tests kiểm tra tập regex literal tương ứng, không thực thi PCRE2
  hoặc parent chain của Wazuh. Missing/fragmented vẫn không khớp demo, không
  bị chuyển thành pass/fail của evaluation.

## 5. Bước tiếp theo trên lab — chưa tự thực hiện

1. Người review độc lập xem rule render, guards, profile/lossy boundary và
   negative cases trước khi cài. Không mang adapter rule 60000 từ clone sang
   manager gốc; giữ `windows_eventchannel` của manager gốc.
2. Tạo kit lab mới trong thư mục mới sau khi chốt bindings và inventory.
   ID 117001 hiện đã có baseline trên manager: **không khai báo `none` giả
   hoặc đổi ID để lách guard**. Bộ tạo kit hiện chỉ nhận ID chưa chiếm dụng.
   Cần quy trình thay revision có kiểm tra target/hash được review riêng;
   không chạy lại hướng dẫn tạo/cài mới như thể ID chưa tồn tại.
3. Backup và hash đúng file demo đang áp dụng; giữ kit/lượt rehearsal cũ.
   Test configuration và positive/negative controls đúng tầng dữ liệu.
   JSON controls không tự đi qua native Windows parent trên manager gốc;
   nếu parent không tới thì dừng, không sửa default decoder để ép match.
4. Sau review, chỉ thay đúng file demo đã xác minh, không cài hai revision
   đồng thời. Re-test/restart có chủ đích, rồi rehearsal mới đúng profile.
   Dùng RunId/thư mục mới; không sửa hoặc tái dùng lượt đã hoàn tất.
5. Trước A/B/C chính thức còn cần frozen export/scope/attestation và evaluation
   profile. Không ghép rehearsal cũ với profile mới để gọi Regression Passed.

Không cần bạn tạo thêm log hoặc chạy lại demo ngay khi đọc tài liệu này.
Không tự push/merge. Ngoại lệ execution policy trên endpoint vẫn cần được
khôi phục về trạng thái trước demo khi kết thúc toàn bộ lab, không đổi ngầm
trong lúc đang so sánh các lượt.

## 6. Gói nâng cấp lab đã chuẩn bị ngày 2026-09-14

Sau khi operator xác nhận hash target và tạo backup, đã chuẩn bị một gói
revision riêng từ kit cũ được pin manifest hash, không dùng luồng cấp ID mới
của `prepare_kit` và không thêm flag bỏ qua occupied-ID guard. Đây là bước
chuẩn bị artifact offline cho lần nâng cấp được duyệt, chưa phải tính năng
CLI tự nâng cấp hoặc triển khai remote.

- Đối chiếu 18/18 file kit cũ; sao chép nguyên bytes hai payload và runner.
- Dùng `render_rule` và bộ synthetic controls của profile đã test để render
  lại artifacts, giữ ID/host/parent; review cả hai XML trước bàn giao.
- Kit mới có `preparation_mode=reviewed_revision_upgrade` và `upgrade_from`:
  manifest hash cũ, baseline hash cũ, exact manager target và backup operator
  cung cấp. Đây là provenance khai báo, không phải remote attestation.
- Inventory metadata giữ danh sách lịch sử và thêm ID đang thay thế 117001,
  có ghi rõ không phải kiểm kê mới đầy đủ. Không khai báo ID này còn trống.
- Manifest được ghi cuối sau khi đối chiếu đủ 18 artifact hashes; đọc lại
  và xác minh lần nữa sau khi ghi. Không sửa kit.json bằng cách cập nhật hash
  cho một file chưa review.
- Thư mục endpoint mới là
  `C:\Users\<user>\Downloads\AEGIS-SafeDemo-NativeV1`. Baseline mới ràng buộc
  đường dẫn này. Không dùng script ở thư mục kit cũ với baseline mới.
- Chưa deploy, chưa chạy preflight/Execute. Quy trình thay rule trên manager
  vẫn phải kiểm tra target bằng hash cũ trước write và có rollback.

Gói ở máy phát triển:
`C:\Users\<devuser>\Downloads\aegis-native-upgrade-20260914`.
Các bindings này chỉ dành cho lab đã duyệt; kit không được commit vào Git.
Hash và checkpoint thao tác xem `ISSUE_12_SAFE_DEMO_CHECKPOINT.md`.
