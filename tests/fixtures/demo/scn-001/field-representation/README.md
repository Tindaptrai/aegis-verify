# Field representation fixtures — SCN-001

Hai document Wazuh **viết tay**, test-only, không sinh bởi
`scripts/prepare_scn001_kit.py`. Mục đích là tránh test vòng lặp: bộ fixture
của kit vừa sinh dữ liệu vừa sinh kỳ vọng, nên không thể phát hiện sai lệch
về cách biểu diễn field.

## Phân biệt hai tầng

| Tầng | `sysmon1-single-backslash` | `sysmon1-doubled-backslash` |
| --- | --- | --- |
| Bytes JSON trong file | `C:\\Synthetic\\powershell.exe` | `C:\\\\Synthetic\\\\powershell.exe` |
| Giá trị sau `json.loads` | `C:\Synthetic\powershell.exe` | `C:\\Synthetic\\powershell.exe` |

Escaping trong JSON thô **không** phải là biểu diễn của giá trị. Mọi kết luận
phải nói rõ đang bàn tầng nào. `backend/tests/test_scn001_field_representation.py`
khẳng định cả hai tầng một cách tường minh.

## ĐÃ CÓ CĂN CỨ — 2026-09-17

Câu hỏi bên dưới **đã được trả lời** bằng evidence lab thật, đọc từ
`ossec-archive-14.json` trên Wazuh manager 4.14.4. Cặp bản ghi cùng host, cùng
PID 7552, cách nhau 0.219 giây.

Kết quả: **cả bốn trường** `image`, `parentImage`, `commandLine` và `path` đều
mang backslash nhân đôi trong giá trị sau decode. Quy ước của study **trước lượt
sửa** cho `canonical_executable` và `command_lines` là sai; study đã được sửa và
`Target` nay từ chối dạng native.

Quy luật chính xác **không phải** "nhân đôi backslash": `commandLine` chứa `\"`
với backslash đơn trước dấu nháy. Đối chiếu với giá trị native đọc từ Windows
Event Log cho thấy **giá trị sau decode bằng dạng JSON-escaped của giá trị
native**. Validator phải dựa trên phép escape đó, không dựa trên đếm backslash.

Chi tiết và số liệu đầy đủ ở `docs/ISSUE_12_SAFE_DEMO_CHECKPOINT.md`, mục
"Finding 1 đã xác minh bằng evidence lab". Phần dưới đây giữ lại nguyên trạng
làm bản ghi lịch sử của câu hỏi trước khi có căn cứ.

## Câu hỏi còn treo, chưa có căn cứ (lịch sử, đã được trả lời ở trên)

`docs/SCN001_EVENTCHANNEL_PROFILE.md` ghi rằng profile
`wazuh-eventchannel-4.14.4-lf-v1` có "backslash nhân đôi trong giá trị field".
Quan sát dẫn tới kết luận đó được thực hiện trên `eventdata.path` của bản ghi
4104. Kit hiện chỉ nhân đôi `path`.

`connectors/wazuh/windows_telemetry.py` map `image`, `parentImage`,
`commandLine` từ **cùng** object `data.win.eventdata` với `path`. Điều đó gợi ý
chúng có thể cùng quy ước, nhưng **gợi ý không phải bằng chứng**: chưa có
export Wazuh thật đã sanitize nào để đối chiếu ba trường này cùng lúc.

Vì vậy study **không** bị sửa theo phỏng đoán. Hai fixture ở đây khóa lại hành
vi hiện tại của cả hai khả năng, để khi có export thật:

- Nếu `image`/`commandLine` thật sự nhân đôi → test doubled sẽ là trường hợp
  đúng, và study phải được sửa cùng một lượt có review.
- Nếu chúng giữ backslash đơn → quy ước hiện tại của study là đúng và không
  cần đổi gì.

## Việc cần làm khi có export thật

Lấy một bản ghi Sysmon Event 1 thật đã sanitize từ manager, đối chiếu đồng thời
`eventdata.image`, `eventdata.commandLine` và `eventdata.path` của bản ghi 4104
tương ứng, rồi cập nhật fixture đúng cùng tài liệu. Không suy quy ước của một
trường sang các trường khác.
