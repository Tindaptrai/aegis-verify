# Suricata A — đọc alert đã xuất từ Wazuh

## 1. Bạn đã có gì?

Phần A đọc **một file JSON chứa một document Wazuh**, lấy alert Suricata trong
`_source.data`, rồi chuyển thành `CanonicalEventV2`. Có thêm `provenance` để giải
thích nguồn trường dữ liệu, chế độ IDS do người gọi khai báo và vị trí bằng chứng.

Đây là bộ đọc fixture offline. Không đăng nhập SIEM, không đổi cấu hình pfSense,
không chạy tấn công, không tải log trực tiếp và chưa đưa ra kết luận detection/
prevention. Không cần export thêm để chạy A với mẫu đã có.

Phạm vi Issue #4 **chưa hoàn tất**: trực tiếp EVE JSONL và bản ghi flow thuộc bước B.
Chưa có CLI đánh giá end-to-end; ví dụ bên dưới gọi API Python đã triển khai.

## 2. Đọc kết quả như thế nào?

| Nội dung | Nguồn sử dụng | Vì sao |
|---|---|---|
| Thời gian sự kiện | `_source.data.timestamp` | Thời gian Suricata; không thay bằng lúc Wazuh nhận |
| IP/port nguồn, đích | `data.src_ip/src_port/dest_ip/dest_port` | Không lấy IP agent hoặc tự bù từ `flow` |
| Protocol | `data.proto` | `UDP` khác application protocol `quic` |
| Signature ID | `data.alert.signature_id` | SID của Suricata, mẫu này `2231000` |
| Rule ID | `_source.rule.id` | Rule Wazuh, mẫu này `86601`; không phải SID |
| Severity | `data.alert.severity` | Giữ thang nguồn; không thay bằng Wazuh rule level |
| Action | `data.alert.action` | Hành động ở phạm vi alert rule, không phải verdict cuối |
| Collector | `_source.agent/manager` trong provenance | Máy thu thập không đồng nghĩa máy phát sinh lưu lượng |
| Flow ID | `provenance.flow_id_raw` | Giữ chuỗi chính xác; canonical v2 chưa có trường flow ID |

Mẫu có thời gian nguồn `2026-04-30T00:18:09.338512+0700`, kết quả UTC là
`2026-04-29T17:18:09.338512Z`. Đây là cùng một thời điểm, không sửa ngày log.
Giữ 0–9 chữ số thập phân khi nguồn có; nhiều chữ số không chứng minh đồng hồ chính xác.
`ingested_at` là thời điểm AEGIS đọc file do người gọi cung cấp, không thay thế thời
gian sự kiện. Giờ Wazuh nhận còn trong raw; không lấy chênh lệch hai giờ làm bằng
chứng độ trễ mạng hoặc clock skew khi chưa có kiểm chứng.

Trường tùy chọn thiếu/null → `null`. Trường có nhưng sai kiểu → lỗi, không âm thầm
sửa hoặc bỏ qua. Không đoán hostname, username, technique, process hay danh tính
asset từ IP agent. Chưa gán mẫu này cho SCN-002/INC-002 hay sự cố nào.

### Lưu ý riêng cho lab IDS của bạn

Gọi với `deployment_mode='ids'`. Mẫu `allowed` không có nghĩa lưu lượng là an toàn.
Nếu nguồn ghi `blocked` trong chế độ `ids`, parser **giữ** `blocked` và thêm cảnh báo
`ids_blocked_action_requires_review`; bạn cần đối chiếu cấu hình/log, không tự đổi
thành IPS hoặc kết luận đã ngăn chặn. Giá trị `unknown` dành cho khi chưa xác minh
chế độ, không phải cơ chế tự nhận diện.

Tham chiếu về phạm vi action của Suricata:
[EVE JSON format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html).
Phiên bản tài liệu này không khẳng định phiên bản Suricata đang chạy trong lab.

## 3. Chạy đối chiếu từng bước trong PowerShell

Chạy ở worktree A, **không dùng venv của root hoặc worktree cũ**:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-4-suricata-wazuh-alert'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
```

Nếu clone sang máy khác: dùng Python >=3.11, `python -m venv .venv`, rồi
`& '.\.venv\Scripts\python.exe' -m pip install -e '.[test]'` ở đúng checkout.
Không đặt `python` trước đường dẫn `python.exe`: file `.exe` không phải script Python.

Sau đó dán **nguyên khối** dưới đây vào PowerShell. Nó chỉ đọc fixture và in ra màn
hình, không ghi đè file, không kết nối hệ thống. Dấu `@'` và `'@` phải ở dòng riêng.

```powershell
@'
from datetime import datetime, timezone
from pathlib import Path
from aegis_verify.connectors.suricata import load_suricata_wazuh_document

path = Path('tests/fixtures/suricata/suricata-wazuh-alert-001.sanitized.json')
result = load_suricata_wazuh_document(
    path,
    source_ref=path.name,
    environment_id='unit-lab',
    ingested_at=datetime.now(timezone.utc),
    deployment_mode='ids',
)
print(result.event.model_dump_json(indent=2))
print(result.provenance.model_dump_json(indent=2))
assert result.event.timestamp.isoformat() == '2026-04-29T17:18:09.338512Z'
assert result.event.signature_id == '2231000'
assert result.event.rule_id == '86601'
assert result.event.raw_event_hash == '9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c'
assert result.event.event_id == 'suricata:evidence-v1:559e130f8ef34149bad4588114937637a06784d9e14361d30fcda44c426593e0'
assert result.provenance.flow_id_raw == '100000000000001.000000'
assert result.provenance.warnings == ()
print('Sample comparison passed')
'@ | & '.\.venv\Scripts\python.exe' -
```

`unit-lab` ở đây là nhãn kiểm thử cố định để đối chiếu ID; khi xử lý evidence của
môi trường khác, truyền nhãn môi trường phù hợp. Không đưa token/IP vào nhãn.

## 4. Bằng chứng và lỗi

SHA-256 tính trên **nguyên byte file đã sanitize**, kể cả BOM/newline và trường
không được map. `raw_event_ref` mẫu là
`suricata-wazuh-alert-001.sanitized.json#L1-L92`: tham chiếu cả wrapper, không giả làm
một dòng EVE gốc. Caller phải lưu lại đúng file cùng provenance; parser không tự
chép hay bảo quản evidence. Hash kiểm tra tính toàn vẹn, không chứng minh tính xác thực.

ID gồm hash bytes, `environment_id`, `source_ref`, record index cố định 1 và nhãn
phiên bản identity. Cùng file/context nhưng đổi thời điểm ingest hoặc chế độ IDS
thì ID không đổi; đổi bytes/tên nguồn/môi trường thì đổi. A và B chưa có dedup liên
nguồn, vì hai bản export có thể biểu diễn cùng event bằng bytes khác nhau.

`source_ref` là nhãn ASCII an toàn dài 1–128 ký tự, không phải đường dẫn tùy ý.
`environment_id` không trắng, tối đa 128 byte UTF-8. File tối đa 256 KiB, depth20,
10.000 node, numeric token128. Chỉ nhận một object, không nhận mảng/search-response,
JSONL, CSV hay bare `_source`. Không nối nhiều JSON bằng tay rồi đưa vào A.

`SuricataParseError.diagnostic` chỉ có mã lỗi, đường dẫn trường cố định, record index
và vị trí cú pháp khi có. Không trả nội dung log/tên khóa lạ/đường dẫn ổ đĩa trong
thông báo lỗi. Ví dụ `unsupported_profile` cho flow hoặc log không có marker
Suricata; `missing_event_time` khi thiếu thời gian; `invalid_field` khi port sai.
Loader có quyền đọc file mà tiến trình có quyền đọc, không phải một filesystem sandbox.

Mẫu raw gốc không nằm trong Git. Bản derivative thay 14 giá trị định danh, bỏ 3
trường packet/payload; xem manifest trong `tests/fixtures/suricata/README.md`.
Không sửa dữ liệu gốc để làm test xanh. Nếu sau này chỉnh sanitize, tạo derivative
có provenance mới và hash tương ứng; không giữ hash cũ cho bytes mới.

## 5. Ngày mai làm B: cần gì và làm ra sao?

A tách adapter Wazuh khỏi mapping Suricata, nên có thể thêm B mà không bỏ A.
B chưa được triển khai hoặc tự hẹn chạy. Khi bạn quay lại, bước đầu là xem mẫu,
chốt hợp đồng rồi mới code.

Bạn chuẩn bị nếu lấy được:

1. **1–3 dòng EVE JSON alert gốc** từ Suricata và **1–3 dòng flow** liên quan nếu có.
   Ưu tiên cùng `flow_id`, giữ timestamp/IP/port nhất quán. Thiếu flow thì nói thiếu,
   không tự ghép hay tạo log. Wazuh export vẫn dùng được cho A nhưng không chứng minh
   định dạng direct EVE. Nếu bị chặn export/quyền đọc, dừng và báo mình; không cần
   đổi cấu hình hoặc vượt quyền chỉ để lấy mẫu.
2. Phiên bản Suricata, interface được theo dõi, múi giờ và xác nhận IDS/IPS nếu biết.
   Không cần mật khẩu, token, certificate, toàn bộ packet capture hay cấu hình hệ thống.
3. Rà soát dữ liệu nhạy cảm trước khi chia sẻ. Trường `packet`, `payload`,
   `payload_printable` có thể chứa bytes nhạy cảm dù IP ngoài đã đổi. Giữ bản gốc
   riêng; không push file chưa sanitize. Mình kiểm tra/sanitize derivative trước Git.

Sau khi có mẫu, mình làm theo thứ tự:

1. So sánh kiểu trường Wazuh với direct EVE; chốt alert/flow được hỗ trợ, bản ghi
   khác skip hay reject, lỗi theo dòng và giới hạn JSONL.
2. Chốt cách biểu diễn flow identity cho downstream. A hiện giữ trong provenance;
   nếu cần đưa vào canonical, phải có thay đổi hợp đồng/version và test riêng được
   bạn duyệt, không lén thêm trường. Giữ nguyên v2 cho A.
3. Viết fixture và test trước; thêm adapter direct EVE, dùng lại phần mapping phù
   hợp. Không bắt direct EVE phải có `_source.rule.groups` hoặc metadata Wazuh.
4. Kiểm tra line-level evidence, hash, alert/flow correlation, thiếu trường, dữ liệu
   sai và hồi quy A. Không dedup chéo A/B khi chưa thiết kế identity rõ ràng.
5. Review độc lập → bạn đối chiếu log/lab → mới đề nghị merge và đánh giá đầy đủ
   acceptance criteria Issue #4.

CSV và connector live vẫn là scope riêng. A không khóa khả năng thêm chúng, nhưng
CSV chỉ map được những cột export thực sự giữ lại; không tái tạo trường bị mất.

## 6. Bạn cần gửi lại gì sau A?

Gửi output pytest, `pip check`, và xác nhận kết quả ví dụ khớp mẫu/IDS của bạn.
Không cần gửi lại log thô hoặc mật khẩu. Chỉ sau human review/lab comparison và
yêu cầu của bạn mới push/merge. Test pass không đồng nghĩa đã validate hệ thống thật.
