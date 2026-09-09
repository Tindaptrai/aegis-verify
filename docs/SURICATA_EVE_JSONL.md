# Suricata B — đọc file EVE JSONL trực tiếp

## 1. A và B đang ở đâu?

A đọc một JSON export của Wazuh chứa alert Suricata. Bạn đã chạy đối chiếu A đạt
826 tests và dependency check sạch. A có trên nhánh
`codex/issue-4-suricata-wazuh-alert`, chưa merge trong lượt triển khai B này.

B đọc trực tiếp file `eve.json`/`.jsonl`, mỗi dòng là một JSON object. B được xây trên
commit A `f872eb2`, ở nhánh `codex/issue-4-suricata-direct-eve`. Nhánh riêng giúp review
phần B mà không gộp lẫn phạm vi A. Chưa push, merge hoặc đóng Issue #4 trong lượt này.

B hỗ trợ `event_type=alert` và `event_type=flow`. Cùng file có DNS/TLS/HTTP… thì B trả
kết quả `skipped` kèm số dòng/hash và lý do, thay vì mất dấu dòng đó. Kết quả parsed
luôn là CanonicalEventV2; schema, scenario ground truth và engine chưa thay đổi.

## 2. Bốn file của bạn thực sự có gì?

Đã đọc toàn bộ 22.536 dòng; mọi dòng đều là JSON object hợp lệ.

| File/interface | Tổng dòng | Alert đã parse | Flow riêng | Dòng loại khác đã skip |
|---|---:|---:|---:|---:|
| WAN | 56 | 41 | 0 | 15 |
| LAN | 10.598 | 199 | 0 | 10.399 |
| MGMT | 10.697 | 1.411 | 0 | 9.286 |
| DMZ | 1.185 | 0 | 0 | 1.185 |
| Tổng | 22.536 | 1.651 | 0 | 20.885 |

Không có lỗi parser khi đọc hết bốn file. `skipped` là loại event chưa được B map;
không có nghĩa lỗi nguồn hoặc thiếu telemetry của cả hệ thống. DMZ chứa DNS/SSH/
HTTP/fileinfo/TLS, nên 0 alert trong export này không chứng minh IDS không hoạt động.

Điểm cần phân biệt: alert có object `flow` bên trong để mô tả kết nối liên quan,
nhưng nó vẫn là `event_type=alert`. Để kiểm chứng flow reader bằng log thật, cần một
dòng riêng có **`"event_type":"flow"`**. Các file hiện tại không có dòng như vậy.
Flow parser đã có unit tests từ dữ liệu mô phỏng rõ nguồn gốc; lab validation cho
flow vẫn chờ mẫu thật. Chưa đủ điều kiện tuyên bố toàn bộ Issue #4 hoàn tất.

## 3. Các quyết định mapping bạn cần hiểu

**Thời gian:** `timestamp` ở top-level là thời gian của bản ghi. B giữ 0–9 chữ số
thập phân, chuẩn hóa offset sang UTC; không lấy `flow.start/end` thay thế. Hai mốc
flow được lưu riêng trong provenance với độ chính xác nguồn. Timestamp nhiều chữ
số chỉ thể hiện độ phân giải, không tự chứng minh đồng hồ lab chính xác.

**Flow ID:** direct EVE nhận JSON integer, giữ chính xác qua số nguyên Python rồi
lưu chuỗi trong `flow_id_raw`; không chuyển qua float. Không dùng flow ID làm
`source_record_id`, vì nhiều event có thể thuộc cùng một flow. `sensor_id` là nhãn
bạn khai báo cho một instance Suricata; `em0` hay `em1` một mình chưa đủ định danh.
So khớp flow cần environment, sensor và bối cảnh capture/thời gian, không chỉ flow ID.
B chưa làm correlation engine hay dedup chéo A/B.

**Rule/SID:** alert lấy `signature_id` từ Suricata SID. Direct EVE không có Wazuh rule
context nên canonical `rule_id` và `source_record_id` là `null`. Không lấy một field
trùng tên bất kỳ để giả làm Wazuh rule.

**Cổng ICMP:** WAN có log ICMP vẫn mang field `src_port/dest_port`. B giữ giá trị
nguồn trong provenance `source_src_port/source_dst_port`, nhưng canonical ports là
`null` với ICMP/ICMPv6/IPv6-ICMP. `icmp_type/code` được giữ riêng. Với TCP/UDP, cổng
được map bình thường. Không đảo IP/port top-level theo endpoint trong object `flow`:
mẫu LAN có packet direction ngược với flow direction.

**Action và IDS:** alert dùng `alert.action=allowed/blocked`, phạm vi `alert_rule`.
Flow dùng `flow.action=pass/drop`, map thành `allowed/blocked` với phạm vi `flow`;
thiếu action thì giữ `null`. `flow.alerted=true` không tạo ra detection conclusion.
IDS + canonical `blocked` vẫn giữ giá trị nguồn và thêm warning
`ids_blocked_action_requires_review`. Cần evidence khác để kết luận prevented.
Ngữ nghĩa action và flow tham chiếu
[Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html).
Đây là phiên bản tài liệu tham khảo, không phải xác nhận lab đang chạy Suricata 8.0.

**Null và lỗi:** thiếu trường tùy chọn → `null`; có nhưng sai kiểu/range → lỗi có số
dòng và đường dẫn trường cố định. Unknown fields được giữ trong file raw mà
`raw_event_ref` trỏ đến, không chèn tùy ý vào canonical.

## 4. Chạy test đối chiếu B

Dùng venv của worktree B:

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-4-suricata-direct-eve'
$aegisTestTemp = 'build/pytest-user-' + [guid]::NewGuid().ToString('N')
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q --basetemp $aegisTestTemp
& '.\.venv\Scripts\python.exe' -m pip check
```

Nếu chạy clone mới, tạo `.venv` với Python >=3.11 rồi cài `-e '.[test]'`. Không
trỏ editable install của worktree A/root sang B vì có thể làm kết quả đối chiếu nhầm.

## 5. Ví dụ đọc một fixture đã sanitize

Dán cả khối trong PowerShell ở worktree B. Script chỉ đọc và in thông tin chọn lọc:

```powershell
@'
from datetime import datetime, timezone
from pathlib import Path
from aegis_verify.connectors.suricata import parse_suricata_eve_jsonl

path = Path('tests/fixtures/suricata/eve-wan.sanitized.jsonl')
records = parse_suricata_eve_jsonl(
    path.read_bytes(), source_ref='eve-test.jsonl', environment_id='unit-lab',
    sensor_id='sensor-lab-1', ingested_at=datetime.now(timezone.utc), deployment_mode='ids',
)
record, = records
assert record.status == 'parsed'
assert record.event.timestamp.isoformat() == '2026-04-03T14:33:28.714277Z'
assert record.event.signature_id == '2100366'
assert record.event.src_port is None and record.event.dst_port is None
assert record.provenance.icmp_type == 8
assert record.event.event_id == 'suricata:eve-evidence-v1:20168dbad90e2b487b1532ba1d70a0f01416e41789585a8f6930fbcbef6e20f6'
print(record.event.model_dump_json(indent=2))
print('Sample comparison passed')
'@ | & '.\.venv\Scripts\python.exe' -
```

`unit-lab` và `sensor-lab-1` là nhãn test cố định để bạn so ID. Trong lượt ingest thật,
đặt nhãn có ý nghĩa và dùng ổn định cho cùng môi trường/instance Suricata.

## 6. Đếm trên bốn file gốc mà không in nội dung log

Khối dưới chỉ dùng cục bộ, không gửi dữ liệu tới dịch vụ nào. Giữ raw ngoài repo:

```powershell
@'
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from aegis_verify.connectors.suricata import iter_suricata_eve_file, SuricataParseError

folder = Path.home() / 'Downloads' / 'suri'
sources = {
    'suricata-wan-20260910-013635.jsonl': 'lab-pfsense-wan',
    'suricata-lan.jsonl': 'lab-pfsense-lan',
    'suricata-dmz.jsonl': 'lab-pfsense-dmz',
    'suricata-mgmt.jsonl': 'lab-pfsense-mgmt',
}
for filename, sensor in sources.items():
    counts = Counter()
    try:
        for record in iter_suricata_eve_file(
            folder / filename, source_ref=filename, environment_id='lab-local',
            sensor_id=sensor, ingested_at=datetime.now(timezone.utc), deployment_mode='ids',
        ):
            counts[record.status] += 1
        print(filename, dict(counts), 'COMPLETE')
    except SuricataParseError as error:
        print(filename, dict(counts), 'INCOMPLETE', error.diagnostic)
'@ | & '.\.venv\Scripts\python.exe' -
```

Tên sensor ở ví dụ là nhãn caller lựa chọn cho bốn instance; kiểm tra topology trước
khi dùng để correlation. Chưa phải mapping asset/identity của toàn SOC.

## 7. Bằng chứng, streaming và giới hạn

Hai API khác nhau về cách nhận kết quả:

- `parse_suricata_eve_jsonl(bytes, ...)` trả tuple khi toàn bộ input được đọc hợp lệ;
  nếu gặp lỗi, hàm raise và không trả tuple một phần.
- `iter_suricata_eve_file(path, ...)` đọc file theo dòng và yield kết quả dần. Nếu
  dòng sau lỗi, những dòng đã yield vẫn có giá trị, nhưng lượt import phải được
  đánh dấu **INCOMPLETE**. Không dùng số dòng đã parse để tuyên bố toàn file pass.
  Đọc hết iterator hoặc gọi `.close()` khi dừng sớm để đóng file.

Mỗi dòng, kể cả skip/blank, giữ số dòng vật lý và SHA-256 của đúng bytes, bao gồm
newline/BOM nếu có. `raw_event_ref` là `source_ref#Ln-Ln`. Parsed event ID ràng buộc
environment, sensor, source label, số dòng và raw hash. Cùng bytes ở hai dòng là hai
evidence records khác nhau. Ingestion time/mode không làm đổi identity. Không dùng
hash để tuyên bố nguồn đã được xác thực.

Source label phải trỏ tới đúng file được lưu giữ; parser không tạo evidence store.
Fixture đã sanitize là derivative có số dòng mới; manifest liên kết dòng derivative
với số dòng/hash của export gốc. Không sửa file gốc để làm parser/test pass.

Giới hạn: 256 KiB/dòng kể cả newline, 32 MiB/file, 100.000 dòng vật lý; JSON depth20,
10.000 node/dòng, numeric token128. Nhận LF/CRLF và dòng cuối không newline; BOM chỉ
được ở đầu file. Bare CR không phân tách record. Không đọc gzip hoặc JSON mảng trong
API này. Với file lớn hơn giới hạn, cần scope/chunking có provenance riêng, không
tự tăng giới hạn ngầm. Đọc file đang được Suricata ghi tiếp không bảo đảm snapshot;
dùng bản copy đã hoàn tất như các file bạn cung cấp.

## 8. Việc còn lại trước khi đóng Issue #4

1. Bạn chạy đối chiếu test và ví dụ B, xem manifest các mẫu đã sanitize.
2. Bổ sung 1–3 dòng **flow riêng** nếu có để kiểm chứng bộ đọc flow trên lab. Không
   đổi `event_type` của alert thành flow và không xem dữ liệu mô phỏng là log thật.
3. Nếu chưa có flow, lần tiếp theo kiểm tra cấu hình EVE output có ghi loại flow
   hay không; việc thiếu flow trong export hiện tại chưa xác định được nguyên nhân.
   Chưa có thay đổi cấu hình, restart dịch vụ hoặc replay lab nào trong lượt này.
4. Review/push/merge A trước, sau đó B; giữ hai PR nhỏ. Sau khi A merge, cập nhật base
   của PR B về main đã có A. Chỉ đánh giá đóng Issue #4 khi acceptance criteria và
   bằng chứng flow đã được review.

Phần code/test B có thể bàn giao ngay trong khi chờ bước 2. Canonical flow field,
correlation engine, CSV/live connectors và dashboard vẫn là các scope riêng.
