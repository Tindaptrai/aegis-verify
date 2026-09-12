# Issue #12 — Thiết kế demo vô hại Gap → Fix → Re-test

Ngày: 2026-09-12. Trạng thái: đề xuất, chờ duyệt bản viết trước triển khai.

Base đã xác minh: `bf4852979293a998e169b06d214486465678360e` (merge PR #25).
Branch: `codex/issue-12-safe-demo`. Không thay đổi root checkout.

## 1. Mục tiêu và giới hạn

Hoàn thiện bộ hướng dẫn và công cụ offline cho Issue #12, dùng nguyên
`SCN-001` phiên bản `0.1.0`. Chứng minh một rule phụ thuộc tên file có thể bỏ
sót hoạt động tương đương sau đổi tên, rồi phát hiện lại sau sửa rule.

Không viết malware, tải payload, kết nối mạng từ payload, sửa registry,
persistence, đọc credential, né phòng vệ hoặc phá dữ liệu. Không tự chạy trên
lab, thay policy PowerShell, tắt bảo vệ, bật archives toàn hệ thống hoặc đổi
ground truth. Không thực hiện dashboard, live connector hoặc issue khác.

Kết quả demo chỉ chứng minh khả năng phát hiện hoạt động thử nghiệm được
định nghĩa, không chứng minh phát hiện mọi PowerShell độc hại.

## 2. Lựa chọn

1. **Đề xuất: bộ demo offline, người vận hành chạy lab.** Tái sử dụng parser,
   validation và comparison; minh bạch log và dễ review. Cần người dùng thu
   evidence và xác nhận tính đầy đủ.
2. Demo hoàn toàn synthetic: nhanh, dùng cho CI và diễn tập giao diện, nhưng
   không thay thế bằng chứng vận hành thật của Issue #12.
3. Điều phối lab tự động/live connector: thuận tiện về sau nhưng thêm quyền,
   secret, API và rollback; không thuộc thay đổi này.

Chọn 1, có test synthetic của 2. Không triển khai 3 song song.

## 3. Ba máy, ba trách nhiệm

| Nơi chạy | Trách nhiệm | Không làm |
| --- | --- | --- |
| Máy phát triển Windows | Chuẩn bị kit, test, đóng gói evidence offline, validate/compare | Không tự SSH hoặc gọi SIEM API |
| Windows lab được duyệt | Kiểm tra Sysmon/4104, chạy payload vô hại, ghi manifest lượt chạy | Không chạy trên máy phát triển thay cho lab |
| Wazuh manager Linux | Kiểm tra rule, logtest, người dùng cài từng revision và thu log | Không cài cả hai revision cùng lúc |

Host, đường dẫn, environment ID và rule ID là tham số được kiểm tra và khóa
trước A; không hard-code IP, token hoặc endpoint. Credential không vào kit.

## 4. Payload và ba lượt chạy

Payload ngắn chỉ in marker công khai `AEGIS_SAFE_DEMO_V1` và thông tin của
chính process PowerShell đang chạy. Không liệt kê process khác hoặc dữ liệu
người dùng. Payload không ghi file; runner chỉ ghi manifest vào thư mục mới
do người dùng chọn. Chạy với quyền người dùng thường nếu chính sách cho phép.

Hai bản `lab_update.ps1` và `maintenance_check.ps1` có **cùng toàn bộ bytes và
SHA-256**. Runner từ chối ghi đè file khác nội dung. Dùng PowerShell executable
và cách gọi cố định, không `ExecutionPolicy Bypass`. Nếu bị policy chặn thì
dừng, không tự nới policy. Một lượt chỉ khởi chạy một process thử nghiệm.

| Lượt | Script | Rule revision | Kỳ vọng, không phải kết quả được đặt sẵn |
| --- | --- | --- | --- |
| A | Tên gốc | Baseline phụ thuộc tên file | A01/A02/A03 satisfied |
| B | Tên mới, cùng hash | Cùng baseline | A01/A02 satisfied; A03 false_negative nếu đủ collection |
| C | Giữ nguyên script của B | Fixed không phụ thuộc tên file | Tất cả satisfied; B→C có thể Regression Passed |

Manifest ghi run ID riêng, thời gian UTC start/end, exit code, process ID,
payload hash, revision/hash rule đã được người vận hành xác nhận. Manifest
không thay thế telemetry và không được đưa thành canonical event giả.

Trước A có rehearsal kiểm tra tên trường, đường dẫn/command line thực tế và
đồng hồ. Rehearsal không được quảng bá là baseline. Sau khi khóa profile,
không chỉnh profile giữa A/B/C để ép kết quả đúng.

## 5. Rule và kiểm tra trên Wazuh

Dùng một custom rule ID còn trống trong dải Wazuh khuyến nghị, giữ cùng ID
ở hai revision. Lưu hai XML template riêng; chỉ render/cài một revision vào
một file demo riêng dưới `etc/rules`, không ghi đè default rules/local_rules.
Không đoán parent SID từ tên agent. Chọn parent theo phiên bản/ruleset thực
tế và kết quả `wazuh-logtest` trước khi cài.

Baseline khớp PowerShell 4104 của tên script gốc. Fixed khớp nội dung script
thử nghiệm đã review, ràng buộc provider/channel/EventID, không khớp tên file.
Không dùng marker đơn độc làm điều kiện phát hiện. Nội dung/pattern chính xác
phải được review cùng payload và thử bằng Wazuh PCRE2/logtest thực tế.

Đây là **rule dựa trên nội dung hoạt động thử nghiệm, bền hơn trước đổi tên**,
không phải mô hình suy luận hành vi tổng quát. 4104 chứng minh script được
ghi nhận; không tự chứng minh mọi statement đã chạy hoàn tất. Manifest và
output tại endpoint là bằng chứng bổ sung để người review xác nhận thực thi.

Logtest cần: tên gốc+tên mới, marker đơn độc, marker/code chỉ trong comment,
script lành tính khác, sai provider/EventID, thiếu script text và 4104 nhiều
mảnh. Nếu negative control vẫn khớp, không tuyên bố fixed đạt.

Trước cài: xác minh ID không trùng, config đang hợp lệ, alert threshold đủ
ghi cả telemetry và demo detection, không có active response gây block hoặc
hành động tự động vì rule demo. Không tự vô hiệu hóa phòng vệ để đạt điều này.
Nếu không xác nhận được, dừng triển khai lab và xin hướng xử lý.

Lưu config-test/logtest và hash revision. Người dùng thực hiện restart manager
có chủ đích sau config test. Kiểm tra dịch vụ/log sau đó. Rollback chỉ gỡ đúng
file demo đã xác minh hash hoặc phục hồi bản backup tương ứng do kit tạo;
không xóa thư mục rules, không sửa/xóa log. Nếu trạng thái file khác manifest,
rollback dừng để người vận hành xem xét.

## 6. Profile và tương thích comparison

Giữ nguyên scenario, canonical schema và engine. Một profile cố định dùng cho
cả A/B/C, bindings cố định gồm host, đường dẫn executable, hai đường dẫn script
được phép và command lines chính xác đã xác minh trong rehearsal.

- A01: Sysmon Event 1 đúng host, executable và một trong hai command lines.
- A02: PowerShell 4104 đúng host và một trong hai script paths.
- A03: PowerShell record đúng scope script, rule ID demo; correlation tới
  A01 bằng hostname + process ID, cửa sổ thời gian hữu hạn đã khóa.

Tái sử dụng `wazuh-sysmon1-v1` và `wazuh-powershell4104-v1`. A03 và anchor
A01 phải là hai evidence IDs khác nhau. Detection record có thể đồng thời
là telemetry A02; không tạo bản sao alert để có thêm witness.

Đề xuất mỗi cửa sổ đánh giá dài 120 giây, launch sau start 10 giây,
correlation delta từ -5 đến +15 giây. Rehearsal phải xác minh phù hợp; nếu
không, chọn lại một cấu hình chung **trước A**. Không sửa timestamp để khớp.
PID reuse là giới hạn: một process demo/lượt, khoảng thời gian hẹp và review
ProcessGuid/record metadata trong raw evidence; không đổi join engine ngầm.

Giữ scenario/profile fingerprints, environment, bindings và độ dài cửa sổ
bằng nhau. Chỉ run IDs, thời điểm, evidence và collection declarations khác.
Rule SIEM được đổi revision, expected rule ID trong profile không đổi.

## 7. Thu evidence và tính đầy đủ

V0 dùng **export thủ công JSON search results từ Wazuh**, không CSV formatted,
không tự kết nối API. Export query được khóa theo host, hai provider/EventID
hỗ trợ và cửa sổ thu thập bao phủ lượt chạy; **không lọc theo expected rule ID**.
Thu cả các trang của cùng snapshot truy vấn nếu có nhiều trang. Nếu không
xác nhận được pagination/snapshot hoặc totals, collection giữ unknown.

Công cụ offline chỉ tách các search hits đã có `_source` thành input documents;
không tạo event từ manifest, không sửa field/timestamp, không chuyển manager
alerts JSONL thành Wazuh hit ngầm. Lưu export gốc bất biến và sidecar nối mỗi
document tới export SHA-256 + vị trí hit + index/ID. Hash của document được
parse và hash export gốc là hai lớp khác nhau, không đánh đồng.

Từ chối duplicate keys/hits, malformed JSON, hit thiếu metadata bắt buộc,
trang trùng hoặc không chứng minh được quan hệ với cùng export. Ghi rõ số
input/hit/document; giới hạn của intake hiện tại vẫn áp dụng. Không cắt bớt
để vừa 100 files hoặc giới hạn report. Nếu vượt, dừng và thu lại một lượt
ngắn/gọn hơn theo thiết kế được duyệt, không bỏ evidence trong lượt cũ.

4104 chỉ hỗ trợ message 1/1 có script text. Nếu log phân mảnh hoặc input
không được parser hỗ trợ, dừng evaluation bundle; không lặng lẽ bỏ record.

Chỉ người vận hành được xác nhận `complete_for_scope` sau khi kiểm tra:

1. Agent, Sysmon, PowerShell logging và manager hoạt động xuyên suốt window.
2. Telemetry và expected detection nếu phát sinh đều có đường tới index đang
   truy vấn; threshold/filter/retention không loại chúng.
3. Đợi ingestion hoàn tất; kiểm tra errors/backlog và đối chiếu bản ghi
   endpoint với manager/index. Nếu không có cơ sở xác nhận hết delay thì unknown.
4. Export đủ hits, không sampling/truncation/gap, scope/timezone đúng.
5. Đồng hồ đủ chính xác cho correlation và toàn window được coverage bao phủ.

Các kiểm tra là **operator attestation**, không phải chứng minh toán học rằng
pipeline không mất log. Tham chiếu checklist/bằng chứng vận hành trong trường
reference. Tool có thể tính fingerprints từ dữ liệu đã chọn nhưng không tự
đặt các cờ assurance true; mỗi lượt xác nhận riêng, không copy declaration.

Nếu không đạt thì vẫn demo được telemetry nhưng kết quả gap phải Inconclusive
hoặc Missing telemetry; không gọi đó là false negative hoặc Regression Passed.

## 8. Kết quả và truy vết

Dùng nguyên `aegis validate` và `aegis compare`. Report giữ evidence IDs,
raw_event_ref và hash. Sidecar export bổ sung đường truy từ document tới bản
export gốc. Không sửa verdict JSON. `Regression Passed` chỉ khi engine/compare
hiện có chấp nhận B là gap đủ bằng chứng, C đạt toàn bộ và không có unknown.

Raw lab exports, manifest chứa định danh thật và report chưa làm sạch nằm
ngoài Git. Bản public là dữ liệu dẫn xuất đã sanitize và ghi nhãn, có hashes
riêng; không giả là nguyên bản. Screenshot được review riêng trước công bố.

## 9. Phần dự kiến thêm và kiểm chứng

- `demos/scn-001/`: payload, Windows runner/preflight, templates và README.
- `detections/wazuh/scn-001/`: hai revision rule template và negative controls.
- `connectors/wazuh/`: helper đóng gói export offline nếu cần code hiểu vendor;
  không đưa logic `_source` vào engine.
- `scripts/`: entry point offline chuẩn bị bundle, manifest và báo kiểm tra.
- `tests/fixtures/demo/scn-001/`: synthetic A/B/C và case không đủ evidence,
  nhãn synthetic rõ ràng, không chép raw lab vào repository.
- `backend/tests/`: tests cho packaging, validation profile, comparison và
  validation đầu vào; kiểm tra runner/manifest theo nền tảng có sẵn.
- `docs/DEMO.md`, hướng dẫn operator tiếng Việt và checkpoint Issue #12.

Ma trận bắt buộc: A/B/C dự kiến; đủ telemetry nhưng collection unknown;
thiếu Sysmon/4104; wrong host/PID/path/rule/time; PID null; fragmented 4104;
same-ID witness; window không bao hết correlation; đổi profile/bindings;
duplicate/malformed/oversized/truncated export; hash mismatch; path traversal;
output tồn tại/symlink; payload hai tên khác hash; evidence trace qua export.

Viết test trước hành vi mới. Chạy tests liên quan, toàn bộ `backend/tests`,
`pip check`, `git diff --check`; báo skip/giới hạn đúng thực tế. Test Python
không thay Wazuh logtest hoặc execution test trên Windows lab.

## 10. Điểm dừng và bàn giao

Bản thiết kế này cần người dùng duyệt trước implementation plan/code. Sau
đó có thể viết kit và test synthetic ngay trên máy phát triển. **Cài rule và
chạy lab chỉ sau preflight, review payload/rule và xác nhận của người dùng.**

Thông tin cần người dùng cung cấp đầu tiên: phiên bản Wazuh manager, custom
rule IDs đang dùng và kết quả config test. Không cần mật khẩu/token hay toàn
bộ cấu hình. Sau đó hướng dẫn kiểm tra parent rule/active response/collection
theo đúng phiên bản, từng bước; không bắt người dùng tự đoán các điều kiện.

Chưa push/merge/đóng Issue #12 tự động. Hoàn thành kit không đồng nghĩa hoàn
thành lab demo; chỉ đóng sau human review và A/B/C có evidence hợp lệ.

## Nguồn đối chiếu

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
  — dải ID custom, vị trí rule và áp dụng thay đổi.
- [Wazuh logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
  — kiểm tra decoder/rule, không thay thế alert thu thật.
- [Wazuh analysisd](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html)
  — version và configuration test.
- [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
  — threshold ảnh hưởng alerts được ghi lại.
