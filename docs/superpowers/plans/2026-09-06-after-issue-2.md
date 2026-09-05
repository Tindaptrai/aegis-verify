# Sau Issue #2 — kế hoạch review và Wazuh fixture

Đây là kế hoạch các bước tiếp theo theo yêu cầu người dùng, không phải lệnh cho
agent tự push/merge hay bắt đầu Issue #3. Issue #3 đã đọc trên GitHub ngày
2026-09-06: https://github.com/Tindaptrai/aegis-verify/issues/3.

## Bước 1 — Người dùng chạy đối chiếu Issue #2

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-2-scenario-yaml-schema'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -c "import aegis_verify; print(aegis_verify.__file__)"
```

Gửi output test và pip check. Đường dẫn import phải thuộc worktree Issue #2,
không phải Issue #1. Không cần gửi mật khẩu, token hay log lab cho bước này.

## Bước 2 — Review, PR và merge Issue #2

- Review diff so với dc09897: schema, YAML policy, public diagnostics và tests.
- Xác nhận ba scenario không đổi; hiểu rõ description chưa phải predicate.
- Xử lý finding bằng test tái hiện trước; chạy lại test nếu có sửa.
- Sau khi người dùng đồng ý: push nhánh và tạo PR liên kết Issue #2, ghi kết quả
  test và giới hạn. Merge chỉ sau xác nhận review; không lấy approval Issue #1 làm
  approval cho Issue #2. Hiện chưa thực hiện bước push/PR/merge này.

## Bước 3 — Chuẩn bị đầu vào cho Issue #3 (cần người dùng)

Mục tiêu: đọc file Wazuh JSON đã làm sạch → CanonicalEvent. Không gọi live API.
Repo hiện chỉ có README ở khu vực fixture Wazuh, chưa có mẫu log thực tế để chốt
format và mapping. Không đoán định dạng export hoặc bịa log incident thay thế.

Trước khi hướng dẫn lệnh lấy log, hỏi người dùng đang có cách truy cập nào:
file export có sẵn, giao diện Wazuh Dashboard, hay terminal của Wazuh Manager.
Chỉ sau khi biết môi trường mới đưa lệnh/đường dẫn cụ thể; không yêu cầu credential.

Gói mẫu ban đầu đề xuất (nhỏ, chỉ từ lab được phép):

- Một file JSON/JSONL export giữ nguyên cấu trúc wrapper thực tế, vài bản ghi đủ
  đại diện (thường 3–10 bản ghi là đủ để bắt đầu khảo sát).
- Nếu thực sự có: một bản ghi có alert/rule và agent, một bản ghi chứa process/
  command line, một bản ghi ít field tùy chọn. Không thêm field hoặc tạo alert để
  đủ checklist; nêu rõ loại nào chưa có. Test malformed sẽ là dữ liệu test nhân
  tạo có nhãn, tách khỏi bằng chứng lab.
- Thông tin phiên bản Wazuh và cách export; múi giờ được ghi hoặc biết chắc;
  tên scenario/hoạt động lab mà bản ghi thuộc về. Chưa rõ thì ghi chưa rõ.
- Làm sạch secret, thông tin tổ chức, host/user/IP nhạy cảm trước khi đính kèm.
  Thay nhất quán các định danh tương quan; giữ cấu trúc, thứ tự, rule IDs, ports và
  mối quan hệ thời gian nếu không nhạy cảm. Ghi lại những trường đã thay thế.
- Bản gốc chưa làm sạch giữ cục bộ trong tests/fixtures/raw/ (Git ignore), không
  commit hoặc dán vào chat. Nếu cần hỗ trợ làm sạch cục bộ, yêu cầu riêng trước.

## Bước 4 — Chốt thiết kế parser trước code Issue #3

Sau khi có mẫu đã review:

1. Xác định JSON document/JSONL và ranh giới từng record; không hỗ trợ mọi kiểu
   export khi chưa có yêu cầu.
2. Lập bảng field gốc → canonical field; phân biệt source_type=wazuh và provider
   gốc. Missing optional → null; missing required → lỗi rõ ràng, không đoán.
3. Chốt event_id ổn định theo môi trường/nguồn/vị trí record; raw_event_ref ở mức
   dòng/record; SHA-256 tính trên đúng bytes đã làm sạch, không hash JSON tái render.
   environment_id và ingested_at do caller cung cấp, không tự lấy thời gian hiện tại.
4. Chốt lỗi record hỏng, vị trí lỗi và chính sách fail-fast/partial result trước
   triển khai; không âm thầm bỏ record rồi báo đủ evidence.
5. Người dùng duyệt mapping và fixture; tạo nhánh Issue #3 từ main đã cập nhật.

## Bước 5 — Triển khai và kiểm chứng Issue #3

- Source-specific parsing chỉ trong connectors/wazuh/; không nhét field vendor
  vào engine/model chung. Cấu hình đóng gói/import phải được test rõ ràng.
- Viết test cho mẫu đại diện, missing fields, malformed JSON/record, timestamp,
  stable ID khi replay, raw reference và exact-byte hash; lỗi không echo input.
- Output chỉ gồm CanonicalEvent hợp lệ; không kết luận detected/prevented chỉ vì
  có rule_id. Giữ toàn bộ test Issue #1/#2 xanh.
- Human review và người dùng đối chiếu output với file lab đã làm sạch, rồi PR.

Issue #3 đạt khi parser đúng hợp đồng và truy vết được từng output về record gốc,
không phải khi toàn bộ AEGIS đã đánh giá được một kịch bản end to end.

## Hướng đi sau parser Wazuh

Tiếp tục các fixture parser Suricata (#4), pfSense (#5), Cowrie (#6) theo mẫu thực
tế đã làm sạch; sau đó engine (#7), CLI (#8), so sánh run (#9). Trước engine cần
review predicate/correlation cụ thể cho assertions; không biến câu mô tả thành
logic bằng suy đoán. Dashboard và live connectors vẫn để sau đường CLI fixture.
