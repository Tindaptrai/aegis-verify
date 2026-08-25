# AEGIS Verify — MVP Product Requirements Document

## 1. Vấn đề

Các tổ chức đã triển khai SIEM, IDS và firewall nhưng thường không có cơ chế kiểm
tra liên tục rằng detection rules vẫn hoạt động đúng sau khi thay đổi cấu hình,
cập nhật hệ thống hoặc xuất hiện biến thể hành vi mới.

## 2. Người dùng mục tiêu

- SOC Analyst
- Detection Engineer
- SOC Lead
- Trung tâm đào tạo hoặc Cyber Range
- Doanh nghiệp vừa và nhỏ sử dụng SOC mã nguồn mở

## 3. Giá trị sản phẩm

AEGIS Verify chạy các kịch bản kiểm thử an toàn, thu thập evidence từ nhiều nguồn,
đánh giá detection coverage và chỉ ra false negative hoặc missing telemetry.

## 4. Luồng sử dụng chính

Chọn môi trường → Chọn scenario → Bắt đầu test run → Thu thập evidence → Đánh giá
Pass/Fail → Phát hiện detection gap → Cập nhật rule → Chạy lại → So sánh kết quả
trước và sau.

## 5. Phạm vi MVP

- 3 security scenarios
- 4 connectors
- Canonical Event Model
- Validation Engine
- Evidence Timeline
- Detection Pass/Fail
- Rule Regression Comparison
- Một dashboard đơn giản

## 6. Không thuộc MVP

- Không xây SIEM mới
- Không làm full SOAR
- Không multi-tenant
- Không billing
- Không autonomous AI response
- Không hỗ trợ tất cả firewall/SIEM
- Không xây machine learning detection

## 7. Chỉ số thành công

- Mỗi kết luận phải liên kết được với raw evidence.
- Cùng một scenario có thể chạy lại nhiều lần.
- Hệ thống phân biệt được Detected, Prevented, Missing Telemetry và Failed.
- Hiển thị được khác biệt giữa hai lần chạy.
- Demo được quy trình Gap → Rule Fix → Re-test → Pass.

## 8. Demo chính

Một biến thể PowerShell an toàn không còn khớp rule dựa trên tên file. AEGIS xác
định telemetry vẫn tồn tại nhưng detection thất bại. Nhóm cập nhật rule dựa trên
hành vi, chạy lại và AEGIS hiển thị `Regression Passed`.

## Quy tắc khóa phạm vi

Sau khi nhóm phê duyệt PRD này, không bổ sung chức năng ngoài phạm vi cho tới khi
MVP chạy end to end. Mọi thay đổi ground truth hoặc tiêu chí thành công cần được
review rõ ràng.
