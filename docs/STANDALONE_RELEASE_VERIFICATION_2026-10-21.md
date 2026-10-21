# Kiểm bộ cài độc lập AEGIS Verify — 21/10/2026

## Kết luận và phạm vi

**Đạt kiểm phần mềm cho bản preview cục bộ trên Windows 11 x64.** Wheel, EXE dạng
thư mục và EXE một tệp đã chạy ngoài checkout, với thư mục làm việc có dấu và
khoảng trắng. EXE được kiểm khi PATH chỉ còn các thư mục hệ thống Windows,
không gọi Python/Node từ PATH. Đây chưa phải kiểm trên một VM Windows mới.

Phiên bản package vẫn là **0.3.0**, snapshot chưa phát hành. Nhận diện đúng bộ
bằng SHA-256 dưới đây; không nhầm với wheel v0.3.0 đã phát hành trước đó.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Wheel | 387023 | `26f1d18bb9f2da6184b5848e36ad2e18a847f9e311823b6c9b8fec650f566d65` |
| EXE một tệp | 15547268 | `46da0806bffda78d3a48e534847bb4156a4996e8cf3482cea68dd9db095298a1` |
| EXE trong bản thư mục | 5893631 | `949dd135fe0bf14084cb35ba33585ce516e5934594d7d7b66455f76c4b404c1f` |

Bản thư mục cần toàn bộ runtime và manifest hash đi kèm; hash EXE riêng không
thay thế việc giữ các file còn lại. Artifact được lưu cục bộ dưới
`dist/windows-preview-20261021/`, được Git bỏ qua. Không đưa binary vào source,
không tạo tag/release hoặc đổi quyền truy cập repository trong công việc này.

## Đã kiểm thực tế

- Fresh venv ngoài source, cài wheel thật và runtime dependency; import từ
  `site-packages`, không dùng editable hook; `pip check` đạt.
- Backend: **3828 passed, 3 skipped**, 602.25 giây. Ba skip thuộc FIFO và quyền
  POSIX không có trên Windows. Sau sửa cuối về notice/demo, 14 test liên quan
  chạy lại: **14 passed**, 5.43 giây.
- Frontend: **108 passed**; TypeScript/Vite production build đạt. Patch Vite
  8.3.0 → 8.3.5 xử lý finding audit của build tooling; `npm audit`: **0 finding**.
- Build: **4 test bảo vệ output** và **2 test sdist/editable** đạt. Sdist loại
  file không nằm trong allowlist; editable build không cần frontend output.
- Cả wheel, onedir và onefile: demo **8 evaluation + 2 report synthetic có sẵn
  + 2 comparison = 12 report**; validate từng ca và compare độc lập đạt.
- Dashboard: HTML và JS/CSS trả 200; danh mục và chi tiết **6 manifest**, report,
  system status đọc được. Hai report lỗi bị từ chối 422; Operations chưa bật.
- Hash evidence sai bị từ chối; output có sẵn được giữ nguyên; dashboard không
  thay đổi report. Giấy phép frontend được giữ trong wheel, kit demo và EXE.
- Kiểm giao diện bằng trình duyệt từ EXE: assertion/EID, timeline và so sánh
  False negative → Detected → Regression Passed hiển thị đúng.

## Kết quả demo đúng mong đợi

| Ca | Kết quả |
| --- | --- |
| SCN-002 control / block | Inconclusive / Prevented |
| SCN-003 | Detected |
| SCN-004 block-siem / historical block / sensor-down | Prevented / Inconclusive / Inconclusive |
| SCN-005 / SCN-006 synthetic | Detected / Detected |
| SCN-002 control → block comparison | Inconclusive |
| SCN-999 synthetic Gap/Fix comparison | Regression Passed |

SCN-002/003/004 là dữ liệu đã làm sạch từ lab; SCN-005/006 và Gap/Fix là mô phỏng.
Kết quả giữ EID và lineage của input, không tạo bằng chứng cho một lượt thử mới.
SCN-001 chỉ có manifest trong bộ công khai; bằng chứng thật vẫn riêng tư.
SCN-999 nằm ngoài danh mục sáu manifest nên registry báo Degraded có giải thích;
không sửa ground truth để làm trạng thái đẹp hơn. Cả sáu manifest vẫn `draft`.

## Những gì chưa được công nhận

- Chưa chạy artifact trên VM Windows mới không có Python/Node/Git, chưa kiểm
  policy EDR và chưa ký số. Bước này cần thực hiện trước thí điểm doanh nghiệp.
- Chưa nghiệm thu live Operations/SSH từ EXE; các chế độ này vẫn cần cấu hình,
  credential, CA và prerequisite hệ thống được người vận hành phê duyệt.
- Chưa có MSI, Windows service, đăng nhập, phân quyền, nhiều người dùng chung
  hoặc dữ liệu đồng bộ. Các hướng này nằm trong
  [thiết kế triển khai doanh nghiệp](ENTERPRISE_DEPLOYMENT.md).
- CI đã bổ sung job cài wheel ngoài source trên Ubuntu/Windows; tài liệu này
  ghi kết quả local, không thay cho kết quả Actions và review người phụ trách.

## Chạy lại kiểm artifact

```text
python -I scripts/smoke_distribution.py --python <external-venv-python> --result wheel.json
python -I scripts/smoke_distribution.py --exe <absolute-aegis.exe> --result exe.json
```

Xem [hướng dẫn build và chạy EXE](WINDOWS_DISTRIBUTION.md) và file `BAT-DAU.md`
trong bộ bàn giao. Hồ sơ local gồm kết quả JSON, ảnh UI, build metadata, giấy
phép và SHA256SUMS. Mã nguồn được chuẩn bị trên nhánh riêng để review trước merge.
