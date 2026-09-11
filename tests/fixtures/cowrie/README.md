# Cowrie fixtures — hướng A và B

Các file JSON trực tiếp trong thư mục này là **hướng A**: 9 derivative đã
sanitize từ 9 Wazuh search-hit Cowrie thực tế, bao phủ sáu loại event của profile
`wazuh-cowrie-v1`. Manifest A ghi tên nguồn, SHA-256 nguồn/derivative, phép biến
đổi, context replay và kết quả parser dự kiến.

Thư mục `native/` là **hướng B**: một JSONL derivative thực tế đã audit cùng
manifest `cowrie-jsonl-v1`. Tám dòng được chọn theo thứ tự từ một source session;
bảy dòng parsed bao phủ đủ sáu kind hỗ trợ và một `cowrie.client.size` là explicit
unsupported skip. Manifest B lưu riêng mapping dòng derivative 1–8 sang dòng
nguồn 8, 11, 12, 13, 15, 16, 17, 19. Không ghép record hoặc session giả.

Các file nguồn A/B vẫn ở ngoài Git và không bị sửa; không lưu reverse alias map.
Alias B thuộc namespace riêng, không tạo identity claim với alias A.

Trong A, chỉ `command-1.sanitized.json` và `command-2.sanitized.json` có cùng
session thực tế; bảy session còn lại không được ghép thành lifecycle giả. Trong
B, cả tám dòng thuộc một source session đã audit. Mọi credential, command và URL
trong fixture/input chỉ là evidence dạng text nhạy cảm bất hoạt: tuyệt đối không
in tùy tiện, chạy hoặc tải.

Hash evidence tính trên đúng bytes derivative. Rule `.gitattributes` chỉ ghim
`native/*.jsonl` về LF vì B hash từng dòng vật lý gồm line ending; không parse rồi
serialize lại fixture. Với A, đặc biệt giữ đúng lexical token của hai số
`full_log.duration`. Khi thêm/thay fixture phải audit lại việc loại credential và
identifier nhạy cảm, cập nhật manifest cùng literal độc lập trong test tương ứng.
Parser không tự sanitize input production bất kỳ. Xem quy trình và giới hạn tại
[`docs/COWRIE_NATIVE_INTAKE.md`](../../../docs/COWRIE_NATIVE_INTAKE.md).
