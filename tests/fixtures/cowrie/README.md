# Cowrie fixtures

Thư mục này chứa 9 derivative JSON đã sanitize từ 9 Wazuh search-hit Cowrie
thực tế, bao phủ sáu loại event của profile `wazuh-cowrie-v1`. Manifest ghi tên
nguồn, SHA-256 nguồn, SHA-256 derivative, phép biến đổi, context replay và kết
quả parser dự kiến. File nguồn vẫn ở ngoài Git và không bị sửa; không lưu reverse
alias map.

Chỉ `command-1.sanitized.json` và `command-2.sanitized.json` có cùng session
thực tế. Bảy session còn lại không được ghép thành lifecycle giả. Chuỗi command
và URL trong fixture chỉ là evidence dạng text: tuyệt đối không chạy hoặc tải.

Hash evidence tính trên đúng bytes derivative. `.gitattributes` ghim JSON về LF;
không parse rồi serialize lại fixture, đặc biệt hai số `full_log.duration` cần giữ
đúng lexical token. Khi thêm hoặc thay fixture phải review lại mọi bản sao trong
`data` và `full_log`, loại credential/identifier nhạy cảm nhất quán, rồi cập nhật
manifest và các literal độc lập trong `backend/tests/test_cowrie_fixtures.py`.
