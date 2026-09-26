# Kịch bản demo cho khách (khoảng 25 phút)

Kịch bản này chạy **hoàn toàn offline**, trên các bundle đã sanitize trong repo.
Không cần lab, credential hay mạng. Mọi verdict được sinh lại trên máy demo bằng
đúng parser và engine thật; bằng chứng gốc của các lượt lab nằm ngoài Git và được
đối chiếu qua SHA-256 trong tài liệu kết quả. Mỗi lệnh dưới đây đã chạy thử ngày
2026-09-27 và cho đúng kết quả ghi bên cạnh.

## 0. Chuẩn bị (một lần)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
cd frontend; npm install; npm run build; cd ..
New-Item -ItemType Directory demo-reports | Out-Null
```

`demo-reports\` nằm ngoài các thư mục fixture; đừng ghi report vào `tests\`.

## 1. Vấn đề (2 phút)

Một đội SOC mua firewall, IDS, SIEM, honeypot, nhưng không chứng minh được rule có
thật sự bắt được hành vi hay không, và khi sửa rule thì không biết có làm hỏng thứ
khác không. AEGIS Verify chạy một kịch bản an toàn, thu bằng chứng từ từng nguồn,
và chỉ kết luận khi có evidence ID cụ thể. Thiếu bằng chứng thì nói là thiếu, không
đoán ([PRD](PRD.md)).

## 2. SCN-002: ngăn chặn thật, không chỉ phát hiện (6 phút)

Lượt **đối chứng** (chưa có rule chặn):

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-002-attempted-exfiltration.yaml --fixture tests\fixtures\cli\scn002-lab-sanitized\control --profile scenarios\profiles\scn-002\profile.json --format json > demo-reports\scn002-control.json
```

Kết quả `Inconclusive`, exit 3. Nói rõ: đây là **đúng thiết kế**, vì A03 đòi
pfSense ghi một hành động *chặn*, mà lượt này chưa có rule chặn.

Lượt **Block**:

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-002-attempted-exfiltration.yaml --fixture tests\fixtures\cli\scn002-lab-sanitized\block --profile scenarios\profiles\scn-002\profile.json --format json > demo-reports\scn002-block.json
```

Kết quả **`Prevented`**, exit 0: endpoint (Sysmon), IDS (Suricata), firewall
(pfSense `block`) và SIEM (Wazuh) cùng khớp một luồng, mỗi assertion có evidence ID.

```powershell
.\.venv\Scripts\python.exe -m aegis_verify compare --before demo-reports\scn002-control.json --after demo-reports\scn002-block.json --format json > demo-reports\scn002-compare.json
```

So sánh ra `Inconclusive` theo thiết kế: `Regression Passed` dành cho luồng
Gap → Fix, khi một `false_negative` trở thành `satisfied`. Kết luận của SCN-002 là
verdict của chính lượt Block ([kết quả](SCN002_RESULT_2026-09-22.md)).

## 3. SCN-003: deception qua NAT, bốn nguồn (5 phút)

```powershell
.\.venv\Scripts\python.exe -m aegis_verify validate --scenario scenarios\SCN-003-internal-deception.yaml --fixture tests\fixtures\cli\scn003-lab-sanitized --profile scenarios\profiles\scn-003\profile.json --format json > demo-reports\scn003.json
```

Kết quả **`Detected`**, exit 0. Điểm nên chỉ ra:

- Kết nối tới địa chỉ decoy bị firewall dịch (DNAT) sang honeypot. Suricata thấy
  đích *trước* NAT, pfSense và Cowrie thấy đích *sau* NAT. Engine không đoán NAT:
  hai miền được nối bằng binding cổng nguồn khai báo trước.
- Cảnh báo Wazuh gắn đúng phiên Cowrie qua một khoá phiên mờ, không lưu session
  ID thô; mật khẩu người gõ có trong log gốc nhưng parser không đọc.
- Cửa sổ tương quan ±2 s là số đo trên lab, không phải số chọn cho đẹp
  ([kết quả](SCN003_RESULT_2026-09-26.md): sáu lượt, năm `Detected`, một lượt
  `Missing telemetry` do lỗi đồng bộ giờ và đã giải thích).

## 4. Dashboard (5 phút)

```powershell
.\.venv\Scripts\python.exe -m aegis_verify dashboard --reports demo-reports --static frontend\dist
```

Mở địa chỉ server in ra. Sidebar có ba run và một bản so sánh. Nên chỉ vào:

- tab Assertions: từng assertion, vai trò (telemetry/detection/prevention),
  outcome và evidence ID;
- tab Timeline: bằng chứng theo thứ tự thời gian, giá trị thiếu để trống;
- các dòng "Collection assurance: unknown" và "Run binding": dashboard **nói rõ
  những gì chưa được chứng minh**, không tô hồng.

Bản so sánh `Regression Passed` minh hoạ đầy đủ có sẵn ở
`tests\fixtures\dashboard` (dữ liệu synthetic, ghi rõ là synthetic).

## 5. SCN-001: Gap → Fix → Re-test trên lab thật (5 phút)

Đây là câu chuyện chính của PRD. Kể bằng [kết quả v3](SCN001_V3_RESULT_2026-09-27.md):

| Lượt | Rule | Payload | Kết quả |
| --- | --- | --- | --- |
| A | theo tên file | `lab_update.ps1` | Detected |
| B | theo tên file | cùng nội dung, đổi tên | **False negative**: gap |
| C | theo hành vi | cùng nội dung, đổi tên | Detected |
| B → C | | | **Regression Passed** |

Hai điểm nên nói thật:

- Rule theo hành vi từng báo nhầm chính công cụ chạy demo. Lỗi này được phát hiện
  trên engine thật, sửa, và chạy lại cả bộ để chứng minh; bằng chứng thu thập của
  lượt B được đối chiếu ba phía (log gốc Windows, SIEM, snapshot).
- "False negative" chỉ được kết luận khi có xác nhận thu thập đầy đủ; thiếu xác
  nhận thì engine trả `Inconclusive`.

Bằng chứng thô của SCN-001 chứa hostname lab nên không nằm trong repo.

## 6. Câu hỏi hay gặp

| Câu hỏi | Trả lời trung thực |
| --- | --- |
| Có chạy live không? | Có công cụ thu thập live từ Wazuh Indexer (chỉ đọc) và đã chạy trên lab; demo này dùng bundle đã sanitize để ai cũng tái lập được. |
| Có phải production không? | Không. Đây là công cụ kiểm chứng cho một người vận hành, lab riêng; chưa có multi-tenant, xác thực nhiều người dùng hay tự chạy scenario. |
| "Detected" có nghĩa hệ thống an toàn? | Không. Nó chỉ nói bằng chứng của lượt đó khớp profile; không phải kết luận về máy hay mạng. |
| Kết quả có bị chỉnh cho đẹp? | Không sửa ground truth, profile hay cửa sổ để lấy verdict; mọi thay đổi có PR, lý do và số đo. |
| Scenario ghi `status: draft`? | Trường này mô tả vòng đời manifest, không phải kết quả. Đổi nó sẽ đổi fingerprint mà mọi profile và study đang ghim, nên được giữ nguyên có chủ đích. |

## 7. Nếu có lab (tuỳ chọn)

Một lượt SCN-003 live mất khoảng 5 phút theo
[runbook](SCN003_CONTROL_RUN_RUNBOOK.md). Không chạy SCN-001 A/B/C trước khách:
cần cài và gỡ rule trên manager và khoảng 40 phút.
