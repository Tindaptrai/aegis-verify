# SCN-004 — Hồ sơ nghiệm thu Lab C (2026-10-07)

Hồ sơ của một đợt nghiệm thu: mục tiêu, kết quả kỳ vọng, kết quả thực tế và đường dẫn
tới bằng chứng của từng lượt. Kịch bản, cấu hình đã chốt, giới hạn và danh sách phiên
bản nằm ở [SCN004_LAB_C.md](SCN004_LAB_C.md); quy trình chạy lại ở
[LABC_RUNBOOK.md](LABC_RUNBOOK.md).

Bản gốc của bằng chứng (log thô, bundle, report có địa chỉ và tên máy thật) **giữ ngoài
Git**. Trong repo chỉ có hồ sơ này, hai bundle đã sanitize và các fixture parser. Mọi
hash dưới đây là của bản gốc hoặc của file trong bundle gốc, nên người review giữ bản
gốc đối chiếu được từng dòng.

## 1. Kết quả theo từng mục tiêu

| Mục tiêu | Kết quả kỳ vọng | Kết quả thực tế | Bằng chứng | Trạng thái |
| --- | --- | --- | --- | --- |
| Đủ ba nguồn, firewall chặn, cùng một luồng | `Prevented`, exit 0, ba assertion `satisfied` | 5/5 lượt đúng | bảng 1, lượt `e9c39177`, `32133603`, `6f19048c`, `be283230`, `2e2b5ac5` | Đạt |
| Firewall cho qua, có máy nhận trong lab | `Inconclusive`, exit 3, A03 `prevention_not_demonstrated`; không kết luận chặn | 2/2 lượt đúng, máy nhận ghi được gói | bảng 1, lượt `5d4d46a0`, `1ac03396` | Đạt |
| Snort ngừng thu | `Inconclusive`, exit 3, A02 `collection_not_confirmed`; không tự suy ra false negative | 2/2 lượt đúng | bảng 1, lượt `4d5afd81`, `bf0f7220` | Đạt |
| Đường log Snort sang Wazuh gián đoạn | Phân biệt được alert IDS tại nguồn với alert SIEM bị thiếu | 2/2 lượt `Prevented`; alert Snort có trong `alert_json`, không có alert Wazuh 130110 cho hai luồng đó, kể cả sau khi agent chạy lại | bảng 1, lượt `ab842ef4`, `52f59d23`; mục 3 dưới đây | Đạt |
| Khôi phục dịch vụ rồi chạy lượt mới | Lượt mới, bằng chứng mới, đạt lại kết quả kỳ vọng | 2/2 lượt đúng; alert Wazuh có lại ở lượt sau khi agent chạy lại | bảng 1, lượt `d31542b1`, `ebff50af` | Đạt |
| Tạo một ca rule chưa phát hiện được, telemetry vẫn đủ | `False negative`, exit 1, A02 `expected_detection_absent` | đúng; 11 điều kiện thu thập đều đạt nên mới khai báo `complete_for_scope` | bảng 1 lượt `f12e4fa7`; bảng 2 cột khai báo | Đạt |
| Sửa rule rồi chạy lại | A02 `satisfied` | 2/2 lượt đúng | bảng 1, lượt `dd82ca67`, `9099c31e` | Đạt |
| `aegis compare` cho `Regression Passed` | trước `false_negative`, sau `satisfied`, không có assertion unknown | đúng: A02 `improvement`, A01 và A03 `unchanged_pass`, bốn trạng thái unknown đều 0 | report so sánh của cặp `f12e4fa7` → `9099c31e` | Đạt |
| Mỗi lượt độc lập, không dùng lại log | mỗi lượt có `run_id`, cửa sổ, binding, report, exit code riêng | 16/16 lượt; công cụ tự từ chối lượt có cửa sổ chứa gói của lượt khác | bảng 1 (cổng nguồn khác nhau từng lượt), bảng 2 (evidence ID khác nhau từng lượt) | Đạt |
| Chạy lặp qua khởi động lại máy ảo | lượt sau khi khởi động lại vẫn đạt | 11 lượt phiên 1, khởi động lại sensor và máy Wazuh, 2 lượt phiên 2 đều `Prevented` | [SCN004_LAB_C.md](SCN004_LAB_C.md) mục 11 | Đạt |
| Alert SIEM thành một assertion được duyệt | — | **Chưa làm**: parser `wazuh-snort-alert-v1` đã có, chưa assertion nào dùng, chờ chủ dự án duyệt | [WAZUH_SNORT_ALERT.md](WAZUH_SNORT_ALERT.md) | Hoãn |

**16/16 lượt nghiệm thu đúng kết quả kỳ vọng.** Một lượt trước đó bị loại vì lỗi quy
trình (chạy thu bằng chứng trước khi gửi probe), được ghi lại là không hợp lệ và không
tính vào 16 lượt; lượt thay thế cùng loại đã chạy lại.

## 2. Từng lượt

### Bảng 1 — Từng lượt: kết quả và assertion

| # | run_id (8) | Nhãn / tình huống | Gửi (UTC) | Cổng nguồn | Kết quả | exit | A01 | A02 | A03 | Đạt kỳ vọng |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `e9c39177` | block / normal | 16:03:54.335 | 56662 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 2 | `32133603` | block / normal | 16:19:12.558 | 51171 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 3 | `5d4d46a0` | allow / normal | 16:31:06.341 | 60987 | **Inconclusive** | 3 | satisfied | satisfied | inconclusive | DUNG |
| 4 | `6f19048c` | block / normal | 16:40:00.217 | 54720 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 5 | `1ac03396` | allow / normal | 16:42:42.921 | 60017 | **Inconclusive** | 3 | satisfied | satisfied | inconclusive | DUNG |
| 6 | `4d5afd81` | block / snort-down | 16:46:37.594 | 60022 | **Inconclusive** | 3 | satisfied | inconclusive | satisfied | DUNG |
| 7 | `d31542b1` | block / recovery | 16:49:27.688 | 60027 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 8 | `bf0f7220` | block / snort-down | 16:53:39.376 | 60032 | **Inconclusive** | 3 | satisfied | inconclusive | satisfied | DUNG |
| 9 | `ab842ef4` | block / wazuh-down | 16:56:41.298 | 60037 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 10 | `52f59d23` | block / wazuh-down | 16:59:24.237 | 60042 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 11 | `ebff50af` | block / recovery | 17:02:15.331 | 60047 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 12 | `be283230` | block / normal | 17:11:29.489 | 61838 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 13 | `2e2b5ac5` | block / normal | 17:14:12.379 | 61843 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 14 | `f12e4fa7` | block / rule-gap | 17:44:46.463 | 64702 | **False negative** | 1 | satisfied | false_negative | satisfied | DUNG |
| 15 | `dd82ca67` | block / rule-fixed | 17:47:55.495 | 64707 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |
| 16 | `9099c31e` | block / rule-fixed | 17:56:44.856 | 60894 | **Prevented** | 0 | satisfied | satisfied | satisfied | DUNG |

### Bảng 2 — Từng lượt: evidence ID và tham chiếu bản ghi gốc

Mỗi ô là ID bằng chứng (12 ký tự đầu) và `raw_event_ref` của bản ghi. Witness của A02 và A03
còn neo vào bản ghi Sysmon của cùng lượt, nên ID của A01 xuất hiện lại trong hai assertion đó.

| run_id (8) | A01 — Sysmon 3 | A02 — Snort | A03 — OPNsense | Khai báo thu thập cho A02 |
| --- | --- | --- | --- | --- |
| `e9c39177` | `b077a7ddc1cd` · `l34088#record=1` | `69c4ec5e2944` · `L1` | `1ac492954fda` · `L119` | unknown |
| `32133603` | `99783cfd1ccf` · `l35886#record=1` | `de2920feb8ee` · `L1` | `c65ddac15151` · `L157` | unknown |
| `5d4d46a0` | `a8df9456d9f1` · `l37080#record=1` | `059dd2658ac1` · `L1` | — | unknown |
| `6f19048c` | `748c4c42dc30` · `l38568#record=1` | `2edca4b61dc1` · `L1` | `356147ff49a5` · `L68` | unknown |
| `1ac03396` | `dbc47ad4b422` · `l39288#record=1` | `a8932d1e5756` · `L1` | — | unknown |
| `4d5afd81` | `f558cf053b2d` · `l40350#record=1` | — | `2ce0430b13cc` · `L104` | unknown |
| `d31542b1` | `96500d56d9bb` · `l40985#record=1` | `1bf483083767` · `L1` | `ee3f5cabf219` · `L94` | unknown |
| `bf0f7220` | `e3b851cbdda9` · `l41890#record=1` | — | `7ba62091482d` · `L106` | unknown |
| `ab842ef4` | `8207e41be406` · `l42516#record=1` | `06b8a2d3d69c` · `L1` | `8117e32cae9e` · `L115` | unknown |
| `52f59d23` | `1fb2166a5069` · `l42553#record=1` | `1f0b7cd99201` · `L1` | `216a6ec24819` · `L93` | unknown |
| `ebff50af` | `8ebf587f1ff7` · `l42737#record=1` | `c49b2f4a1eea` · `L1` | `4715be2d6138` · `L113` | unknown |
| `be283230` | `8b6a94302903` · `l44489#record=1` | `8edcd6a6ee9f` · `L1` | `4ba5c901149f` · `L114` | unknown |
| `2e2b5ac5` | `1c016f1c68eb` · `l45041#record=1` | `6918dec707c9` · `L1` | `70f373e97c08` · `L83` | unknown |
| `f12e4fa7` | `00434420e1d4` · `l48100#record=1` | — | `dc247c41012c` · `L118` | caller-attested |
| `dd82ca67` | `b0743cff9d72` · `l49185#record=1` | `ee54912b3aba` · `L1` | `0e8c85daebf0` · `L124` | unknown |
| `9099c31e` | `1085738a45cc` · `l50277#record=1` | `640286c663c4` · `L1` | `3d642e03877e` · `L183` | caller-attested |

### Bảng 3 — Nguồn gốc bằng chứng (bản gốc giữ ngoài Git)

SHA-256 rút gọn 12 ký tự đầu. `bundle` là file trong gói bằng chứng của lượt, `nguồn` là file
trên máy lab tại thời điểm thu, kèm số dòng đã giữ hoặc số dòng của bản ghi.

| run_id (8) | Sysmon 3 (bundle · dòng trong `archives.json`) | Snort (bundle · nguồn · dòng giữ) | OPNsense (bundle · nguồn · dòng giữ) |
| --- | --- | --- | --- |
| `e9c39177` | `615af3cfdeab` · dòng 34088 | `fc1051c7eef3` · `bbecc3c27e30` · 1 dòng | `c0e55eead08c` · `ab5e879dcb35` + `f8ee697ae0fe` · 202 dòng |
| `32133603` | `9bbb2baf128c` · dòng 35886 | `104e58e734b7` · `771f38b8e8e9` · 1 dòng | `5c67fa5988ab` · `ab5e879dcb35` + `883b29acd0f7` · 284 dòng |
| `5d4d46a0` | `2e60ad1d7b18` · dòng 37080 | `4496f15fe346` · `771f38b8e8e9` · 1 dòng | `a48d6fbaee97` · `ab5e879dcb35` + `f5c4b2953495` · 257 dòng |
| `6f19048c` | `a26557ee8a24` · dòng 38568 | `2041ae79385d` · `9c00ea576aed` · 1 dòng | `3843454fa72f` · `ab5e879dcb35` + `d1dd47abcc84` · 175 dòng |
| `1ac03396` | `56bb539c3c69` · dòng 39288 | `62356a7856e7` · `80fb1dd4af3c` · 1 dòng | `d9dafe0b7850` · `ab5e879dcb35` + `855f0f24d46a` · 263 dòng |
| `4d5afd81` | `27c130c31d11` · dòng 40350 | `e3b0c44298fc` · `80fb1dd4af3c` · 0 dòng | `8495992bb13a` · `ab5e879dcb35` + `ac20c9b23dfe` · 187 dòng |
| `d31542b1` | `b15f40a599fe` · dòng 40985 | `3adc263a0c63` · `6b43d8c63234` · 1 dòng | `17b88937f179` · `ab5e879dcb35` + `3c0c810d940c` · 193 dòng |
| `bf0f7220` | `7c16a08fe241` · dòng 41890 | `e3b0c44298fc` · `6b43d8c63234` · 0 dòng | `4e245ce2fe96` · `ab5e879dcb35` + `024083cb018f` · 185 dòng |
| `ab842ef4` | `0d84a71c23d6` · dòng 42516 | `5d1d29697fce` · `8249633cf5af` · 1 dòng | `6dbc0b480c82` · `ab5e879dcb35` + `f980d0c497d0` · 198 dòng |
| `52f59d23` | `5bbd615de07d` · dòng 42553 | `663d4f7cf044` · `d46e19b73762` · 1 dòng | `6f79b8b31d23` · `ab5e879dcb35` + `165b0600d8b9` · 186 dòng |
| `ebff50af` | `2f94edae6947` · dòng 42737 | `f617e80ef8bf` · `d129388cc517` · 1 dòng | `2308a0edc225` · `ab5e879dcb35` + `182723571c91` · 214 dòng |
| `be283230` | `295220de20d8` · dòng 44489 | `05055a23696a` · `94bbe01477e7` · 1 dòng | `881a1d116462` · `ab5e879dcb35` + `a2f95d5ef830` · 212 dòng |
| `2e2b5ac5` | `b9aec823d777` · dòng 45041 | `e3490b75142a` · `f2c9ee80f140` · 1 dòng | `ad9bdc8026aa` · `ab5e879dcb35` + `4b1d805b77ce` · 219 dòng |
| `f12e4fa7` | `cbd2f761b2d4` · dòng 48100 | `e3b0c44298fc` · `f2c9ee80f140` · 0 dòng | `4eb2a744530a` · `ab5e879dcb35` + `5269212ae679` · 198 dòng |
| `dd82ca67` | `00aacc85f7dd` · dòng 49185 | `5be1de3e4232` · `c445a36ca850` · 1 dòng | `a382a18f9543` · `ab5e879dcb35` + `64af63238119` · 208 dòng |
| `9099c31e` | `d4fd07dab232` · dòng 50277 | `d8441072710f` · `0eff3c5c2711` · 1 dòng | `35e8690bc6be` · `ab5e879dcb35` + `c93c77182fa9` · 275 dòng |

## 3. Phân biệt alert IDS tại nguồn và alert SIEM

Hai lượt `ab842ef4` và `52f59d23` chạy khi agent Wazuh trên sensor đã dừng. Snort vẫn
ghi alert sid 1000010 cho cả hai luồng trong `alert_json.txt` trên sensor, nhưng Wazuh
không sinh alert 130110 cho chúng — kể cả sau khi agent chạy lại, vì agent chỉ đọc dòng
mới (`only-future-events` mặc định là `yes`). Lượt `ebff50af` ngay sau khi agent chạy
lại có alert 130110 bình thường.

Hai bằng chứng này không trộn vào nhau: A02 lấy từ `alert_json` của sensor
(`snort3-alert-json-v1`), còn alert của Wazuh là một bản ghi khác với evidence ID khác
và parser khác (`wazuh-snort-alert-v1`). Thu được log thô và tạo được alert SIEM là hai
việc tách bạch; đợt này chứng minh được cả hai chiều.

## 4. Kiểm dashboard với dữ liệu thật của đợt

Chạy dashboard chỉ đọc với sáu report của đợt (năm lượt và một bản so sánh) cùng thư
mục manifest. Quan sát:

- trang Tổng quan: SCN-004 nằm trong bảng kịch bản với kết quả gần nhất `Prevented`,
  3/3 assertion đạt, 3 evidence và cột collection assurance ghi `caller-attested ×1,
  unknown ×2`; thẻ System status có đủ sáu connector, trong đó Snort và OPNsense là hai
  thẻ mới, đều `not_configured` kèm dòng nói rõ "thấy trong report" không phải trạng
  thái connector;
- hàng KPI đếm **theo kịch bản**, lấy kết quả gần nhất của mỗi manifest, nên một lượt
  `False negative` trong thư mục report không làm KPI đổi; chú thích ngay dưới hàng KPI
  nói đúng điều đó, và danh sách report bên trái vẫn hiện nhãn riêng của từng lượt;
- lượt `be283230`: `Prevented`, 3/3, parsed 214 / skipped 0 / referenced 3, tab
  Assertions có vai trò và evidence ID của từng assertion, tab Timeline có ba mốc;
- lượt `bf0f7220` (Snort ngừng thu): `Inconclusive`, A02 chưa kết luận, kèm khối
  "Collection assurance: unknown cho mọi assertion — thiếu alert trong report này không
  tự chứng minh detection gap";
- lượt `f12e4fa7` (rule hụt): `False negative`, A02 `expected_detection_absent`, kèm
  khối ghi rõ có assertion dựa trên khai báo thu thập của người chạy và câu nhắc
  "attestation không phải bằng chứng độc lập";
- bản so sánh: `Regression Passed`, A02 `improvement` từ `false_negative` sang
  `satisfied`, A01 và A03 `unchanged_pass`, bốn ô trạng thái unknown đều 0.

Dashboard không tự ý nâng trạng thái: mọi lượt đều hiện "Run binding: chưa có dữ liệu"
vì report không khai run binding, và trạng thái tổng chỉ nói về việc có đủ dữ liệu để
trình bày, không nói về mức an toàn của môi trường.

## 5. Bản gốc, bản trong repo và cách đối chiếu

| Hạng mục | Chỗ lưu | Ghi chú |
| --- | --- | --- |
| Log thô, bundle, report, biên nhận probe của 16 lượt | ngoài Git, trên máy chạy lab | mỗi lượt một thư mục `runs/<run_id>/` gồm `bundle/`, `raw/`, `report.json`, `provenance.json`, `receipt.json`, `exit-code.txt` |
| Bảng tổng hợp cả đợt | ngoài Git | `runs/campaign.csv`, một dòng mỗi lượt |
| Lượt không hợp lệ | ngoài Git | `runs/invalid-runs.txt`, kèm lý do |
| Hai bundle đã sanitize | trong repo | [`tests/fixtures/cli/scn004-lab-c-sanitized/`](../tests/fixtures/cli/scn004-lab-c-sanitized/README.md) |
| Fixture alert Wazuh 130110 đã sanitize | trong repo | [`tests/fixtures/wazuh/snort-alert/`](../tests/fixtures/wazuh/snort-alert/README.md) |
| Hồ sơ truy xuất | trong repo | bảng 2 và bảng 3 ở trên |

Cách người review đối chiếu một lượt: lấy `run_id` ở bảng 1, mở `runs/<run_id>/` trong
bộ bằng chứng gốc, so SHA-256 của từng file bundle với bảng 3, rồi so `raw_event_ref`
và evidence ID trong `report.json` với bảng 2. Dòng gốc của mỗi bản ghi tra được bằng
số dòng trong bảng 3 cộng SHA-256 của file nguồn tại thời điểm thu. Không sửa bản gốc
để khớp; sai lệch phải được ghi lại chứ không được chữa.

## 6. Việc còn lại

| Việc | Trạng thái |
| --- | --- |
| Assertion cho alert SIEM (A04) của SCN-004 | hoãn, chờ chủ dự án duyệt; parser đã có |
| Chủ dự án review scenario và profile trước đợt cuối | của chủ dự án |
| Một người khác chạy lại theo runbook, gồm ít nhất một lượt live | chưa làm |
| Merge chuỗi PR theo thứ tự phụ thuộc và replay trên commit main cuối | chưa làm |
