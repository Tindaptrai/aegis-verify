# Phân phối Windows: EXE chạy cục bộ

## Phạm vi bản đầu tiên

AEGIS được đóng gói từ **wheel đã cài trong virtual environment sạch**, có Python
runtime, dashboard đã build, manifest/profile và bộ replay công khai. Người nhận không
cần Python, Node hoặc source checkout để chạy demo offline. Đây là CLI mở từ
terminal; chưa có cửa sổ cài đặt, Windows service hay wizard khi bấm đúp.

- `aegis.exe --version`: xem phiên bản.
- `aegis.exe demo --out <thư mục mới>`: đánh giá fixture công khai, tạo report và
  comparison bằng engine hiện có; không chạy payload hay liên hệ hệ thống thật.
- `aegis.exe dashboard --bundled --reports <thư mục report>`: dùng UI và scenario
  đóng gói; dashboard chạy cục bộ, chỉ đọc mặc định.
- `validate` và `compare` giữ giao diện CLI hiện tại cho bundle của người dùng.

Tài liệu này mô tả quy trình build và tiêu chí kiểm; **build thành công chưa phải
nghiệm thu runtime trên máy sạch**. Gắn kết quả kiểm thực tế với hash artifact
trước khi phát hành. Bản thử chưa được ký số không phải bản triển khai doanh
nghiệp đã chứng nhận; không hướng dẫn người dùng tắt EDR hoặc bỏ qua chính sách.

## Chạy bản được bàn giao

Giữ nguyên thư mục `release`, gồm runtime, `LICENSES`, `BUILD-INFO.json`,
`SHA256SUMS.txt` và `QUICKSTART.md`. Bản `onedir` phải giữ cả thư mục `aegis`;
không chép riêng file EXE ra khỏi runtime của nó.

Từ thư mục `release`, mở PowerShell bằng tài khoản Windows thông thường:

```powershell
$exe = '.\aegis\aegis.exe'
& $exe --version
$demo = Join-Path $env:LOCALAPPDATA ('AEGIS-Verify-demo-' + [guid]::NewGuid().ToString('N'))
& $exe demo --out $demo
& $exe dashboard --bundled --reports (Join-Path $demo 'reports')
```

Với bản `onefile`, đổi `$exe` thành `'.\aegis.exe'`. Mở URL cục bộ được in ra,
xem scenario, assertion, EID, timeline và comparison. Ctrl+C dừng phiên này.
Đường dẫn demo là thư mục con mới trực tiếp của `LOCALAPPDATA` đã tồn tại; lần
đầu không cần có sẵn thư mục dữ liệu AEGIS. Nếu chọn `--out` khác, thư mục cha
phải tồn tại trước.

Bộ replay có **sáu lượt đánh giá từ dữ liệu lab đã khử thông tin nhạy cảm** và
**hai lượt đánh giá synthetic**. Hai report synthetic có sẵn được dùng cho ví dụ
so sánh Gap/Fix riêng. Đây là kiểm phần mềm offline; kết quả demo không chứng minh
hệ thống thật của doanh nghiệp đã phát hiện hành vi. Report và dữ liệu người dùng
lưu ở thư mục riêng, không ghi vào runtime hoặc thư mục giải nén tạm của EXE.

Nếu cổng bận, chọn cổng khác bằng `--port`; không tự dừng tiến trình khác.
Chạy `--help` ở từng lệnh để xem tùy chọn. Không mở dashboard ra mạng nội bộ để
chia sẻ cho nhiều người; xem [hướng triển khai doanh nghiệp](ENTERPRISE_DEPLOYMENT.md).

## Công cụ build và lý do thêm

`packaging/windows/requirements-build.txt` pin **PyInstaller 6.22.3**. Đây là
dependency chỉ dành cho build, đáp ứng yêu cầu phát hành EXE không cần Python;
không thêm vào dependency runtime của AEGIS. Phiên bản được xác nhận có trên
[PyPI](https://pypi.org/project/pyinstaller/6.22.3/).

Build Windows phải chạy trên Windows với kiến trúc Python phù hợp máy nhận.
PyInstaller đóng gói interpreter và module đã cài; nó không phải cross-compiler.
Build `onedir` trước vì dễ chẩn đoán tài nguyên thiếu, sau đó mới thử `onefile`.
Bản một tệp giải nén thành thư mục tạm khi chạy.
[Tài liệu PyInstaller](https://pyinstaller.org/en/v6.22.3/operating-mode.html)

Driver build dùng thư viện chuẩn, không cài gì tự động và không nhập AEGIS từ
checkout. Driver từ chối output đã tồn tại hoặc nằm trong checkout, editable
install, sai pin PyInstaller, thiếu tài nguyên và wheel không khớp provenance.
Nó đối chiếu bytes các file package/metadata đã cài với wheel đầu vào; `RECORD`
được loại vì pip sửa file này khi cài. Thư mục build lỗi được giữ để chẩn đoán.

## Chuẩn bị build environment riêng

Chọn wheel đã qua kiểm trên môi trường sạch. Không dùng `pip install -e .`,
không dùng môi trường phát triển đang có source import hook. Ví dụ dưới đây
dùng đường dẫn wheel minh họa; thay bằng file được duyệt thực tế.

```powershell
$source = (Get-Location).Path
$wheel = 'C:\staging\reviewed\aegis_verify-0.3.0-py3-none-any.whl'
$buildRoot = Join-Path $env:LOCALAPPDATA ('AEGIS-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildRoot | Out-Null
$buildVenv = Join-Path $buildRoot 'venv'
py -3.13 -m venv $buildVenv
$buildPython = Join-Path $buildVenv 'Scripts/python.exe'
& $buildPython -I -m pip install $wheel
& $buildPython -I -m pip install -r (Join-Path $source 'packaging/windows/requirements-build.txt')
& $buildPython -I -m pip check
```

Các lệnh pip thuộc bước chuẩn bị do người build thực hiện; driver không thay đổi
global Python hay environment được chọn. Build dùng installed wheel kể cả khi
driver nằm trong checkout. Không đưa CA, credential, bundle thật hoặc
`raw-evidence` vào wheel và thư mục release.

## Build và kiểm bản thư mục

```powershell
$onedir = Join-Path $buildRoot 'onedir'
& $buildPython -I -X utf8 (Join-Path $source 'packaging/windows/build.py') --python $buildPython --wheel $wheel --out $onedir
$release = Join-Path $onedir 'release'
$exe = Join-Path $release 'aegis/aegis.exe'
```

Driver tạo `release/aegis/aegis.exe` cùng runtime, các license/notice của AEGIS,
Python, dependency và bootloader, quickstart, build info và hash manifest.
`build-context` chứa dữ liệu chẩn đoán build, không cần gửi người dùng.
`BUILD-INFO.json` ghi wheel SHA-256, phiên bản, kiến trúc và package build;
không ghi đường dẫn riêng của máy build vào hồ sơ phát hành.

Thực hiện checklist bên dưới trên chính bản thư mục này. Khi đã đạt mới build
bản một tệp vào **output mới**:

```powershell
$onefile = Join-Path $buildRoot 'onefile'
& $buildPython -I -X utf8 (Join-Path $source 'packaging/windows/build.py') --python $buildPython --wheel $wheel --out $onefile --onefile
```

Kết quả là `onefile/release/aegis.exe`. Chạy lại toàn bộ kiểm runtime cho bản này;
kết quả của onedir không tự chứng minh onefile. Gửi kèm `LICENSES`, quickstart,
build info và manifest dù runtime có thể khởi động từ một EXE. License/notice
cũng được giữ bên trong embedded archive. Dữ liệu người dùng luôn nằm ngoài
archive; đường dẫn resource của frozen app không phải Python interpreter hoặc
thư mục làm việc của người dùng.
[PyInstaller runtime](https://pyinstaller.org/en/v6.22.3/runtime-information.html)

## Checklist nghiệm thu artifact

- [ ] Lưu wheel SHA-256, commit source, OS/kiến trúc và phiên bản build tools.
- [ ] Cài wheel hoặc chạy EXE ngoài source; không có `PYTHONPATH` trỏ checkout.
- [ ] EXE chạy trên Windows thử nghiệm không có Python, Node hoặc Git.
- [ ] Tài khoản thường, CWD bất kỳ, đường dẫn có dấu và khoảng trắng hoạt động.
- [ ] `--version`, `--help`, `validate`, `compare` và public offline `demo` hoạt động.
- [ ] Demo tạo kết quả Gap/Pass/comparison đúng fixture và EID; không có outbound.
- [ ] Dashboard tải HTML/JS/CSS, scenario list/detail, report, timeline, EID và
  comparison. Kiểm bằng browser; HTTP 200 riêng lẻ chưa chứng minh UI dùng được.
- [ ] Input sai/hash lệch vẫn bị từ chối; thiếu dữ liệu không tự thành Pass.
- [ ] Output không đè thư mục đã có; không ghi report vào runtime/Program Files.
- [ ] Cổng bận được báo rõ; Ctrl+C dừng đúng phiên, giữ report, không đổi lab.
- [ ] Kiểm manifest `SHA256SUMS.txt` cho bộ bàn giao; ghi lỗi/giới hạn còn lại.
- [ ] Giữ license/notice và xác nhận trạng thái ký số; kiểm theo EDR thực tế của
  doanh nghiệp trước pilot, không tuyên bố mọi chính sách đều cho phép EXE.

Các kiểm này chỉ đánh giá packaging/runtime. Chúng không thay nghiệm thu live
Lab A/B/C hoặc biến fixture thành bằng chứng thật.

## Thu thập live và điều kiện ngoài bộ cài

Offline replay không cần Python/Node ngoài runtime. Các chế độ khác cần đúng
điều kiện: `collect` qua SSH cần OpenSSH, key và known-hosts được duyệt;
Operations Windows cần PowerShell hệ thống để kiểm ACL, CA, tài khoản quyền đọc,
allowlist và network tới Wazuh được phép. Credential không nhúng trong EXE,
không lưu trong report; không tự bắt đầu thu thập khi khởi động dashboard.

## MSI là mốc tiếp theo

Bản này chưa tạo MSI. MSI thật cần định danh sản phẩm/upgrade ổn định, version,
chữ ký theo chính sách doanh nghiệp, shortcut, silent install, uninstall/upgrade
và quy tắc giữ dữ liệu. Không đổi đuôi EXE thành MSI. Có thể bọc cùng payload
onedir bằng công cụ MSI ở một issue riêng khi payload đã được kiểm.
