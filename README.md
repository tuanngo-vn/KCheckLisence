<div align="center">

<a href="https://kollersi.com">
  <img src="https://kollersi.com/content/images/2025/07/kollersi_logo_2024_tran-2.png" alt="Kollersi" width="220">
</a>

# 🛡️ KCheckLicense

**Công cụ 2-trong-1: kiểm tra bản quyền & gỡ crack — gọn nhẹ, mặc định chỉ đọc, chỉ sửa hệ thống khi bạn xác nhận.**

Quét bản quyền **Windows / Office** và dấu hiệu crack của **IDM · WinRAR · Adobe**, rồi tùy chọn gỡ bỏ đúng những gì phát hiện được — tất cả trong **một file, một menu**.

<br>

[![Build KCheckLicense.exe](https://github.com/tuanngo-vn/KCheckLisence/actions/workflows/build.yml/badge.svg)](https://github.com/tuanngo-vn/KCheckLisence/actions/workflows/build.yml)
![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Safe by default](https://img.shields.io/badge/An%20to%C3%A0n-Dry--run%20m%E1%BA%B7c%20%C4%91%E1%BB%8Bnh-brightgreen)
![Made by](https://img.shields.io/badge/by-kollersi.com-black)

</div>

---

## ✨ Tính năng

- 🖥️ **Thông tin phần cứng** — Mainboard, CPU, RAM, GPU, ổ đĩa (HDD/SSD).
- 🔑 **Bản quyền hệ thống** — phiên bản Windows, trạng thái kích hoạt, kênh phân phối (Retail / OEM / MAK / KMS), Product Key (BIOS OEM + Registry), tình trạng Office.
- 🔍 **Quét crack đa lớp** — gom nhóm theo phần mềm, kèm bằng chứng cụ thể.
- 📊 **4 mức đánh giá** — `SẠCH` · `THÔNG TIN` · `CẢNH BÁO` · `PHÁT HIỆN`.
- 🧹 **Gỡ bỏ tích hợp** — sau khi quét xong, nếu phát hiện crack sẽ hỏi ngay "Bạn có muốn gỡ không?". Mặc định xem trước (dry-run), chỉ đổi hệ thống khi bạn xác nhận.
- 🧾 **Tự xuất báo cáo HTML** — sau khi quét xong, lưu file báo cáo đẹp ra **Desktop** (bấm `R` để mở bằng trình duyệt). Hỗ trợ cả xuất **JSON** cho kiểm kê hàng loạt.

---

## 🚀 Cách dùng nhanh (cho người không rành PowerShell)

> **Double-click file `ChayKiemTra.bat`** — hộp thoại UAC hiện lên thì bấm **Yes**.

Chương trình hiện menu để chọn:

```
  [ 1 ] Kiem tra ban quyen (Check License)
  [ 2 ] Go bo crack da phat hien (Clean)
  [ Q ] Thoat
```

Chọn **1** để quét — nếu phát hiện dấu hiệu crack, chương trình sẽ hỏi ngay **"Bạn có muốn gỡ ngay bây giờ không? (Y/N)"**. Chọn **2** để vào thẳng chế độ gỡ.

File `.bat` tự xin quyền Administrator và chạy script với `-ExecutionPolicy Bypass`, nên không vướng chặn của Windows.

> ⚠️ Giữ `ChayKiemTra.bat` **cùng thư mục** với `KCheckLicense.ps1`.
> Nếu tải từ mạng về báo "chặn": chuột phải file → **Properties** → tick **Unblock** → OK.

Muốn gọn hơn nữa — **1 file `.exe` duy nhất**? Xem mục [Đóng gói thành .exe](#-đóng-gói-thành-exe).

---

## 🕵️ Các dấu hiệu được phát hiện

| Nhóm | Dấu hiệu |
|------|----------|
| **Windows** | KMS server trong registry · KMS38 · hook `SppExtComObjHook.dll` · IFEO debugger hijack · scheduled task & service của KMS tool |
| **Office** | `sppc.dll` giả mạo (kỹ thuật Ohook) trong thư mục cài Office |
| **IDM** | `IDMan.exe` mất chữ ký Tonec (bị vá) · hosts chặn `tonec.com` / `internetdownloadmanager.com` · tường lửa chặn IDM · registry `scansk` (fake serial) |
| **WinRAR** | Phát hiện `rarreg.key` → cảnh báo để rà soát license thật/lậu |
| **Adobe** | hosts chặn máy chủ kích hoạt Adobe · `amtlib.dll` bị vá · artifact GenP / AMT Emulator · Adobe Genuine Service bị tắt/chặn tường lửa |

---

## 🚧 Giới hạn đã biết — kết quả SẠCH không đảm bảo 100%

Công cụ phát hiện dựa trên **dấu vết vận hành** (KMS server, hook DLL, scheduled task/service...). Một số phương pháp kích hoạt mới **không để lại dấu vết đó**, nên **không thể phát hiện được**:

- **TSforge / MAS** — không dùng KMS server, không cần gia hạn định kỳ, không chèn DLL hook. Nó ghi thẳng một "vé kích hoạt" giả vào Physical Store của Windows một lần duy nhất, không còn hoạt động ngầm nào để dò ra. Đây là giới hạn kỹ thuật thật sự, tác giả TSforge cũng không công khai chi tiết để phòng chống.
- **HWID** — còn "vô hình" hơn: phương pháp này lợi dụng lỗ hổng khiến **máy chủ Microsoft thật sự cấp Digital License thật** cho phần cứng đó. Kết quả là giấy phép do chính Microsoft ký, **hoàn toàn giống hệt** trường hợp mua bản quyền thật hoặc nâng cấp từ Windows 7/8 chính chủ — không có công cụ nào (kể cả của Microsoft) phân biệt được bằng cách quét máy.

**Kết luận:** dùng công cụ này để tầm soát các loại crack phổ biến (KMSpico, KMSAuto, Ohook, các tool giả lập KMS...), nhưng **không dùng làm bằng chứng pháp lý tuyệt đối** rằng máy hoàn toàn sạch — vẫn nên đối chiếu với hồ sơ mua bản quyền thật.

---

## ⚙️ Cách dùng nâng cao (dòng lệnh)

Chạy bằng **quyền Administrator** để đọc đầy đủ registry HKLM và cấu hình tường lửa.

```powershell
# Giao diện tương tác (mặc định)
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1

# Chạy một lần rồi thoát (dùng cho script/GPO)
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -NonInteractive

# Xuất JSON ra màn hình
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -Json

# Lưu báo cáo JSON ra file
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -OutputPath report.json

# Chỉ định nơi lưu báo cáo HTML
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -ReportPath D:\baocao.html

# Tắt tự động xuất báo cáo HTML
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -NoReport

# Hiện đầy đủ Product Key ngay từ đầu (mặc định được che)
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -ShowKeys
```

**Phím tắt khi xem báo cáo:** `H` — Ẩn/hiện Product Key · `R` — Mở báo cáo HTML · `C` — Gỡ crack · `Q` / `ESC` — Quay lại menu.

| Tham số | Ý nghĩa |
|---------|---------|
| `-Mode Check` / `-Mode Clean` | Bỏ qua menu, vào thẳng chế độ Kiểm tra hoặc Gỡ bỏ |
| `-Json` | In kết quả dạng JSON ra stdout thay vì giao diện (tự chuyển sang `-Mode Check`) |
| `-OutputPath <path>` | Lưu báo cáo JSON ra file |
| `-ReportPath <path>` | Đường dẫn file `.html` để lưu báo cáo (mặc định tự lưu ra Desktop) |
| `-NoReport` | Không tự động xuất báo cáo HTML |
| `-NonInteractive` | Chạy một lần, không chờ phím/xác nhận (tự chuyển sang `-Mode Check`) |
| `-ShowKeys` | Hiện đầy đủ Product Key từ đầu |
| `-Apply` | Dùng với `-Mode Clean`: thực sự gỡ bỏ (không có thì chỉ xem trước) |
| `-IncludeWarnings` | Gỡ luôn cả mức CẢNH BÁO (KMS server lạ chưa chắc là crack, `rarreg.key` chưa chắc là lậu) |
| `-RemoveAdobePatchedDll` | Xóa `amtlib.dll` bị vá — có thể làm Adobe không mở được cho tới khi Repair/cài lại qua Creative Cloud, mặc định TẮT |
| `-Rearm` | Dùng với `-Mode Clean`: chạy `slmgr /rearm` reset trạng thái kích hoạt Windows sau khi dọn |

```powershell
# Chạy tự động: quét roi go crack neu co, khong hoi gi
powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -Mode Clean -Apply -NonInteractive
```

---

## 🧹 Gỡ crack đã phát hiện

Sau khi quét (menu chọn **1** hoặc `-Mode Check`), nếu phát hiện dấu hiệu crack, chương trình **tự hỏi ngay**: *"Bạn có muốn gỡ ngay bây giờ không? (Y/N)"*. Có thể vào thẳng bằng menu **2** hoặc `-Mode Clean`.

Gỡ đúng những gì đã phát hiện: KMS server giả (loopback), KMS Hook DLL, Office Ohook, IFEO hijack, scheduled task/service của công cụ crack, hosts/firewall bị chặn (Adobe/IDM), registry fake serial (IDM), artifact crack Adobe (GenP/amtemu)...

**Mặc định luôn xem trước danh sách rồi mới hỏi xác nhận — không đổi gì trên máy nếu bạn không đồng ý.**

Sau khi gỡ, khuyến nghị chọn lại **Kiểm tra** để xác nhận đã sạch, và kích hoạt lại Windows/Office bằng key/tài khoản chính chủ.

---

## 📦 Đóng gói thành .exe

Muốn phát hành **một file `.exe` duy nhất** (không cần `.ps1`/`.bat` kèm theo):

- **Trên Windows:** chạy `Build-Exe.ps1` — tự cài PS2EXE và tạo `KCheckLicense.exe` (đã gắn `icon.ico`).
- **Qua GitHub Actions (không cần Windows):** mỗi lần push code lên `main`, workflow tại `.github/workflows/build.yml` tự build `.exe` trên runner Windows và đưa lên **Artifacts** của lần chạy đó (cần đăng nhập GitHub để tải). Muốn phát hành một **bản chính thức** (có link tải công khai, không cần đăng nhập), push kèm tag `v*`:

  ```bash
  git tag v2.1.0
  git push origin v2.1.0
  ```

  Actions sẽ tự tạo **Release** kèm file `.exe` đính sẵn tại `https://github.com/tuanngo-vn/KCheckLisence/releases`.

---

## 📋 Yêu cầu

- Windows 10 / 11 hoặc Windows Server.
- Windows PowerShell 5.1+ hoặc PowerShell 7+.
- Nên chạy bằng **quyền Administrator** để quét đầy đủ.

---

## ⚠️ Lưu ý

Một số dấu hiệu có thể **hợp lệ** trong môi trường doanh nghiệp (ví dụ KMS nội bộ khi máy đã tham gia Domain, hoặc `rarreg.key` mua bản quyền hợp pháp). Các trường hợp này được xếp mức `CẢNH BÁO` / `THÔNG TIN` để bạn tự đối chiếu, **không** kết luận là vi phạm. Công cụ chỉ mang tính tham khảo hỗ trợ rà soát tuân thủ bản quyền.

Chế độ **Gỡ bỏ** thay đổi hệ thống (xóa registry, file, scheduled task, service, sửa hosts) — luôn xem trước danh sách và hỏi xác nhận trước khi thực hiện. Sau khi gỡ, Windows/Office sẽ mất kích hoạt và cần nhập lại key/tài khoản chính chủ.

---

<div align="center">

Made with ❤️ by **[TuanNgoVN](https://kollersi.com)** · <a href="https://kollersi.com">kollersi.com</a>

</div>
