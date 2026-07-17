<div align="center">

<a href="https://kollersi.com">
  <img src="https://kollersi.com/content/images/2025/07/kollersi_logo_2024_tran-2.png" alt="Kollersi" width="220">
</a>

# 🛡️ KCheckLicense

**Công cụ kiểm tra bản quyền & phát hiện phần mềm crack — gọn nhẹ, chỉ đọc, không sửa hệ thống.**

Quét bản quyền **Windows / Office** và dấu hiệu crack của **IDM · WinRAR · Adobe** trong một lần chạy.

<br>

[![Build KCheckLicense.exe](https://github.com/tuanngo-vn/KCheckLisence/actions/workflows/build.yml/badge.svg)](https://github.com/tuanngo-vn/KCheckLisence/actions/workflows/build.yml)
![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Read-only](https://img.shields.io/badge/An%20to%C3%A0n-Ch%E1%BB%89%20%C4%91%E1%BB%8Dc%2C%20kh%C3%B4ng%20s%E1%BB%ADa-brightgreen)
![Made by](https://img.shields.io/badge/by-kollersi.com-black)

</div>

---

## ✨ Tính năng

- 🖥️ **Thông tin phần cứng** — Mainboard, CPU, RAM, GPU, ổ đĩa (HDD/SSD).
- 🔑 **Bản quyền hệ thống** — phiên bản Windows, trạng thái kích hoạt, kênh phân phối (Retail / OEM / MAK / KMS), Product Key (BIOS OEM + Registry), tình trạng Office.
- 🔍 **Quét crack đa lớp** — gom nhóm theo phần mềm, kèm bằng chứng cụ thể.
- 📊 **4 mức đánh giá** — `SẠCH` · `THÔNG TIN` · `CẢNH BÁO` · `PHÁT HIỆN`.
- 🧾 **Tự xuất báo cáo HTML** — sau khi quét xong, lưu file báo cáo đẹp ra **Desktop** (bấm `R` để mở bằng trình duyệt). Hỗ trợ cả xuất **JSON** cho kiểm kê hàng loạt.
- 🔒 **Chỉ đọc** — không thay đổi bất kỳ thứ gì trên máy.

---

## 🚀 Cách dùng nhanh (cho người không rành PowerShell)

> **Double-click file `ChayKiemTra.bat`** — hộp thoại UAC hiện lên thì bấm **Yes**.

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

**Phím tắt (chế độ tương tác):** `H` — Ẩn/hiện Product Key · `R` — Mở báo cáo HTML · `Q` / `ESC` — Thoát.

| Tham số | Ý nghĩa |
|---------|---------|
| `-Json` | In kết quả dạng JSON ra stdout thay vì giao diện |
| `-OutputPath <path>` | Lưu báo cáo JSON ra file |
| `-ReportPath <path>` | Đường dẫn file `.html` để lưu báo cáo (mặc định tự lưu ra Desktop) |
| `-NoReport` | Không tự động xuất báo cáo HTML |
| `-NonInteractive` | Chạy một lần, không chờ phím |
| `-ShowKeys` | Hiện đầy đủ Product Key từ đầu |

---

## 📦 Đóng gói thành .exe

Muốn phát hành **một file `.exe` duy nhất** (không cần `.ps1`/`.bat` kèm theo):

- **Trên Windows:** chạy `Build-Exe.ps1` — tự cài PS2EXE và tạo `KCheckLicense.exe` (đã gắn `icon.ico`).
- **Qua GitHub Actions (không cần Windows):** mỗi lần push code lên `main`, workflow tại `.github/workflows/build.yml` tự build `.exe` trên runner Windows và:
  - Cập nhật vào **Release "latest"** — link tải cố định, luôn là bản mới nhất, không cần thao tác gì thêm:

    **[⬇️ Tải bản mới nhất](https://github.com/tuanngo-vn/KCheckLisence/releases/latest/download/KCheckLicense.exe)**

  - Đưa lên **Artifacts** của lần chạy đó (cần đăng nhập GitHub để tải).
  - Nếu muốn chốt một **phiên bản chính thức** riêng (có link/tag cố định không bị ghi đè), push kèm tag `v*`:

    ```bash
    git tag v2.0.1
    git push origin v2.0.1
    ```

---

## 📋 Yêu cầu

- Windows 10 / 11 hoặc Windows Server.
- Windows PowerShell 5.1+ hoặc PowerShell 7+.
- Nên chạy bằng **quyền Administrator** để quét đầy đủ.

---

## ⚠️ Lưu ý

Một số dấu hiệu có thể **hợp lệ** trong môi trường doanh nghiệp (ví dụ KMS nội bộ khi máy đã tham gia Domain, hoặc `rarreg.key` mua bản quyền hợp pháp). Các trường hợp này được xếp mức `CẢNH BÁO` / `THÔNG TIN` để bạn tự đối chiếu, **không** kết luận là vi phạm. Công cụ chỉ mang tính tham khảo hỗ trợ rà soát tuân thủ bản quyền.

---

<div align="center">

Made with ❤️ by **[TuanNgoVN](https://kollersi.com)** · <a href="https://kollersi.com">kollersi.com</a>

</div>
