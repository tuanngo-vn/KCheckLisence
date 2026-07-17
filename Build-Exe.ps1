<#
.SYNOPSIS
    Đóng gói KCheckLicense.ps1 thành 1 file KCheckLicense.exe duy nhất (không cần .ps1 kèm theo).
.DESCRIPTION
    Dùng module PS2EXE để biên dịch. Chạy file này TRÊN WINDOWS.
    File .exe tạo ra sẽ tự yêu cầu quyền Administrator khi mở.
.NOTES
    Tác giả: TuanNgoVN - https://kollersi.com
    Cách chạy:  chuột phải file này -> Run with PowerShell
                (hoặc)  powershell -ExecutionPolicy Bypass -File .\Build-Exe.ps1
#>

$ErrorActionPreference = 'Stop'
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$source  = Join-Path $here 'KCheckLicense.ps1'
$output  = Join-Path $here 'KCheckLicense.exe'
$icon    = Join-Path $here 'icon.ico'

if (-not (Test-Path $source)) {
    Write-Host "[!] Khong tim thay $source" -ForegroundColor Red
    exit 1
}

# Cai module PS2EXE cho user hien tai neu chua co.
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host '[*] Dang cai module PS2EXE...' -ForegroundColor Yellow
    try {
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
    } catch {
        Write-Host '[!] Khong cai duoc PS2EXE tu PSGallery. Kiem tra ket noi mang / quyen.' -ForegroundColor Red
        Write-Host '    Thu chay truoc:  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned' -ForegroundColor Yellow
        exit 1
    }
}
Import-Module ps2exe

Write-Host "[*] Dang bien dich -> $output" -ForegroundColor Yellow
$iconArgs = @{}
if (Test-Path $icon) { $iconArgs['iconFile'] = $icon } else { Write-Host "[!] Khong tim thay icon.ico, bo qua icon." -ForegroundColor Yellow }

Invoke-ps2exe @iconArgs `
    -InputFile   $source `
    -OutputFile  $output `
    -requireAdmin `
    -noConsole:$false `
    -title       'KCheckLicense' `
    -description 'Kiem tra ban quyen & phat hien crack Windows/Office/IDM/WinRAR/Adobe' `
    -company     'kollersi.com' `
    -product     'KCheckLicense' `
    -version     '2.1.0.0'

if (Test-Path $output) {
    Write-Host "[OK] Da tao file: $output" -ForegroundColor Green
    Write-Host '     Giờ chỉ cần gửi/chạy mình file .exe nay, khong can .ps1 kem theo.' -ForegroundColor Green
} else {
    Write-Host '[!] Bien dich that bai.' -ForegroundColor Red
}
