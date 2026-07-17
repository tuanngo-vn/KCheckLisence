@echo off
chcp 65001 >nul
title KCheckLicense - Kiem tra ban quyen va crack

REM ==========================================================================
REM  Double-click file nay de chay KCheckLicense.
REM  File tu dong xin quyen Administrator (UAC) va bo qua ExecutionPolicy,
REM  nguoi dung khong can biet PowerShell.
REM  Tac gia: TuanNgoVN - https://kollersi.com
REM ==========================================================================

REM --- Kiem tra quyen Administrator ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Dang xin quyen Administrator...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- Da co quyen Admin: chay script (dat thu muc lam viec ve noi chua file .bat) ---
cd /d "%~dp0"

if not exist "%~dp0KCheckLicense.ps1" (
    echo.
    echo [!] Khong tim thay KCheckLicense.ps1 canh file .bat nay.
    echo     Hay de ChayKiemTra.bat va KCheckLicense.ps1 chung mot thu muc.
    echo.
    pause
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0KCheckLicense.ps1"
set "RC=%errorlevel%"

REM Luon dung lai de doc thong bao (khong bao gio tu dong dong cua so)
echo.
if not "%RC%"=="0" (
    echo [!] Script ket thuc voi ma loi: %RC%
) else (
    echo [*] Da chay xong.
)
echo Nhan phim bat ky de dong cua so...
pause >nul
