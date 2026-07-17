@echo off
chcp 65001 >nul
title KCheckLicense - Kiem tra ban quyen & crack

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
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0KCheckLicense.ps1"

REM Giu cua so neu script thoat som do loi
if %errorlevel% neq 0 (
    echo.
    echo [!] Da co loi khi chay script (ma loi: %errorlevel%).
    pause
)
