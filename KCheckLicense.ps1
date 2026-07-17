<#
.SYNOPSIS
    KCheckLicense - Công cụ kiểm tra bản quyền & gỡ crack Windows/Office cùng các
    phần mềm phổ biến (IDM, WinRAR, Adobe). Chạy lên hiện menu chọn Kiểm tra hoặc
    Gỡ bỏ.

.DESCRIPTION
    Công cụ 2-trong-1 dành cho quản trị viên IT và người dùng cuối:
    1) KIỂM TRA - thu thập thông tin phần cứng, trạng thái kích hoạt Windows/Office
       và quét các dấu hiệu thường gặp của công cụ bẻ khóa (KMS emulator, DLL hook,
       IFEO hijack, hosts/firewall chặn máy chủ kích hoạt, binary bị vá chữ ký...).
       Chế độ này CHỈ đọc và báo cáo, không thay đổi gì trên máy.
    2) GỠ BỎ - gỡ đúng những gì bước Kiểm tra phát hiện. Mặc định chạy dry-run (chỉ
       xem trước); phải xác nhận hoặc thêm -Apply mới thực sự thay đổi hệ thống.

    Kết quả mang tính tham khảo; một vài dấu hiệu có thể là hợp lệ trong môi trường
    doanh nghiệp (ví dụ KMS nội bộ có Domain) - các trường hợp này được xếp mức
    CẢNH BÁO và KHÔNG bị gỡ tự động trừ khi dùng -IncludeWarnings.

.PARAMETER Mode
    'Check' = chỉ quét (bỏ qua menu), 'Clean' = chỉ gỡ crack (bỏ qua menu). Nếu bỏ
    trống và đang chạy tương tác, công cụ hiện menu để chọn.

.PARAMETER Apply
    Dùng với Mode Clean (hoặc khi chọn Gỡ crack trong menu): thực sự gỡ bỏ. Nếu
    không có, chỉ xem trước (dry-run), không đổi gì trên máy.

.PARAMETER IncludeWarnings
    Gỡ luôn cả các mục ở mức CẢNH BÁO (ví dụ KMS server lạ chưa chắc là crack,
    rarreg.key chưa chắc là lậu). Mặc định KHÔNG đụng vào mức Cảnh báo.

.PARAMETER RemoveAdobePatchedDll
    Xóa luôn file amtlib.dll bị vá (dấu hiệu AMT Emulator). CẢNH BÁO: có thể làm
    Adobe không mở được cho tới khi Repair/cài lại qua Creative Cloud. Mặc định TẮT.

.PARAMETER Rearm
    Chạy slmgr /rearm để reset trạng thái kích hoạt Windows sau khi dọn crack.

.PARAMETER Json
    Xuất kết quả dưới dạng JSON ra stdout thay vì giao diện tương tác.

.PARAMETER OutputPath
    Đường dẫn file để lưu báo cáo JSON. Có thể dùng cùng chế độ tương tác.

.PARAMETER ReportPath
    Đường dẫn file .html để lưu báo cáo. Nếu bỏ trống, báo cáo HTML được tự động
    tạo ra Desktop sau khi quét xong (trừ khi dùng -NoReport hoặc -Json).

.PARAMETER NoReport
    Không tự động xuất báo cáo HTML sau khi quét.

.PARAMETER NonInteractive
    Chạy một lần rồi thoát, không chờ phím bấm (phù hợp khi chạy qua script/GPO).

.PARAMETER ShowKeys
    Hiển thị đầy đủ Product Key ngay từ đầu (mặc định được che).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1
    (hiện menu chọn Kiểm tra / Gỡ bỏ)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -Mode Check -Json -OutputPath report.json

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\KCheckLicense.ps1 -Mode Clean -Apply -NonInteractive

.NOTES
    Tác giả : TuanNgoVN (https://kollersi.com)
    Yêu cầu : Windows PowerShell 5.1+ / PowerShell 7+. Nên chạy bằng quyền Administrator
              để đọc đầy đủ registry HKLM và cấu hình tường lửa.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Check', 'Clean')][string]$Mode,
    [switch]$Apply,
    [switch]$IncludeWarnings,
    [switch]$RemoveAdobePatchedDll,
    [switch]$Rearm,
    [switch]$Json,
    [string]$OutputPath,
    [string]$ReportPath,
    [switch]$NoReport,
    [switch]$NonInteractive,
    [switch]$ShowKeys
)

# StrictMode 1.0: bắt lỗi biến chưa khởi tạo nhưng vẫn cho phép truy cập thuộc tính
# registry tùy chọn (nhiều check chủ động thăm dò khóa có thể không tồn tại).
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'SilentlyContinue'

# ============================================================================
# HẰNG SỐ & CẤU HÌNH
# ============================================================================

# Version: chỉ tăng khi thay đổi lớn (tính năng mới). Build: tăng thêm 1 mỗi lần
# sửa/vá lỗi, dù nhỏ, để người dùng phân biệt được đang chạy bản nào khi báo lỗi.
$script:Version   = '2.1'
$script:Build     = 13
$script:BuildDate = '2026-07-17'
$script:UnknownVi = 'Không xác định'

# Application ID của Windows / Office trong SoftwareLicensingProduct
$script:WindowsAppId = '55c92734-d682-4d71-983e-d6ec3f16059f'
$script:OfficeAppId  = '0ff1ce15-a989-479d-afc2-fb5b53c84000'

# Trạng thái finding và độ ưu tiên (cao hơn = nghiêm trọng hơn)
$script:StatusRank = @{ Clean = 0; Info = 1; Warning = 2; Detected = 3 }

# Tên miền máy chủ kích hoạt bị crack thường chặn trong hosts/tường lửa.
# Khi các tên miền này bị trỏ về 0.0.0.0/127.0.0.1 => chặn kiểm tra bản quyền.
$script:LicenseDomains = @{
    Adobe = @(
        'adobe.io', 'lm.licenses.adobe.com', 'na1r.services.adobe.com',
        'hlrcv.stage.adobe.com', 'practivate.adobe', 'activate.adobe',
        'ereg.adobe', 'adobe-dns', 'genuine.adobe', 'prod.adobegenuine',
        'ic.adobe.io', 'cc-api-data.adobe.io'
    )
    IDM   = @('internetdownloadmanager.com', 'tonec.com', 'registeridm')
}

# ============================================================================
# TIỆN ÍCH DÙNG CHUNG
# ============================================================================

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Clean', 'Info', 'Warning', 'Detected')][string]$Status,
        [Parameter(Mandatory)][string]$Details,
        [string[]]$Evidence = @()
    )
    [PSCustomObject]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Rank     = $script:StatusRank[$Status]
        Details  = $Details
        Evidence = $Evidence
    }
}

# Bỏ dấu tiếng Việt + thay ký tự trang trí non-ASCII -> ASCII.
# Dùng cho hiển thị console (chạy đúng trên mọi máy, không bao giờ ra '?').
# Dữ liệu gốc (báo cáo HTML/JSON) KHÔNG dùng hàm này nên vẫn đủ dấu.
function Remove-Diacritics {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    # Ký tự trang trí hay dùng -> ASCII
    $Text = $Text -replace '[•·]', '-' -replace '[─—–]', '-' -replace '[└├│]', ' ' `
                  -replace '→', '->' -replace '⚠', '(!)' -replace '[“”]', '"' -replace '[‘’]', "'"
    # đ/Đ không phải dấu thanh, phải thay tay
    $Text = $Text -replace 'đ', 'd' -replace 'Đ', 'D'
    # Tách dấu thanh rồi loại bỏ (à->a, ế->e, ị->i, ...)
    $norm = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $norm.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

# Kiểm tra một binary có bị giả mạo/vá hay không.
# Trả về $null nếu file không tồn tại; ngược lại trả object mô tả chữ ký số.
function Get-BinaryTrust {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedSigner = 'Microsoft'
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $sig = Get-AuthenticodeSignature -FilePath $Path
    $signerSubject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    $trusted = $sig -and $sig.Status -eq 'Valid' -and $signerSubject -like "*$ExpectedSigner*"
    [PSCustomObject]@{
        Path      = $Path
        Trusted   = [bool]$trusted
        SigStatus = if ($sig) { "$($sig.Status)" } else { 'NoSignature' }
        Signer    = $signerSubject
    }
}

# Đọc các dòng ánh xạ đang hoạt động trong file hosts (bỏ qua comment).
function Get-HostsEntries {
    $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) { return @() }
    $i = 0
    foreach ($raw in (Get-Content -LiteralPath $hostsPath)) {
        $i++
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2) {
            [PSCustomObject]@{ LineNumber = $i; IP = $parts[0]; Hostname = ($parts[1..($parts.Count - 1)] -join ' '); Raw = $line }
        }
    }
}

# Tìm rule tường lửa Outbound đang chặn một trong các file thực thi cho trước.
function Find-OutboundBlockRule {
    param([Parameter(Mandatory)][string[]]$ExeNames)
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return @() }
    $hits = @()
    try {
        $rules = Get-NetFirewallRule -Enabled True -Direction Outbound -Action Block -ErrorAction Stop
        foreach ($rule in $rules) {
            $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            if (-not $app -or -not $app.Program) { continue }
            foreach ($exe in $ExeNames) {
                if ($app.Program -like "*$exe*") {
                    $hits += "$($rule.DisplayName) -> $($app.Program)"
                    break
                }
            }
        }
    } catch { }
    return $hits
}

# Tìm các entry hosts chặn một nhóm tên miền bản quyền.
function Find-BlockedDomains {
    param(
        [Parameter(Mandatory)][object[]]$HostsEntries,
        [Parameter(Mandatory)][string[]]$Domains
    )
    $hits = @()
    foreach ($entry in $HostsEntries) {
        $blocking = $entry.IP -in @('0.0.0.0', '127.0.0.1', '::1')
        if (-not $blocking) { continue }
        foreach ($dom in $Domains) {
            if ($entry.Hostname -like "*$dom*") {
                $hits += $entry.Raw
                break
            }
        }
    }
    return $hits
}

function Test-IsAdministrator {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ============================================================================
# 1. THU THẬP THÔNG TIN PHẦN CỨNG
# ============================================================================

function Get-HardwareInfo {
    $board = Get-CimInstance Win32_BaseBoard
    $motherboard = if ($board) { "$($board.Manufacturer.Trim()) $($board.Product.Trim())" } else { $script:UnknownVi }

    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cpuName = $script:UnknownVi; $cores = 0; $threads = 0
    if ($cpu) {
        $cpuName = ($cpu.Name -replace '\s+', ' ').Trim()
        $cores = $cpu.NumberOfCores
        $threads = $cpu.NumberOfLogicalProcessors
    }

    $mem = Get-CimInstance Win32_PhysicalMemory
    $ramBytes = 0; $ramSpeed = 0; $ramSlots = 0
    if ($mem) {
        $ramSlots = @($mem).Count
        foreach ($m in $mem) {
            $ramBytes += [uint64]$m.Capacity
            if ($m.Speed -gt $ramSpeed) { $ramSpeed = $m.Speed }
        }
    }

    $gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name.Trim() })
    $gpuStr = if ($gpus.Count) { $gpus -join ' / ' } else { $script:UnknownVi }

    $disks = @()
    foreach ($disk in (Get-CimInstance Win32_DiskDrive)) {
        $sizeGB = [Math]::Round($disk.Size / 1GB, 1)
        $media = 'HDD'
        $pDisk = Get-CimInstance -Namespace ROOT/Microsoft/Windows/Storage -ClassName MSFT_PhysicalDisk |
                 Where-Object { $_.DeviceId -eq $disk.Index -or $_.FriendlyName -eq $disk.Model } |
                 Select-Object -First 1
        if ($pDisk) {
            switch ([int]$pDisk.MediaType) {
                3 { $media = 'HDD' }
                4 { $media = 'SSD' }
                5 { $media = 'SCM' }
                default { $media = 'SSD/HDD' }
            }
        } elseif ($disk.Model -match 'SSD|NVMe|Solid State|eMMC') {
            $media = 'SSD'
        }
        $disks += "$($disk.Model.Trim()) ($sizeGB GB - $media)"
    }

    [PSCustomObject]@{
        Motherboard = $motherboard
        Cpu         = $cpuName
        CpuCores    = $cores
        CpuThreads  = $threads
        RamGB       = [Math]::Round($ramBytes / 1GB, 1)
        RamSpeed    = $ramSpeed
        RamSlots    = $ramSlots
        Gpu         = $gpuStr
        Disks       = if ($disks.Count) { $disks -join ', ' } else { $script:UnknownVi }
    }
}

# ============================================================================
# 2. THÔNG TIN BẢN QUYỀN WINDOWS / OFFICE
# ============================================================================

# Giải mã Product Key từ DigitalProductId trong registry (Windows 10/11).
function Get-DecodedRegistryKey {
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $dpid = (Get-ItemProperty -Path $regPath -Name 'DigitalProductId').DigitalProductId
        if (-not $dpid -or $dpid.Count -lt 67) { return 'Không tìm thấy' }

        $isWin8 = ([Math]::Truncate($dpid[66] / 6)) -band 1
        $dpid[66] = ($dpid[66] -band 0xF7) -bor (($isWin8 -band 2) * 4)

        $chars = 'BCDFGHJKMPQRTVWXY2346789'
        $keyOffset = 52
        $key = ''
        $last = 0
        for ($i = 24; $i -ge 0; $i--) {
            $current = 0
            for ($j = 14; $j -ge 0; $j--) {
                $current = $current * 256
                $current = $dpid[$j + $keyOffset] + $current
                $dpid[$j + $keyOffset] = [Math]::Truncate($current / 24)
                $current = $current % 24
            }
            $key = $chars[$current] + $key
            $last = $current
        }
        if ($isWin8 -eq 1) {
            $part1 = $key.Substring(1, $last)
            $part2 = $key.Substring($last + 1, $key.Length - ($last + 1))
            $key = $part1 + 'N' + $part2
        }
        $formatted = ''
        for ($i = 0; $i -lt 25; $i++) {
            $formatted += $key[$i]
            if (($i + 1) % 5 -eq 0 -and $i -ne 24) { $formatted += '-' }
        }
        return $formatted
    } catch {
        return 'Không thể giải mã (Registry bị ẩn)'
    }
}

function Get-WindowsLicenseInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $edition = if ($os) { $os.Caption.Trim() } else { $script:UnknownVi }

    $oemKey = 'Không tìm thấy'
    $oemRaw = (Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey
    if ($oemRaw -and $oemRaw.Trim()) { $oemKey = $oemRaw.Trim() }

    $info = [PSCustomObject]@{
        Edition      = $edition
        Status       = $script:UnknownVi
        Channel      = $script:UnknownVi
        IsKms        = $false
        IsKms38      = $false
        KmsServer    = ''
        GraceMinutes = 0
        OemKey       = $oemKey
        RegistryKey  = Get-DecodedRegistryKey
    }

    $filter = "ApplicationID = '$($script:WindowsAppId)' AND PartialProductKey IS NOT NULL"
    $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter |
           Where-Object { $_.LicenseStatus -eq 1 } | Select-Object -First 1
    if (-not $lic) {
        $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter | Select-Object -First 1
    }
    if (-not $lic) { return $info }

    $statusMap = @{
        0 = 'Chưa kích hoạt (Unlicensed)'
        1 = 'Đã kích hoạt (Licensed)'
        2 = 'Thời gian ân hạn (OOB Grace)'
        3 = 'Thời gian gia hạn (OOT Grace)'
        4 = 'Hết hạn ân hạn phi bản quyền (Non-Genuine Grace)'
        5 = 'Trạng thái thông báo (Notification)'
        6 = 'Thời gian gia hạn mở rộng (Extended Grace)'
    }
    $info.Status = $statusMap[[int]$lic.LicenseStatus]
    if (-not $info.Status) { $info.Status = 'Chưa kích hoạt' }

    switch -Wildcard ($lic.Description) {
        '*RETAIL*'     { $info.Channel = 'Retail Channel (Bán lẻ)'; break }
        '*OEM*'        { $info.Channel = 'OEM Channel (Nhà sản xuất)'; break }
        '*VOLUME_MAK*' { $info.Channel = 'Volume:MAK (Khóa kích hoạt nhiều lần)'; break }
        '*VOLUME_KMS*' { $info.Channel = 'Volume:GVLK (KMS Client)'; $info.IsKms = $true; break }
        default        { $info.Channel = 'Volume Channel (Doanh nghiệp)' }
    }
    if ($lic.KeyManagementServiceMachine) { $info.KmsServer = $lic.KeyManagementServiceMachine }

    $info.GraceMinutes = [int]$lic.GracePeriodRemaining
    if ($info.IsKms -and $info.GraceMinutes -gt 1000000) { $info.IsKms38 = $true }

    return $info
}

function Get-OfficeLicenseInfo {
    $products = @()
    $filter = "ApplicationID = '$($script:OfficeAppId)' AND PartialProductKey IS NOT NULL"
    foreach ($obj in (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter)) {
        $products += [PSCustomObject]@{
            Name      = $obj.Name
            Status    = if ($obj.LicenseStatus -eq 1) { 'Đã kích hoạt' } else { 'Chưa kích hoạt' }
            KmsServer = $obj.KeyManagementServiceMachine
        }
    }
    foreach ($obj in (Get-CimInstance -ClassName OfficeSoftwareProtectionProduct -Filter 'PartialProductKey IS NOT NULL')) {
        $products += [PSCustomObject]@{
            Name      = $obj.Name
            Status    = if ($obj.LicenseStatus -eq 1) { 'Đã kích hoạt' } else { 'Chưa kích hoạt' }
            KmsServer = $obj.KeyManagementServiceMachine
        }
    }
    return , $products
}

# ============================================================================
# 3. MODULE QUÉT: KÍCH HOẠT WINDOWS
# ============================================================================

function Invoke-WindowsActivationScan {
    param([Parameter(Mandatory)]$WinInfo)
    $findings = @()
    $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain

    # CHECK: máy chủ KMS cấu hình trong registry (Windows & Office)
    $kmsSources = @{
        Windows = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform')
        Office  = @(
            'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform'
        )
    }
    foreach ($source in $kmsSources.Keys) {
        $server = ''
        foreach ($path in $kmsSources[$source]) {
            if (Test-Path $path) {
                $val = (Get-ItemProperty -Path $path -Name 'KeyManagementServiceName').KeyManagementServiceName
                if ($val) { $server = $val; break }
            }
        }
        $findings += (Get-KmsServerFinding -Server $server -Source $source -DomainJoined $domainJoined)
    }

    # CHECK: KMS38 (gia hạn kích hoạt tới 2038)
    if ($WinInfo.IsKms38) {
        $findings += New-Finding -Category 'Windows' -Name 'Kích hoạt KMS38' -Status 'Detected' `
            -Details "Bản quyền kích hoạt bằng KMS38 (kéo dài thời gian dùng thử tới 19/01/2038, còn lại $($WinInfo.GraceMinutes) phút)." `
            -Evidence @("GracePeriodRemaining=$($WinInfo.GraceMinutes)")
    } else {
        $findings += New-Finding -Category 'Windows' -Name 'Kích hoạt KMS38' -Status 'Clean' `
            -Details 'Không phát hiện hack thời gian KMS38.'
    }

    # CHECK: KMS Hook DLL (SppExtComObjHook.dll)
    $hookFiles = @(
        (Join-Path $env:windir 'System32\SppExtComObjHook.dll'),
        (Join-Path $env:windir 'SppExtComObjHook.dll')
    )
    $findings += (Get-TamperFinding -Category 'Windows' -Name 'KMS Hook (SppExtComObjHook.dll)' `
        -Files $hookFiles -ExpectedSigner 'Microsoft' `
        -DetectedText 'Phát hiện DLL hook hệ thống dùng để bẻ khóa kích hoạt Windows.' `
        -CleanText 'Không phát hiện file hook SppExtComObjHook.dll.')

    # CHECK: IFEO Debugger Hijack
    $ifeoPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SppExtComObj.exe',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osppsvc.exe'
    )
    $ifeoHits = @()
    foreach ($path in $ifeoPaths) {
        if (-not (Test-Path $path)) { continue }
        $props = Get-ItemProperty -Path $path
        if ($props.Debugger -or $props.VerifierDlls -or $props.MonitorProcess) {
            $val = if ($props.Debugger) { "Debugger=$($props.Debugger)" } else { "VerifierDlls=$($props.VerifierDlls)" }
            $ifeoHits += "$(Split-Path $path -Leaf): $val"
        }
    }
    if ($ifeoHits.Count) {
        $findings += New-Finding -Category 'Windows' -Name 'IFEO Debugger Hijack' -Status 'Detected' `
            -Details 'Phát hiện chuyển hướng tiến trình kích hoạt qua Image File Execution Options - kỹ thuật bẻ khóa bản quyền.' `
            -Evidence $ifeoHits
    } else {
        $findings += New-Finding -Category 'Windows' -Name 'IFEO Debugger Hijack' -Status 'Clean' `
            -Details 'Không phát hiện khóa chuyển hướng tiến trình kích hoạt.'
    }

    # CHECK: Scheduled Task ẩn của công cụ crack
    $suspiciousTaskNames = @('AutoKMS', 'KMSAuto', 'KMSConnectionMonitor', 'KMS-Activator', 'MAS_KMS', 'KMSeldi')
    $taskHits = @()
    foreach ($task in (Get-ScheduledTask)) {
        $match = $suspiciousTaskNames | Where-Object { $task.TaskName -like "*$_*" }
        if (-not $match) {
            $execStr = ($task.Actions.Execute -join ' ').ToLower()
            $match = $suspiciousTaskNames | Where-Object { $execStr -like "*$($_.ToLower())*" }
        }
        if ($match) { $taskHits += "$($task.TaskPath)$($task.TaskName)" }
    }
    if ($taskHits.Count) {
        $findings += New-Finding -Category 'Windows' -Name 'Tác vụ tự động gia hạn kích hoạt' -Status 'Detected' `
            -Details 'Phát hiện scheduled task của công cụ crack.' -Evidence $taskHits
    } else {
        $findings += New-Finding -Category 'Windows' -Name 'Tác vụ tự động gia hạn kích hoạt' -Status 'Clean' `
            -Details 'Không phát hiện tác vụ tự động gia hạn KMS lậu.'
    }

    # CHECK: Windows service của công cụ crack
    $suspiciousServices = @('AutoKMS', 'KMSpico Service', 'KMSeldi')
    $svcHits = @()
    foreach ($name in $suspiciousServices) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue }
        if ($svc) { $svcHits += "$($svc.Name) ($($svc.Status))" }
    }
    if ($svcHits.Count) {
        $findings += New-Finding -Category 'Windows' -Name 'Dịch vụ crack chạy ngầm' -Status 'Detected' `
            -Details 'Phát hiện dịch vụ bẻ khóa bản quyền.' -Evidence $svcHits
    } else {
        $findings += New-Finding -Category 'Windows' -Name 'Dịch vụ crack chạy ngầm' -Status 'Clean' `
            -Details 'Không phát hiện dịch vụ bẻ khóa chạy ngầm.'
    }

    return $findings
}

function Get-KmsServerFinding {
    param([string]$Server, [string]$Source, [bool]$DomainJoined)
    if (-not $Server -or -not $Server.Trim()) {
        return New-Finding -Category 'Windows' -Name "Máy chủ KMS ($Source)" -Status 'Clean' `
            -Details 'Không cấu hình máy chủ KMS ngoài.'
    }
    $srv = $Server.ToLower().Trim()
    if ($srv -in @('127.0.0.1', 'localhost', '::1')) {
        return New-Finding -Category 'Windows' -Name "Máy chủ KMS ($Source)" -Status 'Detected' `
            -Details "Cấu hình KMS nội bộ (loopback: $Server) - dấu hiệu KMS Emulator cục bộ." -Evidence @($Server)
    }
    if (-not $DomainJoined) {
        return New-Finding -Category 'Windows' -Name "Máy chủ KMS ($Source)" -Status 'Warning' `
            -Details "Cấu hình KMS server từ xa ($Server) nhưng máy không thuộc Domain - có thể là KMS công cộng." -Evidence @($Server)
    }
    return New-Finding -Category 'Windows' -Name "Máy chủ KMS ($Source)" -Status 'Info' `
        -Details "Dùng KMS doanh nghiệp ($Server) qua kết nối Domain." -Evidence @($Server)
}

# Hàm dùng chung: kiểm tra danh sách file có bị vá/giả mạo chữ ký không.
function Get-TamperFinding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Files,
        [string]$ExpectedSigner = 'Microsoft',
        [Parameter(Mandatory)][string]$DetectedText,
        [Parameter(Mandatory)][string]$CleanText
    )
    $evidence = @()
    foreach ($file in $Files) {
        $trust = Get-BinaryTrust -Path $file -ExpectedSigner $ExpectedSigner
        if ($null -eq $trust) { continue }
        if (-not $trust.Trusted) {
            $evidence += "$file [chữ ký: $($trust.SigStatus)]"
        }
    }
    if ($evidence.Count) {
        return New-Finding -Category $Category -Name $Name -Status 'Detected' -Details $DetectedText -Evidence $evidence
    }
    return New-Finding -Category $Category -Name $Name -Status 'Clean' -Details $CleanText
}

# ============================================================================
# 3b. MODULE QUÉT: OFFICE OHOOK
# ============================================================================

function Invoke-OfficeActivationScan {
    $paths = @(
        (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\System\sppc.dll')
    )
    if (${env:ProgramFiles(x86)}) {
        $paths += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\vfs\System\sppc.dll')
    }
    return Get-TamperFinding -Category 'Office' -Name 'Office Ohook (sppc.dll)' `
        -Files $paths -ExpectedSigner 'Microsoft' `
        -DetectedText 'Phát hiện sppc.dll giả mạo trong thư mục Office (kỹ thuật Ohook kích hoạt lậu Office). sppc.dll hợp lệ chỉ nằm trong System32.' `
        -CleanText 'Không phát hiện Ohook sppc.dll trong thư mục Office.'
}

# ============================================================================
# 3c. MODULE QUÉT: INTERNET DOWNLOAD MANAGER (IDM)
# ============================================================================

function Invoke-IdmScan {
    param([object[]]$HostsEntries)
    $findings = @()

    $idmPaths = @()
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) { $idmPaths += (Join-Path $base 'Internet Download Manager\IDMan.exe') }
    }
    $installed = $idmPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if (-not $installed) {
        return @(New-Finding -Category 'IDM' -Name 'Internet Download Manager' -Status 'Clean' `
            -Details 'Không phát hiện IDM cài trên máy.')
    }

    # 1) Binary IDMan.exe phải được ký bởi Tonec Inc. - bản vá sẽ hỏng chữ ký.
    $trust = Get-BinaryTrust -Path $installed -ExpectedSigner 'Tonec'
    if ($trust -and -not $trust.Trusted) {
        $findings += New-Finding -Category 'IDM' -Name 'IDMan.exe bị vá' -Status 'Detected' `
            -Details "IDMan.exe không còn chữ ký số hợp lệ của Tonec Inc. - dấu hiệu file thực thi bị patch/crack." `
            -Evidence @("$installed [chữ ký: $($trust.SigStatus)]")
    } else {
        $findings += New-Finding -Category 'IDM' -Name 'IDMan.exe bị vá' -Status 'Clean' `
            -Details 'IDMan.exe giữ nguyên chữ ký số hợp lệ của Tonec Inc.'
    }

    # 2) Hosts chặn máy chủ đăng ký của IDM/Tonec (crack chặn kiểm tra bản quyền).
    $blocked = @(Find-BlockedDomains -HostsEntries $HostsEntries -Domains $script:LicenseDomains.IDM)
    if ($blocked.Count) {
        $findings += New-Finding -Category 'IDM' -Name 'Chặn máy chủ đăng ký IDM' -Status 'Detected' `
            -Details 'File hosts đang chặn máy chủ đăng ký của Tonec/IDM để né kiểm tra bản quyền.' -Evidence $blocked
    }

    # 3) Tường lửa chặn outbound IDMan.exe (thường đi kèm crack).
    $fw = @(Find-OutboundBlockRule -ExeNames @('IDMan.exe'))
    if ($fw.Count) {
        $findings += New-Finding -Category 'IDM' -Name 'Tường lửa chặn IDMan.exe' -Status 'Warning' `
            -Details 'Có rule tường lửa chặn IDM kết nối ra ngoài - thường dùng để ngăn IDM xác thực bản quyền.' -Evidence $fw
    }

    # 4) Registry đăng ký đáng ngờ (fake serial).
    $regPath = 'HKCU:\Software\DownloadManager'
    if (Test-Path $regPath) {
        $p = Get-ItemProperty -Path $regPath
        if ($p.Serial -and ($p.PSObject.Properties.Name -contains 'scansk')) {
            $findings += New-Finding -Category 'IDM' -Name 'Registry đăng ký IDM đáng ngờ' -Status 'Warning' `
                -Details 'IDM đã đăng ký kèm khóa "scansk" - mẫu thường thấy ở fake serial/crack. Hãy đối chiếu với hóa đơn mua bản quyền.' `
                -Evidence @("$regPath\Serial", "$regPath\scansk")
        }
    }

    return , $findings
}

# ============================================================================
# 3d. MODULE QUÉT: WINRAR
# ============================================================================

function Invoke-WinrarScan {
    $installDirs = @()
    $regExe = (Get-ItemProperty 'HKLM:\SOFTWARE\WinRAR' -Name 'exe64' -ErrorAction SilentlyContinue).exe64
    if (-not $regExe) {
        $regExe = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\WinRAR' -Name 'exe32' -ErrorAction SilentlyContinue).exe32
    }
    if ($regExe) { $installDirs += (Split-Path $regExe -Parent) }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) { $installDirs += (Join-Path $base 'WinRAR') }
    }
    $installDirs = $installDirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    if (-not $installDirs) {
        return @(New-Finding -Category 'WinRAR' -Name 'WinRAR' -Status 'Clean' -Details 'Không phát hiện WinRAR cài trên máy.')
    }

    foreach ($dir in $installDirs) {
        $keyFile = Join-Path $dir 'rarreg.key'
        if (Test-Path -LiteralPath $keyFile) {
            $registeredTo = ''
            $lines = @(Get-Content -LiteralPath $keyFile -TotalCount 3)
            if ($lines.Count -ge 2) { $registeredTo = $lines[1].Trim() }
            # WinRAR không thực sự cần crack (vẫn chạy sau thời gian dùng thử); rarreg.key
            # có thể là bản quyền mua hợp lệ HOẶC khóa bị chia sẻ/rò rỉ => cảnh báo để rà soát.
            return @(New-Finding -Category 'WinRAR' -Name 'WinRAR đăng ký bằng rarreg.key' -Status 'Warning' `
                -Details "Phát hiện file bản quyền rarreg.key (đăng ký cho: '$registeredTo'). Cần xác minh đây là license mua hợp lệ, không phải khóa chia sẻ/lậu." `
                -Evidence @($keyFile))
        }
    }
    return @(New-Finding -Category 'WinRAR' -Name 'WinRAR' -Status 'Info' `
        -Details 'WinRAR đã cài nhưng không có rarreg.key (bản dùng thử/chưa đăng ký).')
}

# ============================================================================
# 3e. MODULE QUÉT: ADOBE
# ============================================================================

function Invoke-AdobeScan {
    param([object[]]$HostsEntries)
    $findings = @()

    $adobeRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles) |
        Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Adobe' } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique

    if (-not $adobeRoots -and -not (Get-Service -DisplayName '*Adobe*' -ErrorAction SilentlyContinue)) {
        return @(New-Finding -Category 'Adobe' -Name 'Adobe' -Status 'Clean' -Details 'Không phát hiện sản phẩm Adobe trên máy.')
    }

    # 1) Hosts chặn máy chủ kích hoạt/genuine của Adobe (dấu hiệu crack kinh điển).
    $blocked = @(Find-BlockedDomains -HostsEntries $HostsEntries -Domains $script:LicenseDomains.Adobe)
    if ($blocked.Count) {
        $findings += New-Finding -Category 'Adobe' -Name 'Chặn máy chủ kích hoạt Adobe' -Status 'Detected' `
            -Details 'File hosts đang chặn máy chủ license/genuine của Adobe - kỹ thuật thường dùng để bẻ khóa Adobe.' -Evidence $blocked
    }

    # 2) amtlib.dll bị vá (AMT Emulator / amtemu) trong thư mục Adobe.
    $patchedAmt = @()
    foreach ($root in $adobeRoots) {
        foreach ($dll in (Get-ChildItem -LiteralPath $root -Filter 'amtlib.dll' -Recurse -ErrorAction SilentlyContinue)) {
            $trust = Get-BinaryTrust -Path $dll.FullName -ExpectedSigner 'Adobe'
            if ($trust -and -not $trust.Trusted) {
                $patchedAmt += "$($dll.FullName) [chữ ký: $($trust.SigStatus)]"
            }
        }
    }
    if ($patchedAmt.Count) {
        $findings += New-Finding -Category 'Adobe' -Name 'amtlib.dll bị vá' -Status 'Detected' `
            -Details 'Phát hiện amtlib.dll không có chữ ký hợp lệ của Adobe - dấu hiệu AMT Emulator/crack.' -Evidence $patchedAmt
    }

    # 3) Artifact của công cụ crack Adobe (GenP, amtemu...).
    $crackArtifacts = @()
    foreach ($root in $adobeRoots) {
        foreach ($pattern in @('amtemu*.exe', 'GenP*.exe', '*Adobe*GenP*')) {
            $crackArtifacts += (Get-ChildItem -LiteralPath $root -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName)
        }
    }
    if ($crackArtifacts.Count) {
        $findings += New-Finding -Category 'Adobe' -Name 'Công cụ crack Adobe' -Status 'Detected' `
            -Details 'Phát hiện tập tin của công cụ bẻ khóa Adobe (GenP/AMT Emulator).' -Evidence ($crackArtifacts | Select-Object -Unique)
    }

    # 4) Adobe Genuine Service bị vô hiệu hóa trong khi Adobe đã cài.
    $ags = Get-Service -Name 'AGSService', 'AGMService' -ErrorAction SilentlyContinue
    $fwAdobe = @(Find-OutboundBlockRule -ExeNames @('AdobeGCClient.exe', 'AdobeIPCBroker.exe', 'Adobe Desktop Service.exe'))
    if ($fwAdobe.Count) {
        $findings += New-Finding -Category 'Adobe' -Name 'Tường lửa chặn dịch vụ Adobe' -Status 'Warning' `
            -Details 'Có rule tường lửa chặn dịch vụ Adobe kết nối ra ngoài - thường dùng để né kiểm tra bản quyền.' -Evidence $fwAdobe
    }
    if ($ags -and ($ags | Where-Object { $_.StartType -eq 'Disabled' })) {
        $disabled = $ags | Where-Object { $_.StartType -eq 'Disabled' } | ForEach-Object { $_.Name }
        $findings += New-Finding -Category 'Adobe' -Name 'Adobe Genuine Service bị tắt' -Status 'Warning' `
            -Details 'Dịch vụ Adobe Genuine bị vô hiệu hóa - có thể do crack chặn kiểm tra bản quyền.' -Evidence $disabled
    }

    if (-not $findings.Count) {
        $findings += New-Finding -Category 'Adobe' -Name 'Adobe' -Status 'Clean' `
            -Details 'Đã cài Adobe nhưng không phát hiện dấu hiệu crack.'
    }
    return , $findings
}

# ============================================================================
# 3f. GO BO CRACK (CLEANUP ACTIONS) - go dung nhung gi cac ham quet o tren phat hien
# ============================================================================

function New-Action {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Applicable,
        [Parameter(Mandatory)][string]$Details,
        [string]$Risk = 'Safe',   # Safe | Warning | Risky
        [scriptblock]$ApplyAction
    )
    [PSCustomObject]@{
        Category    = $Category
        Name        = $Name
        Applicable  = $Applicable
        Details     = $Details
        Risk        = $Risk
        ApplyAction = $ApplyAction
    }
}

function Get-CleanupActions {
    param([bool]$IncludeWarnings, [bool]$RemoveAdobePatchedDll)

    $actions = @()
    $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain

    # --- Windows KMS registry (loopback = chac chan la crack) ---
    $winKmsPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    if (Test-Path $winKmsPath) {
        $srv = (Get-ItemProperty -Path $winKmsPath -Name 'KeyManagementServiceName').KeyManagementServiceName
        if ($srv) {
            $isLoopback = $srv.ToLower().Trim() -in @('127.0.0.1', 'localhost', '::1')
            $risk = if ($isLoopback) { 'Safe' } else { 'Warning' }
            $applicable = $isLoopback -or $IncludeWarnings
            $actions += New-Action -Category 'Windows' -Name 'Windows KMS server registry' -Risk $risk `
                -Applicable $applicable `
                -Details "Gia tri hien tai: $srv $(if ($isLoopback) {'(loopback - crack)'} elseif (-not $domainJoined) {'(khong Domain - nghi ngo)'} else {'(co Domain - co the hop le)'})" `
                -ApplyAction {
                    Remove-ItemProperty -Path $winKmsPath -Name 'KeyManagementServiceName' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $winKmsPath -Name 'KeyManagementServicePort' -ErrorAction SilentlyContinue
                    cscript //B //nologo "$env:windir\system32\slmgr.vbs" /ckms | Out-Null
                }
        }
    }

    # --- Office KMS registry ---
    $officeKmsPaths = @(
        'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform'
    )
    foreach ($p in $officeKmsPaths) {
        if (Test-Path $p) {
            $srv = (Get-ItemProperty -Path $p -Name 'KeyManagementServiceName').KeyManagementServiceName
            if ($srv) {
                $isLoopback = $srv.ToLower().Trim() -in @('127.0.0.1', 'localhost', '::1')
                $risk = if ($isLoopback) { 'Safe' } else { 'Warning' }
                $applicable = $isLoopback -or $IncludeWarnings
                $actions += New-Action -Category 'Office' -Name "Office KMS server registry ($p)" -Risk $risk `
                    -Applicable $applicable `
                    -Details "Gia tri hien tai: $srv" `
                    -ApplyAction {
                        param($regPath = $p)
                        Remove-ItemProperty -Path $regPath -Name 'KeyManagementServiceName' -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'KeyManagementServicePort' -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
    }

    # --- Office: go OSPP KMS host + product key da nap (neu tim thay ospp.vbs) ---
    $osppDir = $null
    foreach ($ver in @('Office16', 'Office15', 'Office14')) {
        foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ($base) {
                $cand = Join-Path $base "Microsoft Office\$ver"
                if (Test-Path (Join-Path $cand 'ospp.vbs')) { $osppDir = $cand; break }
            }
        }
        if ($osppDir) { break }
    }
    if ($osppDir) {
        $actions += New-Action -Category 'Office' -Name 'Go KMS host + product key qua ospp.vbs' -Risk 'Safe' `
            -Applicable $true -Details "Tim thay ospp.vbs tai: $osppDir" `
            -ApplyAction {
                param($dir = $osppDir)
                Push-Location $dir
                cscript //B //nologo ospp.vbs /remhst | Out-Null
                Pop-Location
            }.GetNewClosure()
    }

    # --- KMS Hook DLL (SppExtComObjHook.dll) ---
    $hookFiles = @(
        (Join-Path $env:windir 'System32\SppExtComObjHook.dll'),
        (Join-Path $env:windir 'SppExtComObjHook.dll')
    )
    foreach ($f in $hookFiles) {
        if (Test-Path -LiteralPath $f) {
            $trust = Get-BinaryTrust -Path $f -ExpectedSigner 'Microsoft'
            if ($trust -and -not $trust.Trusted) {
                $actions += New-Action -Category 'Windows' -Name "KMS Hook DLL: $f" -Risk 'Safe' `
                    -Applicable $true -Details "Chu ky: $($trust.SigStatus)" `
                    -ApplyAction {
                        param($file = $f)
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
    }

    # --- Office Ohook (sppc.dll trong thu muc Office) ---
    $officeSppc = @()
    if ($env:ProgramFiles) { $officeSppc += (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\System\sppc.dll') }
    if (${env:ProgramFiles(x86)}) { $officeSppc += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\root\vfs\System\sppc.dll') }
    foreach ($f in $officeSppc) {
        if (Test-Path -LiteralPath $f) {
            $trust = Get-BinaryTrust -Path $f -ExpectedSigner 'Microsoft'
            if ($trust -and -not $trust.Trusted) {
                $actions += New-Action -Category 'Office' -Name "Office Ohook: $f" -Risk 'Safe' `
                    -Applicable $true -Details "Chu ky: $($trust.SigStatus)" `
                    -ApplyAction {
                        param($file = $f)
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
    }

    # --- IFEO Debugger Hijack ---
    $ifeoPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SppExtComObj.exe',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osppsvc.exe'
    )
    foreach ($p in $ifeoPaths) {
        if (Test-Path $p) {
            $props = Get-ItemProperty -Path $p
            if ($props.Debugger -or $props.VerifierDlls -or $props.MonitorProcess) {
                $actions += New-Action -Category 'Windows' -Name "IFEO hijack: $(Split-Path $p -Leaf)" -Risk 'Safe' `
                    -Applicable $true -Details "Registry key: $p" `
                    -ApplyAction {
                        param($regPath = $p)
                        Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
    }

    # --- Scheduled tasks cua cong cu crack ---
    $suspiciousTaskNames = @(
        'AutoKMS', 'KMSAuto', 'KMSConnectionMonitor', 'KMS-Activator', 'MAS_KMS', 'KMSeldi',
        'Activation-Renewal', 'Online_KMS_Activation_Script-Renewal', 'Activation-Run_Once', 'KMS_VL_ALL'
    )
    foreach ($task in (Get-ScheduledTask)) {
        $match = $suspiciousTaskNames | Where-Object { $task.TaskName -like "*$_*" }
        if (-not $match) {
            $execStr = ($task.Actions.Execute -join ' ').ToLower()
            $match = $suspiciousTaskNames | Where-Object { $execStr -like "*$($_.ToLower())*" }
        }
        if ($match) {
            $taskPath = $task.TaskPath; $taskName = $task.TaskName
            $actions += New-Action -Category 'Windows' -Name "Scheduled task: $taskPath$taskName" -Risk 'Safe' `
                -Applicable $true -Details 'Task tu dong gia han kich hoat lau' `
                -ApplyAction {
                    param($tPath = $taskPath, $tName = $taskName)
                    Unregister-ScheduledTask -TaskName $tName -TaskPath $tPath -Confirm:$false -ErrorAction SilentlyContinue
                }.GetNewClosure()
        }
    }

    # --- Windows services cua cong cu crack ---
    $suspiciousServices = @('AutoKMS', 'KMSpico Service', 'KMSeldi', 'KMSELDI')
    foreach ($name in $suspiciousServices) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue }
        if ($svc) {
            $svcName = $svc.Name
            $actions += New-Action -Category 'Windows' -Name "Service: $svcName" -Risk 'Safe' `
                -Applicable $true -Details "Trang thai hien tai: $($svc.Status)" `
                -ApplyAction {
                    param($sName = $svcName)
                    Stop-Service -Name $sName -Force -ErrorAction SilentlyContinue
                    sc.exe delete $sName | Out-Null
                }.GetNewClosure()
        }
    }

    # --- Thu muc du lieu cua cong cu crack (Digital & Online Activation Script) ---
    $crackFolders = @(
        'C:\ProgramData\Activation-Renewal',
        'C:\ProgramData\Online_KMS_Activation'
    )
    foreach ($folder in $crackFolders) {
        if (Test-Path -LiteralPath $folder) {
            $actions += New-Action -Category 'Windows' -Name "Thu muc crack: $folder" -Risk 'Safe' `
                -Applicable $true -Details 'Thu muc du lieu cua cong cu KMS activation script' `
                -ApplyAction {
                    param($f = $folder)
                    takeown /f $f /r /d y | Out-Null
                    icacls $f /grant administrators:F /t | Out-Null
                    Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue
                }.GetNewClosure()
        }
    }

    # --- Hosts file: go dong chan Adobe/IDM ---
    $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    $hostsEntries = Get-HostsEntries
    $allDomains = $script:LicenseDomains.Adobe + $script:LicenseDomains.IDM
    $blockedLines = @()
    foreach ($entry in $hostsEntries) {
        if ($entry.IP -notin @('0.0.0.0', '127.0.0.1', '::1')) { continue }
        foreach ($dom in $allDomains) {
            if ($entry.Hostname -like "*$dom*") { $blockedLines += $entry.LineNumber; break }
        }
    }
    if ($blockedLines.Count) {
        $actions += New-Action -Category 'Adobe/IDM' -Name 'Hosts file chan may chu ban quyen' -Risk 'Safe' `
            -Applicable $true -Details "$($blockedLines.Count) dong bi chan (se sao luu hosts truoc khi sua)" `
            -ApplyAction {
                param($path = $hostsPath, $lines = $blockedLines)
                $backup = "$path.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                Copy-Item -LiteralPath $path -Destination $backup -Force
                $content = Get-Content -LiteralPath $path
                $kept = for ($i = 0; $i -lt $content.Count; $i++) { if (($i + 1) -notin $lines) { $content[$i] } }
                Set-Content -LiteralPath $path -Value $kept -Encoding ASCII
            }.GetNewClosure()
    }

    # --- Firewall rules chan Adobe/IDM ---
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        $exeTargets = @('IDMan.exe', 'AdobeGCClient.exe', 'AdobeIPCBroker.exe', 'Adobe Desktop Service.exe')
        try {
            $rules = Get-NetFirewallRule -Enabled True -Direction Outbound -Action Block -ErrorAction Stop
            foreach ($rule in $rules) {
                $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                if (-not $app -or -not $app.Program) { continue }
                $hit = $exeTargets | Where-Object { $app.Program -like "*$_*" }
                if ($hit) {
                    $ruleName = $rule.DisplayName; $ruleId = $rule.Name
                    $actions += New-Action -Category 'Adobe/IDM' -Name "Firewall rule chan: $ruleName" -Risk 'Safe' `
                        -Applicable $true -Details "Chan: $($app.Program)" `
                        -ApplyAction {
                            param($rId = $ruleId)
                            Remove-NetFirewallRule -Name $rId -ErrorAction SilentlyContinue
                        }.GetNewClosure()
                }
            }
        } catch { }
    }

    # --- IDM: registry dang ky dang ngo (fake serial) ---
    $idmRegPath = 'HKCU:\Software\DownloadManager'
    if (Test-Path $idmRegPath) {
        $p = Get-ItemProperty -Path $idmRegPath
        if ($p.Serial -and ($p.PSObject.Properties.Name -contains 'scansk')) {
            $actions += New-Action -Category 'IDM' -Name 'IDM registry fake serial (scansk)' -Risk 'Safe' `
                -Applicable $true -Details 'Go Serial/scansk de tro ve trang thai chua dang ky' `
                -ApplyAction {
                    Remove-ItemProperty -Path $idmRegPath -Name 'Serial' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $idmRegPath -Name 'scansk' -ErrorAction SilentlyContinue
                }
        }
    }

    # --- WinRAR: rarreg.key (tro ve ban dung thu, khuyen mua ban quyen that) ---
    $winrarDirs = @()
    $regExe = (Get-ItemProperty 'HKLM:\SOFTWARE\WinRAR' -Name 'exe64' -ErrorAction SilentlyContinue).exe64
    if (-not $regExe) { $regExe = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\WinRAR' -Name 'exe32' -ErrorAction SilentlyContinue).exe32 }
    if ($regExe) { $winrarDirs += (Split-Path $regExe -Parent) }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($base) { $winrarDirs += (Join-Path $base 'WinRAR') } }
    foreach ($dir in ($winrarDirs | Select-Object -Unique)) {
        $keyFile = Join-Path $dir 'rarreg.key'
        if (Test-Path -LiteralPath $keyFile) {
            $actions += New-Action -Category 'WinRAR' -Name "rarreg.key: $keyFile" -Risk 'Warning' `
                -Applicable $IncludeWarnings -Details 'CANH BAO: co the la license mua hop le. Chi go neu chac chan la lau/chia se.' `
                -ApplyAction {
                    param($f = $keyFile)
                    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                }.GetNewClosure()
        }
    }

    # --- Adobe: artifact cua cong cu crack (GenP/amtemu) ---
    $adobeRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles) |
        Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Adobe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique
    foreach ($root in $adobeRoots) {
        foreach ($pattern in @('amtemu*.exe', 'GenP*.exe', '*Adobe*GenP*')) {
            foreach ($f in (Get-ChildItem -LiteralPath $root -Filter $pattern -Recurse -ErrorAction SilentlyContinue)) {
                $fPath = $f.FullName
                $actions += New-Action -Category 'Adobe' -Name "Cong cu crack: $fPath" -Risk 'Safe' `
                    -Applicable $true -Details 'File cua cong cu bam khoa Adobe' `
                    -ApplyAction {
                        param($file = $fPath)
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
        # amtlib.dll bi va - CHI go neu duoc bat rieng, vi day la thay doi manh
        foreach ($dll in (Get-ChildItem -LiteralPath $root -Filter 'amtlib.dll' -Recurse -ErrorAction SilentlyContinue)) {
            $trust = Get-BinaryTrust -Path $dll.FullName -ExpectedSigner 'Adobe'
            if ($trust -and -not $trust.Trusted) {
                $dllPath = $dll.FullName
                $actions += New-Action -Category 'Adobe' -Name "amtlib.dll bi va: $dllPath" -Risk 'Risky' `
                    -Applicable ([bool]$RemoveAdobePatchedDll) `
                    -Details 'CANH BAO: xoa file nay co the lam ung dung Adobe khong mo duoc. Sau khi xoa, hay Repair/cai lai qua Creative Cloud.' `
                    -ApplyAction {
                        param($file = $dllPath)
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }.GetNewClosure()
            }
        }
    }

    return , $actions
}

# ============================================================================
# 4. LỚP ĐIỀU PHỐI (ORCHESTRATION)
# ============================================================================

function Invoke-FullScan {
    $hostsEntries = @(Get-HostsEntries)
    $winInfo = Get-WindowsLicenseInfo
    $officeInfo = Get-OfficeLicenseInfo

    $findings = @()
    $findings += Invoke-WindowsActivationScan -WinInfo $winInfo
    $findings += Invoke-OfficeActivationScan
    $findings += Invoke-IdmScan -HostsEntries $hostsEntries
    $findings += Invoke-WinrarScan
    $findings += Invoke-AdobeScan -HostsEntries $hostsEntries

    [PSCustomObject]@{
        GeneratedAt = (Get-Date).ToString('s')
        Computer    = $env:COMPUTERNAME
        IsAdmin     = Test-IsAdministrator
        Hardware    = Get-HardwareInfo
        Windows     = $winInfo
        Office      = $officeInfo
        Findings    = $findings
        Summary     = [PSCustomObject]@{
            Detected = @($findings | Where-Object { $_.Status -eq 'Detected' }).Count
            Warning  = @($findings | Where-Object { $_.Status -eq 'Warning' }).Count
            Clean    = @($findings | Where-Object { $_.Status -eq 'Clean' }).Count
        }
    }
}

# ============================================================================
# 5. LỚP HIỂN THỊ
# ============================================================================

function Get-MaskedKey {
    param([string]$Key)
    if ($Key -eq 'Không tìm thấy' -or $Key -like '*Không thể*') { return $Key }
    if ($Key -like 'BBBBB-BBBBB-BBBBB-BBBBB-BBBBB*') { return $Key }   # Digital License mặc định
    if ($Key.Length -eq 29) { return "XXXXX-XXXXX-XXXXX-XXXXX-" + $Key.Substring(24, 5) }
    return 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
}

function Write-Banner {
    Write-Host '========================================================================' -ForegroundColor Gray
    Write-Host '   _  __   ____ _               _    _     _                          ' -ForegroundColor Cyan
    Write-Host '  | |/ /  / ___| |__   ___  ___| | _| |   (_) ___ ___ _ __  ___  ___  ' -ForegroundColor Cyan
    Write-Host "  | ' /  | |   | '_ \ / _ \/ __| |/ / |   | |/ __/ _ \ '_ \/ __|/ _ \ " -ForegroundColor Cyan
    Write-Host '  | . \  | |___| | | |  __/ (__|   <| |___| | (_|  __/ | | \__ \  __/ ' -ForegroundColor Cyan
    Write-Host '  |_|\_\  \____|_| |_|\___|\___|_|\_\_____|_|\___\___|_| |_|___/\___| ' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  KCheckLicense v$($script:Version) (Build $($script:Build) - $($script:BuildDate)) - Kiem tra & go bo crack" -ForegroundColor White
    Write-Host '  Windows / Office / IDM / WinRAR / Adobe' -ForegroundColor DarkGray
    Write-Host '  Developed by TuanNgoVN  -  https://kollersi.com' -ForegroundColor DarkGray
    Write-Host '========================================================================' -ForegroundColor Gray
    Write-Host ''
}

function Show-Report {
    param([Parameter(Mandatory)]$Report, [bool]$RevealKeys)

    Clear-Host
    Write-Banner

    $hw = $Report.Hardware
    Write-Host '[I. THONG TIN PHAN CUNG]' -ForegroundColor Cyan
    Write-Host '  - Mainboard   : ' -NoNewline; Write-Host (Remove-Diacritics $hw.Motherboard) -ForegroundColor White
    Write-Host '  - CPU         : ' -NoNewline; Write-Host (Remove-Diacritics "$($hw.Cpu) ($($hw.CpuCores) cores / $($hw.CpuThreads) threads)") -ForegroundColor White
    Write-Host '  - RAM         : ' -NoNewline; Write-Host (Remove-Diacritics "$($hw.RamGB) GB ($($hw.RamSpeed) MHz, $($hw.RamSlots) thanh)") -ForegroundColor White
    Write-Host '  - GPU         : ' -NoNewline; Write-Host (Remove-Diacritics $hw.Gpu) -ForegroundColor White
    Write-Host '  - O luu tru   : ' -NoNewline; Write-Host (Remove-Diacritics $hw.Disks) -ForegroundColor White
    Write-Host ''

    $win = $Report.Windows
    Write-Host '[II. BAN QUYEN HE THONG]' -ForegroundColor Cyan
    Write-Host '  - Windows              : ' -NoNewline; Write-Host (Remove-Diacritics $win.Edition) -ForegroundColor White
    Write-Host '  - Trang thai kich hoat : ' -NoNewline
    if ($win.Status -like '*Đã kích hoạt*') { Write-Host (Remove-Diacritics $win.Status) -ForegroundColor Green } else { Write-Host (Remove-Diacritics $win.Status) -ForegroundColor Red }
    Write-Host '  - Kenh phan phoi       : ' -NoNewline; Write-Host (Remove-Diacritics $win.Channel) -ForegroundColor White

    $oem = if ($RevealKeys) { $win.OemKey } else { Get-MaskedKey $win.OemKey }
    $reg = if ($RevealKeys) { $win.RegistryKey } else { Get-MaskedKey $win.RegistryKey }
    Write-Host '  - Product Key (BIOS)   : ' -NoNewline
    Write-Host (Remove-Diacritics $oem) -ForegroundColor $(if ($win.OemKey -eq 'Không tìm thấy') { 'DarkGray' } else { 'Yellow' })
    Write-Host '  - Product Key (Reg)    : ' -NoNewline
    Write-Host (Remove-Diacritics $reg) -ForegroundColor $(if ($win.RegistryKey -like '*Không thể*') { 'DarkGray' } else { 'Yellow' })

    if ($Report.Office.Count) {
        Write-Host '  - Microsoft Office     :' -ForegroundColor Cyan
        foreach ($off in $Report.Office) {
            Write-Host "    - $(Remove-Diacritics $off.Name) : " -NoNewline
            if ($off.Status -eq 'Đã kích hoạt') { Write-Host (Remove-Diacritics $off.Status) -ForegroundColor Green -NoNewline } else { Write-Host (Remove-Diacritics $off.Status) -ForegroundColor Red -NoNewline }
            if ($off.KmsServer) { Write-Host " (KMS: $($off.KmsServer))" -ForegroundColor Yellow } else { Write-Host ' (kenh chinh chu)' -ForegroundColor Gray }
        }
    } else {
        Write-Host '  - Microsoft Office     : ' -NoNewline; Write-Host 'Khong phat hien Office co ban quyen' -ForegroundColor DarkGray
    }
    Write-Host ''

    Write-Host '[III. KET QUA QUET CRACK / HACKTOOL]' -ForegroundColor Cyan
    $lastCategory = ''
    foreach ($f in ($Report.Findings | Sort-Object Category)) {
        if ($f.Category -ne $lastCategory) {
            Write-Host "  -- $($f.Category) --" -ForegroundColor DarkCyan
            $lastCategory = $f.Category
        }
        switch ($f.Status) {
            'Clean'    { $label = '[ SACH      ]'; $color = 'Green' }
            'Info'     { $label = '[ THONG TIN ]'; $color = 'Gray' }
            'Warning'  { $label = '[ CANH BAO  ]'; $color = 'Yellow' }
            'Detected' { $label = '[ PHAT HIEN ]'; $color = 'Red' }
        }
        Write-Host "  $label " -ForegroundColor $color -NoNewline
        Write-Host (Remove-Diacritics "$($f.Name): $($f.Details)") -ForegroundColor $(if ($f.Status -eq 'Clean') { 'White' } else { $color })
        foreach ($ev in $f.Evidence) { Write-Host (Remove-Diacritics "               -> $ev") -ForegroundColor DarkGray }
    }
    Write-Host ''

    Write-Host '[IV. KET LUAN]' -ForegroundColor Cyan
    $s = $Report.Summary
    if ($s.Detected -gt 0) {
        Write-Host '========================================================================' -ForegroundColor Red
        Write-Host "  KET LUAN: PHAT HIEN DAU HIEU CRACK ($($s.Detected) muc nghiem trong, $($s.Warning) canh bao)." -ForegroundColor Red
        Write-Host '  Khuyen nghi: go bo cong cu be khoa va su dung ban quyen chinh hang.' -ForegroundColor Yellow
        Write-Host '========================================================================' -ForegroundColor Red
    } elseif ($s.Warning -gt 0) {
        Write-Host '========================================================================' -ForegroundColor Yellow
        Write-Host "  KET LUAN: CO $($s.Warning) CANH BAO can ra soat (khong phat hien file crack truc tiep)." -ForegroundColor Yellow
        Write-Host '  Hay doi chieu voi ho so mua ban quyen / chinh sach doanh nghiep.' -ForegroundColor White
        Write-Host '========================================================================' -ForegroundColor Yellow
    } else {
        Write-Host '========================================================================' -ForegroundColor Green
        Write-Host '  KET LUAN: HE THONG SACH / BAN QUYEN HOP LE.' -ForegroundColor Green
        Write-Host '========================================================================' -ForegroundColor Green
    }
    if (-not $Report.IsAdmin) {
        Write-Host '  (!) Dang chay KHONG co quyen Administrator - mot so muc co the khong doc duoc day du.' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

# ============================================================================
# 5b. XUẤT BÁO CÁO HTML
# ============================================================================

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

# Tạo file báo cáo HTML tự chứa (inline CSS) từ đối tượng report.
function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][string]$Path
    )

    $statusVi = @{ Clean = 'SẠCH'; Info = 'THÔNG TIN'; Warning = 'CẢNH BÁO'; Detected = 'PHÁT HIỆN' }
    $hw  = $Report.Hardware
    $win = $Report.Windows
    $s   = $Report.Summary

    # Banner kết luận
    if ($s.Detected -gt 0) {
        $verdictClass = 'detected'
        $verdictText  = "PHÁT HIỆN DẤU HIỆU CRACK — $($s.Detected) mục nghiêm trọng, $($s.Warning) cảnh báo. Khuyến nghị gỡ bỏ công cụ bẻ khóa và dùng bản quyền chính hãng."
    } elseif ($s.Warning -gt 0) {
        $verdictClass = 'warning'
        $verdictText  = "CÓ $($s.Warning) CẢNH BÁO cần rà soát (không phát hiện file crack trực tiếp). Hãy đối chiếu với hồ sơ mua bản quyền / chính sách doanh nghiệp."
    } else {
        $verdictClass = 'clean'
        $verdictText  = 'HỆ THỐNG SẠCH / BẢN QUYỀN HỢP LỆ.'
    }

    $rows = New-Object System.Collections.Generic.List[string]

    # Bảng phần cứng
    $hwPairs = [ordered]@{
        'Mainboard' = $hw.Motherboard
        'CPU'       = "$($hw.Cpu) ($($hw.CpuCores) cores / $($hw.CpuThreads) threads)"
        'RAM'       = "$($hw.RamGB) GB ($($hw.RamSpeed) MHz, $($hw.RamSlots) thanh)"
        'GPU'       = $hw.Gpu
        'Ổ lưu trữ' = $hw.Disks
    }
    foreach ($k in $hwPairs.Keys) {
        $rows.Add("<tr><th>$(ConvertTo-HtmlSafe $k)</th><td>$(ConvertTo-HtmlSafe ([string]$hwPairs[$k]))</td></tr>")
    }
    $hwTable = "<table class='kv'>$($rows -join '')</table>"

    # Bảng bản quyền
    $rows.Clear()
    $rows.Add("<tr><th>Windows</th><td>$(ConvertTo-HtmlSafe $win.Edition)</td></tr>")
    $actClass = if ($win.Status -like '*Đã kích hoạt*') { 'ok' } else { 'bad' }
    $rows.Add("<tr><th>Trạng thái kích hoạt</th><td class='$actClass'>$(ConvertTo-HtmlSafe $win.Status)</td></tr>")
    $rows.Add("<tr><th>Kênh phân phối</th><td>$(ConvertTo-HtmlSafe $win.Channel)</td></tr>")
    $rows.Add("<tr><th>Product Key (BIOS)</th><td>$(ConvertTo-HtmlSafe $win.OemKey)</td></tr>")
    $rows.Add("<tr><th>Product Key (Registry)</th><td>$(ConvertTo-HtmlSafe $win.RegistryKey)</td></tr>")
    if ($Report.Office.Count) {
        foreach ($off in $Report.Office) {
            $k = if ($off.KmsServer) { " (KMS: $($off.KmsServer))" } else { '' }
            $rows.Add("<tr><th>Office</th><td>$(ConvertTo-HtmlSafe "$($off.Name): $($off.Status)$k")</td></tr>")
        }
    } else {
        $rows.Add("<tr><th>Office</th><td>Không phát hiện Office có bản quyền</td></tr>")
    }
    $licTable = "<table class='kv'>$($rows -join '')</table>"

    # Danh sách finding
    $rows.Clear()
    foreach ($f in ($Report.Findings | Sort-Object Category, @{ Expression = 'Rank'; Descending = $true })) {
        $ev = ''
        if ($f.Evidence -and $f.Evidence.Count) {
            $items = ($f.Evidence | ForEach-Object { "<li>$(ConvertTo-HtmlSafe ([string]$_))</li>" }) -join ''
            $ev = "<ul class='evidence'>$items</ul>"
        }
        $rows.Add(@"
<tr class='f-$($f.Status.ToLower())'>
  <td><span class='pill $($f.Status.ToLower())'>$($statusVi[$f.Status])</span></td>
  <td class='cat'>$(ConvertTo-HtmlSafe $f.Category)</td>
  <td><strong>$(ConvertTo-HtmlSafe $f.Name)</strong><div class='det'>$(ConvertTo-HtmlSafe $f.Details)</div>$ev</td>
</tr>
"@)
    }
    $findTable = "<table class='findings'><thead><tr><th>Mức</th><th>Nhóm</th><th>Chi tiết</th></tr></thead><tbody>$($rows -join '')</tbody></table>"

    $adminNote = if (-not $Report.IsAdmin) {
        "<p class='note'>⚠ Báo cáo được tạo khi KHÔNG có quyền Administrator — một số mục có thể chưa đọc đủ.</p>"
    } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KCheckLicense Report - $(ConvertTo-HtmlSafe $Report.Computer)</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:'Segoe UI',Roboto,Arial,sans-serif; background:#f4f6f9; color:#1f2733; line-height:1.5; }
  .wrap { max-width:960px; margin:0 auto; padding:24px 16px 48px; }
  header { display:flex; align-items:center; gap:16px; flex-wrap:wrap; padding:20px 24px; background:#0d1b2a; color:#fff; border-radius:14px; }
  header img { height:44px; background:#fff; padding:4px; border-radius:6px; }
  header h1 { font-size:20px; margin:0; }
  header .sub { font-size:13px; opacity:.75; }
  .meta { margin-left:auto; text-align:right; font-size:12px; opacity:.8; }
  .verdict { margin:18px 0; padding:16px 20px; border-radius:12px; font-weight:600; }
  .verdict.clean { background:#e6f7ec; color:#0f7a3d; border:1px solid #b6e6c8; }
  .verdict.warning { background:#fff6e0; color:#96690a; border:1px solid #f4dfa1; }
  .verdict.detected { background:#fdeaea; color:#b3261e; border:1px solid #f3bcbc; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin:8px 0 20px; }
  .card { flex:1; min-width:120px; text-align:center; background:#fff; border:1px solid #e6eaf0; border-radius:12px; padding:14px; }
  .card .n { font-size:28px; font-weight:700; }
  .card.detected .n { color:#b3261e; } .card.warning .n { color:#96690a; } .card.clean .n { color:#0f7a3d; }
  .card .l { font-size:12px; color:#68727f; text-transform:uppercase; letter-spacing:.04em; }
  h2 { font-size:15px; margin:26px 0 10px; color:#0d1b2a; border-left:4px solid #2f6fed; padding-left:10px; }
  table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e6eaf0; border-radius:12px; overflow:hidden; }
  .kv th { text-align:left; width:210px; background:#f7f9fc; color:#48525f; font-weight:600; vertical-align:top; }
  .kv th, .kv td { padding:9px 14px; border-bottom:1px solid #eef1f5; font-size:14px; }
  .kv td.ok { color:#0f7a3d; font-weight:600; } .kv td.bad { color:#b3261e; font-weight:600; }
  .findings th { background:#f7f9fc; text-align:left; font-size:12px; color:#48525f; padding:10px 14px; }
  .findings td { padding:12px 14px; border-bottom:1px solid #eef1f5; font-size:14px; vertical-align:top; }
  .findings td.cat { color:#5b6672; white-space:nowrap; }
  .pill { display:inline-block; padding:3px 10px; border-radius:999px; font-size:11px; font-weight:700; white-space:nowrap; }
  .pill.clean { background:#e6f7ec; color:#0f7a3d; } .pill.info { background:#eef1f5; color:#5b6672; }
  .pill.warning { background:#fff6e0; color:#96690a; } .pill.detected { background:#fdeaea; color:#b3261e; }
  tr.f-detected { background:#fffafa; } tr.f-warning { background:#fffdf6; }
  .det { color:#68727f; font-size:13px; margin-top:2px; }
  ul.evidence { margin:6px 0 0; padding-left:18px; font-size:12px; color:#7a8493; font-family:Consolas,monospace; }
  .note { color:#96690a; font-size:13px; }
  footer { text-align:center; margin-top:30px; font-size:12px; color:#8a94a2; }
  footer a { color:#2f6fed; text-decoration:none; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <a href="https://kollersi.com"><img src="https://kollersi.com/content/images/2025/07/kollersi_logo_2024_tran-2.png" alt="Kollersi"></a>
    <div>
      <h1>🛡️ KCheckLicense — Báo cáo kiểm tra bản quyền</h1>
      <div class="sub">Windows · Office · IDM · WinRAR · Adobe · v$($script:Version) (Build $($script:Build))</div>
    </div>
    <div class="meta">
      Máy: <strong>$(ConvertTo-HtmlSafe $Report.Computer)</strong><br>
      Thời điểm: $(ConvertTo-HtmlSafe $Report.GeneratedAt)
    </div>
  </header>

  <div class="verdict $verdictClass">KẾT LUẬN: $(ConvertTo-HtmlSafe $verdictText)</div>
  $adminNote

  <div class="cards">
    <div class="card detected"><div class="n">$($s.Detected)</div><div class="l">Phát hiện</div></div>
    <div class="card warning"><div class="n">$($s.Warning)</div><div class="l">Cảnh báo</div></div>
    <div class="card clean"><div class="n">$($s.Clean)</div><div class="l">Sạch</div></div>
  </div>

  <h2>Thông tin phần cứng</h2>
  $hwTable

  <h2>Bản quyền hệ thống</h2>
  $licTable

  <h2>Kết quả quét crack / hacktool</h2>
  $findTable

  <footer>Tạo bởi <strong>KCheckLicense v$($script:Version) (Build $($script:Build))</strong> · Developed by TuanNgoVN · <a href="https://kollersi.com">kollersi.com</a></footer>
</div>
</body>
</html>
"@

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $html | Out-File -FilePath $Path -Encoding UTF8
}

# ============================================================================
# 6. LUONG "KIEM TRA" VA "GO BO" (goi tu menu hoac tu -Mode)
# ============================================================================

function Invoke-CheckFlow {
    Write-Host '[*] Dang quet he thong, vui long cho...' -ForegroundColor Yellow
    $report = Invoke-FullScan

    if ($OutputPath) {
        $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "[*] Da luu bao cao JSON: $OutputPath" -ForegroundColor Green
    }

    $htmlReportPath = $null
    if ($ReportPath) {
        $htmlReportPath = $ReportPath
    } elseif (-not $NoReport -and -not $Json) {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $desktop = [Environment]::GetFolderPath('Desktop')
        if (-not $desktop) { $desktop = (Get-Location).Path }
        $htmlReportPath = Join-Path $desktop "KCheckLicense_${env:COMPUTERNAME}_$stamp.html"
    }
    if ($htmlReportPath) {
        try {
            Export-HtmlReport -Report $report -Path $htmlReportPath
            Write-Host "[*] Da xuat bao cao HTML: $htmlReportPath" -ForegroundColor Green
        } catch {
            Write-Host "[!] Khong xuat duoc bao cao HTML: $($_.Exception.Message)" -ForegroundColor Red
            $htmlReportPath = $null
        }
    }

    if ($Json) {
        $report | ConvertTo-Json -Depth 6
        return
    }

    $revealKeys = [bool]$ShowKeys
    Show-Report -Report $report -RevealKeys $revealKeys

    $hotkeyHint = if ($htmlReportPath) {
        '  [ H ] An/Hien Key  |  [ R ] Mo bao cao HTML  |  [ C ] Go crack  |  [ Q/ESC ] Quay lai'
    } else {
        '  [ H ] An/Hien Key  |  [ C ] Go crack  |  [ Q/ESC ] Quay lai'
    }
    if ($htmlReportPath) { Write-Host "  Bao cao da luu: $htmlReportPath" -ForegroundColor DarkGray }

    if ($NonInteractive) { return }

    # Hoi ngay neu phat hien crack - dung theo yeu cau: check xong hoi co muon go khong.
    if ($report.Summary.Detected -gt 0) {
        Write-Host ''
        Write-Host "[!] Phat hien $($report.Summary.Detected) muc co dau hieu crack." -ForegroundColor Red
        Write-Host 'Ban co muon go ngay bay gio khong? (Y/N)' -ForegroundColor Yellow
        $ans = Read-Host
        if ($ans -in @('Y', 'y')) {
            Invoke-CleanFlow
            return
        }
    }

    Write-Host $hotkeyHint -ForegroundColor Cyan
    Write-Host '------------------------------------------------------------------------' -ForegroundColor Gray

    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'H') {
            $revealKeys = -not $revealKeys
            Show-Report -Report $report -RevealKeys $revealKeys
            if ($htmlReportPath) { Write-Host "  Bao cao da luu: $htmlReportPath" -ForegroundColor DarkGray }
            Write-Host $hotkeyHint -ForegroundColor Cyan
            Write-Host '------------------------------------------------------------------------' -ForegroundColor Gray
        } elseif ($key.Key -eq 'R' -and $htmlReportPath) {
            if (Test-Path -LiteralPath $htmlReportPath) {
                Start-Process $htmlReportPath
                Write-Host "  [*] Dang mo bao cao trong trinh duyet..." -ForegroundColor Green
            }
        } elseif ($key.Key -eq 'C') {
            Invoke-CleanFlow
            return
        } elseif ($key.Key -eq 'Q' -or $key.Key -eq 'Escape') {
            break
        }
    }
}

function Invoke-CleanFlow {
    Clear-Host
    Write-Banner

    if (-not (Test-IsAdministrator)) {
        Write-Host '[!] Can chay bang quyen Administrator de go crack day du.' -ForegroundColor Red
        Write-Host '    Chuot phai PowerShell -> Run as administrator, roi chay lai.' -ForegroundColor Yellow
        if (-not $NonInteractive) { Read-Host 'Nhan Enter de quay lai' | Out-Null }
        return
    }

    Write-Host '[*] Dang quet cac dau hieu crack tren may...' -ForegroundColor Yellow
    $actions = Get-CleanupActions -IncludeWarnings:([bool]$IncludeWarnings) -RemoveAdobePatchedDll:([bool]$RemoveAdobePatchedDll)
    $toApply = @($actions | Where-Object { $_.Applicable })
    Write-Host ''

    if (-not $actions.Count) {
        Write-Host '[OK] Khong tim thay dau hieu crack nao tren may. Khong can go gi ca.' -ForegroundColor Green
        if (-not $NonInteractive) { Read-Host 'Nhan Enter de quay lai' | Out-Null }
        return
    }

    Write-Host "[DANH SACH PHAT HIEN ($($actions.Count) muc)]" -ForegroundColor Cyan
    $lastCat = ''
    foreach ($a in $actions) {
        if ($a.Category -ne $lastCat) {
            Write-Host "  -- $($a.Category) --" -ForegroundColor DarkCyan
            $lastCat = $a.Category
        }
        $tag = if ($a.Applicable) { '[ SE GO     ]' } else { '[ BO QUA    ]' }
        $color = switch ($a.Risk) { 'Risky' { 'Red' } 'Warning' { 'Yellow' } default { if ($a.Applicable) { 'Green' } else { 'DarkGray' } } }
        Write-Host "  $tag " -ForegroundColor $color -NoNewline
        Write-Host "$($a.Name)" -ForegroundColor White
        Write-Host "               $($a.Details)" -ForegroundColor DarkGray
    }
    Write-Host ''

    if (-not $toApply.Count) {
        Write-Host '[OK] Khong co muc nao can go (co the do -IncludeWarnings/-RemoveAdobePatchedDll chua bat).' -ForegroundColor Green
        if (-not $NonInteractive) { Read-Host 'Nhan Enter de quay lai' | Out-Null }
        return
    }

    $doApply = [bool]$Apply
    if (-not $doApply -and -not $NonInteractive) {
        Write-Host "Co $($toApply.Count) muc co the go. Ban co muon GO NGAY BAY GIO khong? (Y/N)" -ForegroundColor Yellow
        $ans = Read-Host
        $doApply = ($ans -in @('Y', 'y'))
    }
    if (-not $doApply) {
        Write-Host '[*] Khong thay doi gi tren may.' -ForegroundColor Yellow
        if (-not $NonInteractive) { Read-Host 'Nhan Enter de quay lai' | Out-Null }
        return
    }

    Write-Host ''
    Write-Host '[*] Dang go...' -ForegroundColor Yellow
    $ok = 0; $fail = 0
    foreach ($a in $toApply) {
        try {
            if ($a.ApplyAction) { & $a.ApplyAction }
            Write-Host "  [ OK ] $($a.Name)" -ForegroundColor Green
            $ok++
        } catch {
            Write-Host "  [LOI ] $($a.Name): $($_.Exception.Message)" -ForegroundColor Red
            $fail++
        }
    }

    if ($Rearm) {
        Write-Host ''
        Write-Host '[*] Dang chay slmgr /rearm (reset trang thai kich hoat Windows)...' -ForegroundColor Yellow
        cscript //B //nologo "$env:windir\system32\slmgr.vbs" /rearm | Out-Null
        Write-Host '[*] Da rearm. Can KHOI DONG LAI may de co hieu luc.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '========================================================================' -ForegroundColor Green
    Write-Host "  HOAN TAT: da go $ok muc thanh cong, $fail muc loi." -ForegroundColor Green
    Write-Host '  Khuyen nghi: chay lai Kiem tra ban quyen de xac nhan da sach.' -ForegroundColor White
    Write-Host '  Windows/Office se can KICH HOAT LAI bang key/tai khoan chinh chu.' -ForegroundColor White
    Write-Host '========================================================================' -ForegroundColor Green
    Write-Host ''
    if (-not $NonInteractive) { Read-Host 'Nhan Enter de quay lai' | Out-Null }
}

# ============================================================================
# 7. ĐIỂM VÀO CHƯƠNG TRÌNH
# ============================================================================

# Lưu trạng thái console gốc để khôi phục khi thoát (không làm hỏng cửa sổ PowerShell
# đang mở nếu người dùng chạy trực tiếp .ps1).
$origOutEnc = $null; $origInEnc = $null; $origCodePage = $null
try { $origOutEnc = [Console]::OutputEncoding } catch { }
try { $origInEnc  = [Console]::InputEncoding } catch { }
try { $origCodePage = ([string](chcp)) -replace '[^0-9]', '' } catch { }

function Restore-ConsoleState {
    param($OutEnc, $InEnc, $CodePage)
    try { if ($OutEnc)   { [Console]::OutputEncoding = $OutEnc } } catch { }
    try { if ($InEnc)    { [Console]::InputEncoding  = $InEnc } } catch { }
    try { if ($CodePage) { chcp $CodePage > $null 2>&1 } } catch { }
}

try {
    # Chuyển console sang UTF-8 (KHÔNG BOM) để hiển thị tiếng Việt.
    try {
        chcp 65001 > $null 2>&1
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [Console]::OutputEncoding = $utf8NoBom
        try { [Console]::InputEncoding = $utf8NoBom } catch { }
        $OutputEncoding = $utf8NoBom
    } catch { }

    # Hiện version/build ngay trên tiêu đề cửa sổ - thấy được không cần đọc nội dung.
    try { $Host.UI.RawUI.WindowTitle = "KCheckLicense v$($script:Version) Build $($script:Build)" } catch { }

    if ($Mode -eq 'Clean') {
        Clear-Host; Write-Banner
        Invoke-CleanFlow
    } elseif ($Mode -eq 'Check' -or $Json -or $NonInteractive) {
        Clear-Host; Write-Banner
        Invoke-CheckFlow
    } else {
        # Menu tuong tac: chon Kiem tra hoac Go bo.
        while ($true) {
            Clear-Host
            Write-Banner
            Write-Host '  [ 1 ] Kiem tra ban quyen (Check License)' -ForegroundColor White
            Write-Host '  [ 2 ] Go bo crack da phat hien (Clean)' -ForegroundColor White
            Write-Host '  [ Q ] Thoat' -ForegroundColor White
            Write-Host ''
            $choice = Read-Host 'Chon'
            switch ($choice.Trim().ToUpper()) {
                '1' { Clear-Host; Write-Banner; Invoke-CheckFlow }
                '2' { Clear-Host; Write-Banner; Invoke-CleanFlow }
                'Q' { break }
                default { Write-Host '[!] Lua chon khong hop le.' -ForegroundColor Red; Start-Sleep -Milliseconds 800 }
            }
            if ($choice.Trim().ToUpper() -eq 'Q') { break }
        }
    }

    Write-Host 'Da thoat. Cam on ban da su dung KCheckLicense!' -ForegroundColor Green
}
finally {
    # Luôn khôi phục encoding/codepage gốc dù thoát bằng Q, Ctrl+C hay gặp lỗi.
    Restore-ConsoleState -OutEnc $origOutEnc -InEnc $origInEnc -CodePage $origCodePage
}
