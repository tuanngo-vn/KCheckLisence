<#
.SYNOPSIS
    KCleanCrack - Go bo cong cu crack Windows/Office/IDM/WinRAR/Adobe, khoi phuc
    trang thai ban quyen sach. Cong cu di kem voi KCheckLicense.ps1 (dung de quet).

.DESCRIPTION
    Go bo dung nhung gi KCheckLicense.ps1 phat hien: KMS server gia (loopback),
    KMS Hook DLL, Office Ohook, IFEO hijack, scheduled task/service cua cong cu
    crack, hosts/firewall bi chan de ne kiem tra ban quyen Adobe/IDM, va cac dau
    hieu khac.

    MAC DINH CHAY DRY-RUN: chi liet ke nhung gi SE bi go, KHONG thay doi gi tren
    may. Phai them tham so -Apply moi thuc su thuc hien go bo.

.PARAMETER Apply
    Thuc su thuc hien go bo. Neu khong co tham so nay, cong cu chi xem truoc.

.PARAMETER IncludeWarnings
    Go luon ca cac muc o muc CANH BAO (vi du KMS server tu xa khong ro nguon goc
    nhung khong chac chan la crack). Mac dinh KHONG dung vao muc Canh bao vi co
    the la cau hinh doanh nghiep hop le.

.PARAMETER RemoveAdobePatchedDll
    Xoa luon file amtlib.dll da bi va trong thu muc Adobe (dau hieu AMT Emulator).
    CANH BAO: xoa file nay co the lam ung dung Adobe khong mo duoc cho toi khi ban
    Repair/cai lai qua Creative Cloud. Mac dinh TAT vi day la thay doi manh.

.PARAMETER Rearm
    Chay slmgr /rearm de reset trang thai kich hoat Windows sau khi don crack.
    Luu y: rearm co gioi han so lan dung tren moi may, chi nen dung khi can.

.PARAMETER NonInteractive
    Khong hoi xac nhan tung buoc khi dung voi -Apply (dung cho script tu dong).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\KCleanCrack.ps1
    (chi xem truoc, khong doi gi)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\KCleanCrack.ps1 -Apply

.NOTES
    Tac gia : TuanNgoVN (https://kollersi.com)
    Yeu cau : Chay bang quyen Administrator.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$IncludeWarnings,
    [switch]$RemoveAdobePatchedDll,
    [switch]$Rearm,
    [switch]$NonInteractive
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'SilentlyContinue'

$script:Version   = '1.0'
$script:Build     = 1
$script:BuildDate = '2026-07-17'

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
# TIEN ICH DUNG CHUNG
# ============================================================================

function Test-IsAdministrator {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

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
        Category   = $Category
        Name       = $Name
        Applicable = $Applicable
        Details    = $Details
        Risk       = $Risk
        ApplyAction = $ApplyAction
        Result     = $null
    }
}

function Get-BinaryTrust {
    param([Parameter(Mandatory)][string]$Path, [string]$ExpectedSigner = 'Microsoft')
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $sig = Get-AuthenticodeSignature -FilePath $Path
    $signerSubject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    $trusted = $sig -and $sig.Status -eq 'Valid' -and $signerSubject -like "*$ExpectedSigner*"
    [PSCustomObject]@{ Trusted = [bool]$trusted; SigStatus = if ($sig) { "$($sig.Status)" } else { 'NoSignature' } }
}

function Get-HostsEntries {
    $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) { return @() }
    $i = 0
    foreach ($raw in (Get-Content -LiteralPath $hostsPath)) {
        $i++
        $line = $raw.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '\s+'
            if ($parts.Count -ge 2) {
                [PSCustomObject]@{ LineNumber = $i; IP = $parts[0]; Hostname = ($parts[1..($parts.Count-1)] -join ' '); Raw = $raw }
            }
        }
    }
}

# ============================================================================
# THU THAP DANH SACH HANH DONG CAN GO
# ============================================================================

function Get-CleanupActions {
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
        # amtlib.dll bi va - CHI go neu -RemoveAdobePatchedDll duoc bat, vi day la thay doi manh
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
# HIEN THI + THUC THI
# ============================================================================

function Write-Banner {
    Write-Host '========================================================================' -ForegroundColor Gray
    Write-Host "  KCleanCrack v$($script:Version) (Build $($script:Build) - $($script:BuildDate))" -ForegroundColor White
    Write-Host '  Go bo cong cu crack Windows/Office/IDM/WinRAR/Adobe' -ForegroundColor DarkGray
    Write-Host '  Dung kem voi KCheckLicense.ps1 de quet lai sau khi go' -ForegroundColor DarkGray
    Write-Host '  Developed by TuanNgoVN  -  https://kollersi.com' -ForegroundColor DarkGray
    Write-Host '========================================================================' -ForegroundColor Gray
    Write-Host ''
}

try {
    chcp 65001 > $null 2>&1
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [Console]::OutputEncoding = $utf8NoBom
} catch { }

try { $Host.UI.RawUI.WindowTitle = "KCleanCrack v$($script:Version) Build $($script:Build)" } catch { }

Clear-Host
Write-Banner

if (-not (Test-IsAdministrator)) {
    Write-Host '[!] Can chay bang quyen Administrator de go crack day du.' -ForegroundColor Red
    Write-Host '    Chuot phai PowerShell -> Run as administrator, roi chay lai.' -ForegroundColor Yellow
    if (-not $NonInteractive) { Read-Host 'Nhan Enter de thoat' | Out-Null }
    exit 1
}

Write-Host '[*] Dang quet cac dau hieu crack tren may...' -ForegroundColor Yellow
$actions = Get-CleanupActions
$toApply = @($actions | Where-Object { $_.Applicable })

Write-Host ''
if (-not $actions.Count) {
    Write-Host '[OK] Khong tim thay dau hieu crack nao tren may. Khong can go gi ca.' -ForegroundColor Green
    if (-not $NonInteractive) { Read-Host 'Nhan Enter de thoat' | Out-Null }
    exit 0
}

Write-Host "[III. DANH SACH PHAT HIEN ($($actions.Count) muc)]" -ForegroundColor Cyan
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

if (-not $Apply) {
    Write-Host '========================================================================' -ForegroundColor Yellow
    Write-Host "  CHE DO XEM TRUOC (khong thay doi gi tren may)." -ForegroundColor Yellow
    Write-Host "  Co $($toApply.Count) muc se duoc go neu chay lai voi tham so -Apply." -ForegroundColor Yellow
    Write-Host '  Vi du: powershell -ExecutionPolicy Bypass -File .\KCleanCrack.ps1 -Apply' -ForegroundColor White
    Write-Host '========================================================================' -ForegroundColor Yellow
    if (-not $NonInteractive) { Read-Host 'Nhan Enter de thoat' | Out-Null }
    exit 0
}

if (-not $toApply.Count) {
    Write-Host '[OK] Khong co muc nao can go (co the do -IncludeWarnings/-RemoveAdobePatchedDll chua bat).' -ForegroundColor Green
    if (-not $NonInteractive) { Read-Host 'Nhan Enter de thoat' | Out-Null }
    exit 0
}

if (-not $NonInteractive) {
    Write-Host "Ban sap go $($toApply.Count) muc. Cac thay doi gom: xoa registry, file, scheduled task, service, sua hosts." -ForegroundColor Yellow
    $confirm = Read-Host 'Go tiep tuc? (Y/N)'
    if ($confirm -notin @('Y', 'y')) {
        Write-Host '[*] Da huy, khong thay doi gi.' -ForegroundColor Yellow
        exit 0
    }
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
Write-Host '  Khuyen nghi: chay lai KCheckLicense.ps1 de xac nhan da sach.' -ForegroundColor White
Write-Host '  Windows/Office se can KICH HOAT LAI bang key/tai khoan chinh chu.' -ForegroundColor White
Write-Host '========================================================================' -ForegroundColor Green
Write-Host ''

if (-not $NonInteractive) { Read-Host 'Nhan Enter de thoat' | Out-Null }
