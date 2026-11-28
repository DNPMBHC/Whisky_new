# Anti-cheat minimal Windows 11 24H2 ARM64 Guest optimizer (one-click rollback).
# Owner: @DNPMBHC
# Restores services, scheduled tasks, HKCU registry tweaks, and user UWP registrations
# from snapshot-initial.json and verifies post-rollback consistency.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProfilePath,
    [string]$StateDirectory = (Join-Path $env:SystemDrive 'graphics-lab\guest-optimizer')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-FileSha256Lower([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Convert-StartModeToStartupType([string]$StartMode) {
    switch ($StartMode) {
        'Auto' { return 'Automatic' }
        'Manual' { return 'Manual' }
        'Disabled' { return 'Disabled' }
        default { return 'Manual' }
    }
}

function Get-LoadedRealUserHiveRoots {
    $roots = @()
    try {
        $items = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $sid = [string]$item.PSChildName
            if ($sid -match '^S-1-5-21-[0-9-]+$' -and -not $sid.EndsWith('_Classes')) {
                $roots += ('Registry::HKEY_USERS\' + $sid)
            }
        }
    } catch { }
    return @($roots)
}

function Convert-HkcuPathToHivePath([string]$HkcuPath, [string]$HiveRoot) {
    $suffix = $HkcuPath -replace '^(?i)HKCU:\\', ''
    if ($HiveRoot -eq 'HKCU:') {
        return ('HKCU:\' + $suffix)
    }
    return ($HiveRoot + '\' + $suffix)
}

function Read-SecurityAndPrismInvariants($Profile) {
    $secureBoot = $null
    try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $false }

    $tpmPresent = $false
    $tpmEnabled = $false
    try {
        $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm
        if ($null -ne $tpm) {
            $tpmPresent = $true
            $tpmEnabled = [bool]$tpm.IsEnabled_InitialValue
        }
    } catch { }

    $bcdSafe = $false
    try {
        $bcd = @(& bcdedit.exe /enum '{current}' 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $unsafe = @($bcd | Where-Object { $_ -match '^\s*(testsigning|nointegritychecks)\s+(yes|on|true|1|enabled)\s*$' })
            $bcdSafe = ($unsafe.Count -eq 0)
        }
    } catch { }

    $prismResults = @()
    $allPrismVerified = $true
    $allPrismSigned = $true
    foreach ($rel in @($Profile.protected_whitelist.prism_files)) {
        $full = Join-Path $env:SystemRoot ([string]$rel)
        $exists = Test-Path -LiteralPath $full
        $sigStatus = 'Missing'
        if ($exists) {
            try {
                $sigStatus = [string](Get-AuthenticodeSignature -FilePath $full).Status
            } catch {
                $sigStatus = 'Error'
            }
        }
        if (-not $exists) { $allPrismVerified = $false }
        if ($sigStatus -ne 'Valid') { $allPrismSigned = $false }
        $prismResults += [ordered]@{
            relative_path = [string]$rel
            exists = $exists
            signature_status = $sigStatus
        }
    }

    $qgaRunning = $false
    try {
        $qga = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
        if ($null -ne $qga -and $qga.Status -eq 'Running') { $qgaRunning = $true }
    } catch { }

    return [ordered]@{
        secure_boot_enabled = $secureBoot
        tpm_present = $tpmPresent
        tpm_enabled = $tpmEnabled
        bcd_safe = $bcdSafe
        prism_files_verified = $allPrismVerified
        prism_signatures_valid = $allPrismSigned
        prism_files = $prismResults
        qga_service_running = $qgaRunning
    }
}

function Read-GuestMetrics {
    $processes = @(Get-Process -ErrorAction SilentlyContinue)
    $runningServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
    $usedBytes = [int64]($drive.Size - $drive.FreeSpace)
    return [ordered]@{
        process_count = $processes.Count
        running_service_count = $runningServices.Count
        system_drive_total_bytes = [int64]$drive.Size
        system_drive_used_bytes = $usedBytes
        system_drive_free_bytes = [int64]$drive.FreeSpace
    }
}

$snapshotPath = Join-Path $StateDirectory 'snapshot-initial.json'
if (-not (Test-Path -LiteralPath $snapshotPath)) {
    throw 'initial snapshot is missing; refusing rollback'
}

$profileData = Get-Content -Raw -LiteralPath $ProfilePath | ConvertFrom-Json
$snapshot = Get-Content -Raw -LiteralPath $snapshotPath | ConvertFrom-Json
$profileSha = Get-FileSha256Lower $ProfilePath
$scriptSha = Get-FileSha256Lower $PSCommandPath

$mismatches = @()
$restoredServices = @()
foreach ($svc in @($snapshot.services)) {
    if (-not $svc.exists) { continue }
    $name = [string]$svc.name
    $targetStartup = Convert-StartModeToStartupType ([string]$svc.start_mode)
    try {
        Set-Service -Name $name -StartupType $targetStartup -ErrorAction Stop | Out-Null
        if ($null -ne $svc.delayed_autostart) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name 'DelayedAutostart' -Value ([int]$svc.delayed_autostart) -ErrorAction SilentlyContinue | Out-Null
        }
        if ($svc.state -eq 'Running') {
            & sc.exe start $name 2>$null | Out-Null
        }
        $afterCim = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'", "''") + "'") -ErrorAction SilentlyContinue
        $modeMatches = ($null -ne $afterCim -and [string]$afterCim.StartMode -eq [string]$svc.start_mode)
        if (-not $modeMatches) {
            $mismatches += "service:$name:start_mode"
        }
        $restoredServices += [ordered]@{
            name = $name
            expected_start_mode = [string]$svc.start_mode
            actual_start_mode = if ($null -ne $afterCim) { [string]$afterCim.StartMode } else { $null }
            matched = $modeMatches
        }
    } catch {
        $restoredServices += [ordered]@{
            name = $name
            expected_start_mode = [string]$svc.start_mode
            actual_start_mode = 'error'
            matched = $false
        }
        $mismatches += "service:$name:error"
    }
}

$restoredTasks = @()
foreach ($task in @($snapshot.scheduled_tasks)) {
    if (-not $task.exists) { continue }
    $taskPath = [string]$task.task_path
    $taskName = [string]$task.task_name
    try {
        if ($task.state -eq 'Disabled') {
            Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        } else {
            Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        }
        $afterTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        $expectedDisabled = ($task.state -eq 'Disabled')
        $actualDisabled = ($null -ne $afterTask -and $afterTask.State -eq 'Disabled')
        $matched = ($expectedDisabled -eq $actualDisabled)
        if (-not $matched) {
            $mismatches += "task:$taskPath$taskName"
        }
        $restoredTasks += [ordered]@{
            task = ($taskPath + $taskName)
            matched = $matched
        }
    } catch {
        $restoredTasks += [ordered]@{ task = ($taskPath + $taskName); matched = $false }
        $mismatches += "task:$taskPath$taskName:error"
    }
}

$restoredUwp = @()
foreach ($uwp in @($snapshot.uwp_packages)) {
    if (-not $uwp.installed) { continue }
    $pkgName = [string]$uwp.name
    $current = @(Get-AppxPackage -Name $pkgName -ErrorAction SilentlyContinue)
    if ($current.Count -gt 0) {
        $restoredUwp += [ordered]@{ name = $pkgName; status = 'present'; matched = $true }
        continue
    }
    $reregistered = $false
    foreach ($item in @($uwp.packages)) {
        if ($item.manifest_exists -and $item.manifest_path -and (Test-Path -LiteralPath $item.manifest_path)) {
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register $item.manifest_path -ErrorAction Stop | Out-Null
                $reregistered = $true
            } catch { }
        }
    }
    $after = @(Get-AppxPackage -Name $pkgName -ErrorAction SilentlyContinue)
    $matched = ($after.Count -gt 0)
    if (-not $matched) {
        $mismatches += "uwp:$pkgName"
    }
    $restoredUwp += [ordered]@{
        name = $pkgName
        status = if ($matched) { 'reregistered' } else { 'missing_after_rollback' }
        matched = $matched
    }
}

$restoredRegistry = @()
$rollbackRealUserHives = Get-LoadedRealUserHiveRoots
$rollbackUserHives = @('HKCU:') + @($rollbackRealUserHives)
$verifyHiveRoot = if ($rollbackRealUserHives.Count -gt 0) { $rollbackRealUserHives[0] } else { 'HKCU:' }
foreach ($reg in @($snapshot.registry_tweaks)) {
    $regPath = [string]$reg.path
    $regName = [string]$reg.name
    if (-not $regPath.StartsWith('HKCU:\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $mismatches += "registry:$regName:unsafe_scope"
        continue
    }
    try {
        foreach ($hiveRoot in $rollbackUserHives) {
            $resolvedPath = Convert-HkcuPathToHivePath $regPath $hiveRoot
            if ($reg.existed) {
                if (-not (Test-Path -LiteralPath $resolvedPath)) {
                    New-Item -Path $resolvedPath -Force | Out-Null
                }
                New-ItemProperty -Path $resolvedPath -Name $regName -Value $reg.value -PropertyType ([string]$reg.kind) -Force | Out-Null
            } else {
                if (Test-Path -LiteralPath $resolvedPath) {
                    Remove-ItemProperty -Path $resolvedPath -Name $regName -ErrorAction SilentlyContinue
                }
            }
        }
        $verifyPath = Convert-HkcuPathToHivePath $regPath $verifyHiveRoot
        if ($reg.existed) {
            $afterVal = (Get-Item -LiteralPath $verifyPath).GetValue($regName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $matched = ([string]$afterVal -eq [string]$reg.value)
        } else {
            $stillExists = $false
            if (Test-Path -LiteralPath $verifyPath) {
                $stillExists = ((Get-Item -LiteralPath $verifyPath).Property -contains $regName)
            }
            $matched = (-not $stillExists)
        }
        if (-not $matched) {
            $mismatches += "registry:$regName"
        }
        $restoredRegistry += [ordered]@{ name = $regName; matched = $matched }
    } catch {
        $restoredRegistry += [ordered]@{ name = $regName; matched = $false }
        $mismatches += "registry:$regName:error"
    }
}

try {
    Get-Process -Name 'MaltCursorBridge' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($null -ne (Get-ScheduledTask -TaskName 'MaltCursorBridge' -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName 'MaltCursorBridge' -Confirm:$false -ErrorAction SilentlyContinue
    }
} catch { }

$restoredGaming = [ordered]@{
    update_pause_services = @()
    pagefile = $null
    power_scheme_guid = $null
    win32_priority_separation = $null
    memory_compression = $null
    locale_and_ime = $null
}

if ($null -ne $snapshot.PSObject.Properties['gaming_session'] -and $null -ne $snapshot.gaming_session) {
    $gs = $snapshot.gaming_session

    # 1. Restore update pause services
    foreach ($svc in @($gs.update_pause_services)) {
        if (-not $svc.exists) { continue }
        $name = [string]$svc.name
        $targetStartup = Convert-StartModeToStartupType ([string]$svc.start_mode)
        try {
            try {
                Set-Service -Name $name -StartupType $targetStartup -ErrorAction Stop | Out-Null
            } catch {
                $scMode = if ($targetStartup -eq 'Automatic') { 'auto' } elseif ($targetStartup -eq 'Disabled') { 'disabled' } else { 'demand' }
                & sc.exe config $name start= $scMode 2>$null | Out-Null
            }
            if ($null -ne $svc.delayed_autostart) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name 'DelayedAutostart' -Value ([int]$svc.delayed_autostart) -ErrorAction SilentlyContinue | Out-Null
            }
            if ($svc.state -eq 'Running') {
                & sc.exe start $name 2>$null | Out-Null
            }
            $afterCim = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'", "''") + "'") -ErrorAction SilentlyContinue
            $modeMatches = ($null -ne $afterCim -and [string]$afterCim.StartMode -eq [string]$svc.start_mode)
            if (-not $modeMatches) { $mismatches += "gaming_update_service:$name" }
            $restoredGaming.update_pause_services += [ordered]@{
                name = $name
                expected_start_mode = [string]$svc.start_mode
                actual_start_mode = if ($null -ne $afterCim) { [string]$afterCim.StartMode } else { $null }
                matched = $modeMatches
            }
        } catch {
            $restoredGaming.update_pause_services += [ordered]@{ name = $name; matched = $false }
            $mismatches += "gaming_update_service:$name:error"
        }
    }

    # 2. Restore pagefile configuration
    if ($null -ne $gs.pagefile) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $mmRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            if ($gs.pagefile.automatic_managed -eq $true) {
                Set-ItemProperty -Path $mmRegPath -Name 'PagingFiles' -Type MultiString -Value ([string[]]@('?:\pagefile.sys')) -ErrorAction SilentlyContinue
                Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true } | Out-Null
            } else {
                Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } | Out-Null
                $pfSpecs = @()
                foreach ($entry in @($gs.pagefile.entries)) {
                    $pfSpecs += ("$($entry.name) $([int]$entry.initial_size_mb) $([int]$entry.maximum_size_mb)")
                }
                Set-ItemProperty -Path $mmRegPath -Name 'PagingFiles' -Type MultiString -Value ([string[]]$pfSpecs) -ErrorAction Stop
            }
            $afterAuto = [bool](Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
            $pfMatched = ($afterAuto -eq [bool]$gs.pagefile.automatic_managed)
            if (-not $pfMatched) { $mismatches += 'gaming_pagefile' }
            $restoredGaming.pagefile = [ordered]@{
                expected_automatic = [bool]$gs.pagefile.automatic_managed
                actual_automatic = $afterAuto
                matched = $pfMatched
            }
        } catch {
            $restoredGaming.pagefile = [ordered]@{ matched = $false; error = $_.Exception.Message }
            $mismatches += 'gaming_pagefile:error'
        }
    }

    # 3. Restore active power scheme
    if (-not [string]::IsNullOrWhiteSpace([string]$gs.power_scheme_guid)) {
        try {
            & powercfg.exe /setactive ([string]$gs.power_scheme_guid) 2>$null | Out-Null
            $line = (& powercfg.exe /getactivescheme 2>$null | Out-String)
            $actualGuid = if ($line -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $Matches[1].ToLowerInvariant() } else { $null }
            $pMatched = ($actualGuid -eq ([string]$gs.power_scheme_guid).ToLowerInvariant())
            if (-not $pMatched) { $mismatches += 'gaming_power_scheme' }
            $restoredGaming.power_scheme_guid = [ordered]@{ expected = [string]$gs.power_scheme_guid; actual = $actualGuid; matched = $pMatched }
        } catch {
            $restoredGaming.power_scheme_guid = [ordered]@{ matched = $false }
            $mismatches += 'gaming_power_scheme:error'
        }
    }

    # 4. Restore Win32PrioritySeparation
    if ($null -ne $gs.win32_priority_separation) {
        try {
            $prioPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'
            New-ItemProperty -Path $prioPath -Name 'Win32PrioritySeparation' -Value ([int]$gs.win32_priority_separation) -PropertyType DWord -Force | Out-Null
            $actualPrio = [int](Get-ItemProperty -Path $prioPath -Name 'Win32PrioritySeparation').Win32PrioritySeparation
            $prMatched = ($actualPrio -eq [int]$gs.win32_priority_separation)
            if (-not $prMatched) { $mismatches += 'gaming_win32_priority_separation' }
            $restoredGaming.win32_priority_separation = [ordered]@{ expected = [int]$gs.win32_priority_separation; actual = $actualPrio; matched = $prMatched }
        } catch {
            $restoredGaming.win32_priority_separation = [ordered]@{ matched = $false }
            $mismatches += 'gaming_win32_priority_separation:error'
        }
    }

    # 5. Restore MemoryCompression
    if ($null -ne $gs.memory_compression) {
        try {
            $expectedMc = [bool]$gs.memory_compression
            $mmBefore = Get-MMAgent -ErrorAction SilentlyContinue
            $curMc = if ($null -ne $mmBefore -and $null -ne $mmBefore.MemoryCompression) { [bool]$mmBefore.MemoryCompression } else { $null }
            if ($curMc -ne $expectedMc) {
                if ($expectedMc) {
                    Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
                } else {
                    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
                }
                for ($mcTry = 0; $mcTry -lt 6; $mcTry++) {
                    Start-Sleep -Milliseconds 500
                    $mmPoll = Get-MMAgent -ErrorAction SilentlyContinue
                    if ($null -ne $mmPoll -and $null -ne $mmPoll.MemoryCompression) {
                        $curMc = [bool]$mmPoll.MemoryCompression
                        if ($curMc -eq $expectedMc) { break }
                    }
                }
            }
            $mcMatched = ($curMc -eq $expectedMc)
            if (-not $mcMatched) { $mismatches += 'gaming_memory_compression' }
            $restoredGaming.memory_compression = [ordered]@{ expected = $expectedMc; actual = $curMc; matched = $mcMatched }
        } catch {
            $restoredGaming.memory_compression = [ordered]@{ matched = $false }
            $mismatches += 'gaming_memory_compression:error'
        }
    } else {
        $restoredGaming.memory_compression = [ordered]@{ expected = $null; actual = $null; matched = $true; note = 'preserved_unmodified_sysmain_stopped_at_snapshot' }
    }

    # 6. Restore Locale & IME
    if ($null -ne $gs.locale_and_ime) {
        try {
            if (-not [string]::IsNullOrWhiteSpace([string]$gs.locale_and_ime.system_locale)) {
                Set-WinSystemLocale -SystemLocale ([string]$gs.locale_and_ime.system_locale) -ErrorAction SilentlyContinue
            }
            $iu = $gs.locale_and_ime.interactive_user
            $user = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
            if ($null -ne $iu -and -not [string]::IsNullOrWhiteSpace($user)) {
                $origLangs = @($iu.langs | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                if ($origLangs.Count -eq 0) { $origLangs = @('en-US') }
                $langCsv = ($origLangs | ForEach-Object { "'" + [string]$_ + "'" }) -join ', '
                $origUi = if ($iu.ui) { [string]$iu.ui } else { '' }
                $origCul = if ($iu.culture) { [string]$iu.culture } else { 'en-US' }
                $rbOut = Join-Path $StateDirectory 'locale-rollback-tmp.json'
                $rbScript = Join-Path $StateDirectory 'WhiskyOpt_RollbackLocale.ps1'
                $rbBody = @"
`$ErrorActionPreference = 'Continue'
Set-WinUserLanguageList -LanguageList @($langCsv) -Force
if ([string]::IsNullOrWhiteSpace('$origUi')) {
    Set-WinUILanguageOverride -ErrorAction SilentlyContinue
} else {
    Set-WinUILanguageOverride -Language '$origUi' -ErrorAction SilentlyContinue
}
Set-Culture '$origCul' -ErrorAction SilentlyContinue
Set-WinDefaultInputMethodOverride -ErrorAction SilentlyContinue
@{ langs = @(Get-WinUserLanguageList | ForEach-Object { `$_.LanguageTag }) } | ConvertTo-Json -Compress | Set-Content -Encoding UTF8 -LiteralPath '$rbOut'
"@
                Set-Content -LiteralPath $rbScript -Value $rbBody -Encoding UTF8
                if (Test-Path -LiteralPath $rbOut) { Remove-Item -LiteralPath $rbOut -Force -ErrorAction SilentlyContinue }
                $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $rbScript + '"')
                $princ = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
                Register-ScheduledTask -TaskName 'WhiskyOpt_RollbackLocale' -Action $act -Principal $princ -Force | Out-Null
                Start-ScheduledTask -TaskName 'WhiskyOpt_RollbackLocale'
                for ($i = 0; $i -lt 20; $i++) {
                    if (Test-Path -LiteralPath $rbOut) { break }
                    Start-Sleep -Milliseconds 500
                }
                Unregister-ScheduledTask -TaskName 'WhiskyOpt_RollbackLocale' -Confirm:$false -ErrorAction SilentlyContinue
            }
            $restoredGaming.locale_and_ime = [ordered]@{ matched = $true; system_locale = [string]$gs.locale_and_ime.system_locale }
        } catch {
            $restoredGaming.locale_and_ime = [ordered]@{ matched = $false; error = $_.Exception.Message }
            $mismatches += 'gaming_locale:error'
        }
    }
}

$metricsAfter = Read-GuestMetrics
$invariants = Read-SecurityAndPrismInvariants $profileData
$invariantsPassed = (
    $invariants.secure_boot_enabled -eq $true -and
    $invariants.tpm_present -eq $true -and
    $invariants.tpm_enabled -eq $true -and
    $invariants.bcd_safe -eq $true -and
    $invariants.prism_files_verified -eq $true -and
    $invariants.prism_signatures_valid -eq $true -and
    $invariants.qga_service_running -eq $true
)

$report = [ordered]@{
    schema_version = 1
    profile_revision = if ($null -ne $profileData.profile_revision) { [int]$profileData.profile_revision } else { 1 }
    profile_version = if ($null -ne $profileData.PSObject.Properties['profile_version'] -and $profileData.profile_version) { [string]$profileData.profile_version } else { '3.0' }
    owner = '@DNPMBHC'
    action = 'rollback'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    profile_id = [string]$profileData.profile_id
    profile_sha256 = $profileSha
    script_sha256 = $scriptSha
    snapshot_profile_sha256 = [string]$snapshot.profile_sha256
    rollback_consistent = ($mismatches.Count -eq 0)
    mismatch_count = $mismatches.Count
    mismatches = $mismatches
    security_invariants_passed = $invariantsPassed
    security_invariants = $invariants
    metrics_after = $metricsAfter
    restored = [ordered]@{
        services = $restoredServices
        scheduled_tasks = $restoredTasks
        uwp_packages = $restoredUwp
        registry_tweaks = $restoredRegistry
        gaming_session = $restoredGaming
    }
}

$reportPath = Join-Path $StateDirectory 'last-rollback-report.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $reportPath

$report | ConvertTo-Json -Depth 8 -Compress
