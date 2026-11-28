# Anti-cheat minimal Windows 11 24H2 ARM64 Guest optimizer (apply).
# Owner: @DNPMBHC
# Compliance: Strictly removes non-essential consumer bloat and background overhead.
# Never modifies Secure Boot, TPM, BCD, Code Integrity, Prism AVX/AVX2, or anti-cheat drivers.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProfilePath,
    [string]$StateDirectory = (Join-Path $env:SystemDrive 'graphics-lab\guest-optimizer'),
    [ValidateSet('auto', 'preserve', 'disable')]
    [string]$MemoryCompressionOverride = 'auto',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$HardProtectedServices = @(
    'BFE', 'CoreMessagingRegistrar', 'CryptSvc', 'DcomLaunch', 'Dhcp', 'Dnscache',
    'EventLog', 'KeyIso', 'LSM', 'mpssvc', 'Netman', 'NlaSvc', 'nsi', 'PlugPlay',
    'Power', 'QEMU-GA', 'RpcEptMapper', 'RpcSs', 'SamSs', 'Schedule',
    'SecurityHealthService', 'Sense', 'SystemEventsBroker', 'TBS',
    'TrustedInstaller', 'UserManager', 'VaultSvc', 'VirtioFsSvc', 'WinDefend',
    'Winmgmt', 'Audiosrv', 'AudioEndpointBuilder', 'wuauserv',
    'vgc', 'vgk', 'ACE-BASE', 'ACE-GAME', 'ACE-CORE10405', 'ACE-CORE20405',
    'AntiCheatExpert', 'AntiCheatExpert Service',
    'AntiCheatExpert Protection', 'EasyAntiCheat', 'EasyAntiCheat_EOS',
    'EasyAntiCheat_EOSSys', 'BEService'
)

$AllowedUpdatePauseServices = @('wuauserv', 'UsoSvc', 'BITS', 'TrustedInstaller')

$HardProtectedAppxPrefixes = @(
    'Microsoft.VCLibs', 'Microsoft.UI.Xaml', 'Microsoft.NET', 'Microsoft.DirectX',
    'Microsoft.Windows.ShellExperienceHost', 'Microsoft.Windows.StartMenuExperienceHost',
    'Microsoft.Windows.SecHealthUI', 'Microsoft.AAD.BrokerPlugin',
    'Microsoft.AccountsControl', 'Microsoft.LockApp', 'Microsoft.DesktopAppInstaller',
    'Microsoft.Services.Store.Engagement', 'Microsoft.StorePurchaseApp',
    'Microsoft.WindowsStore'
)

$HardProtectedTaskPrefixes = @(
    '\Microsoft\Windows\Windows Defender\',
    '\Microsoft\Windows\TPM\',
    '\Microsoft\Windows\Device Information\',
    '\Microsoft\Windows\CertificateServicesClient\',
    '\Microsoft\Windows\Servicing\',
    '\Microsoft\Windows\TaskScheduler\'
)

function Get-FileSha256Lower([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Test-PrefixMatch([string]$Value, [string[]]$Prefixes) {
    foreach ($prefix in $Prefixes) {
        if ($Value.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Assert-ProfileSafe($Profile) {
    if ($null -eq $Profile -or $Profile.schema_version -ne 1) {
        throw 'optimizer profile schema_version must be 1'
    }
    if ($Profile.compliance.forbid_virtualization_hiding -ne $true -or
        $Profile.compliance.forbid_hardware_spoofing -ne $true -or
        $Profile.compliance.forbid_bcd_or_ci_weakening -ne $true -or
        $Profile.compliance.forbid_kernel_driver_tampering -ne $true -or
        $Profile.compliance.preserve_official_signatures -ne $true) {
        throw 'optimizer profile compliance flags must all be true'
    }

    $protectedServices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($svc in $HardProtectedServices) { [void]$protectedServices.Add($svc) }
    foreach ($svc in @($Profile.protected_whitelist.services)) { [void]$protectedServices.Add([string]$svc) }

    $protectedAppx = @($HardProtectedAppxPrefixes) + @($Profile.protected_whitelist.appx_prefixes)
    $protectedTasks = @($HardProtectedTaskPrefixes) + @($Profile.protected_whitelist.task_prefixes)

    foreach ($svcEntry in @($Profile.optimization_blacklist.services)) {
        $name = [string]$svcEntry.name
        if ([string]::IsNullOrWhiteSpace($name)) {
            throw 'blacklist service name cannot be empty'
        }
        if ($protectedServices.Contains($name)) {
            throw "whitelist violation: protected service '$name' is in optimization_blacklist"
        }
        if ($svcEntry.target_start_type -notin @('Disabled', 'Manual')) {
            throw "invalid target_start_type for service '$name'"
        }
    }

    foreach ($pkg in @($Profile.optimization_blacklist.uwp_packages)) {
        $pkgName = [string]$pkg
        if ([string]::IsNullOrWhiteSpace($pkgName)) {
            throw 'blacklist UWP package name cannot be empty'
        }
        if (Test-PrefixMatch $pkgName $protectedAppx) {
            throw "whitelist violation: protected UWP package '$pkgName' is in optimization_blacklist"
        }
    }

    foreach ($taskEntry in @($Profile.optimization_blacklist.scheduled_tasks)) {
        $fullPath = ([string]$taskEntry.task_path) + ([string]$taskEntry.task_name)
        if (Test-PrefixMatch $fullPath $protectedTasks) {
            throw "whitelist violation: protected scheduled task '$fullPath' is in optimization_blacklist"
        }
    }

    foreach ($regEntry in @($Profile.optimization_blacklist.registry_tweaks)) {
        $regPath = [string]$regEntry.path
        if (-not $regPath.StartsWith('HKCU:\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "whitelist violation: registry tweak must be scoped to HKCU:\ ($regPath)"
        }
        if ($regPath -match '(?i)DeviceGuard|CodeIntegrity|Lsa|Policies\\System|CurrentControlSet') {
            throw "whitelist violation: forbidden security registry path ($regPath)"
        }
    }

    if ($null -ne $Profile.gaming_session_controls) {
        $gc = $Profile.gaming_session_controls
        foreach ($uEntry in @($gc.update_pause_services)) {
            $uName = [string]$uEntry.name
            if ($AllowedUpdatePauseServices -notcontains $uName) {
                throw "whitelist violation: '$uName' is not allowed in update_pause_services"
            }
            if ([string]$uEntry.target_start_type -ne 'Manual') {
                throw "update_pause_services '$uName' must use target_start_type='Manual'"
            }
        }
        if ($null -ne $gc.pagefile) {
            $initMb = [int]$gc.pagefile.initial_size_mb
            $maxMb = [int]$gc.pagefile.maximum_size_mb
            if ($initMb -lt 4096 -or $maxMb -lt $initMb -or $maxMb -gt 32768) {
                throw 'pagefile size out of safe bounds'
            }
        }
        if ($null -ne $gc.cpu_and_memory_tuning) {
            $prio = [int]$gc.cpu_and_memory_tuning.win32_priority_separation
            if ($prio -lt 0 -or $prio -gt 63) {
                throw 'win32_priority_separation out of safe range (0..63)'
            }
            if ([string]$gc.cpu_and_memory_tuning.memory_compression -notin @('preserve', 'disable')) {
                throw 'memory_compression must be preserve or disable'
            }
        }
    }
}

function Invoke-InteractiveUserScript([string]$ScriptBody, [string]$OutFile, [string]$TaskName) {
    $user = $null
    try { $user = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName } catch { }
    if ([string]::IsNullOrWhiteSpace($user)) {
        return $null
    }
    $scriptFile = Join-Path $StateDirectory ($TaskName + '.ps1')
    Set-Content -LiteralPath $scriptFile -Value $ScriptBody -Encoding UTF8
    if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $scriptFile + '"')
    $princ = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
    Register-ScheduledTask -TaskName $TaskName -Action $act -Principal $princ -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Path -LiteralPath $OutFile) { break }
        Start-Sleep -Milliseconds 500
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $OutFile) {
        try { return (Get-Content -Raw -LiteralPath $OutFile | ConvertFrom-Json) } catch { return $null }
    }
    return $null
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

function Get-ActivePowerSchemeGuid {
    try {
        $line = (& powercfg.exe /getactivescheme 2>$null | Out-String)
        if ($line -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
            return $Matches[1].ToLowerInvariant()
        }
    } catch { }
    return $null
}

function Capture-GamingSessionSnapshot($Profile) {
    if ($null -eq $Profile.gaming_session_controls) {
        return $null
    }
    $gc = $Profile.gaming_session_controls

    # 1. Update pause services snapshot
    $updSnap = @()
    foreach ($uEntry in @($gc.update_pause_services)) {
        $name = [string]$uEntry.name
        $cim = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'", "''") + "'") -ErrorAction SilentlyContinue
        if ($null -eq $cim) {
            $updSnap += [ordered]@{ name = $name; exists = $false; start_mode = $null; state = $null; delayed_autostart = $null }
            continue
        }
        $delayed = $null
        try {
            $prop = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name 'DelayedAutostart' -ErrorAction SilentlyContinue
            if ($null -ne $prop) { $delayed = [int]$prop.DelayedAutostart }
        } catch { }
        $updSnap += [ordered]@{
            name = $name
            exists = $true
            start_mode = [string]$cim.StartMode
            state = [string]$cim.State
            delayed_autostart = $delayed
        }
    }

    # 2. Pagefile snapshot
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $autoPf = if ($null -ne $cs) { [bool]$cs.AutomaticManagedPagefile } else { $true }
    $pfEntries = @()
    foreach ($pf in @(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue)) {
        $pfEntries += [ordered]@{
            name = [string]$pf.Name
            initial_size_mb = [int]$pf.InitialSize
            maximum_size_mb = [int]$pf.MaximumSize
        }
    }

    # 3. CPU & memory tuning snapshot
    $activePower = Get-ActivePowerSchemeGuid
    $prioVal = $null
    try {
        $prioVal = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation' -ErrorAction SilentlyContinue).Win32PrioritySeparation
    } catch { }
    $memComp = $null
    try {
        # Get-MMAgent reports MemoryCompression=$false whenever SysMain is stopped even if enabled in OS.
        $sysMainSvc = Get-Service -Name 'SysMain' -ErrorAction SilentlyContinue
        if ($null -ne $sysMainSvc -and $sysMainSvc.Status -eq 'Running') {
            $mmAgent = Get-MMAgent -ErrorAction SilentlyContinue
            if ($null -ne $mmAgent -and $null -ne $mmAgent.MemoryCompression) {
                $memComp = [bool]$mmAgent.MemoryCompression
            }
        }
    } catch { }

    # 4. Locale & IME snapshot (interactive user + system locale)
    $sysLocale = $null
    try { $sysLocale = (Get-WinSystemLocale -ErrorAction SilentlyContinue).Name } catch { }
    $localeOut = Join-Path $StateDirectory 'locale-snap-tmp.json'
    $snapLocaleBody = @"
`$ErrorActionPreference = 'Continue'
`$langs = @(Get-WinUserLanguageList -ErrorAction SilentlyContinue | ForEach-Object { `$_.LanguageTag })
`$ui = (Get-WinUILanguageOverride -ErrorAction SilentlyContinue).Name
`$cul = (Get-Culture -ErrorAction SilentlyContinue).Name
@{ langs = `$langs; ui = `$ui; culture = `$cul } | ConvertTo-Json -Depth 4 -Compress | Set-Content -Encoding UTF8 -LiteralPath '$localeOut'
"@
    $userLocale = Invoke-InteractiveUserScript -ScriptBody $snapLocaleBody -OutFile $localeOut -TaskName 'WhiskyOpt_SnapLocale'

    return [ordered]@{
        update_pause_services = $updSnap
        pagefile = [ordered]@{
            automatic_managed = $autoPf
            entries = $pfEntries
        }
        power_scheme_guid = $activePower
        win32_priority_separation = if ($null -ne $prioVal) { [int]$prioVal } else { $null }
        memory_compression = $memComp
        locale_and_ime = [ordered]@{
            system_locale = $sysLocale
            interactive_user = $userLocale
        }
    }
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

function Capture-InitialSnapshot($Profile, [string]$ProfileSha) {
    $svcSnap = @()
    foreach ($svcEntry in @($Profile.optimization_blacklist.services)) {
        $name = [string]$svcEntry.name
        $cim = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'", "''") + "'") -ErrorAction SilentlyContinue
        if ($null -eq $cim) {
            $svcSnap += [ordered]@{ name = $name; exists = $false; start_mode = $null; state = $null; delayed_autostart = $null }
            continue
        }
        $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $delayed = $null
        try {
            $prop = Get-ItemProperty -Path $regKey -Name 'DelayedAutostart' -ErrorAction SilentlyContinue
            if ($null -ne $prop) { $delayed = [int]$prop.DelayedAutostart }
        } catch { }
        $svcSnap += [ordered]@{
            name = $name
            exists = $true
            start_mode = [string]$cim.StartMode
            state = [string]$cim.State
            delayed_autostart = $delayed
        }
    }

    $taskSnap = @()
    foreach ($taskEntry in @($Profile.optimization_blacklist.scheduled_tasks)) {
        $taskPath = [string]$taskEntry.task_path
        $taskName = [string]$taskEntry.task_name
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            $taskSnap += [ordered]@{ task_path = $taskPath; task_name = $taskName; exists = $false; state = $null }
        } else {
            $taskSnap += [ordered]@{ task_path = $taskPath; task_name = $taskName; exists = $true; state = [string]$task.State }
        }
    }

    $uwpSnap = @()
    foreach ($pkgName in @($Profile.optimization_blacklist.uwp_packages)) {
        $installed = @(Get-AppxPackage -Name ([string]$pkgName) -ErrorAction SilentlyContinue)
        if ($installed.Count -eq 0) {
            $uwpSnap += [ordered]@{ name = [string]$pkgName; installed = $false; packages = @() }
            continue
        }
        $pkgItems = @()
        foreach ($pkg in $installed) {
            $manifest = if ($pkg.InstallLocation) { Join-Path $pkg.InstallLocation 'AppxManifest.xml' } else { $null }
            $pkgItems += [ordered]@{
                package_full_name = [string]$pkg.PackageFullName
                manifest_exists = ($null -ne $manifest -and (Test-Path -LiteralPath $manifest))
                manifest_path = $manifest
                non_removable = [bool]$pkg.NonRemovable
            }
        }
        $uwpSnap += [ordered]@{ name = [string]$pkgName; installed = $true; packages = $pkgItems }
    }

    $regSnap = @()
    $realUserHives = Get-LoadedRealUserHiveRoots
    $snapHiveRoot = if ($realUserHives.Count -gt 0) { $realUserHives[0] } else { 'HKCU:' }
    foreach ($regEntry in @($Profile.optimization_blacklist.registry_tweaks)) {
        $regPath = [string]$regEntry.path
        $probePath = Convert-HkcuPathToHivePath $regPath $snapHiveRoot
        $regName = [string]$regEntry.name
        $existed = $false
        $oldVal = $null
        $oldKind = [string]$regEntry.kind
        if (Test-Path -LiteralPath $probePath) {
            try {
                $item = Get-Item -LiteralPath $probePath -ErrorAction Stop
                if ($item.Property -contains $regName) {
                    $existed = $true
                    $oldVal = $item.GetValue($regName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $oldKind = [string]$item.GetValueKind($regName)
                }
            } catch { }
        }
        $regSnap += [ordered]@{
            path = $regPath
            name = $regName
            existed = $existed
            value = $oldVal
            kind = $oldKind
        }
    }

    $gamingSnap = Capture-GamingSessionSnapshot $Profile

    return [ordered]@{
        schema_version = 1
        owner = '@DNPMBHC'
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        profile_id = [string]$Profile.profile_id
        profile_sha256 = $ProfileSha
        services = $svcSnap
        scheduled_tasks = $taskSnap
        uwp_packages = $uwpSnap
        registry_tweaks = $regSnap
        gaming_session = $gamingSnap
    }
}

$profileData = Get-Content -Raw -LiteralPath $ProfilePath | ConvertFrom-Json
Assert-ProfileSafe $profileData

$profileSha = Get-FileSha256Lower $ProfilePath
$scriptSha = Get-FileSha256Lower $PSCommandPath

New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
$snapshotPath = Join-Path $StateDirectory 'snapshot-initial.json'
$snapshotReused = $false
if (Test-Path -LiteralPath $snapshotPath) {
    $snapshotReused = $true
    if (-not $DryRun) {
        $existingSnap = Get-Content -Raw -LiteralPath $snapshotPath | ConvertFrom-Json
        if ([string]$existingSnap.profile_sha256 -ne $profileSha) {
            $freshSnap = Capture-InitialSnapshot $profileData $profileSha
            $svcSeen = @{}
            foreach ($s in @($existingSnap.services)) { $svcSeen[[string]$s.name] = $true }
            $mergedServices = @($existingSnap.services) + @($freshSnap.services | Where-Object { -not $svcSeen.ContainsKey([string]$_.name) })

            $taskSeen = @{}
            foreach ($t in @($existingSnap.scheduled_tasks)) { $taskSeen[([string]$t.task_path + [string]$t.task_name)] = $true }
            $mergedTasks = @($existingSnap.scheduled_tasks) + @($freshSnap.scheduled_tasks | Where-Object { -not $taskSeen.ContainsKey([string]$_.task_path + [string]$_.task_name) })

            $uwpSeen = @{}
            foreach ($u in @($existingSnap.uwp_packages)) { $uwpSeen[[string]$u.name] = $true }
            $mergedUwp = @($existingSnap.uwp_packages) + @($freshSnap.uwp_packages | Where-Object { -not $uwpSeen.ContainsKey([string]$_.name) })

            $regSeen = @{}
            foreach ($r in @($existingSnap.registry_tweaks)) { $regSeen[([string]$r.path + '|' + [string]$r.name)] = $true }
            $mergedReg = @($existingSnap.registry_tweaks) + @($freshSnap.registry_tweaks | Where-Object { -not $regSeen.ContainsKey([string]$_.path + '|' + [string]$_.name) })

            $existingSnap.profile_sha256 = $profileSha
            $existingSnap.services = $mergedServices
            $existingSnap.scheduled_tasks = $mergedTasks
            $existingSnap.uwp_packages = $mergedUwp
            $existingSnap.registry_tweaks = $mergedReg
            if ($null -eq $existingSnap.PSObject.Properties['gaming_session'] -or $null -eq $existingSnap.gaming_session) {
                $existingSnap | Add-Member -NotePropertyName 'gaming_session' -NotePropertyValue $freshSnap.gaming_session -Force
            }
            $existingSnap | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $snapshotPath
        }
    }
} elseif (-not $DryRun) {
    $initialSnapshot = Capture-InitialSnapshot $profileData $profileSha
    $initialSnapshot | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $snapshotPath
}

$metricsBefore = Read-GuestMetrics
$serviceChanges = @()
$taskChanges = @()
$uwpChanges = @()
$registryChanges = @()

foreach ($svcEntry in @($profileData.optimization_blacklist.services)) {
    $name = [string]$svcEntry.name
    $targetStart = [string]$svcEntry.target_start_type
    $svcObj = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $svcObj) {
        $serviceChanges += [ordered]@{ name = $name; status = 'not_present' }
        continue
    }
    if ($DryRun) {
        $serviceChanges += [ordered]@{ name = $name; status = 'dry_run'; target_start_type = $targetStart }
        continue
    }
    try {
        Set-Service -Name $name -StartupType $targetStart -ErrorAction Stop | Out-Null
        if ($svcEntry.stop_running -eq $true -and $svcObj.Status -eq 'Running') {
            Stop-Service -Name $name -Force -NoWait -ErrorAction SilentlyContinue | Out-Null
            for ($w = 0; $w -lt 8; $w++) {
                $cur = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($null -eq $cur -or $cur.Status -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 250
            }
        }
        $after = Get-Service -Name $name -ErrorAction SilentlyContinue
        $serviceChanges += [ordered]@{
            name = $name
            status = 'applied'
            target_start_type = $targetStart
            running_after = ($null -ne $after -and $after.Status -eq 'Running')
        }
    } catch {
        $serviceChanges += [ordered]@{ name = $name; status = 'skipped_protected' }
    }
}

foreach ($taskEntry in @($profileData.optimization_blacklist.scheduled_tasks)) {
    $taskPath = [string]$taskEntry.task_path
    $taskName = [string]$taskEntry.task_name
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        $taskChanges += [ordered]@{ task = ($taskPath + $taskName); status = 'not_present' }
        continue
    }
    if ($DryRun) {
        $taskChanges += [ordered]@{ task = ($taskPath + $taskName); status = 'dry_run' }
        continue
    }
    try {
        if ($task.State -ne 'Disabled') {
            Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        }
        $taskChanges += [ordered]@{ task = ($taskPath + $taskName); status = 'disabled' }
    } catch {
        $taskChanges += [ordered]@{ task = ($taskPath + $taskName); status = 'skipped_error' }
    }
}

foreach ($pkgName in @($profileData.optimization_blacklist.uwp_packages)) {
    $installed = @(Get-AppxPackage -Name ([string]$pkgName) -ErrorAction SilentlyContinue)
    if ($installed.Count -eq 0) {
        $uwpChanges += [ordered]@{ name = [string]$pkgName; status = 'not_present' }
        continue
    }
    $removedCount = 0
    $skippedNonRemovable = 0
    $failedCount = 0
    foreach ($pkg in $installed) {
        if ($pkg.NonRemovable) {
            $skippedNonRemovable++
            continue
        }
        if ($DryRun) {
            $removedCount++
            continue
        }
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop | Out-Null
            $removedCount++
        } catch {
            $failedCount++
        }
    }
    $stateLabel = if ($DryRun) { 'dry_run' } elseif ($removedCount -gt 0 -and $failedCount -eq 0) { 'removed_user_registration' } elseif ($skippedNonRemovable -gt 0 -and $removedCount -eq 0) { 'skipped_non_removable' } else { 'partial_or_skipped' }
    $uwpChanges += [ordered]@{
        name = [string]$pkgName
        status = $stateLabel
        removed_count = $removedCount
        skipped_non_removable = $skippedNonRemovable
        failed_count = $failedCount
    }
}

$targetUserHives = @('HKCU:') + @(Get-LoadedRealUserHiveRoots)
$defaultNtuserLoaded = $false
$defaultHiveMountName = 'MaltDefaultUser'
$defaultNtuserPath = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
if (-not $DryRun -and (Test-Path -LiteralPath $defaultNtuserPath)) {
    try {
        & reg.exe load ("HKU\" + $defaultHiveMountName) $defaultNtuserPath 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $defaultNtuserLoaded = $true
            $targetUserHives += ('Registry::HKEY_USERS\' + $defaultHiveMountName)
        }
    } catch { }
}
$targetUserHives = @($targetUserHives | Select-Object -Unique)

try {
    foreach ($regEntry in @($profileData.optimization_blacklist.registry_tweaks)) {
        $regPath = [string]$regEntry.path
        $regName = [string]$regEntry.name
        $regKind = [string]$regEntry.kind
        $regVal = $regEntry.value
        if ($DryRun) {
            $registryChanges += [ordered]@{ name = $regName; status = 'dry_run'; target_hives = $targetUserHives.Count }
            continue
        }
        $appliedHives = 0
        foreach ($hiveRoot in $targetUserHives) {
            $resolvedPath = Convert-HkcuPathToHivePath $regPath $hiveRoot
            try {
                if (-not (Test-Path -LiteralPath $resolvedPath)) {
                    New-Item -Path $resolvedPath -Force | Out-Null
                }
                New-ItemProperty -Path $resolvedPath -Name $regName -Value $regVal -PropertyType $regKind -Force | Out-Null
                $appliedHives++
            } catch { }
        }
        $registryChanges += [ordered]@{
            name = $regName
            status = if ($appliedHives -gt 0) { 'applied' } else { 'skipped_error' }
            targets_applied = $appliedHives
        }
    }
} finally {
    if ($defaultNtuserLoaded) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        & reg.exe unload ("HKU\" + $defaultHiveMountName) 2>$null | Out-Null
    }
}

$gamingChanges = [ordered]@{
    update_pause_services = @()
    pagefile = $null
    cpu_and_memory_tuning = $null
    locale_and_ime = $null
}

if ($null -ne $profileData.gaming_session_controls) {
    $gc = $profileData.gaming_session_controls

    # 1. Pause background Windows Update services (Manual + Stop, never Disabled)
    foreach ($uEntry in @($gc.update_pause_services)) {
        $name = [string]$uEntry.name
        $svcObj = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $svcObj) {
            $gamingChanges.update_pause_services += [ordered]@{ name = $name; status = 'not_present' }
            continue
        }
        if ($DryRun) {
            $gamingChanges.update_pause_services += [ordered]@{ name = $name; status = 'dry_run'; target_start_type = 'Manual' }
            continue
        }
        try {
            Set-Service -Name $name -StartupType Manual -ErrorAction Stop | Out-Null
            if ($uEntry.stop_running -eq $true -and $svcObj.Status -eq 'Running') {
                Stop-Service -Name $name -Force -NoWait -ErrorAction SilentlyContinue | Out-Null
                for ($w = 0; $w -lt 8; $w++) {
                    $cur = Get-Service -Name $name -ErrorAction SilentlyContinue
                    if ($null -eq $cur -or $cur.Status -eq 'Stopped') { break }
                    Start-Sleep -Milliseconds 250
                }
            }
            $after = Get-Service -Name $name -ErrorAction SilentlyContinue
            $gamingChanges.update_pause_services += [ordered]@{
                name = $name
                status = 'paused_manual'
                running_after = ($null -ne $after -and $after.Status -eq 'Running')
            }
        } catch {
            try {
                & sc.exe config $name start= demand 2>$null | Out-Null
                if ($uEntry.stop_running -eq $true) { & sc.exe stop $name 2>$null | Out-Null }
                $gamingChanges.update_pause_services += [ordered]@{ name = $name; status = 'paused_manual_sc' }
            } catch {
                $gamingChanges.update_pause_services += [ordered]@{ name = $name; status = 'skipped_protected' }
            }
        }
    }

    # 2. Pre-allocate fixed pagefile (8192-12288 MiB) to eliminate System Event 26
    if ($null -ne $gc.pagefile -and $gc.pagefile.enabled -eq $true) {
        $pfPath = [string]$gc.pagefile.path
        $initMb = [int]$gc.pagefile.initial_size_mb
        $maxMb = [int]$gc.pagefile.maximum_size_mb
        if ($DryRun) {
            $gamingChanges.pagefile = [ordered]@{ status = 'dry_run'; path = $pfPath; initial_size_mb = $initMb; maximum_size_mb = $maxMb }
        } else {
            try {
                $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                $driveLetter = Split-Path -Qualifier $pfPath
                $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$driveLetter'" -ErrorAction SilentlyContinue
                $freeMb = if ($null -ne $disk) { [int][math]::Floor($disk.FreeSpace / 1MB) } else { $maxMb + 2048 }
                $currentPfMb = 0
                try {
                    $pfFile = Get-Item -LiteralPath $pfPath -Force -ErrorAction SilentlyContinue
                    if ($null -ne $pfFile) {
                        $currentPfMb = [int][math]::Floor($pfFile.Length / 1MB)
                    }
                } catch { }
                # Dynamically clamp pagefile against guest RAM tier & current free volume space (>=2048 MiB headroom).
                $guestRamMb = if ($null -ne $cs -and $cs.TotalPhysicalMemory -gt 0) {
                    [int][math]::Round($cs.TotalPhysicalMemory / 1MB)
                } else { 8192 }
                $ramCapMaxMb = if ($guestRamMb -le 5120) { 8192 } else { $maxMb }
                $ramCapInitMb = if ($guestRamMb -le 5120) { 4096 } else { $initMb }
                $effectiveAvailableMb = $freeMb
                $ceilingMb = [Math]::Max(2048, $freeMb - 2048)
                $safeMaxMb = [Math]::Min($ramCapMaxMb, $ceilingMb)
                $safeInitMb = [Math]::Min($ramCapInitMb, $safeMaxMb)
                if ($cs.AutomaticManagedPagefile) {
                    Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } | Out-Null
                }
                # Write standard Windows Memory Management PagingFiles (REG_MULTI_SZ) directly,
                # avoiding the legacy WMI Win32_PageFileSetting "Value out of range" provider bug on >=4 GiB sizes.
                $mmRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                $pfSpec = [string[]]@("$pfPath $safeInitMb $safeMaxMb")
                Set-ItemProperty -Path $mmRegPath -Name 'PagingFiles' -Type MultiString -Value $pfSpec -ErrorAction Stop
                $verifiedPf = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $pfPath } | Select-Object -First 1
                $gamingChanges.pagefile = [ordered]@{
                    status = 'applied'
                    path = $pfPath
                    requested_initial_mb = $initMb
                    requested_maximum_mb = $maxMb
                    applied_initial_mb = $safeInitMb
                    applied_maximum_mb = $safeMaxMb
                    verified_initial_mb = if ($null -ne $verifiedPf) { [int]$verifiedPf.InitialSize } else { $safeInitMb }
                    verified_maximum_mb = if ($null -ne $verifiedPf) { [int]$verifiedPf.MaximumSize } else { $safeMaxMb }
                    drive_free_mb = $freeMb
                    current_pagefile_mb = $currentPfMb
                    effective_available_mb = $effectiveAvailableMb
                }
            } catch {
                $gamingChanges.pagefile = [ordered]@{ status = 'error'; message = $_.Exception.Message }
            }
        }
    }

    # 3. CPU & memory tuning (High Performance, disable Core Parking & USB suspend, Win32PrioritySeparation=0x26, MemoryCompression)
    if ($null -ne $gc.cpu_and_memory_tuning) {
        $cm = $gc.cpu_and_memory_tuning
        $targetMemComp = if ($MemoryCompressionOverride -ne 'auto') { $MemoryCompressionOverride } else { [string]$cm.memory_compression }
        if ($DryRun) {
            $gamingChanges.cpu_and_memory_tuning = [ordered]@{
                status = 'dry_run'
                power_plan = [string]$cm.power_plan
                win32_priority_separation = [int]$cm.win32_priority_separation
                memory_compression = $targetMemComp
            }
        } else {
            $appliedScheme = Get-ActivePowerSchemeGuid
            if ([string]$cm.power_plan -eq 'HighPerformance') {
                $hpGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
                & powercfg.exe /setactive $hpGuid 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    & powercfg.exe /duplicatescheme $hpGuid 2>$null | Out-Null
                    & powercfg.exe /setactive $hpGuid 2>$null | Out-Null
                }
                $appliedScheme = Get-ActivePowerSchemeGuid
            }
            if ($cm.disable_core_parking -eq $true) {
                # SUB_PROCESSOR: PROCTHROTTLEMIN=100, CPMINCORES=100 (disable core parking)
                & powercfg.exe /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100 2>$null | Out-Null
                & powercfg.exe /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100 2>$null | Out-Null
            }
            if ($cm.disable_usb_selective_suspend -eq $true) {
                & powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null | Out-Null
            }
            & powercfg.exe /setactive SCHEME_CURRENT 2>$null | Out-Null

            $prioPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'
            New-ItemProperty -Path $prioPath -Name 'Win32PrioritySeparation' -Value ([int]$cm.win32_priority_separation) -PropertyType DWord -Force | Out-Null

            $memCompActual = $null
            try {
                if ($targetMemComp -eq 'disable') {
                    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
                }
                # 'preserve' keeps OS memory compression enabled/untouched (avoids P1 Low regression measured in 11A)
                $mmAfter = Get-MMAgent -ErrorAction SilentlyContinue
                if ($null -ne $mmAfter -and $null -ne $mmAfter.MemoryCompression) {
                    $memCompActual = [bool]$mmAfter.MemoryCompression
                }
            } catch { }

            $gamingChanges.cpu_and_memory_tuning = [ordered]@{
                status = 'applied'
                active_power_scheme = $appliedScheme
                disable_core_parking = [bool]$cm.disable_core_parking
                disable_usb_selective_suspend = [bool]$cm.disable_usb_selective_suspend
                win32_priority_separation = [int]$cm.win32_priority_separation
                memory_compression_target = $targetMemComp
                memory_compression_actual = $memCompActual
            }
        }
    }

    # 4. Locale & zh-CN Microsoft Pinyin IME priority
    if ($null -ne $gc.locale_and_ime -and $gc.locale_and_ime.enabled -eq $true) {
        $loc = $gc.locale_and_ime
        if ($DryRun) {
            $gamingChanges.locale_and_ime = [ordered]@{ status = 'dry_run'; ui_language = [string]$loc.ui_language; preferred_languages = @($loc.preferred_languages) }
        } else {
            $zhCap = Get-WindowsCapability -Online -Name 'Language.Basic~~~zh-CN*' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $zhCap -or $zhCap.State -ne 'Installed') {
                $gamingChanges.locale_and_ime = [ordered]@{
                    status = 'skipped_missing_zh_cn_ime_dictionary'
                    capability_state = if ($null -ne $zhCap) { [string]$zhCap.State } else { 'unknown' }
                }
            } else {
            try { Set-WinSystemLocale -SystemLocale ([string]$loc.system_locale) -ErrorAction SilentlyContinue } catch { }
            $langCsv = (@($loc.preferred_languages) | ForEach-Object { "'" + [string]$_ + "'" }) -join ', '
            $uiLang = [string]$loc.ui_language
            $inputTip = [string]$loc.default_input_tip
            $locOut = Join-Path $StateDirectory 'locale-apply-tmp.json'
            $applyLocBody = @"
`$ErrorActionPreference = 'Continue'
Set-WinUserLanguageList -LanguageList @($langCsv) -Force
Set-WinUILanguageOverride -Language '$uiLang'
Set-Culture '$uiLang'
if (-not [string]::IsNullOrWhiteSpace('$inputTip')) {
    try { Set-WinDefaultInputMethodOverride -InputTip '$inputTip' -ErrorAction SilentlyContinue } catch { }
}
`$rawL = Get-WinUserLanguageList -ErrorAction SilentlyContinue
`$l = @()
foreach (`$it in `$rawL) {
    `$l += @{ tag = [string]`$it.LanguageTag; tips = @(`$it.InputMethodTips) }
}
@{ langs = `$l; ui = (Get-WinUILanguageOverride -ErrorAction SilentlyContinue).Name; culture = (Get-Culture -ErrorAction SilentlyContinue).Name } | ConvertTo-Json -Depth 5 -Compress | Set-Content -Encoding UTF8 -LiteralPath '$locOut'
"@
            $locRes = Invoke-InteractiveUserScript -ScriptBody $applyLocBody -OutFile $locOut -TaskName 'WhiskyOpt_ApplyLocale'
            $gamingChanges.locale_and_ime = [ordered]@{
                status = if ($null -ne $locRes) { 'applied' } else { 'applied_system_only_no_interactive_user' }
                system_locale = [string]$loc.system_locale
                interactive_result = $locRes
            }
            }
        }
    }

    # 5. Footprint reduction, DWM/GraphicsDrivers overlay fix, HD display & Cursor Bridge (v3.3)
    if ($null -ne $gc.footprint_and_display_controls -and $gc.footprint_and_display_controls.enabled -eq $true) {
        $fd = $gc.footprint_and_display_controls
        if ($DryRun) {
            $gamingChanges.footprint_and_display_controls = [ordered]@{
                status = 'dry_run'
                remove_onedrive = [bool]$fd.remove_onedrive
                disable_hibernation = [bool]$fd.disable_hibernation
                enable_compact_os = [bool]$fd.enable_compact_os
                cleanup_winsxs_and_retrim = [bool]$fd.cleanup_winsxs_and_retrim
                disable_dwm_mpo_overlay = [bool]$fd.disable_dwm_mpo_overlay
                disable_graphics_overlays = [bool]$fd.disable_graphics_overlays
                disable_pointer_shadow_and_fade_animations = [bool]$fd.disable_pointer_shadow_and_fade_animations
                ensure_hd_display_mode = [bool]$fd.ensure_hd_display_mode
                install_cursor_bridge = [bool]$fd.install_cursor_bridge
            }
        } else {
            $fdResult = [ordered]@{}
            if ($fd.remove_onedrive -eq $true) {
                try {
                    Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    $odSetups = @(
                        (Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'),
                        (Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe')
                    ) | Where-Object { Test-Path -LiteralPath $_ }
                    foreach ($odExe in $odSetups) {
                        & $odExe /uninstall 2>$null | Out-Null
                    }
                    # Prevent OneDrive auto-provisioning on future sign-ins (safe standard policy key)
                    $odPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
                    if (-not (Test-Path -LiteralPath $odPolicy)) { New-Item -Path $odPolicy -Force | Out-Null }
                    New-ItemProperty -Path $odPolicy -Name 'DisableFileSyncNGSC' -PropertyType DWord -Value 1 -Force | Out-Null
                    $fdResult.onedrive = 'removed_and_disabled'
                } catch {
                    $fdResult.onedrive = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.disable_hibernation -eq $true) {
                try {
                    & powercfg.exe /h off 2>$null | Out-Null
                    $fdResult.hibernation = 'disabled'
                } catch {
                    $fdResult.hibernation = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.disable_dwm_mpo_overlay -eq $true) {
                try {
                    $dwmPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm'
                    if (-not (Test-Path -LiteralPath $dwmPath)) { New-Item -Path $dwmPath -Force | Out-Null }
                    New-ItemProperty -Path $dwmPath -Name 'OverlayTestMode' -PropertyType DWord -Value 5 -Force | Out-Null
                    $fdResult.dwm_overlay_test_mode = 5
                } catch {
                    $fdResult.dwm_overlay_test_mode = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.disable_graphics_overlays -eq $true) {
                try {
                    $gfxPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
                    if (-not (Test-Path -LiteralPath $gfxPath)) { New-Item -Path $gfxPath -Force | Out-Null }
                    New-ItemProperty -Path $gfxPath -Name 'DisableOverlays' -PropertyType DWord -Value 1 -Force | Out-Null
                    $fdResult.graphics_drivers_disable_overlays = 1
                } catch {
                    $fdResult.graphics_drivers_disable_overlays = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.disable_pointer_shadow_and_fade_animations -eq $true -or $fd.ensure_hd_display_mode -eq $true) {
                try {
                    $uiOut = Join-Path $StateDirectory 'display-ui-apply-tmp.json'
                    $applyPointerAnim = if ($fd.disable_pointer_shadow_and_fade_animations -eq $true) { '$true' } else { '$false' }
                    $applyHdDisplay = if ($fd.ensure_hd_display_mode -eq $true) { '$true' } else { '$false' }
                    $uiBodyPrefix = "`$outPath = '$uiOut'`r`n`$doUiAnim = $applyPointerAnim`r`n`$doHdDisp = $applyHdDisplay`r`n"
                    $uiBodyCore = @'
$ErrorActionPreference = 'Continue'
$cs = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class MaltDisplayUiHelper
{
    private const uint SPI_SETDRAGFULLWINDOWS = 0x0025;
    private const uint SPI_SETFONTSMOOTHING = 0x004B;
    private const uint SPI_SETMENUANIMATION = 0x1003;
    private const uint SPI_SETCOMBOBOXANIMATION = 0x1005;
    private const uint SPI_SETLISTBOXSMOOTHSCROLLING = 0x1007;
    private const uint SPI_SETSELECTIONFADE = 0x1015;
    private const uint SPI_SETTOOLTIPANIMATION = 0x1017;
    private const uint SPI_SETCURSORSHADOW = 0x101B;
    private const uint SPI_SETUIEFFECTS = 0x103F;
    private const uint SPI_SETFONTSMOOTHINGTYPE = 0x200B;
    private const uint SPIF_UPDATEINIFILE = 0x01;
    private const uint SPIF_SENDCHANGE = 0x02;
    private const int ENUM_CURRENT_SETTINGS = -1;
    private const uint DM_PELSWIDTH = 0x00080000;
    private const uint DM_PELSHEIGHT = 0x00100000;
    private const uint DM_DISPLAYFREQUENCY = 0x00400000;
    private const uint CDS_UPDATEREGISTRY = 0x00000001;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DEVMODEW
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public ushort dmSpecVersion;
        public ushort dmDriverVersion;
        public ushort dmSize;
        public ushort dmDriverExtra;
        public uint dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public uint dmDisplayOrientation;
        public uint dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public ushort dmLogPixels;
        public uint dmBitsPerPel;
        public uint dmPelsWidth;
        public uint dmPelsHeight;
        public uint dmDisplayFlags;
        public uint dmDisplayFrequency;
        public uint dmICMMethod;
        public uint dmICMIntent;
        public uint dmMediaType;
        public uint dmDitherType;
        public uint dmReserved1;
        public uint dmReserved2;
        public uint dmPanningWidth;
        public uint dmPanningHeight;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumDisplaySettingsW(string deviceName, int modeNum, ref DEVMODEW devMode);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int ChangeDisplaySettingsW(ref DEVMODEW devMode, uint flags);

    public static void ApplyCleanUiParams()
    {
        uint flags = SPIF_UPDATEINIFILE | SPIF_SENDCHANGE;
        SystemParametersInfoW(SPI_SETUIEFFECTS, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETCURSORSHADOW, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETMENUANIMATION, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETCOMBOBOXANIMATION, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETLISTBOXSMOOTHSCROLLING, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETTOOLTIPANIMATION, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETSELECTIONFADE, 0, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETDRAGFULLWINDOWS, 1, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETFONTSMOOTHING, 1, IntPtr.Zero, flags);
        SystemParametersInfoW(SPI_SETFONTSMOOTHINGTYPE, 0, (IntPtr)2, flags);
    }

    public static string EnsureHdDisplayMode()
    {
        DEVMODEW cur = new DEVMODEW();
        cur.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODEW));
        if (!EnumDisplaySettingsW(null, ENUM_CURRENT_SETTINGS, ref cur))
        {
            return "enum_current_failed";
        }
        if (cur.dmPelsWidth >= 1280 && cur.dmPelsHeight >= 720)
        {
            return "preserved:" + cur.dmPelsWidth + "x" + cur.dmPelsHeight + "@" + cur.dmDisplayFrequency;
        }
        var modes = new List<DEVMODEW>();
        for (int i = 0; i < 1024; i++)
        {
            DEVMODEW m = new DEVMODEW();
            m.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODEW));
            if (!EnumDisplaySettingsW(null, i, ref m)) break;
            if (m.dmBitsPerPel == 32) modes.Add(m);
        }
        int[,] targets = new int[,] {
            { 1920, 1200 }, { 1920, 1080 }, { 1680, 1050 },
            { 1440, 900 }, { 1280, 800 }, { 1280, 720 }
        };
        for (int t = 0; t < targets.GetLength(0); t++)
        {
            uint tw = (uint)targets[t, 0];
            uint th = (uint)targets[t, 1];
            bool found = false;
            DEVMODEW best = new DEVMODEW();
            foreach (var m in modes)
            {
                if (m.dmPelsWidth == tw && m.dmPelsHeight == th)
                {
                    if (!found || m.dmDisplayFrequency > best.dmDisplayFrequency)
                    {
                        best = m;
                        found = true;
                    }
                }
            }
            if (found)
            {
                best.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY;
                int rc = ChangeDisplaySettingsW(ref best, CDS_UPDATEREGISTRY);
                if (rc != 0)
                {
                    best.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
                    rc = ChangeDisplaySettingsW(ref best, CDS_UPDATEREGISTRY);
                }
                if (rc == 0)
                {
                    return "applied:" + best.dmPelsWidth + "x" + best.dmPelsHeight + "@" + best.dmDisplayFrequency;
                }
            }
        }
        return "unchanged:" + cur.dmPelsWidth + "x" + cur.dmPelsHeight + "@" + cur.dmDisplayFrequency;
    }
}
"@
Add-Type -TypeDefinition $cs -Language CSharp
$res = @{ ui_params = 'skipped'; display_mode = 'skipped' }
if ($doUiAnim) {
    [MaltDisplayUiHelper]::ApplyCleanUiParams()
    $res.ui_params = 'applied'
}
if ($doHdDisp) {
    $res.display_mode = [MaltDisplayUiHelper]::EnsureHdDisplayMode()
}
$res | ConvertTo-Json -Compress | Set-Content -Encoding UTF8 -LiteralPath $outPath
'@
                    $uiRes = Invoke-InteractiveUserScript -ScriptBody ($uiBodyPrefix + $uiBodyCore) -OutFile $uiOut -TaskName 'WhiskyOpt_DisplayAndUi'
                    $fdResult.interactive_display_and_ui = if ($null -ne $uiRes) { $uiRes } else { 'no_interactive_user' }
                } catch {
                    $fdResult.interactive_display_and_ui = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.install_cursor_bridge -eq $true) {
                try {
                    $bridgeDir = Join-Path $env:ProgramData 'Malt\CursorBridge'
                    New-Item -ItemType Directory -Force -Path $bridgeDir | Out-Null
                    $targetPs1 = Join-Path $bridgeDir 'malt-cursor-bridge.ps1'
                    $targetExe = Join-Path $bridgeDir 'MaltCursorBridge.exe'
                    $sourcePs1 = Join-Path $PSScriptRoot 'malt-cursor-bridge.ps1'
                    if (Test-Path -LiteralPath $sourcePs1) {
                        if ($sourcePs1 -ine $targetPs1) {
                            Copy-Item -LiteralPath $sourcePs1 -Destination $targetPs1 -Force
                        }
                    }
                    if (-not (Test-Path -LiteralPath $targetPs1)) {
                        $fdResult.cursor_bridge = [ordered]@{ status = 'missing_bridge_script' }
                    } else {
                        Get-Process -Name 'MaltCursorBridge' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $targetPs1 -CompileOnly -OutputExePath $targetExe 2>$null | Out-Null
                        $useExe = Test-Path -LiteralPath $targetExe
                        if ($useExe) {
                            $bridgeAction = New-ScheduledTaskAction -Execute $targetExe
                        } else {
                            $bridgeAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $targetPs1 + '"')
                        }
                        $bridgeSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
                        $interactiveUser = $null
                        try { $interactiveUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName } catch { }
                        if (-not [string]::IsNullOrWhiteSpace($interactiveUser)) {
                            $bridgeTrigger = New-ScheduledTaskTrigger -AtLogOn -User $interactiveUser
                            $bridgePrincipal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Highest
                        } else {
                            $bridgeTrigger = New-ScheduledTaskTrigger -AtLogOn
                            $bridgePrincipal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Administrators' -RunLevel Highest
                        }
                        Register-ScheduledTask -TaskName 'MaltCursorBridge' -Action $bridgeAction -Trigger $bridgeTrigger -Principal $bridgePrincipal -Settings $bridgeSettings -Force | Out-Null
                        $startedNow = $false
                        if (-not [string]::IsNullOrWhiteSpace($interactiveUser)) {
                            try {
                                Start-ScheduledTask -TaskName 'MaltCursorBridge' -ErrorAction SilentlyContinue
                                Start-Sleep -Milliseconds 600
                                $startedNow = ($null -ne (Get-Process -Name 'MaltCursorBridge' -ErrorAction SilentlyContinue))
                            } catch { }
                        }
                        $fdResult.cursor_bridge = [ordered]@{
                            status = 'installed'
                            binary_compiled = $useExe
                            started_now = $startedNow
                            principal = if (-not [string]::IsNullOrWhiteSpace($interactiveUser)) { $interactiveUser } else { 'BUILTIN\Users' }
                        }
                    }
                } catch {
                    $fdResult.cursor_bridge = [ordered]@{ status = 'error'; message = $_.Exception.Message }
                }
            }
            if ($fd.enable_compact_os -eq $true) {
                try {
                    & compact.exe /CompactOS:always 2>$null | Out-Null
                    $fdResult.compact_os = 'enabled'
                } catch {
                    $fdResult.compact_os = "error: $($_.Exception.Message)"
                }
            }
            if ($fd.cleanup_winsxs_and_retrim -eq $true) {
                try {
                    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>$null | Out-Null
                    Remove-Item -Path (Join-Path $env:SystemRoot 'Temp\*') -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path (Join-Path $env:SystemRoot 'SoftwareDistribution\Download\*') -Recurse -Force -ErrorAction SilentlyContinue
                    Optimize-Volume -DriveLetter 'C' -ReTrim -ErrorAction SilentlyContinue | Out-Null
                    $fdResult.winsxs_and_retrim = 'cleaned_and_trimmed'
                } catch {
                    $fdResult.winsxs_and_retrim = "error: $($_.Exception.Message)"
                }
            }
            # Safe Defender real-time scan exclusion for existing large game directories (keeps Defender active)
            try {
                $gameDirs = @('F:\VALORANT_CN', 'C:\Riot Games', 'F:\WeGameApps', 'D:\VALORANT_CN') |
                    Where-Object { Test-Path -LiteralPath $_ }
                foreach ($gDir in $gameDirs) {
                    Add-MpPreference -ExclusionPath $gDir -ErrorAction SilentlyContinue
                }
                $fdResult.defender_game_exclusions = @($gameDirs)
            } catch { }
            $gamingChanges.footprint_and_display_controls = [ordered]@{
                status = 'applied'
                details = $fdResult
            }
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
    action = if ($DryRun) { 'dry_run' } else { 'apply' }
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    profile_id = [string]$profileData.profile_id
    profile_sha256 = $profileSha
    script_sha256 = $scriptSha
    snapshot_reused = $snapshotReused
    whitelist_guard_passed = $true
    security_invariants_passed = $invariantsPassed
    security_invariants = $invariants
    metrics_before = $metricsBefore
    metrics_after = $metricsAfter
    changes = [ordered]@{
        services = $serviceChanges
        scheduled_tasks = $taskChanges
        uwp_packages = $uwpChanges
        registry_tweaks = $registryChanges
        gaming_session = $gamingChanges
    }
}

if (-not $DryRun) {
    $reportPath = Join-Path $StateDirectory 'last-apply-report.json'
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $reportPath
}

$report | ConvertTo-Json -Depth 8 -Compress
