#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only on-device diagnosis for Windows Autopilot (ESP) and Autopilot device preparation.

.DESCRIPTION
    ZakitPro Kit 1 - Deployment Doctor, modules M3/M4/M5.
    Shift+F10 friendly. Reads registry, event logs and IME logs, builds a phase-ordered timeline,
    matches signals against known-causes.json and prints plain-English verdicts.

    What it reads (nothing is changed):
      - ESP tracking: HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking
        (Win32App_* InstallationState: 1 NotInstalled, 2 InProgress, 3 Completed, 4 Error, per Learn)
        and whether the ...\Device\Setup key exists
      - HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings (all values, as published by field sources)
      - Subkeys named InitialProvisioning / ProvisioningProgress under the Provisioning, Autopilot and
        IntuneManagementExtension registry trees (searched, because published paths may change)
      - Event logs discovered by name: *Bootstrapper* (Device Prep), ModernDeployment-Diagnostics-Provider
        Autopilot (event IDs 807, 809, 815, 908), CodeIntegrity Operational (event ID 3033)
      - IME install state and version (uninstall registry, service), IME logs folder,
        AppWorkload.log lines containing EspPhase, IntuneManagementExtension.log 'actively refused'
      - Signals for the 30-minute PowerShell script timeout
    Then it prints the MDMDiagnosticsTool command to collect logs BEFORE any reset. It does not run it.

    Output: console verdicts, plus DeviceDiagnostic-<date>.html and .json in -OutputPath.
    Writing the two report files is the only file activity.

.PARAMETER OutputPath
    Folder for the reports. Default: $env:TEMP. Use a USB drive letter at Shift+F10 (for example D:\).

.PARAMETER KnownCausesPath
    Path to known-causes.json. Default: ..\data\known-causes.json relative to this script.

.PARAMETER MaxEvents
    Maximum events read per log. Default 500.

.PARAMETER NoHtml
    Skip the HTML report (JSON and console only).

.PARAMETER ExpectedMode
    What you expected this device to run: Any (default), AutopilotV1 or DevicePrep. With DevicePrep, seeing
    ESP raises KC-024 (a registered Autopilot profile took precedence). With Any, ESP is only reported as context.

.PARAMETER SamplePath
    Offline practice mode. Folder with a device.json (fake registry values, events, OS and IME service data)
    and an optional IMELogs subfolder. When set, the script reads ONLY that folder: no registry, event log,
    WMI or service query on this computer. Sample folders ship in ..\sample-data\ (fake data).

.PARAMETER PassThru
    Also return the verdict objects to the pipeline (for scripting). Off by default so the console stays clean.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File D:\Kit1\scripts\Invoke-DeviceDiagnostic.ps1 -OutputPath D:\
    At Shift+F10 in OOBE. Process-scoped bypass only, for this one run; reports go to the USB drive.

.EXAMPLE
    .\Invoke-DeviceDiagnostic.ps1 -SamplePath ..\sample-data\device-prep-failure -OutputPath .\sample-out
    Practice run on fake sample data; works on any machine, touches nothing on this computer.

.EXAMPLE
    .\Invoke-DeviceDiagnostic.ps1 -ExpectedMode DevicePrep -PassThru | Where-Object Severity -eq 'Fail'
    You expected Device Prep; returns verdict objects and filters to failures.

.OUTPUTS
    With -PassThru: PSCustomObject[] verdicts (Severity, Signal, Finding, KnownCauseIds). Always writes HTML and JSON.

.NOTES
    Name:         Invoke-DeviceDiagnostic.ps1
    Version:      1.3.1 (2026-10-16)
    Publisher:    ZakitPro - Abderrazak Elbouchikhi (Zak) - hello@zakitpro.com
    Requires:     Windows 10/11, Windows PowerShell 5.1. Run elevated (or as SYSTEM at Shift+F10) to read all
                  logs. No modules, no network, no Graph.
    Registry paths for Device Prep are undocumented by Microsoft, published by field sources in 2024-2025, and may change.
                  Missing keys are reported as 'not found', never as errors.
    Tested on:    Not tested on a device. Parse-checked and linted with PSScriptAnalyzer only.
    Changelog:    See CHANGELOG.md.
    Disclaimer:   Provided AS IS, without warranty of any kind. Test on a non-production device first.
                  You are responsible for running it in your environment.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $env:TEMP,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KnownCausesPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\data\known-causes.json'),

    [Parameter()]
    [ValidateRange(10, 10000)]
    [int]$MaxEvents = 500,

    [Parameter()]
    [switch]$NoHtml,

    [Parameter()]
    [ValidateSet('Any', 'AutopilotV1', 'DevicePrep')]
    [string]$ExpectedMode = 'Any',

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SamplePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Timeline = [System.Collections.Generic.List[object]]::new()
$script:Signals = [System.Collections.Generic.List[object]]::new()
$script:Facts = [ordered]@{}
$PhaseOrder = @{ 'Enrollment' = 1; 'DevicePrep' = 2; 'ESP-DevicePreparation' = 2; 'ESP-DeviceSetup' = 3; 'ESP-AccountSetup' = 4; 'Unknown' = 9 }

function Add-TimelineEvent {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][Nullable[datetime]]$Time,
        [Parameter(Mandatory)][ValidateSet('Enrollment', 'DevicePrep', 'ESP-DevicePreparation', 'ESP-DeviceSetup', 'ESP-AccountSetup', 'Unknown')][string]$Phase,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )
    $script:Timeline.Add([PSCustomObject]@{ Time = $Time; Phase = $Phase; Source = $Source; Message = $Message })
}

function Add-Signal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Signal,
        [Parameter(Mandatory)][ValidateSet('Fail', 'Warn', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Finding
    )
    if (@($script:Signals | Where-Object { $_.Signal -eq $Signal }).Count -gt 0) {
        Write-Verbose -Message "Signal $Signal already raised; keeping the first (most severe) finding."
        return
    }
    $script:Signals.Add([PSCustomObject]@{ Severity = $Severity; Signal = $Signal; Finding = $Finding; KnownCauseIds = @() })
}


# ------------------------------------------------------------------ data access (live or -SamplePath)
$script:Sample = $null
if ($SamplePath) {
    $sampleFile = Join-Path -Path $SamplePath -ChildPath 'device.json'
    if (-not (Test-Path -LiteralPath $sampleFile)) { throw "Sample mode: '$sampleFile' not found." }
    $script:Sample = Get-Content -LiteralPath $sampleFile -Raw | ConvertFrom-Json
    $script:SampleKeys = [ordered]@{}
    foreach ($prop in @($script:Sample.registry.PSObject.Properties)) { $script:SampleKeys[$prop.Name.TrimEnd('\')] = $prop.Value }
}

function ConvertTo-ZkSampleKey {
    [OutputType([object])]
    <# Builds an object shaped like a registry key from sample data. In memory only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $vals = @{}
    if ($script:SampleKeys.Contains($Path) -and $null -ne $script:SampleKeys[$Path]) { foreach ($v in @($script:SampleKeys[$Path].PSObject.Properties)) { $vals[$v.Name] = $v.Value } }
    $o = [PSCustomObject]@{ Name = ($Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'); PSChildName = ($Path -split '\\')[-1]; Vals = $vals }
    $o | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Vals.Keys) }
    $o | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($n) $this.Vals[$n] }
    $o
}

function Get-ZkSampleKeyPath {
    [OutputType([string[]])]
    <# All sample key paths, including implied parent keys. #>
    [CmdletBinding()]
    param()
    $all = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $script:SampleKeys.Keys) {
        $parts = $k -split '\\'
        for ($i = 2; $i -le $parts.Count; $i++) { [void]$all.Add(($parts[0..($i - 1)] -join '\')) }
    }
    @($all)
}

function Test-ZkPath {
    [OutputType([bool])]
    <# Test-Path, or a lookup in the sample data for HKLM paths in -SamplePath mode. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    if ($script:Sample -and $LiteralPath -like 'HKLM:*') { return (@(Get-ZkSampleKeyPath) -contains $LiteralPath.TrimEnd('\')) }
    Test-Path -LiteralPath $LiteralPath
}

function Get-ZkRegistryKey {
    [OutputType([object])]
    <# Get-Item for a registry key, or the sample key. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    if ($script:Sample) { return (ConvertTo-ZkSampleKey -Path $LiteralPath.TrimEnd('\')) }
    Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
}

function Get-ZkRegistrySubkey {
    [OutputType([object])]
    <# Get-ChildItem for registry keys (optionally recursive), or sample keys. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath, [Parameter()][switch]$Recurse, [Parameter()][int]$Depth = -1)
    if ($script:Sample) {
        $root = $LiteralPath.TrimEnd('\')
        $rootDepth = @($root -split '\\').Count
        return @(Get-ZkSampleKeyPath | Where-Object { $_ -like "$root\*" } | Where-Object {
                $d = @($_ -split '\\').Count - $rootDepth
                if ($Recurse) { ($Depth -lt 0) -or ($d -le $Depth + 1) } else { $d -eq 1 }
            } | Sort-Object | ForEach-Object { ConvertTo-ZkSampleKey -Path $_ })
    }
    if ($Recurse -and $Depth -ge 0) { return @(Get-ChildItem -LiteralPath $LiteralPath -Recurse -Depth $Depth -ErrorAction SilentlyContinue) }
    if ($Recurse) { return @(Get-ChildItem -LiteralPath $LiteralPath -Recurse -ErrorAction SilentlyContinue) }
    @(Get-ChildItem -LiteralPath $LiteralPath -ErrorAction SilentlyContinue)
}

function Get-ZkWinEvent {
    [OutputType([object])]
    <# Get-WinEvent (-ListLog or -FilterHashtable), or the sample events. Read-only. #>
    [CmdletBinding()]
    param([Parameter()][string]$ListLog, [Parameter()][hashtable]$FilterHashtable, [Parameter()][int]$MaxEvents = 500)
    if ($script:Sample) {
        $ev = @($script:Sample.events)
        if ($ListLog) { return @($ev | Where-Object { $_.LogName -like $ListLog } | Group-Object -Property LogName | ForEach-Object { [PSCustomObject]@{ LogName = $_.Name; RecordCount = $_.Count } }) }
        $sel = @($ev | Where-Object { $_.LogName -eq $FilterHashtable.LogName -and (-not $FilterHashtable.ContainsKey('Id') -or @($FilterHashtable.Id) -contains [int]$_.Id) })
        if ($sel.Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
        return @($sel | Select-Object -First $MaxEvents | ForEach-Object { [PSCustomObject]@{ Id = [int]$_.Id; TimeCreated = (Get-Date).AddMinutes(-[int]$_.MinutesAgo); Level = [int]$_.Level; LevelDisplayName = $_.LevelDisplayName; Message = $_.Message; LogName = $_.LogName } })
    }
    if ($ListLog) { return @(Get-WinEvent -ListLog $ListLog -ErrorAction SilentlyContinue) }
    @(Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction Stop)
}

function Get-ZkOperatingSystem {
    [OutputType([object])]
    <# Win32_OperatingSystem, or the sample OS. Read-only. #>
    [CmdletBinding()]
    param()
    if ($script:Sample) { return [PSCustomObject]@{ Caption = $script:Sample.os.Caption; BuildNumber = $script:Sample.os.BuildNumber; LastBootUpTime = (Get-Date).AddHours(-1) } }
    Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
}

function Get-ZkImeService {
    [OutputType([object])]
    <# The IME service, or the sample service state (null when absent). Read-only. #>
    [CmdletBinding()]
    param()
    if ($script:Sample) { if ($script:Sample.imeService) { return [PSCustomObject]@{ Status = $script:Sample.imeService } } else { return $null } }
    Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
}

function Get-RegistryValueSafe {
    [OutputType([object])]
    <# Returns a hashtable of value name -> data for a key, or $null if missing. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-ZkPath -LiteralPath $Path)) { return $null }
    try {
        $item = Get-ZkRegistryKey -LiteralPath $Path
        $h = [ordered]@{}
        foreach ($n in $item.GetValueNames()) { $h[$n] = $item.GetValue($n) }
        return $h
    }
    catch {
        Write-Verbose -Message "Could not read $Path : $($_.Exception.Message)"
        return $null
    }
}

function Find-RegistrySubkey {
    [OutputType([object])]
    <# Bounded recursive search for subkeys with a given leaf name. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$LeafName, [Parameter()][int]$Depth = 4)
    if (-not (Test-ZkPath -LiteralPath $Root)) { return @() }
    try {
        return @(Get-ZkRegistrySubkey -LiteralPath $Root -Recurse -Depth $Depth |
                Where-Object { $_.PSChildName -eq $LeafName })
    }
    catch {
        Write-Verbose -Message "Search under $Root failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-EventSafe {
    [OutputType([object])]
    <# Finds logs by wildcard name and reads recent events. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogPattern, [Parameter()][int[]]$Id, [Parameter()][int]$Max = 500)
    $out = @()
    $logs = @(Get-ZkWinEvent -ListLog $LogPattern | Where-Object { $_.RecordCount -gt 0 })
    foreach ($log in $logs) {
        $filter = @{ LogName = $log.LogName }
        if ($Id) { $filter.Id = $Id }
        try {
            $out += @(Get-ZkWinEvent -FilterHashtable $filter -MaxEvents $Max)
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') { Write-Verbose -Message "Read $($log.LogName) failed: $($_.Exception.Message)" }
        }
    }
    return , $out
}

# ------------------------------------------------------------------ device basics
try {
    $os = Get-ZkOperatingSystem
    $script:Facts.OS = "$($os.Caption) build $($os.BuildNumber)"
    $script:Facts.LastBoot = $os.LastBootUpTime
}
catch { $script:Facts.OS = "Unknown ($($_.Exception.Message))" }
$script:Facts.Computer = if ($script:Sample) { 'SAMPLE: ' + [string]$script:Sample.computer } else { $env:COMPUTERNAME }
$script:Facts.Source = if ($script:Sample) { "Sample data: $SamplePath (fake)" } else { 'This device (live read)' }
$script:Facts.RunAt = (Get-Date).ToString('o')
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { Write-Verbose -Message "Elevation check unavailable: $($_.Exception.Message)" }
$script:Facts.Elevated = $isAdmin
if (-not $isAdmin -and -not $script:Sample) { Write-Warning -Message 'Not elevated: some event logs and registry keys may be unreadable.' }

# ------------------------------------------------------------------ M3: ESP tracking (APv1)
$espRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
$espPresent = Test-ZkPath -LiteralPath $espRoot
$script:Facts.EspTrackingKey = $espPresent
if ($espPresent) {
    if ($ExpectedMode -eq 'DevicePrep') {
        Add-Signal -Signal 'D_ESP_PRESENT_EXPECTED_DP' -Severity 'Warn' -Finding 'You expected Device Prep, but this device ran the Enrollment Status Page (ESP tracking key exists). A registered Autopilot profile probably took precedence.'
    }
    $deviceSetup = Test-ZkPath -LiteralPath "$espRoot\Device\Setup"
    $script:Facts.EspDeviceSetupKey = $deviceSetup
    $stateNames = @{ 1 = 'NotInstalled'; 2 = 'InProgress'; 3 = 'Completed'; 4 = 'Error' }
    $appKeys = @(Get-ZkRegistrySubkey -LiteralPath $espRoot -Recurse | Where-Object { $_.PSChildName -like 'Win32App_*' })
    foreach ($k in $appKeys) {
        $state = $k.GetValue('InstallationState')
        if ($null -eq $state) { continue }
        $phase = if ($k.Name -match '\\Device\\') { 'ESP-DeviceSetup' } else { 'ESP-AccountSetup' }
        $name = if ($stateNames.ContainsKey([int]$state)) { $stateNames[[int]$state] } else { "Unknown($state)" }
        Add-TimelineEvent -Time $null -Phase $phase -Source 'ESP Sidecar' -Message "$($k.PSChildName) InstallationState=$state ($name)"
        if ([int]$state -eq 4) {
            Add-Signal -Signal 'D_ESP_APP_ERROR' -Severity 'Fail' -Finding "$($k.PSChildName) has InstallationState 4 (Error) in $phase. This stops ESP app installs."
        }
    }
    $script:Facts.EspTrackedWin32Apps = $appKeys.Count
}

# ------------------------------------------------------------------ M4: Device Prep footprint (APv2)
$apSettings = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
$script:Facts.AutopilotSettings = $apSettings
if ($apSettings) {
    foreach ($n in $apSettings.Keys) {
        Add-TimelineEvent -Time $null -Phase 'Unknown' -Source 'AutopilotSettings' -Message ("{0} = {1}" -f $n, ([string]$apSettings[$n]).Substring(0, [Math]::Min(300, ([string]$apSettings[$n]).Length)))
    }
}
$dpKeys = @()
foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Provisioning', 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot', 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension') {
    $dpKeys += Find-RegistrySubkey -Root $root -LeafName 'InitialProvisioning'
    $dpKeys += Find-RegistrySubkey -Root $root -LeafName 'ProvisioningProgress'
}
$dpKeys = @($dpKeys | Sort-Object -Property Name -Unique)
$script:Facts.DevicePrepKeys = @($dpKeys | ForEach-Object { $_.Name })
foreach ($k in $dpKeys) {
    foreach ($n in $k.GetValueNames()) {
        $v = [string]$k.GetValue($n)
        Add-TimelineEvent -Time $null -Phase 'DevicePrep' -Source $k.PSChildName -Message ("{0} = {1}" -f $n, $v.Substring(0, [Math]::Min(400, $v.Length)))
    }
}
function Get-JsonLeaf {
    <# Flattens parsed JSON into path/value leaves. Read-only, in memory. #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter()][AllowNull()]$Node, [Parameter()][string]$Path = '$', [Parameter()][int]$Depth = 0)
    if ($Depth -gt 12) { return }
    if ($null -eq $Node) { return }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) { Get-JsonLeaf -Node $p.Value -Path "$Path.$($p.Name)" -Depth ($Depth + 1) }
    }
    elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        $i = 0
        foreach ($n in $Node) { Get-JsonLeaf -Node $n -Path "$Path[$i]" -Depth ($Depth + 1); $i++ }
    }
    else {
        [PSCustomObject]@{ Path = $Path; Name = ($Path -split '[.\[]')[-1].TrimEnd(']'); Value = [string]$Node }
    }
}

function Test-DevicePrepFailureLeaf {
    <# Generic rule: the Device Prep progress schema is not published, so match on names and values only.
       Flags: CSP-style PageError* names with a non-empty, non-zero value; names containing status/state/result/
       phase/error with a value containing 'fail' or 'error'; names containing errorcode/hresult with a non-zero value. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name, [Parameter()][AllowEmptyString()][string]$Value)
    $zero = @('', '0', '0x0', '0x00000000', 'null', 'none', 'false')
    if ($Name -match '^PageError(Phase|Code|Details)$') { return ($zero -notcontains $Value.Trim().ToLowerInvariant()) }
    if ($Name -match '(?i)error ?code|hresult|errorcode') { return ($zero -notcontains $Value.Trim().ToLowerInvariant()) }
    if ($Name -match '(?i)status|state|result|phase|error') { return ($Value -match '(?i)fail|error') }
    return $false
}

$dpHits = [System.Collections.Generic.List[object]]::new()
# Field names published by Patch My PC (Ultimate guide to troubleshoot Autopilot Device Preparation): current and previous workload phase
$dpContext = [System.Collections.Generic.List[string]]::new()
$dpSources = @()
foreach ($k in $dpKeys) { foreach ($n in $k.GetValueNames()) { $dpSources += [PSCustomObject]@{ Source = "$($k.PSChildName)\$n"; Name = $n; Value = [string]$k.GetValue($n) } } }
if ($apSettings) { foreach ($n in $apSettings.Keys) { $dpSources += [PSCustomObject]@{ Source = "AutopilotSettings\$n"; Name = $n; Value = [string]$apSettings[$n] } } }
foreach ($src in $dpSources) {
    $text = $src.Value.Trim()
    if ($text.StartsWith('{') -or $text.StartsWith('[')) {
        try {
            $parsed = $text | ConvertFrom-Json -ErrorAction Stop
            $leaves = @(Get-JsonLeaf -Node $parsed)
            $flagged = @($leaves | Where-Object { Test-DevicePrepFailureLeaf -Name $_.Name -Value $_.Value })
            # One verdict line per JSON object, with its name/id fields as context
            $groups = $flagged | Group-Object -Property { $_.Path.Substring(0, [Math]::Max(0, $_.Path.LastIndexOf('.'))) }
            foreach ($g in $groups) {
                $parentPath = $g.Name
                $context = @($leaves | Where-Object { $_.Path.StartsWith("$parentPath.") -and $_.Path.LastIndexOf('.') -eq $parentPath.Length -and $_.Name -match '(?i)name|id$|type' } | Select-Object -First 3 | ForEach-Object { "$($_.Name)=$($_.Value)" })
                $vals = ($g.Group | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
                $dpHits.Add("$($src.Source) $parentPath $(if ($context) { '[' + ($context -join '; ') + '] ' })$vals")
            }
            foreach ($leaf in @($leaves | Where-Object { $_.Name -in 'OrchestrationContext', 'PreviousProgress' })) { $dpContext.Add("$($leaf.Name)=$($leaf.Value)") }
        }
        catch { Write-Verbose -Message "$($src.Source) is not valid JSON: $($_.Exception.Message)" }
    }
    elseif ($src.Name -in 'OrchestrationContext', 'PreviousProgress') { $dpContext.Add("$($src.Name)=$text") }
    elseif (Test-DevicePrepFailureLeaf -Name $src.Name -Value $text) {
        $dpHits.Add("$($src.Source) = $text")
    }
}
$dpHits = [System.Collections.Generic.List[object]]@($dpHits | Select-Object -Unique)
$script:Facts.DevicePrepFailureValues = @($dpHits)
$dpContext = @($dpContext | Select-Object -Unique)
$script:Facts.DevicePrepPhaseContext = $dpContext
$dpPhaseNote = if ($dpContext.Count -gt 0) { " Last workload phase: $($dpContext -join '; ')." } else { '' }
foreach ($h in $dpHits) { Add-TimelineEvent -Time $null -Phase 'DevicePrep' -Source 'Device Prep progress (parsed)' -Message $h.Substring(0, [Math]::Min(400, $h.Length)) }
if ($dpHits.Count -gt 0) {
    $shown = ($dpHits | Select-Object -First 3) -join ' | '
    Add-Signal -Signal 'D_DP_PROGRESS_FAILURE' -Severity 'Fail' -Finding "Device Prep progress data reports $($dpHits.Count) failure/error value(s): $shown.$dpPhaseNote"
}

$bootEvents = Get-EventSafe -LogPattern '*Bootstrapper*' -Max $MaxEvents
foreach ($e in $bootEvents) {
    $msg = if ($e.Message) { ($e.Message -split "`r?`n")[0] } else { "(no message) Id $($e.Id)" }
    Add-TimelineEvent -Time $e.TimeCreated -Phase 'DevicePrep' -Source "Bootstrapper $($e.Id) $($e.LevelDisplayName)" -Message $msg
}
$script:Facts.BootstrapperEvents = $bootEvents.Count
if (($bootEvents.Count -gt 0 -or $dpKeys.Count -gt 0) -and -not $espPresent) {
    Add-Signal -Signal 'D_DP_FOOTPRINT' -Severity 'Info' -Finding 'Device Prep footprint found (Bootstrapper events or InitialProvisioning/ProvisioningProgress keys) and no ESP: treat as a Device Prep run.'
}
if (($bootEvents.Count -gt 0 -or $dpKeys.Count -gt 0) -and -not $espPresent -and $dpHits.Count -eq 0) {
    Add-Signal -Signal 'D_DP_NO_FAILURE_FOUND' -Severity 'Info' -Finding "Device Prep ran but its progress data holds no failure value the parser recognises. If the screen timed out, compare the policy's 'Minutes allowed before showing installation error' with your apps and scripts, then read the Bootstrapper events.$dpPhaseNote"
}
$bootErrors = @($bootEvents | Where-Object { $_.Level -in 1, 2 })
if ($bootErrors.Count -gt 0) {
    Add-Signal -Signal 'D_DP_BOOTSTRAPPER_ERROR' -Severity 'Warn' -Finding "$($bootErrors.Count) error-level Bootstrapper events. Read them in the timeline, latest first."
}

# ------------------------------------------------------------------ M3: Autopilot event log
# Label IME/Code Integrity rows by flow: ESP's Device preparation phase vs the Device Prep product
$imePhase = if ($espPresent) { 'ESP-DevicePreparation' } elseif ($bootEvents.Count -gt 0 -or $dpKeys.Count -gt 0) { 'DevicePrep' } else { 'Unknown' }
$apEvents = Get-EventSafe -LogPattern '*ModernDeployment-Diagnostics-Provider*' -Max $MaxEvents
foreach ($e in $apEvents) {
    $msg = if ($e.Message) { ($e.Message -split "`r?`n")[0] } else { "(no message) Id $($e.Id)" }
    Add-TimelineEvent -Time $e.TimeCreated -Phase 'Enrollment' -Source "Autopilot $($e.Id)" -Message $msg
}
if (@($apEvents | Where-Object { $_.Id -eq 807 }).Count) { Add-Signal -Signal 'D_EVT_807' -Severity 'Fail' -Finding 'Autopilot event 807 (ZtdDeviceIsNotRegistered).' }
if (@($apEvents | Where-Object { $_.Id -in 809, 815 }).Count) { Add-Signal -Signal 'D_EVT_809_815' -Severity 'Fail' -Finding 'Autopilot event 809/815 (no profile).' }
if (@($apEvents | Where-Object { $_.Id -eq 908 }).Count) { Add-Signal -Signal 'D_EVT_908' -Severity 'Fail' -Finding 'Autopilot event 908 (serial/product key mismatch).' }

# ------------------------------------------------------------------ M1-5: Code Integrity 3033
$ciEvents = Get-EventSafe -LogPattern '*CodeIntegrity*' -Id 3033 -Max $MaxEvents
foreach ($e in $ciEvents) {
    $msg = if ($e.Message) { ($e.Message -split "`r?`n")[0] } else { 'Event 3033' }
    Add-TimelineEvent -Time $e.TimeCreated -Phase $imePhase -Source 'CodeIntegrity 3033' -Message $msg
}
$ciIme = @($ciEvents | Where-Object { $_.Message -match 'Intune|IntuneManagementExtension|WixToolset|\\Installer\\' })
if ($ciIme.Count -gt 0) {
    Add-Signal -Signal 'D_CI3033' -Severity 'Fail' -Finding "$($ciIme.Count) Code Integrity 3033 events mention Intune/IME/WixToolset/Installer paths. App Control may be blocking the IME install."
}
elseif ($ciEvents.Count -gt 0) {
    Add-Signal -Signal 'D_CI3033_OTHER' -Severity 'Info' -Finding "$($ciEvents.Count) Code Integrity 3033 events, none mention IME. Review them if ESP stalls at MDM preparation."
}

# ------------------------------------------------------------------ IME presence and version
$imeVersion = $null
foreach ($u in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    if (-not (Test-ZkPath -LiteralPath $u)) { continue }
    foreach ($k in @(Get-ZkRegistrySubkey -LiteralPath $u)) {
        if ([string]$k.GetValue('DisplayName') -eq 'Microsoft Intune Management Extension') { $imeVersion = [string]$k.GetValue('DisplayVersion') }
    }
}
$imeService = Get-ZkImeService
$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$imeLogDir = if ($script:Sample) { Join-Path -Path $SamplePath -ChildPath 'IMELogs' } else { Join-Path -Path $programData -ChildPath 'Microsoft\IntuneManagementExtension\Logs' }
$script:Facts.ImeVersion = $imeVersion
$script:Facts.ImeService = if ($imeService) { [string]$imeService.Status } else { 'Not found' }
$script:Facts.ImeLogs = Test-Path -LiteralPath $imeLogDir
if (-not $imeVersion -and -not $imeService) {
    if ($ciIme.Count -gt 0) {
        Add-Signal -Signal 'D_IME_MISSING_CI3033' -Severity 'Fail' -Finding "Intune Management Extension is not installed and $($ciIme.Count) Code Integrity 3033 event(s) point at its installer: App Control is the likely blocker."
    }
    else {
        Add-Signal -Signal 'D_IME_MISSING' -Severity 'Warn' -Finding 'Intune Management Extension is not installed, and no Code Integrity 3033 event points at it. If ESP is at "Preparing your device for mobile management", IME never installed or never reported; look at connectivity and enrollment before App Control.'
    }
}
elseif ($imeVersion) {
    $affected = @('1.101.103.0', '1.101.105.0', '1.101.109.0', '1.101.111.0')
    if ($affected -contains $imeVersion) {
        $sev = if ($ciIme.Count -gt 0) { 'Warn' } else { 'Info' }
        $note = if ($imeVersion -eq '1.101.109.0') { ' (1.101.109.0 is also the fix for service incident IT1272653; that is a separate issue.)' } else { '' }
        Add-Signal -Signal 'D_IME_AFFECTED_VERSION' -Severity $sev -Finding "IME $imeVersion carries the DLL field sources report App Control blocking (fixed in 1.103.101.0). Only matters if App Control is enforced$(if ($sev -eq 'Warn') { ', and 3033 events say it is' } else { '' }).$note"
    }
    Add-TimelineEvent -Time $null -Phase $imePhase -Source 'IME' -Message "IME installed, version $imeVersion, service $($script:Facts.ImeService)"
}

# ------------------------------------------------------------------ IME logs: EspPhase, actively refused, script timeout text
if ($script:Facts.ImeLogs) {
    $appWorkload = Join-Path -Path $imeLogDir -ChildPath 'AppWorkload.log'
    if (Test-Path -LiteralPath $appWorkload) {
        $esp = @(Select-String -LiteralPath $appWorkload -Pattern 'EspPhase' -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -Last 20)
        foreach ($m in $esp) { Add-TimelineEvent -Time $null -Phase 'Unknown' -Source 'AppWorkload.log' -Message $m.Line.Substring(0, [Math]::Min(300, $m.Line.Length)) }
        if ($esp.Count -gt 0) { Add-Signal -Signal 'D_APPWORKLOAD_ESPPHASE' -Severity 'Info' -Finding "AppWorkload.log has $($esp.Count) recent EspPhase lines (last 20 in timeline). Compare an app's final state against the ESP phase it finished in." }
    }
    $imeLog = Join-Path -Path $imeLogDir -ChildPath 'IntuneManagementExtension.log'
    if (Test-Path -LiteralPath $imeLog) {
        $refused = @(Select-String -LiteralPath $imeLog -Pattern 'actively refused' -SimpleMatch -ErrorAction SilentlyContinue)
        if ($refused.Count -gt 0) {
            Add-Signal -Signal 'D_IME_LOG_ACTIVELY_REFUSED' -Severity 'Warn' -Finding "$($refused.Count) 'actively refused' lines in IntuneManagementExtension.log: a download endpoint may be blocked on this network."
        }
    }
    $timeoutHits = @(Get-ChildItem -LiteralPath $imeLogDir -Filter '*.log' -ErrorAction SilentlyContinue |
            Select-String -Pattern 'timeout|timed out' -ErrorAction SilentlyContinue |
            Where-Object { $_.Line -match 'powershell|script' } | Select-Object -Last 10)
    foreach ($m in $timeoutHits) { Add-TimelineEvent -Time $null -Phase 'ESP-DeviceSetup' -Source "$($m.Filename)" -Message $m.Line.Substring(0, [Math]::Min(300, $m.Line.Length)) }
    if ($timeoutHits.Count -gt 0) {
        Add-Signal -Signal 'D_SCRIPT_TIMEOUT_GAP' -Severity 'Warn' -Finding "IME logs contain $($timeoutHits.Count) script lines mentioning a timeout. Intune scripts run before Win32 apps and time out after 30 minutes; a hung script holds ESP for that long. Text match only: read the lines."
    }
}
if ($espPresent -and -not $script:Facts.EspDeviceSetupKey -and $script:Facts.ImeService -eq 'Running') {
    Add-Signal -Signal 'D_SCRIPT_TIMEOUT_GAP' -Severity 'Info' -Finding 'ESP tracking exists but ...\Device\Setup has not appeared yet while IME runs. In one field case a hung device script delayed this key by exactly 30 minutes. Re-run in 10 minutes and compare.'
}

# ------------------------------------------------------------------ match against known causes
$knownCauses = @()
if (Test-Path -LiteralPath $KnownCausesPath) {
    try { $knownCauses = @((Get-Content -LiteralPath $KnownCausesPath -Raw | ConvertFrom-Json).causes) }
    catch { Write-Warning -Message "known-causes.json unreadable: $($_.Exception.Message)" }
}
else { Write-Warning -Message "known-causes.json not found at $KnownCausesPath" }
foreach ($s in $script:Signals) {
    $s.KnownCauseIds = @($knownCauses | Where-Object { @($_.signals) -contains $s.Signal } | ForEach-Object { $_.id })
}

# ------------------------------------------------------------------ verdicts
$ordered = @($script:Timeline | Sort-Object -Property @{ Expression = { $PhaseOrder[$_.Phase] } }, @{ Expression = { if ($_.Time) { $_.Time } else { [datetime]::MaxValue } } })
$sevOrder = @{ 'Fail' = 1; 'Warn' = 2; 'Info' = 3 }
$verdicts = @($script:Signals | Sort-Object -Property @{ Expression = { $sevOrder[$_.Severity] } })
$mode = if ($espPresent) { 'Autopilot v1 (ESP seen)' } elseif ($script:Facts.BootstrapperEvents -gt 0 -or $dpKeys.Count -gt 0) { 'Device Prep (no ESP, APv2 footprint)' } else { 'Undetermined (no ESP or Device Prep footprint found)' }
$script:Facts.DeploymentType = $mode

$collectMd = 'md C:\Temp   (or: New-Item -Path C:\Temp -ItemType Directory -Force)'
$collect = 'mdmdiagnosticstool.exe -area Autopilot -cab C:\Temp\AutopilotDiag.cab'
$collectTpm = 'mdmdiagnosticstool.exe -area "Autopilot;TPM" -cab C:\Temp\AutopilotDiag.cab'

Write-Information -MessageData "`nZakitPro Deployment Doctor - device diagnostic 1.3.1 (read-only)" -InformationAction Continue
Write-Information -MessageData "Expected: $ExpectedMode | Deployment type: $mode | $($script:Facts.OS) | IME: $(if ($imeVersion) { $imeVersion } else { 'not installed' })" -InformationAction Continue
if ($verdicts.Count -eq 0) { Write-Information -MessageData 'No known-cause signals found.' -InformationAction Continue }
foreach ($v in $verdicts) {
    Write-Information -MessageData ("[{0}] {1}" -f $v.Severity.ToUpper(), $v.Finding) -InformationAction Continue
    foreach ($cid in $v.KnownCauseIds) {
        $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1
        Write-Information -MessageData ("       Fix ({0}): {1}`n       Why: {2}" -f $cid, $c.fix, $c.cause) -InformationAction Continue
    }
}
Write-Information -MessageData "`nBefore any reset, collect logs (copy the CAB off the device):`n  $collectMd`n  $collect`n  Self-deploying, pre-provisioning or any other physical device (per Learn): $collectTpm`nAlso check Intune for an auto-collected diagnostics bundle first." -InformationAction Continue

function ConvertTo-ZkReportStatus {
    <#
    .SYNOPSIS
        Maps a result, severity or confidence word to a report colour: red, yellow, green or grey.
    .PARAMETER Value
        For example Pass, Warn, Fail, High, Medium, Low, Info, NotChecked.
    .EXAMPLE
        ConvertTo-ZkReportStatus -Value 'Fail'
    .EXAMPLE
        ConvertTo-ZkReportStatus -Value 'Medium'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()][AllowEmptyString()][string]$Value)
    switch -Regex ($Value) {
        '^(Fail|High|Error)' { return 'red' }
        '^(Warn|Medium|Low)' { return 'yellow' }
        '^(Pass|OK|Healthy)' { return 'green' }
        default { return 'grey' }
    }
}

function Get-ZkNextStepLink {
    <#
    .SYNOPSIS
        Builds the 'Next step' control: a button to the first Microsoft Learn URL, else the KC/check code.
    .PARAMETER Url
        Candidate source URLs. Only https://learn.microsoft.com/ links are used.
    .PARAMETER Code
        Known-cause or check code shown when no Learn URL exists.
    .EXAMPLE
        Get-ZkNextStepLink -Url 'https://learn.microsoft.com/x' -Code 'KC-001'
    .EXAMPLE
        Get-ZkNextStepLink -Code 'KC-002'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()][string[]]$Url, [Parameter()][string]$Code)
    $learn = @($Url | Where-Object { $_ -match '^https://learn\.microsoft\.com/' }) | Select-Object -First 1
    if ($learn) { return '<a class="next" href="' + [System.Net.WebUtility]::HtmlEncode($learn) + '" rel="noopener noreferrer">Next step</a>' }
    if ($Code) { return '<span class="next next-code" title="See this code in the full kit">' + [System.Net.WebUtility]::HtmlEncode($Code) + '</span>' }
    return '<span class="next next-code">Review evidence</span>'
}

function ConvertTo-ZkDashboardHtml {
    <#
    .SYNOPSIS
        Renders a self-contained HTML dashboard (inline CSS and vanilla JS, no external resources).
    .DESCRIPTION
        Each finding needs Status, Scope, Check, Finding, Evidence and NextHtml (from Get-ZkNextStepLink).
        All text is HTML-escaped here; ExtraHtml must already be escaped by the caller.
        The table is fully visible without JavaScript; JS only adds filtering, search and the theme toggle.
    .PARAMETER Title
        Page heading.
    .PARAMETER Subtitle
        Plain-text line under the heading.
    .PARAMETER Finding
        Finding objects.
    .PARAMETER ExtraHtml
        Pre-escaped HTML appended after the findings table.
    .PARAMETER Brand
        Product name shown above the title.
    .PARAMETER Banner
        Plain-text notice shown under the header.
    .EXAMPLE
        ConvertTo-ZkDashboardHtml -Title 'Report' -Subtitle 'Sample' -Finding $rows
    .EXAMPLE
        ConvertTo-ZkDashboardHtml -Title 'Report' -Subtitle 'Sample' -Finding @() -ExtraHtml '<p>x</p>'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter()][string]$Subtitle,
        [Parameter()][AllowEmptyCollection()][object[]]$Finding = @(),
        [Parameter()][string]$ExtraHtml = '',
        [Parameter()][string]$Brand = 'ZakitPro Deployment Doctor',
        [Parameter()][string]$Banner = 'Read-only, local report. Not tested against a live tenant. Test in non-production first. This file makes no network requests.'
    )
    $enc = { param($x) [System.Net.WebUtility]::HtmlEncode([string]$x) }
    $label = @{ red = 'Critical'; yellow = 'Warning'; green = 'Passed'; grey = 'Info' }
    $count = @{ red = 0; yellow = 0; green = 0; grey = 0 }
    $statuses = New-Object -TypeName System.Collections.Generic.List[string]
    $rows = New-Object -TypeName System.Text.StringBuilder
    $hasConf = @($Finding | Where-Object { $_.PSObject.Properties['Confidence'] -and -not [string]::IsNullOrWhiteSpace([string]$_.Confidence) }).Count -gt 0
    foreach ($f in @($Finding)) {
        $c = ConvertTo-ZkReportStatus -Value ([string]$f.Status)
        $count[$c]++
        $st = [string]$f.Status
        if (-not $statuses.Contains($st)) { $statuses.Add($st) }
        $ev = & $enc $f.Evidence
        $evCell = if ([string]::IsNullOrWhiteSpace([string]$f.Evidence)) { '<span class="muted">None</span>' } else { '<details><summary>Show evidence</summary><pre>' + $ev + '</pre></details><pre class="print-ev">' + $ev + '</pre>' }
        [void]$rows.Append('<tr data-sev="' + $c + '" data-st="' + (& $enc $st) + '"><td><span class="st st-' + $c + '" data-status="' + $c + '">' + $label[$c] + '</span></td><td>' + (& $enc $st) + '</td>' + $(if ($hasConf) { '<td>' + $(if ($f.PSObject.Properties['Confidence']) { & $enc $f.Confidence } else { '' }) + '</td>' } else { '' }) + '<td>' + (& $enc $f.Scope) + '</td><td>' + (& $enc $f.Check) + '</td><td>' + (& $enc $f.Finding) + '</td><td>' + $evCell + '</td><td>' + $f.NextHtml + '</td></tr>' + "`n")
    }
    if (@($Finding).Count -eq 0) { [void]$rows.Append('<tr><td colspan="8" class="muted">No checks produced output.</td></tr>') }
    $scored = $count.red + $count.yellow + $count.green
    $score = if ($scored -gt 0) { [int][Math]::Round(100 * ($count.green + 0.5 * $count.yellow) / $scored) } else { 100 }
    $rawScore = $score
    $capped = $false
    if ($count.red -gt 0 -and $score -gt 49) { $score = 49; $capped = $true }
    $scoreClass = if ($count.red -gt 0) { 'red' } elseif ($score -ge 85) { 'green' } elseif ($score -ge 60) { 'yellow' } else { 'red' }
    $legend = 'Weighting: Passed = 1, Warning = 0.5, Critical = 0; Info and not-checked rows are not scored. Any Critical finding caps the score at 49 and turns the ring red.'
    $scoreNote = if ($count.red -gt 0) { '<div class="crit" role="alert">Critical issues present' + $(if ($capped) { ' (score capped at 49; uncapped ' + $rawScore + ')' } else { '' }) + '</div>' } else { '<div class="muted">out of 100</div>' }
    $stOptions = ($statuses | Sort-Object | ForEach-Object { '<option value="' + (& $enc $_) + '">' + (& $enc $_) + '</option>' }) -join ''
    $css = @'
:root{--bg:#ffffff;--surface:#eef6ff;--card:#ffffff;--text:#060f30;--muted:#4b5563;--secondary:#263d76;--border:#dbe3f0;--link:#0369a1;--btn:#0369a1;--btn-text:#ffffff;
--red-bg:#fee2e2;--red-fg:#991b1b;--yellow-bg:#fef9c3;--yellow-fg:#854d0e;--green-bg:#dcfce7;--green-fg:#166534;--grey-bg:#f3f4f6;--grey-fg:#374151;--head:#060f30;--head-text:#ffffff;color-scheme:light}
:root[data-theme=dark]{--bg:#060f30;--surface:#1a2752;--card:#0d1940;--text:#f4f7ff;--muted:#c6d9ff;--secondary:#c6d9ff;--border:#263d76;--link:#7dd3fc;--btn:#0ea5e9;--btn-text:#060f30;
--red-bg:#7f1d1d;--red-fg:#fee2e2;--yellow-bg:#713f12;--yellow-fg:#fef9c3;--green-bg:#14532d;--green-fg:#dcfce7;--grey-bg:#263d76;--grey-fg:#f4f7ff;--head:#1a2752;--head-text:#f4f7ff;color-scheme:dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#060f30;--surface:#1a2752;--card:#0d1940;--text:#f4f7ff;--muted:#c6d9ff;--secondary:#c6d9ff;--border:#263d76;--link:#7dd3fc;--btn:#0ea5e9;--btn-text:#060f30;
--red-bg:#7f1d1d;--red-fg:#fee2e2;--yellow-bg:#713f12;--yellow-fg:#fef9c3;--green-bg:#14532d;--green-fg:#dcfce7;--grey-bg:#263d76;--grey-fg:#f4f7ff;--head:#1a2752;--head-text:#f4f7ff;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:24px}header.top{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;margin-bottom:16px}
.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--secondary);font-weight:700}h1{margin:2px 0 4px;font-size:24px}h2{font-size:17px;margin:28px 0 10px;color:var(--secondary)}h3{font-size:15px;color:var(--secondary)}
.muted,.meta{color:var(--muted)}.meta{font-size:13px}.banner{background:var(--surface);border-left:4px solid var(--btn);border-radius:8px;padding:10px 14px;margin:0 0 18px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;box-shadow:0 1px 2px rgba(6,15,48,.06)}
.card .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}.card .v{font-size:28px;font-weight:700;margin-top:2px}.card.red{border-top:4px solid var(--red-fg)}.card.yellow{border-top:4px solid var(--yellow-fg)}.card.green{border-top:4px solid var(--green-fg)}.card.grey{border-top:4px solid var(--grey-fg)}
.score{display:flex;align-items:center;gap:14px}.ring{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:20px;border:6px solid var(--border)}.ring.green{border-color:var(--green-fg)}.ring.yellow{border-color:var(--yellow-fg)}.ring.red{border-color:var(--red-fg)}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:end;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px;margin-bottom:10px}.filters label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:4px}
.filters input,.filters select{font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:6px 10px;min-width:170px}
button.tg{font:inherit;cursor:pointer;background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:9999px;padding:6px 14px}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;background:var(--card)}table{border-collapse:collapse;width:100%}th{background:var(--head);color:var(--head-text);text-align:left;padding:9px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0}
td{padding:9px 10px;border-top:1px solid var(--border);vertical-align:top;word-break:break-word}tbody tr:hover{background:var(--surface)}
.st{display:inline-block;border-radius:9999px;padding:2px 10px;font-size:12px;font-weight:700;white-space:nowrap;word-break:keep-all}
#zk-findings th:nth-child(1),#zk-findings td:nth-child(1){min-width:104px;white-space:nowrap}#zk-findings th:nth-child(2),#zk-findings td:nth-child(2){min-width:96px;white-space:nowrap;word-break:keep-all}
.crit{display:inline-block;margin-top:4px;background:var(--red-bg);color:var(--red-fg);font-weight:700;font-size:12px;border-radius:9999px;padding:2px 10px}.legend{font-size:12px;color:var(--muted);margin-top:6px;max-width:260px}.card.scorecard{grid-column:span 2}.st-red{background:var(--red-bg);color:var(--red-fg)}.st-yellow{background:var(--yellow-bg);color:var(--yellow-fg)}.st-green{background:var(--green-bg);color:var(--green-fg)}.st-grey{background:var(--grey-bg);color:var(--grey-fg)}
details summary{cursor:pointer;color:var(--link);font-weight:600}pre{white-space:pre-wrap;word-break:break-word;margin:6px 0 0;font:12px/1.5 ui-monospace,"Cascadia Mono",Consolas,monospace;background:var(--surface);padding:8px;border-radius:6px}.print-ev{display:none}
a{color:var(--link)}a.next{display:inline-block;background:var(--btn);color:var(--btn-text);text-decoration:none;font-weight:700;border-radius:8px;padding:6px 12px;white-space:nowrap}a.next:focus,button.tg:focus,.filters input:focus,.filters select:focus{outline:3px solid #47c0f8;outline-offset:2px}
.next-code{display:inline-block;border:1px solid var(--border);border-radius:8px;padding:5px 10px;font-weight:700;white-space:nowrap}code{font-family:ui-monospace,Consolas,monospace;background:var(--surface);padding:1px 4px;border-radius:4px}
footer{margin-top:28px;font-size:12px;color:var(--muted);border-top:1px solid var(--border);padding-top:12px}.hidden-js{display:none}
@media print{:root,:root[data-theme=dark]{--bg:#ffffff;--surface:#f3f4f6;--card:#ffffff;--text:#000000;--muted:#374151;--secondary:#060f30;--border:#9ca3af;--link:#000000;--head:#ffffff;--head-text:#000000;color-scheme:light}
.filters,button.tg,details{display:none !important}.print-ev{display:block}.wrap{max-width:none;padding:0}th{position:static;border-bottom:2px solid #000}tr{page-break-inside:avoid}.st{border:1px solid #000}
a.next{background:none;color:#000;border:1px solid #000}a.next:after{content:" (" attr(href) ")";font-weight:400;word-break:break-all}.card{box-shadow:none}tbody tr[hidden]{display:table-row !important}}
'@
    $js = @'
(function(){var d=document,r=d.documentElement;
function setT(t){r.setAttribute("data-theme",t);try{window.localStorage.setItem("zk-theme",t)}catch(e){}}
try{var s=window.localStorage.getItem("zk-theme");if(s==="dark"||s==="light"){r.setAttribute("data-theme",s)}}catch(e){}
var f=d.getElementById("zk-filters"),b=d.getElementById("zk-theme");if(f){f.classList.remove("hidden-js")}if(b){b.classList.remove("hidden-js");
b.addEventListener("click",function(){var cur=r.getAttribute("data-theme");if(!cur){cur=(window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light"}setT(cur==="dark"?"light":"dark")})}
var q=d.getElementById("zk-q"),sv=d.getElementById("zk-sev"),st=d.getElementById("zk-st"),n=d.getElementById("zk-count"),rows=d.querySelectorAll("#zk-findings tbody tr[data-sev]");
function apply(){var t=(q.value||"").toLowerCase(),a=sv.value,b2=st.value,v=0;for(var i=0;i<rows.length;i++){var x=rows[i],ok=(!a||x.getAttribute("data-sev")===a)&&(!b2||x.getAttribute("data-st")===b2)&&(!t||x.textContent.toLowerCase().indexOf(t)>=0);x.hidden=!ok;if(ok){v++}}if(n){n.textContent=v+" of "+rows.length+" shown"}}
if(q&&sv&&st){q.addEventListener("input",apply);sv.addEventListener("change",apply);st.addEventListener("change",apply);apply()}
window.addEventListener("beforeprint",function(){for(var i=0;i<rows.length;i++){rows[i].hidden=false}});
})();
'@
    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.Append('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; script-src ''unsafe-inline''; img-src data:; base-uri ''none''; form-action ''none''">')
    [void]$sb.Append('<meta name="referrer" content="no-referrer"><title>' + (& $enc $Title) + '</title><style>' + $css + '</style></head><body><div class="wrap">')
    [void]$sb.Append('<header class="top"><div><div class="brand">' + (& $enc $Brand) + '</div><h1>' + (& $enc $Title) + '</h1><div class="meta">' + (& $enc $Subtitle) + '</div></div>')
    [void]$sb.Append('<button type="button" id="zk-theme" class="tg hidden-js" aria-label="Toggle dark or light theme">Toggle theme</button></header>')
    [void]$sb.Append('<div class="banner">' + (& $enc $Banner) + '</div>')
    [void]$sb.Append('<section class="grid" aria-label="Summary"><div class="card scorecard" title="' + (& $enc $legend) + '"><div class="score"><div class="ring ' + $scoreClass + '" aria-label="Health score ' + $score + ' out of 100" data-capped="' + $(if ($capped) { 'true' } else { 'false' }) + '">' + $score + '</div><div><div class="k">Health score</div>' + $scoreNote + '</div></div><div class="legend" id="zk-legend">' + (& $enc $legend) + '</div></div>')
    foreach ($k in 'red', 'yellow', 'green', 'grey') { [void]$sb.Append('<div class="card ' + $k + '"><div class="k">' + $label[$k] + '</div><div class="v">' + $count[$k] + '</div></div>') }
    [void]$sb.Append('</section><h2>Findings</h2>')
    [void]$sb.Append('<div id="zk-filters" class="filters hidden-js" role="search"><label>Search<input id="zk-q" type="search" placeholder="Filter by any text"></label>')
    [void]$sb.Append('<label>Severity<select id="zk-sev"><option value="">All</option><option value="red">Critical</option><option value="yellow">Warning</option><option value="green">Passed</option><option value="grey">Info</option></select></label>')
    [void]$sb.Append('<label>Status<select id="zk-st"><option value="">All</option>' + $stOptions + '</select></label><span id="zk-count" class="muted" aria-live="polite"></span></div>')
    [void]$sb.Append('<div class="tablewrap"><table id="zk-findings"><thead><tr><th>Severity</th><th>Status</th>' + $(if ($hasConf) { '<th>Confidence</th>' } else { '' }) + '<th>Scope</th><th>Check</th><th>Finding</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>')
    [void]$sb.Append($rows.ToString())
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append($ExtraHtml)
    [void]$sb.Append('<footer>Health score = round(100 x (Passed + 0.5 x Warning) / (Passed + Warning + Critical)); Info and not-checked rows are excluded, and the score is 100 when nothing was scored. If any Critical finding exists, the score is capped at 49 and shown in red. It summarises this run only and is not a security rating. Generated locally by a read-only script; no data leaves this file.</footer>')
    [void]$sb.Append('</div><script>' + $js + '</script></body></html>')
    $sb.ToString()
}

# ------------------------------------------------------------------ reports
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonFile = Join-Path -Path $OutputPath -ChildPath "DeviceDiagnostic-$stamp.json"
$allCauseIds = @($verdicts | ForEach-Object { $_.KnownCauseIds })
    [PSCustomObject]@{
        Tool     = 'ZakitPro Kit 1 Invoke-DeviceDiagnostic 1.3.1'
        Facts    = $script:Facts
        Verdicts = $verdicts
        Timeline = $ordered
        Causes   = @($knownCauses | Where-Object { $allCauseIds -contains $_.id })
        Collect  = @($collectMd, $collect, $collectTpm)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    if (-not $NoHtml) {
        $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
        $dash = foreach ($v in $verdicts) {
            $urls = @(); $why = @()
            foreach ($cid in @($v.KnownCauseIds)) {
                $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1
                if ($c) { $urls += @($c.source_urls); $why += ('{0}: {1} Fix: {2}' -f $cid, $c.cause, $c.fix) }
            }
            [pscustomobject]@{ Status = $v.Severity; Scope = 'Device'; Check = $v.Signal; Finding = $v.Finding; Evidence = ((@("Signal: $($v.Signal)") + $why) -join "`n"); NextHtml = (Get-ZkNextStepLink -Url $urls -Code (@($v.KnownCauseIds) -join ', ')) }
        }
        if (@($verdicts).Count -eq 0) { $dash = @([pscustomobject]@{ Status = 'Pass'; Scope = 'Device'; Check = 'Known-cause signals'; Finding = 'No known-cause signals found.'; Evidence = ''; NextHtml = '<span class="next next-code">Keep the logs</span>' }) }
        $tRows = foreach ($t in $ordered) { $ph = if ($t.Phase -eq 'Unknown') { 'Context (no time)' } else { $t.Phase }; "<tr><td>$(& $enc $ph)</td><td>$(& $enc $t.Time)</td><td>$(& $enc $t.Source)</td><td>$(& $enc $t.Message)</td></tr>" }
        $extra = "<h2>Collect before reset</h2><p><code>$(& $enc $collectMd)</code><br><code>$(& $enc $collect)</code><br><code>$(& $enc $collectTpm)</code> (self-deploying, pre-provisioning or any other physical device, per Learn; user-driven mode: the first command)</p>" +
        "<h2>Timeline</h2><p class=`"muted`">Phase order; times approximate; registry rows have no time.</p><div class=`"tablewrap`"><table><thead><tr><th>Phase</th><th>Time</th><th>Source</th><th>Message</th></tr></thead><tbody>$($tRows -join "`n")</tbody></table></div>"
        $htmlFile = Join-Path -Path $OutputPath -ChildPath "DeviceDiagnostic-$stamp.html"
        ConvertTo-ZkDashboardHtml -Title 'Device diagnostic' -Subtitle ('Kit 1 | {0} | {1} | {2} | IME {3} | run {4}' -f $script:Facts.Source, $mode, $script:Facts.OS, $imeVersion, $script:Facts.RunAt) -Banner $(if ($script:Sample) { 'Sample run on FAKE data. Nothing on this computer was read.' } else { 'Read-only, local report. Not tested on a real device. Test on a non-production device first. This file makes no network requests.' }) -Finding @($dash) -ExtraHtml $extra | Set-Content -LiteralPath $htmlFile -Encoding UTF8
    }
    Write-Information -MessageData "Reports written to $OutputPath" -InformationAction Continue
}
catch {
    Write-Error -Message "Could not write reports to $OutputPath : $($_.Exception.Message)"
}
if ($PassThru) { $verdicts }
