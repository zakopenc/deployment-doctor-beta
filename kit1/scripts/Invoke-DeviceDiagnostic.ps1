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

.PARAMETER PassThru
    Also return the verdict objects to the pipeline (for scripting). Off by default so the console stays clean.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File D:\Kit1\scripts\Invoke-DeviceDiagnostic.ps1 -OutputPath D:\
    At Shift+F10 in OOBE. Process-scoped bypass only, for this one run; reports go to the USB drive.

.EXAMPLE
    .\Invoke-DeviceDiagnostic.ps1 -ExpectedMode DevicePrep -PassThru | Where-Object Severity -eq 'Fail'
    You expected Device Prep; returns verdict objects and filters to failures.

.OUTPUTS
    With -PassThru: PSCustomObject[] verdicts (Severity, Signal, Finding, KnownCauseIds). Always writes HTML and JSON.

.NOTES
    Name:         Invoke-DeviceDiagnostic.ps1
    Version:      1.3.0 (2026-10-16)
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
    [switch]$PassThru
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

function Get-RegistryValueSafe {
    [OutputType([object])]
    <# Returns a hashtable of value name -> data for a key, or $null if missing. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
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
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    try {
        return @(Get-ChildItem -LiteralPath $Root -Recurse -Depth $Depth -ErrorAction SilentlyContinue |
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
    $logs = @(Get-WinEvent -ListLog $LogPattern -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })
    foreach ($log in $logs) {
        $filter = @{ LogName = $log.LogName }
        if ($Id) { $filter.Id = $Id }
        try {
            $out += @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop)
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') { Write-Verbose -Message "Read $($log.LogName) failed: $($_.Exception.Message)" }
        }
    }
    return , $out
}

# ------------------------------------------------------------------ device basics
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $script:Facts.OS = "$($os.Caption) build $($os.BuildNumber)"
    $script:Facts.LastBoot = $os.LastBootUpTime
}
catch { $script:Facts.OS = "Unknown ($($_.Exception.Message))" }
$script:Facts.Computer = $env:COMPUTERNAME
$script:Facts.RunAt = (Get-Date).ToString('o')
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { Write-Verbose -Message "Elevation check unavailable: $($_.Exception.Message)" }
$script:Facts.Elevated = $isAdmin
if (-not $isAdmin) { Write-Warning -Message 'Not elevated: some event logs and registry keys may be unreadable.' }

# ------------------------------------------------------------------ M3: ESP tracking (APv1)
$espRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
$espPresent = Test-Path -LiteralPath $espRoot
$script:Facts.EspTrackingKey = $espPresent
if ($espPresent) {
    if ($ExpectedMode -eq 'DevicePrep') {
        Add-Signal -Signal 'D_ESP_PRESENT_EXPECTED_DP' -Severity 'Warn' -Finding 'You expected Device Prep, but this device ran the Enrollment Status Page (ESP tracking key exists). A registered Autopilot profile probably took precedence.'
    }
    $deviceSetup = Test-Path -LiteralPath "$espRoot\Device\Setup"
    $script:Facts.EspDeviceSetupKey = $deviceSetup
    $stateNames = @{ 1 = 'NotInstalled'; 2 = 'InProgress'; 3 = 'Completed'; 4 = 'Error' }
    $appKeys = @(Get-ChildItem -LiteralPath $espRoot -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Win32App_*' })
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
    if (-not (Test-Path -LiteralPath $u)) { continue }
    foreach ($k in @(Get-ChildItem -LiteralPath $u -ErrorAction SilentlyContinue)) {
        if ([string]$k.GetValue('DisplayName') -eq 'Microsoft Intune Management Extension') { $imeVersion = [string]$k.GetValue('DisplayVersion') }
    }
}
$imeService = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$imeLogDir = Join-Path -Path $programData -ChildPath 'Microsoft\IntuneManagementExtension\Logs'
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

Write-Information -MessageData "`nZakitPro Deployment Doctor - device diagnostic 1.3.0 (read-only)" -InformationAction Continue
Write-Information -MessageData "Expected: $ExpectedMode | Deployment type: $mode | $($script:Facts.OS) | IME: $(if ($imeVersion) { $imeVersion } else { 'not installed' })" -InformationAction Continue
if ($verdicts.Count -eq 0) { Write-Information -MessageData 'No known-cause signals found.' -InformationAction Continue }
foreach ($v in $verdicts) {
    Write-Information -MessageData ("[{0}] {1}" -f $v.Severity.ToUpper(), $v.Finding) -InformationAction Continue
    foreach ($cid in $v.KnownCauseIds) {
        $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1
        Write-Information -MessageData ("       Fix ({0}): {1}`n       Why: {2}" -f $cid, $c.fix, $c.cause) -InformationAction Continue
    }
}
Write-Information -MessageData "`nBefore any reset, collect logs (copy the CAB off the device):`n  $collectMd`n  $collect`n  Pre-provisioning/self-deploying only: $collectTpm`nAlso check Intune for an auto-collected diagnostics bundle first." -InformationAction Continue

$script:ZkReportCss = 'body{font-family:Inter,''Segoe UI'',Arial,sans-serif;font-size:13px;margin:24px;color:#060f30;background:#ffffff}h1{color:#060f30;margin-bottom:4px}h2{color:#263d76;border-bottom:2px solid #eef6ff;padding-bottom:4px}h3{color:#263d76}.meta{color:#4b5563}.warnbox{background:#eef6ff;border-left:4px solid #263d76;padding:8px 12px;margin:12px 0}table{border-collapse:collapse;width:100%;margin:8px 0 18px}th{background:#060f30;color:#ffffff;text-align:left;padding:6px}td{padding:6px;border-bottom:1px solid #e5e7eb;vertical-align:top;word-break:break-word}code{font-family:''JetBrains Mono'',Consolas,monospace;background:#eef6ff;padding:1px 3px;word-break:break-all}.st{display:inline-block;border-radius:9999px;padding:2px 10px;font-size:11px;font-weight:700;white-space:nowrap}.st-green{background:#dcfce7;color:#166534}.st-yellow{background:#fef9c3;color:#854d0e}.st-red{background:#fee2e2;color:#991b1b}.st-grey{background:#f3f4f6;color:#374151}a{color:#0369a1}a.next{font-weight:600}.summary span{margin-right:12px}@media print{body{margin:0;font-size:11px}a{color:#060f30;text-decoration:underline}a.next:after{content:'' ('' attr(href) '')'';font-weight:400;word-break:break-all}th{background:#ffffff !important;color:#060f30 !important;border-bottom:2px solid #060f30}tr{page-break-inside:avoid}.st{border:1px solid #374151}}'

function ConvertTo-ZkReportStatus {
    <#
    .SYNOPSIS
        Maps a result or severity word to a report status colour (green, yellow, red or grey).
    .PARAMETER Value
        Result/severity text, for example Pass, Warn, Fail, High, Medium, Low, Info, NotChecked.
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

function Get-ZkReportBadge {
    <#
    .SYNOPSIS
        Returns an HTML status pill with a text label (colour is never the only signal).
    .PARAMETER Value
        Result/severity text shown on the pill.
    .EXAMPLE
        Get-ZkReportBadge -Value 'Pass'
    .EXAMPLE
        Get-ZkReportBadge -Value 'High'
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()][AllowEmptyString()][string]$Value)
    $s = ConvertTo-ZkReportStatus -Value $Value
    '<span class="st st-{0}" data-status="{0}">{1}</span>' -f $s, [System.Net.WebUtility]::HtmlEncode($Value)
}

function Get-ZkNextStepLink {
    <#
    .SYNOPSIS
        Builds the 'what to do next' anchor: the first Microsoft Learn URL, else the KC code text.
    .PARAMETER Url
        Candidate source URLs.
    .PARAMETER Code
        Known-cause or check code, used when no Learn URL exists.
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
    if ($learn) { return '<a class="next" href="{0}">Microsoft Learn: what to do next</a>' -f [System.Net.WebUtility]::HtmlEncode($learn) }
    if ($Code) { return '<span class="next">See {0} in the full kit</span>' -f [System.Net.WebUtility]::HtmlEncode($Code) }
    return '<span class="next">Review the evidence</span>'
}

# ------------------------------------------------------------------ reports
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonFile = Join-Path -Path $OutputPath -ChildPath "DeviceDiagnostic-$stamp.json"
$allCauseIds = @($verdicts | ForEach-Object { $_.KnownCauseIds })
    [PSCustomObject]@{
        Tool     = 'ZakitPro Kit 1 Invoke-DeviceDiagnostic 1.3.0'
        Facts    = $script:Facts
        Verdicts = $verdicts
        Timeline = $ordered
        Causes   = @($knownCauses | Where-Object { $allCauseIds -contains $_.id })
        Collect  = @($collectMd, $collect, $collectTpm)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    if (-not $NoHtml) {
        $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
        $vRows = foreach ($v in $verdicts) {
            $urls = @(); foreach ($cid in $v.KnownCauseIds) { $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1; $urls += @($c.source_urls) }
            $next = Get-ZkNextStepLink -Url $urls -Code ($v.KnownCauseIds -join ', ')
            "<tr><td>$(Get-ZkReportBadge -Value $v.Severity)</td><td>$(& $enc $v.Signal)</td><td>$(& $enc $v.Finding)</td><td>$(& $enc ($v.KnownCauseIds -join ', '))</td><td>$next</td></tr>"
        }
        if (@($verdicts).Count -eq 0) { $vRows = "<tr><td>$(Get-ZkReportBadge -Value 'Pass')</td><td></td><td>No known-cause signals found.</td><td></td><td><span class=`"next`">Keep the logs if the problem returns</span></td></tr>" }
        $tRows = foreach ($t in $ordered) { $ph = if ($t.Phase -eq 'Unknown') { 'Context (no time)' } else { $t.Phase }; "<tr><td>$(& $enc $ph)</td><td>$(& $enc $t.Time)</td><td>$(& $enc $t.Source)</td><td>$(& $enc $t.Message)</td></tr>" }
        $htmlFile = Join-Path -Path $OutputPath -ChildPath "DeviceDiagnostic-$stamp.html"
        @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZakitPro Device Diagnostic</title>
<style>$($script:ZkReportCss)</style></head><body>
<h1>Deployment Doctor: device diagnostic</h1>
<p class="meta">$(& $enc $mode) &middot; $(& $enc $script:Facts.OS) &middot; IME $(& $enc $imeVersion) &middot; run $(& $enc $script:Facts.RunAt)</p>
<div class="warnbox"><b>Read-only, local report.</b> Not tested against a live tenant. Test in non-production first. No data leaves this file.</div>
<h2>Checks</h2><table><thead><tr><th>Status</th><th>Signal</th><th>Evidence</th><th>Known cause</th><th>What to do next</th></tr></thead><tbody>$($vRows -join "`n")</tbody></table>
<h2>Collect before reset</h2><p><code>$(& $enc $collectMd)</code><br><code>$(& $enc $collect)</code><br><code>$(& $enc $collectTpm)</code> (pre-provisioning/self-deploying only)</p>
<h2>Timeline (phase order; times approximate, registry rows have no time)</h2>
<table><thead><tr><th>Phase</th><th>Time</th><th>Source</th><th>Message</th></tr></thead><tbody>$($tRows -join "`n")</tbody></table>
</body></html>
"@ | Set-Content -LiteralPath $htmlFile -Encoding UTF8
    }
    Write-Information -MessageData "Reports written to $OutputPath" -InformationAction Continue
}
catch {
    Write-Error -Message "Could not write reports to $OutputPath : $($_.Exception.Message)"
}
if ($PassThru) { $verdicts }
