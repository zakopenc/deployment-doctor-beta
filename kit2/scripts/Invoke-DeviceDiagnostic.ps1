#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only, on-device Win32 app diagnosis: parses IME logs and the Win32Apps registry,
    builds a per-app timeline and matches it against the known-causes database.

.DESCRIPTION
    ZakitPro Kit 2 - Win32 App Deployment Doctor. Device diagnostic.

    What it reads (nothing is written except the two report files in -OutputPath):
      - IME logs in C:\ProgramData\Microsoft\IntuneManagementExtension\Logs (or -LogPath):
        IntuneManagementExtension*.log, AppWorkload*.log (if present), AppActionProcessor*.log,
        including rolled-over copies.
      - HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps (ComplianceStateMessage /
        EnforcementStateMessage JSON, GRS entry count). Skipped with -SkipRegistry.
      - The IntuneManagementExtension service state and file version.

    The log parser is a clean-room implementation written from the CMTrace record format
    (<![LOG[message]LOG]!><time=".." date=".." component=".." context="" type="N" thread="N" file="..">)
    and the IME step messages that Microsoft documents (support tip "Understanding the flow behind
    deployment, delivery, and processing of a Win32 application"). It does not use or port code from
    any unlicensed project. Lines it cannot classify stay in the raw timeline.

    Output: a JSON file and an HTML file with, per app, a timeline, the registry state, the signals
    found and the matching verdicts (each with sources from known-causes.json).

.PARAMETER LogPath
    Folder with IME logs. Default: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs.
    Point it at a copied log folder to analyse logs offline (add -SkipRegistry).

.PARAMETER OutputPath
    Folder for the reports. Default: $env:TEMP\ZakitPro-Kit2

.PARAMETER AppId
    Only report on these Intune app IDs (GUIDs).

.PARAMETER DaysBack
    Ignore log records older than this many days. Default 14.

.PARAMETER KnownCausesPath
    Path to known-causes.json. Default: next to this script.

.PARAMETER TenantReportPath
    Optional JSON report from Invoke-TenantPreCheck.ps1. Adds app names, detection rules and
    tenant findings to each app section.

.PARAMETER ExpectNewVersion
    Say that you expected a new version to install. Then an app that IME found "already detected"
    before install is reported as KC-002 (detection rule too broad) instead of as a normal step.
.PARAMETER NoHtml
    Skip the HTML report (JSON and console summary only).
.PARAMETER PassThru
    Also return the summary object (report paths and counts) to the pipeline. Without it the
    script prints a console summary only.
.PARAMETER SkipRegistry
    Don't read the registry or the service (offline log analysis).

.EXAMPLE
    .\Invoke-DeviceDiagnostic.ps1
    Analyses this device (run elevated so the IME log folder is readable).

.EXAMPLE
    .\Invoke-DeviceDiagnostic.ps1 -LogPath D:\Collected\Logs -SkipRegistry -TenantReportPath .\Kit2-TenantPreCheck.json
    Analyses logs copied from another device and cross-references the tenant report.

.OUTPUTS
    PSCustomObject with ReportJson, ReportHtml, AppCount and VerdictCount.

.NOTES
    Name:        Invoke-DeviceDiagnostic.ps1
    Version:     1.2.0 (2026-10-16)
    Publisher:   ZakitPro (zakitpro.com), author Abderrazak Elbouchikhi (Zak). Support: hello@zakitpro.com
    Requires:    Windows PowerShell 5.1 or PowerShell 7.x. Local admin recommended (log folder ACL).
                 No modules, no network, no Graph.
    Tested on:   NOT tested on a live device. PSScriptAnalyzer and Pester unit tests with synthetic
                 log fixtures (built from the documented format) on PowerShell 7.4.6 (Linux).
    Changelog:   See CHANGELOG.md
    Reuse:       CMTrace record layout as documented by cmtraceopen (MIT, Adam Gell); see CREDITS.md.

    DISCLAIMER: Provided AS IS, without warranty of any kind. Test on a non-production device first.
    You are responsible for running it in your environment. The script is read-only by design.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console summary for the technician; data goes to the report files and, with -PassThru, the pipeline.')]
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = (Join-Path -Path ([System.Environment]::GetFolderPath('CommonApplicationData')) -ChildPath 'Microsoft\IntuneManagementExtension\Logs'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'ZakitPro-Kit2'),

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string[]]$AppId,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 14,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KnownCausesPath = (Join-Path -Path $PSScriptRoot -ChildPath 'known-causes.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantReportPath,

    [Parameter()]
    [switch]$SkipRegistry,

    [Parameter()]
    [switch]$ExpectNewVersion,

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [switch]$NoHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:KitVersion = '1.2.0'
$script:GuidPattern = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
$script:SuccessCodes = @(0, 1641, 3010)   # MsiExec docs: 1641 and 3010 "indicate success"

function ConvertFrom-ZkCmLogText {
    <#
    .SYNOPSIS
        Parses CMTrace-format log text into records. Clean-room implementation.
    .PARAMETER Text
        Full file content.
    .PARAMETER SourceName
        File name to stamp on each record.
    .EXAMPLE
        ConvertFrom-ZkCmLogText -Text (Get-Content -Raw -Path .\AppWorkload.log) -SourceName AppWorkload.log
    .EXAMPLE
        ConvertFrom-ZkCmLogText -Text $sample -SourceName test
    .OUTPUTS
        PSCustomObject[] with Time, Component, Type, Thread, Message, Source
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Text,
        [Parameter(Mandatory)] [string]$SourceName
    )
    # A record can span several physical lines, so match across the whole text.
    $pattern = '<!\[LOG\[(?<msg>.*?)\]LOG\]!><time="(?<time>[^"]*)"\s+date="(?<date>[^"]*)"\s+component="(?<comp>[^"]*)"\s+context="[^"]*"\s+type="(?<type>[^"]*)"\s+thread="(?<thread>[^"]*)"\s+file="[^"]*"\s*>'
    $rx = New-Object -TypeName System.Text.RegularExpressions.Regex -ArgumentList $pattern, ([System.Text.RegularExpressions.RegexOptions]::Singleline)
    $out = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($m in $rx.Matches($Text)) {
        $t = $m.Groups['time'].Value
        # Time: HH:mm:ss.fffffff with an optional +/-bias (minutes) as in ConfigMgr logs.
        $bias = $null
        if ($t -match '^(?<hms>\d{1,2}:\d{1,2}:\d{1,2})(?:\.(?<frac>\d+))?(?<bias>[+-]\d+)?$') {
            $frac = if ($Matches['frac']) { $Matches['frac'].Substring(0, [Math]::Min(3, $Matches['frac'].Length)).PadRight(3, '0') } else { '000' }
            if ($Matches['bias']) { $bias = [int]$Matches['bias'] }
            $stamp = '{0} {1}.{2}' -f $m.Groups['date'].Value, $Matches['hms'], $frac
            $dt = [datetime]::MinValue
            $ok = [datetime]::TryParseExact($stamp, [string[]]@('M-d-yyyy H:m:s.fff', 'MM-dd-yyyy HH:mm:ss.fff', 'M-d-yyyy HH:mm:ss.fff'),
                [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)
            if (-not $ok) { Write-Verbose -Message "Unparsed time: $stamp"; $dt = $null }
        }
        else { $dt = $null }
        $typeValue = 0
        [void][int]::TryParse($m.Groups['type'].Value, [ref]$typeValue)
        $out.Add([pscustomobject]@{
                Time      = $dt
                Bias      = $bias
                Component = $m.Groups['comp'].Value
                Type      = $typeValue
                Thread    = $m.Groups['thread'].Value
                Message   = $m.Groups['msg'].Value.Trim()
                Source    = $SourceName
            })
    }
    return $out.ToArray()
}

function Get-ZkImeLogRecord {
    <#
    .SYNOPSIS
        Reads the IME log files that matter for Win32 apps.
    .PARAMETER Path
        Log folder.
    .PARAMETER DaysBack
        Age filter.
    .EXAMPLE
        Get-ZkImeLogRecord -Path C:\ProgramData\Microsoft\IntuneManagementExtension\Logs -DaysBack 7
    .EXAMPLE
        Get-ZkImeLogRecord -Path .\fixtures -DaysBack 365
    .OUTPUTS
        PSCustomObject with Records and Files
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [int]$DaysBack
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Records = @(); Files = @() }
    }
    $files = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop | Where-Object {
            $_.Name -match '^(_?IntuneManagementExtension|AppWorkload|AppActionProcessor)(-\d{8}-\d{6})?\.log$' -or
            $_.Name -match '^(_?IntuneManagementExtension|AppWorkload|AppActionProcessor).*\.log$'
        })
    $cutoff = (Get-Date).AddDays(-$DaysBack)
    $all = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($f in $files) {
        try {
            # The IME keeps its current log open for writing, so share read/write access.
            $fs = New-Object -TypeName System.IO.FileStream -ArgumentList $f.FullName, ([System.IO.FileMode]::Open), ([System.IO.FileAccess]::Read), ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            try {
                $sr = New-Object -TypeName System.IO.StreamReader -ArgumentList $fs, ([System.Text.Encoding]::UTF8), $true
                try { $text = $sr.ReadToEnd() } finally { $sr.Dispose() }
            }
            finally { $fs.Dispose() }
        }
        catch {
            Write-Warning -Message "Can't read $($f.FullName): $($_.Exception.Message). Run elevated?"
            continue
        }
        foreach ($r in (ConvertFrom-ZkCmLogText -Text $text -SourceName $f.Name)) {
            if ($null -eq $r.Time -or $r.Time -ge $cutoff) { $all.Add($r) }
        }
    }
    [pscustomobject]@{ Records = $all.ToArray(); Files = @($files | ForEach-Object { $_.Name }) }
}

function Get-ZkLogSignal {
    <#
    .SYNOPSIS
        Classifies one log message. Patterns follow documented IME step messages.
    .PARAMETER Message
        Log message text.
    .EXAMPLE
        Get-ZkLogSignal -Message 'lpExitCode 1618'
    .EXAMPLE
        Get-ZkLogSignal -Message 'applicationDetected: False'
    .OUTPUTS
        PSCustomObject with Kind and Value, or $null
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Message)
    $m = $Message
    # 'lpExitCode' per the Learn support tip; one field write-up renders it 'IpExitCode', so accept both.
    $unmapped = $m -match '(?i)without mapping'
    # A detection-script line also carries 'exitCode'; it is a detection result, not an installer exit.
    if ($m -match '(?i)applicationDetected\W{0,3}(?<d>True|False)') { return [pscustomobject]@{ Kind = 'detected'; Value = $Matches['d'].ToLowerInvariant() } }
    if ($m -match '(?i)\b[lI]pExitCode[:=\s]{0,3}(?<c>-?\d+)') { return [pscustomobject]@{ Kind = 'exit'; Value = [int64]$Matches['c']; Unmapped = $unmapped } }
    if ($m -match '(?i)\bexit\s*code[:=\s]{0,3}(?<c>-?\d+)') { return [pscustomobject]@{ Kind = 'exit'; Value = [int64]$Matches['c']; Unmapped = $unmapped } }
    if ($m -match '(?i)without mapping') { return [pscustomobject]@{ Kind = 'unmapped'; Value = '' } }
    if ($m -match '(?i)\bGRS|global re-?evaluation|global retry') { return [pscustomobject]@{ Kind = 'grs'; Value = '' } }
    if ($m -match '(?i)time(d)?\s?out') { return [pscustomobject]@{ Kind = 'timeout'; Value = '' } }
    if ($m -match '(?i)requirement[^.]{0,40}not (met|satisf)|RequirementsNotMet|not applicable') { return [pscustomobject]@{ Kind = 'requirement-not-met'; Value = '' } }
    if ($m -match '(?i)download[^.]{0,60}(fail|error)') { return [pscustomobject]@{ Kind = 'download-error'; Value = '' } }
    if ($m -match '(?i)Content\\Incoming|download (job|start)') { return [pscustomobject]@{ Kind = 'download'; Value = '' } }
    if ($m -match '(?i)IMECache') { return [pscustomobject]@{ Kind = 'cache'; Value = '' } }
    if ($m -match '(?i)EnforcementStateMessage|ComplianceStateMessage') { return [pscustomobject]@{ Kind = 'state'; Value = '' } }
    if ($m -match '(?i)get policies') { return [pscustomobject]@{ Kind = 'policy'; Value = '' } }
    return $null
}

function Get-ZkAppTimeline {
    <#
    .SYNOPSIS
        Groups log records by app ID and derives signals in time order.
    .PARAMETER Record
        Parsed log records.
    .PARAMETER KnownAppId
        App IDs known from the registry, tenant report or -AppId.
    .DESCRIPTION
        A record is attributed to an app when it contains the app's GUID. Records on the same thread
        that follow, without another known GUID, are attributed to the same app and marked Inferred.
    .EXAMPLE
        Get-ZkAppTimeline -Record $records -KnownAppId $ids
    .EXAMPLE
        Get-ZkAppTimeline -Record @() -KnownAppId @()
    .OUTPUTS
        Hashtable appId -> PSCustomObject (Events, Signals)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Record,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$KnownAppId
    )
    $known = @{}
    foreach ($k in $KnownAppId) { $known[$k.ToLowerInvariant()] = $true }
    $byApp = @{}
    $threadApp = @{}
    $sorted = @($Record | Sort-Object -Property @{ Expression = { if ($_.Time) { $_.Time } else { [datetime]::MaxValue } } })
    foreach ($r in $sorted) {
        $app = $null; $inferred = $false
        foreach ($g in [regex]::Matches($r.Message, $script:GuidPattern)) {
            $gl = $g.Value.ToLowerInvariant()
            if ($known.ContainsKey($gl)) { $app = $gl; break }
        }
        $threadKey = '{0}|{1}' -f $r.Source, $r.Thread
        if ($app) { $threadApp[$threadKey] = $app }
        elseif ($r.Thread -and $threadApp.ContainsKey($threadKey)) { $app = $threadApp[$threadKey]; $inferred = $true }
        if (-not $app) { continue }
        if (-not $byApp.ContainsKey($app)) {
            $byApp[$app] = [pscustomobject]@{ Events = New-Object -TypeName System.Collections.Generic.List[object]; Signals = New-Object -TypeName System.Collections.Generic.List[string]; LastExit = $null; LastDetected = $null; Name = $null }
        }
        $entry = $byApp[$app]
        if (-not $entry.Name -and -not $inferred -and $r.Message -match "(?i)\bname='(?<n>[^']{1,200})'") { $entry.Name = $Matches['n'] }
        $sig = Get-ZkLogSignal -Message $r.Message
        $label = ''
        if ($sig) {
            switch ($sig.Kind) {
                'exit' {
                    $entry.LastExit = $sig.Value
                    $entry.Signals.Add("exit:$($sig.Value)")
                    if ($sig.Unmapped) { $entry.Signals.Add('unmapped') }
                    if ($script:SuccessCodes -contains [int64]$sig.Value) { $entry.Signals.Add('exit:success') }
                    $label = "Installer exit code $($sig.Value)"
                }
                'detected' {
                    $phase = if ($null -eq $entry.LastExit) { 'pre' } else { 'post' }
                    $entry.Signals.Add("detected:$($sig.Value):$phase")
                    $entry.LastDetected = $sig.Value
                    # The next detection starts a new evaluation cycle.
                    $entry.LastExit = $null
                    $label = "Detection = $($sig.Value) ($phase-install)"
                }
                default {
                    $entry.Signals.Add(($sig.Kind + $(if ($sig.Value) { ":$($sig.Value)" } else { '' })))
                    $label = $sig.Kind
                }
            }
        }
        elseif ($r.Type -eq 3) { $label = 'error line' }
        $entry.Events.Add([pscustomobject]@{
                Time     = if ($r.Time) { $r.Time.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                Source   = $r.Source
                Type     = $r.Type
                Signal   = $label
                Inferred = $inferred
                Message  = if ($r.Message.Length -gt 400) { $r.Message.Substring(0, 400) + ' ...' } else { $r.Message }
            })
    }
    foreach ($k in @($byApp.Keys)) {
        if ($byApp[$k].LastDetected -eq 'true') { $byApp[$k].Signals.Add('final:detected') }
    }
    return $byApp
}

function Get-ZkWin32AppRegistryState {
    <#
    .SYNOPSIS
        Reads Win32Apps registry state (read-only).
    .PARAMETER RootPath
        Registry root. Default HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps
    .EXAMPLE
        Get-ZkWin32AppRegistryState
    .EXAMPLE
        Get-ZkWin32AppRegistryState -RootPath 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
    .OUTPUTS
        PSCustomObject[] one per user/device context and app
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter()] [string]$RootPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps')
    $out = New-Object -TypeName System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $RootPath)) { return $out.ToArray() }
    foreach ($ctx in @(Get-ChildItem -LiteralPath $RootPath -ErrorAction Stop)) {
        $ctxName = Split-Path -Path $ctx.Name -Leaf
        $grsCount = 0
        $grsPath = Join-Path -Path $ctx.PSPath -ChildPath 'GRS'
        if (Test-Path -LiteralPath $grsPath) { $grsCount = @(Get-ChildItem -LiteralPath $grsPath -ErrorAction SilentlyContinue).Count }
        foreach ($appKey in @(Get-ChildItem -LiteralPath $ctx.PSPath -ErrorAction Stop | Where-Object { (Split-Path -Path $_.Name -Leaf) -match "^$($script:GuidPattern)(_\d+)?$" })) {
            $leaf = Split-Path -Path $appKey.Name -Leaf
            $id = ($leaf -split '_')[0].ToLowerInvariant()
            $compliance = $null; $enforcement = $null
            foreach ($k in @($appKey) + @(Get-ChildItem -LiteralPath $appKey.PSPath -Recurse -ErrorAction SilentlyContinue)) {
                $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if ($null -eq $props) { continue }
                foreach ($n in @('ComplianceStateMessage', 'EnforcementStateMessage')) {
                    $p = $props.PSObject.Properties[$n]
                    if ($p -and $p.Value) {
                        try { $obj = [string]$p.Value | ConvertFrom-Json -ErrorAction Stop }
                        catch { $obj = [pscustomobject]@{ Raw = [string]$p.Value } }
                        if ($n -eq 'ComplianceStateMessage') { $compliance = $obj } else { $enforcement = $obj }
                    }
                }
            }
            $out.Add([pscustomobject]@{
                    Context         = if ($ctxName -eq '00000000-0000-0000-0000-000000000000') { 'Device' } else { "User $ctxName" }
                    AppId           = $id
                    KeyName         = $leaf
                    Compliance      = $compliance
                    Enforcement     = $enforcement
                    GrsEntriesInCtx = $grsCount
                })
        }
    }
    return $out.ToArray()
}

function Get-ZkImeServiceInfo {
    <#
    .SYNOPSIS
        Reads IME service state and version (read-only).
    .PARAMETER MinimumVersion
        Minimum supported version.
    .EXAMPLE
        Get-ZkImeServiceInfo -MinimumVersion '1.58.103.0'
    .EXAMPLE
        (Get-ZkImeServiceInfo -MinimumVersion '1.58.103.0').Signals
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string]$MinimumVersion)
    $signals = New-Object -TypeName System.Collections.Generic.List[string]
    $svc = $null
    try { $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='IntuneManagementExtension'" -ErrorAction Stop }
    catch { Write-Verbose -Message "Service query failed: $($_.Exception.Message)" }
    if ($null -eq $svc) {
        $signals.Add('ime:missing')
        return [pscustomobject]@{ Installed = $false; State = ''; Version = ''; Signals = $signals.ToArray() }
    }
    $exe = ([string]$svc.PathName).Trim('"')
    if ($exe -match '^(?<p>.+?\.exe)') { $exe = $Matches['p'].Trim('"') }
    $ver = ''
    if (Test-Path -LiteralPath $exe) { $ver = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion }
    if ($svc.State -ne 'Running') { $signals.Add('ime:stopped') }
    $parsed = $null
    if ($ver -and [version]::TryParse(($ver -split ' ')[0], [ref]$parsed) -and $parsed -lt [version]$MinimumVersion) { $signals.Add('ime:old') }
    [pscustomobject]@{ Installed = $true; State = $svc.State; Version = $ver; Signals = $signals.ToArray() }
}

function Get-ZkVerdict {
    <#
    .SYNOPSIS
        Matches signals against the known-causes database.
    .PARAMETER Signal
        Signal strings for one app (or the device).
    .PARAMETER KnownCause
        Database object.
    .EXAMPLE
        Get-ZkVerdict -Signal @('exit:0','exit:success','detected:false:post') -KnownCause $db
    .EXAMPLE
        Get-ZkVerdict -Signal @('ime:missing') -KnownCause $db
    .OUTPUTS
        PSCustomObject[] verdicts
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$Signal,
        [Parameter(Mandatory)] $KnownCause
    )
    $out = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($c in @($KnownCause.causes)) {
        $ds = $c.deviceSignals
        if ($null -eq $ds) { continue }
        $names = @($ds.PSObject.Properties | ForEach-Object { $_.Name })
        if ($names.Count -eq 0) { continue }
        $matched = New-Object -TypeName System.Collections.Generic.List[string]
        $ok = $true
        if ($names -contains 'all') {
            foreach ($p in @($ds.all)) {
                $hit = @($Signal | Where-Object { $_ -match $p })
                if ($hit.Count -eq 0) { $ok = $false; break }
                $matched.Add($hit[0])
            }
        }
        if ($ok -and $names -contains 'any') {
            $hit = @($Signal | Where-Object { $s = $_; @($ds.any | Where-Object { $s -match $_ }).Count -gt 0 })
            if ($hit.Count -eq 0) { $ok = $false } else { $matched.Add($hit[0]) }
        }
        if ($ok -and $names -contains 'none') {
            foreach ($p in @($ds.none)) { if (@($Signal | Where-Object { $_ -match $p }).Count -gt 0) { $ok = $false } }
        }
        if ($ok -and $matched.Count -gt 0) {
            $out.Add([pscustomobject]@{
                    CauseId      = $c.id
                    Title        = $c.title
                    Confidence   = if ($matched.Count -ge 2) { 'High' } else { 'Medium' }
                    Matched      = ($matched | Select-Object -Unique) -join ', '
                    RankedCauses = @($c.rankedCauses)
                    Checks       = @($c.checks)
                    Fix          = @($c.fix)
                    Rollback     = $c.rollback
                    Confirm      = $c.confirm
                    Sources      = @($c.sources)
                })
        }
    }
    return $out.ToArray()
}

function Get-ZkSignalCoverage {
    <#
    .SYNOPSIS
        Splits signals into explained (by a verdict), context (normal steps) and unexplained.
    .DESCRIPTION
        Every signal the diagnostic emits should either support a verdict or be a known normal step
        listed in known-causes.json 'contextSignals'. Anything else is reported as unexplained so it
        is never silently dropped.
    .PARAMETER Signal
        Signals for one app or the device.
    .PARAMETER Verdict
        Verdicts returned by Get-ZkVerdict for those signals.
    .PARAMETER KnownCause
        Parsed known-causes.json.
    .EXAMPLE
        Get-ZkSignalCoverage -Signal @('exit:0','detected:true:post') -Verdict @() -KnownCause $db
    .EXAMPLE
        Get-ZkSignalCoverage -Signal $app.Signals -Verdict $app.Verdicts -KnownCause $db
    .OUTPUTS
        PSCustomObject with Context and Unexplained string arrays
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$Signal,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Verdict,
        [Parameter(Mandatory)] $KnownCause
    )
    $explained = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($v in @($Verdict)) {
        foreach ($c in @($KnownCause.causes | Where-Object { $_.id -eq $v.CauseId })) {
            $pats = @()
            foreach ($n in 'all', 'any') { if ($c.deviceSignals.PSObject.Properties[$n]) { $pats += @($c.deviceSignals.$n) } }
            foreach ($sg in @($Signal)) { foreach ($pt in $pats) { if ($sg -match $pt) { [void]$explained.Add($sg) } } }
        }
    }
    $context = New-Object -TypeName System.Collections.Generic.List[string]
    $unexplained = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($sg in @($Signal)) {
        if ($explained.Contains($sg)) { continue }
        $ctx = @(@($KnownCause.contextSignals) | Where-Object { $sg -match $_.pattern } | Select-Object -First 1)
        if ($ctx.Count -gt 0) { $context.Add(('{0} - {1}' -f $sg, $ctx[0].meaning)) }
        elseif ($sg -ne 'final:detected') { $unexplained.Add($sg) }
    }
    [pscustomobject]@{ Context = $context.ToArray(); Unexplained = $unexplained.ToArray() }
}

function ConvertTo-ZkHtmlEncoded {
    <#
    .SYNOPSIS
        HTML-encodes text.
    .PARAMETER Text
        Text.
    .EXAMPLE
        ConvertTo-ZkHtmlEncoded -Text '<b>'
    .EXAMPLE
        'a&b' | ConvertTo-ZkHtmlEncoded
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(ValueFromPipeline)] [AllowNull()] [AllowEmptyString()] [string]$Text)
    process { [System.Net.WebUtility]::HtmlEncode([string]$Text) }
}

function Invoke-ZkDeviceDiagnostic {
    <#
    .SYNOPSIS
        Main read-only routine (separated for tests).
    .PARAMETER LogPath
        Log folder.
    .PARAMETER AppId
        App filter.
    .PARAMETER DaysBack
        Age filter.
    .PARAMETER KnownCause
        Database object.
    .PARAMETER TenantReport
        Optional tenant report object.
    .PARAMETER SkipRegistry
        Offline mode.
    .EXAMPLE
        Invoke-ZkDeviceDiagnostic -LogPath $p -DaysBack 14 -KnownCause $db
    .EXAMPLE
        Invoke-ZkDeviceDiagnostic -LogPath .\logs -DaysBack 365 -KnownCause $db -SkipRegistry
    .OUTPUTS
        PSCustomObject report
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter()] [string[]]$AppId,
        [Parameter(Mandatory)] [int]$DaysBack,
        [Parameter(Mandatory)] $KnownCause,
        [Parameter()] $TenantReport,
        [Parameter()] [switch]$SkipRegistry,
        [Parameter()] [switch]$ExpectNewVersion
    )
    $deviceSignals = New-Object -TypeName System.Collections.Generic.List[string]
    $ime = $null; $reg = @()
    if (-not $SkipRegistry) {
        $ime = Get-ZkImeServiceInfo -MinimumVersion $KnownCause.imeMinimumVersion.value
        foreach ($s in $ime.Signals) { $deviceSignals.Add($s) }
        try { $reg = Get-ZkWin32AppRegistryState }
        catch { Write-Warning -Message "Registry read failed: $($_.Exception.Message)" }
    }
    if (-not (Test-Path -LiteralPath $LogPath)) {
        Write-Warning -Message "Log folder not found: '$LogPath'. Check -LogPath, or run elevated on the device. The report will say 'No IME logs found' (KC-021)."
    }
    $logs = Get-ZkImeLogRecord -Path $LogPath -DaysBack $DaysBack
    if (@($logs.Files).Count -eq 0) { $deviceSignals.Add('logs:none') }

    $tenantApps = @{}
    if ($TenantReport) { foreach ($a in @($TenantReport.Apps)) { $tenantApps[([string]$a.Id).ToLowerInvariant()] = $a } }
    $ids = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($i in @($AppId)) { if ($i) { [void]$ids.Add($i.ToLowerInvariant()) } }
    if ($ids.Count -eq 0) {
        foreach ($r in @($reg)) { [void]$ids.Add($r.AppId) }
        foreach ($k in $tenantApps.Keys) { [void]$ids.Add($k) }
        if ($ids.Count -eq 0) {
            # Offline with no other source: use GUIDs that appear in lines mentioning detection or exit codes.
            foreach ($r in @($logs.Records)) {
                if ($r.Message -match '(?i)applicationDetected|lpExitCode|Win32App') {
                    foreach ($g in [regex]::Matches($r.Message, $script:GuidPattern)) { [void]$ids.Add($g.Value.ToLowerInvariant()) }
                }
            }
        }
    }
    $timeline = Get-ZkAppTimeline -Record @($logs.Records) -KnownAppId @($ids)

    $enfMap = $KnownCause.enforcementStateMap.values
    $cmpMap = $KnownCause.complianceStateMap.values
    $apps = foreach ($id in @($ids)) {
        $signals = New-Object -TypeName System.Collections.Generic.List[string]
        $events = @()
        if ($timeline.ContainsKey($id)) {
            foreach ($s in $timeline[$id].Signals) { $signals.Add($s) }
            $events = $timeline[$id].Events.ToArray()
        }
        $regStates = @($reg | Where-Object { $_.AppId -eq $id })
        $stateText = foreach ($rs in $regStates) {
            $es = $null; $ec = $null; $cs = $null
            if ($rs.Enforcement -and $rs.Enforcement.PSObject.Properties['EnforcementState']) { $es = [string]$rs.Enforcement.EnforcementState }
            if ($rs.Enforcement -and $rs.Enforcement.PSObject.Properties['ErrorCode']) { $ec = $rs.Enforcement.ErrorCode }
            if ($rs.Compliance -and $rs.Compliance.PSObject.Properties['ComplianceState']) { $cs = [string]$rs.Compliance.ComplianceState }
            if ($es) { $signals.Add("enforcement:$es") }
            if ($null -ne $ec -and "$ec" -ne '' -and "$ec" -ne '0') { $signals.Add("errorcode:$ec") }
            $esName = if ($es -and $enfMap.PSObject.Properties[$es]) { $enfMap.$es } else { 'raw value, not decoded' }
            $csName = if ($cs -and $cmpMap.PSObject.Properties[$cs]) { $cmpMap.$cs } else { 'raw value, not decoded' }
            '{0}: EnforcementState {1} ({2}), ErrorCode {3}, ComplianceState {4} ({5}), GRS entries in context {6}' -f $rs.Context, $es, $esName, $ec, $cs, $csName, $rs.GrsEntriesInCtx
        }
        $t = $null
        if ($tenantApps.ContainsKey($id)) { $t = $tenantApps[$id] }
        $tenantFindings = @()
        if ($TenantReport) { $tenantFindings = @($TenantReport.Findings | Where-Object { ([string]$_.AppId).ToLowerInvariant() -eq $id }) }
        if ($ExpectNewVersion) { $signals.Add('expect:new-version') }
        $uniqueSignals = @($signals | Select-Object -Unique)
        $verdicts = @(Get-ZkVerdict -Signal $uniqueSignals -KnownCause $KnownCause)
        if ($uniqueSignals -contains 'final:detected') {
            # A later evaluation detected the app, so earlier failures are history, not the current state.
            foreach ($v in $verdicts) { $v.Confidence = 'Low (a later evaluation detected the app)' }
        }
        $coverage = Get-ZkSignalCoverage -Signal $uniqueSignals -Verdict $verdicts -KnownCause $KnownCause
        [pscustomobject]@{
            AppId          = $id
            Name           = if ($t) { $t.DisplayName } elseif ($timeline.ContainsKey($id) -and $timeline[$id].Name) { $timeline[$id].Name } else { '(name not in the logs; add -TenantReportPath)' }
            DetectionRules = if ($t) { $t.DetectionRules } else { @() }
            InstallCommand = if ($t) { $t.InstallCommand } else { '' }
            RunAs          = if ($t) { $t.RunAs } else { '' }
            RegistryState  = @($stateText)
            Signals        = $uniqueSignals
            Verdicts       = $verdicts
            Context        = $coverage.Context
            Unexplained    = $coverage.Unexplained
            TenantFindings = $tenantFindings
            Timeline       = $events
        }
    }
    $deviceVerdicts = @(Get-ZkVerdict -Signal $deviceSignals.ToArray() -KnownCause $KnownCause)
    [pscustomobject]@{
        KitVersion     = $script:KitVersion
        GeneratedLocal = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        Computer       = [System.Environment]::MachineName
        LogPath        = $LogPath
        LogFiles       = @($logs.Files)
        RecordCount    = @($logs.Records).Count
        Ime            = $ime
        DeviceSignals  = $deviceSignals.ToArray()
        DeviceVerdicts = $deviceVerdicts
        Apps           = @($apps | Sort-Object -Property @{ Expression = { -1 * @($_.Verdicts).Count } }, Name)
        KnownCausesDb  = '{0} (checked {1})' -f $KnownCause.version, $KnownCause.dateChecked
    }
}

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

function Export-ZkDeviceReport {
    <#
    .SYNOPSIS
        Writes JSON and HTML device reports.
    .PARAMETER Report
        Report object.
    .PARAMETER OutputPath
        Folder.
    .PARAMETER NoHtml
        Write only the JSON report.
    .EXAMPLE
        Export-ZkDeviceReport -Report $r -OutputPath $env:TEMP
    .EXAMPLE
        Export-ZkDeviceReport -Report $r -OutputPath .\out
    .OUTPUTS
        PSCustomObject with Json and Html paths
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Report, [Parameter(Mandatory)] [string]$OutputPath, [Parameter()] [switch]$NoHtml)
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $json = Join-Path -Path $OutputPath -ChildPath "Kit2-DeviceDiagnostic-$stamp.json"
    $html = Join-Path -Path $OutputPath -ChildPath "Kit2-DeviceDiagnostic-$stamp.html"
    $Report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $json -Encoding UTF8
    if ($NoHtml) { return [pscustomobject]@{ Json = $json; Html = $null } }
    $e = { param($x) [System.Net.WebUtility]::HtmlEncode([string]$x) }
    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZakitPro Kit 2 - Device diagnostic</title><style>')
    [void]$sb.Append($script:ZkReportCss)
    [void]$sb.Append('</style></head><body><h1>Win32 App Deployment Doctor: device diagnostic</h1>')
    $imeText = if ($Report.Ime) { 'IME service: {0}, version {1}' -f $Report.Ime.State, $Report.Ime.Version } else { 'IME service: not checked (offline mode)' }
    [void]$sb.AppendFormat('<p class="meta">{0} | generated {1} (device local time) | Kit 2 v{2} | signal map {3}<br>{4} | log files: {5} | records parsed: {6}</p>', (& $e $Report.Computer), (& $e $Report.GeneratedLocal), $Report.KitVersion, (& $e $Report.KnownCausesDb), (& $e $imeText), (& $e ($Report.LogFiles -join ', ')), $Report.RecordCount)
    [void]$sb.Append('<div class="warnbox"><b>Read-only, local report.</b> Not tested against a live tenant. Test in non-production first. No data leaves this file.</div>')
    [void]$sb.Append('<h2>Checks</h2><table><thead><tr><th>Status</th><th>Scope</th><th>Finding</th><th>Evidence (matched signals)</th><th>What to do next</th></tr></thead><tbody>')
    foreach ($v in @($Report.DeviceVerdicts)) {
        [void]$sb.AppendFormat('<tr><td>{0}</td><td>Device</td><td>{1} ({2})</td><td><code>{3}</code></td><td>{4}</td></tr>', (Get-ZkReportBadge -Value 'High'), (& $e $v.Title), (& $e $v.CauseId), (& $e $v.Matched), (Get-ZkNextStepLink -Url @($v.Sources | ForEach-Object { $_.url }) -Code $v.CauseId))
    }
    foreach ($a in @($Report.Apps)) {
        foreach ($v in @($a.Verdicts)) {
            [void]$sb.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2} ({3})</td><td><code>{4}</code></td><td>{5}</td></tr>', (Get-ZkReportBadge -Value $v.Confidence), (& $e $a.Name), (& $e $v.Title), (& $e $v.CauseId), (& $e $v.Matched), (Get-ZkNextStepLink -Url @($v.Sources | ForEach-Object { $_.url }) -Code $v.CauseId))
        }
        if (@($a.Verdicts).Count -eq 0) {
            if (@($a.Signals) -contains 'final:detected') { $st = 'Pass'; $msg = 'Detected on the last evaluation; no fault found.'; $nx = '<span class="next">If the portal still shows a failure, wait for it to catch up</span>' }
            else { $st = 'Info'; $msg = 'No known cause matched.'; $nx = '<span class="next">Read the timeline from the last exit code backwards</span>' }
            [void]$sb.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><code>{3}</code></td><td>{4}</td></tr>', (Get-ZkReportBadge -Value $st), (& $e $a.Name), $msg, (& $e ($a.Signals -join ', ')), $nx)
        }
    }
    [void]$sb.Append('</tbody></table><h2>Apps</h2>')
    foreach ($a in @($Report.Apps)) {
        [void]$sb.AppendFormat('<h3>{0} <code>{1}</code></h3>', (& $e $a.Name), (& $e $a.AppId))
        if ($a.RegistryState) { [void]$sb.AppendFormat('<p><b>Registry state:</b> {0}</p>', (& $e ($a.RegistryState -join ' | '))) }
        [void]$sb.AppendFormat('<p><b>Signals:</b> <code>{0}</code></p>', (& $e ($a.Signals -join ', ')))
        if (@($a.DetectionRules).Count -gt 0) {
            [void]$sb.AppendFormat('<p><b>Detection rules (from tenant report):</b> <code>{0}</code></p>', (& $e ((@($a.DetectionRules) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 }) -join ' ; ')))
        }
        if (@($a.Unexplained).Count -gt 0) { [void]$sb.AppendFormat('<p><b>Signals not covered by the signal map:</b> <code>{0}</code></p>', (& $e ($a.Unexplained -join ', '))) }
        if (@($a.Context).Count -gt 0) { [void]$sb.AppendFormat('<p><b>Normal steps seen (context):</b> {0}</p>', (& $e ($a.Context -join ' | '))) }
        foreach ($tf in @($a.TenantFindings)) { [void]$sb.AppendFormat('<p>{0} Tenant check {1}: {2}</p>', (Get-ZkReportBadge -Value $tf.Severity), (& $e $tf.CheckId), (& $e $tf.Message)) }
        [void]$sb.Append('<table><thead><tr><th>Time</th><th>Log</th><th>Signal</th><th>Message</th></tr></thead><tbody>')
        foreach ($ev in @($a.Timeline)) {
            $cls = if ($ev.Type -eq 3) { ' style="color:#991b1b"' } else { '' }
            $inf = if ($ev.Inferred) { ' (thread)' } else { '' }
            [void]$sb.AppendFormat('<tr{0}><td>{1}</td><td>{2}</td><td>{3}{4}</td><td>{5}</td></tr>', $cls, (& $e $ev.Time), (& $e $ev.Source), (& $e $ev.Signal), $inf, (& $e $ev.Message))
        }
        [void]$sb.Append('</tbody></table>')
    }
    [void]$sb.Append('<p class="meta">Read-only report. "(thread)" = line attributed to the app because it followed an app line on the same thread. Registry state names are community-decoded; undecoded values are shown raw.</p></body></html>')
    Set-Content -LiteralPath $html -Value $sb.ToString() -Encoding UTF8
    [pscustomobject]@{ Json = $json; Html = $html }
}

# ---- main ----
if ($MyInvocation.InvocationName -ne '.') {
    try { $db = Get-Content -LiteralPath $KnownCausesPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Could not read known-causes.json at '$KnownCausesPath': $($_.Exception.Message)" }
    $tenant = $null
    if ($TenantReportPath) {
        try { $tenant = Get-Content -LiteralPath $TenantReportPath -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { throw "Could not read the tenant report '$TenantReportPath': $($_.Exception.Message)" }
    }
    $report = Invoke-ZkDeviceDiagnostic -LogPath $LogPath -AppId $AppId -DaysBack $DaysBack -KnownCause $db -TenantReport $tenant -SkipRegistry:$SkipRegistry -ExpectNewVersion:$ExpectNewVersion
    $files = Export-ZkDeviceReport -Report $report -OutputPath $OutputPath -NoHtml:$NoHtml
    $summary = [pscustomobject]@{
        ReportJson   = $files.Json
        ReportHtml   = $files.Html
        AppCount     = @($report.Apps).Count
        VerdictCount = [int](@($report.Apps | ForEach-Object { @($_.Verdicts).Count }) | Measure-Object -Sum).Sum + @($report.DeviceVerdicts).Count
    }
    Write-Host ''
    Write-Host ('ZakitPro Kit 2 device diagnostic v{0} (read-only)' -f $script:KitVersion)
    $imeLine = if ($report.Ime) { 'IME: {0}, version {1}' -f $report.Ime.State, $report.Ime.Version } else { 'IME: not checked (-SkipRegistry)' }
    Write-Host ('{0} | log files: {1} | records: {2}' -f $imeLine, @($report.LogFiles).Count, $report.RecordCount)
    foreach ($v in @($report.DeviceVerdicts)) { Write-Host ('  DEVICE  {0}  {1}' -f $v.CauseId, $v.Title) -ForegroundColor Yellow }
    foreach ($a in @($report.Apps)) {
        $top = @($a.Verdicts | Sort-Object -Property @{ Expression = { if ($_.Confidence -eq 'High') { 0 } elseif ($_.Confidence -eq 'Medium') { 1 } else { 2 } } })
        $line = if ($top.Count -gt 0) { '{0} {1} ({2})' -f $top[0].CauseId, $top[0].Title, $top[0].Confidence }
        elseif (@($a.Signals) -contains 'final:detected') { 'detected on the last evaluation; no fault found' }
        else { 'no known cause matched; read the timeline' }
        if ($top.Count -gt 1) { $line += (' +{0} more' -f ($top.Count - 1)) }
        if (@($a.Unexplained).Count -gt 0) { $line += (' | {0} unexplained signal(s)' -f @($a.Unexplained).Count) }
        Write-Host ('  {0} [{1}]: {2}' -f $a.Name, $a.AppId, $line)
    }
    if (@($report.Apps).Count -eq 0) { Write-Host '  No Win32 app activity found in the logs for the period checked.' }
    if ($files.Html) { Write-Host ('Report: {0}' -f $files.Html) } else { Write-Host ('Report (JSON only): {0}' -f $files.Json) }
    if ($PassThru) { $summary }
}
