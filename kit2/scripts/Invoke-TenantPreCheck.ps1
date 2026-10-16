#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
<#
.SYNOPSIS
    Read-only audit of Intune Win32 apps: detection rules, requirements, return codes,
    dependency and supersedence chains, assignments and install-status summaries.

.DESCRIPTION
    ZakitPro Kit 2 - Win32 App Deployment Doctor. Tenant pre-check.

    The script connects to Microsoft Graph with READ scopes only and sends GET requests only.
    A guard function refuses any other HTTP method. Nothing in the tenant is created, changed
    or deleted.

    For every Win32 app (or the ones matching -AppNameFilter) it reads the app definition
    (Graph beta), its assignments, its relationships (dependencies and supersedence) and its
    install summary. It then runs the checks listed in known-causes.json (ruleType "tenant")
    and writes a JSON report and an HTML report.

    The JSON report can be given to Invoke-DeviceDiagnostic.ps1 (-TenantReportPath) so the
    device report shows app names and detection rules next to each log timeline.

    Graph permissions (delegated), each checked on Microsoft Learn on Oct 15, 2026:
      DeviceManagementApps.Read.All  mobileApps list/get, assignments, relationships, installSummary
      Group.Read.All                 resolve assignment group names (group get)
      Application.Read.All           ONLY with -IncludeAgentAppCheck (servicePrincipal list)
    No ReadWrite scope is requested.

.PARAMETER OutputPath
    Folder for the reports. Created if it doesn't exist. Default: .\ZakitPro-Kit2-Reports

.PARAMETER AppNameFilter
    Only audit apps whose display name contains this text (case-insensitive).

.PARAMETER TenantId
    Optional tenant ID or domain to pass to Connect-MgGraph. No tenant ID is stored in the script.

.PARAMETER KnownCausesPath
    Path to known-causes.json. Default: known-causes.json next to this script.

.PARAMETER IncludeAgentAppCheck
    Also look up the "Microsoft Intune Windows Agent" service principal by display name and
    report whether it is enabled. Adds the Application.Read.All scope.

.PARAMETER SkipInstallSummary
    Don't read per-app install summaries (faster on large tenants).

.PARAMETER NoHtml
    Skip the HTML report (JSON and console only).

.PARAMETER PassThru
    Also return the summary object (report paths and counts) to the pipeline. Without it the
    script prints a console summary only.
.PARAMETER SkipConnect
    Don't call Connect-MgGraph. Use an existing Graph session (it must hold the read scopes).

.EXAMPLE
    .\Invoke-TenantPreCheck.ps1
    Audits every Win32 app and writes JSON + HTML to .\ZakitPro-Kit2-Reports

.EXAMPLE
    .\Invoke-TenantPreCheck.ps1 -AppNameFilter "Acrobat" -OutputPath C:\Temp\Kit2 -IncludeAgentAppCheck
    Audits only apps with "Acrobat" in the name and also checks the Intune Windows Agent app.

.OUTPUTS
    PSCustomObject with ReportJson, ReportHtml, AppCount and FindingCount.

.NOTES
    Name:        Invoke-TenantPreCheck.ps1
    Version:     1.2.2 (2026-10-16)
    Publisher:   ZakitPro (zakitpro.com), author Abderrazak Elbouchikhi (Zak). Support: hello@zakitpro.com
    Requires:    Windows PowerShell 5.1 or PowerShell 7.x; Microsoft.Graph.Authentication 2.x;
                 an Intune role that can read apps (for example Intune Read Only Operator).
    Tested on:   NOT tested against a live tenant. Static analysis (PSScriptAnalyzer) and Pester unit
                 tests with mocked Graph responses only, on PowerShell 7.4.6 (Linux). See CHANGELOG.md.
    Changelog:   See CHANGELOG.md
    Reuse:       The beta endpoint and isof('microsoft.graph.win32LobApp') filter pattern follows
                 MSEndpointMgr/IntuneWin32App (MIT). No code copied. See CREDITS.md.

    DISCLAIMER: Provided AS IS, without warranty of any kind. Test in a non-production tenant first.
    You are responsible for running it in your environment. The script is read-only by design.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console summary for the technician; data goes to the report files and, with -PassThru, the pipeline.')]
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'ZakitPro-Kit2-Reports'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AppNameFilter,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KnownCausesPath = (Join-Path -Path $PSScriptRoot -ChildPath 'known-causes.json'),

    [Parameter()]
    [switch]$IncludeAgentAppCheck,

    [Parameter()]
    [switch]$SkipInstallSummary,

    [Parameter()]
    [switch]$SkipConnect,

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [switch]$NoHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:KitVersion = '1.2.2'
$script:GraphBase = 'https://graph.microsoft.com/beta'

function Invoke-ZkGraphGet {
    <#
    .SYNOPSIS
        Read-only Graph helper. Sends GET only and follows @odata.nextLink paging.
    .PARAMETER Uri
        Relative (to the beta endpoint) or absolute Graph URI.
    .PARAMETER Method
        Must be GET. Present only so a wrong call fails loudly instead of writing.
    .EXAMPLE
        Invoke-ZkGraphGet -Uri '/deviceAppManagement/mobileApps'
    .EXAMPLE
        Invoke-ZkGraphGet -Uri '/groups/00000000-0000-0000-0000-000000000000?$select=displayName' -Single
    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET')]
        [string]$Method = 'GET',

        [Parameter()]
        [switch]$Single
    )
    if ($Method -ne 'GET') { throw 'Read-only guard: only GET is allowed.' }
    $next = if ($Uri -like 'https://*') { $Uri } else { $script:GraphBase + $Uri }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    do {
        try {
            $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $msg = $_.Exception.Message
            $hint = ''
            if ($msg -match '(?i)403|Forbidden|Authorization_RequestDenied|insufficient privileges') { $hint = ' Hint: the signed-in account or consent is missing a read scope (DeviceManagementApps.Read.All, Group.Read.All, or Application.Read.All for -IncludeAgentAppCheck), or the account has no Intune role that can read apps.' }
            elseif ($msg -match '(?i)401|Unauthorized|not connected|Connect-MgGraph') { $hint = ' Hint: run Connect-MgGraph first (or drop -SkipConnect).' }
            elseif ($msg -match '(?i)404|NotFound|ResourceNotFound') { $hint = ' Hint: the object may have been deleted while the check ran.' }
            throw "Graph GET failed for '$next': $msg$hint"
        }
        if ($Single) { return $page }
        if ($page.PSObject.Properties.Name -contains 'value') {
            foreach ($item in @($page.value)) { $results.Add($item) }
        }
        else {
            $results.Add($page)
        }
        $next = $null
        if ($page.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $page.'@odata.nextLink' }
    } while ($next)
    return $results.ToArray()
}

function Get-ZkPropertyValue {
    <#
    .SYNOPSIS
        Returns a property value or $null without tripping StrictMode.
    .PARAMETER InputObject
        Object to read.
    .PARAMETER Name
        Property name.
    .EXAMPLE
        Get-ZkPropertyValue -InputObject $app -Name 'rules'
    .EXAMPLE
        Get-ZkPropertyValue -InputObject $rule -Name 'check32BitOn64System'
    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function New-ZkFinding {

    <#
    .SYNOPSIS
        Builds one finding object.
    .PARAMETER CheckId
        Check ID from known-causes.json (for example T01).
    .PARAMETER Severity
        High, Medium, Low or Info.
    .PARAMETER AppId
        Intune app ID.
    .PARAMETER AppName
        App display name.
    .PARAMETER Message
        Plain-English finding.
    .PARAMETER Evidence
        The exact value that triggered the finding.
    .EXAMPLE
        New-ZkFinding -CheckId T01 -Severity Medium -AppId $id -AppName 'App' -Message 'x' -Evidence 'y'
    .EXAMPLE
        New-ZkFinding -CheckId T16 -Severity Info -AppId $id -AppName 'App' -Message 'Install summary' -Evidence '3 failed'
    .OUTPUTS
        PSCustomObject
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only; changes no system state.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$CheckId,
        [Parameter(Mandatory)] [ValidateSet('High', 'Medium', 'Low', 'Info')] [string]$Severity,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$AppId,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$AppName,
        [Parameter(Mandatory)] [string]$Message,
        [Parameter()] [AllowEmptyString()] [string]$Evidence = ''
    )
    [pscustomobject]@{
        CheckId  = $CheckId
        Severity = $Severity
        AppId    = $AppId
        AppName  = $AppName
        Message  = $Message
        Evidence = $Evidence
    }
}

function Test-ZkWin32AppDefinition {
    <#
    .SYNOPSIS
        Runs the definition checks (T01-T09, T15) on one Win32 app object. Pure function, no Graph calls.
    .PARAMETER App
        A win32LobApp object as returned by Graph beta.
    .EXAMPLE
        Test-ZkWin32AppDefinition -App $app
    .EXAMPLE
        $apps | ForEach-Object { Test-ZkWin32AppDefinition -App $_ }
    .OUTPUTS
        PSCustomObject[] findings
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] $App)

    $f = New-Object -TypeName System.Collections.Generic.List[object]
    $id = [string](Get-ZkPropertyValue -InputObject $App -Name 'id')
    $name = [string](Get-ZkPropertyValue -InputObject $App -Name 'displayName')
    $install = [string](Get-ZkPropertyValue -InputObject $App -Name 'installCommandLine')
    $uninstall = [string](Get-ZkPropertyValue -InputObject $App -Name 'uninstallCommandLine')

    # T01 bare powershell.exe => 32-bit PowerShell (Learn: Add Win32 app)
    foreach ($pair in @(@('install', $install), @('uninstall', $uninstall))) {
        $cmd = $pair[1]
        if ($cmd -match '(?i)\bpowershell(\.exe)?\b' -and $cmd -notmatch '(?i)sysnative') {
            $f.Add((New-ZkFinding -CheckId 'T01' -Severity 'Medium' -AppId $id -AppName $name `
                        -Message "The $($pair[0]) command calls powershell.exe without Sysnative, so it runs 32-bit PowerShell. HKLM\SOFTWARE writes land in WOW6432Node and System32 maps to SysWOW64." `
                        -Evidence $cmd))
        }
    }
    # T02 env vars in uninstall command are not expanded
    if ($uninstall -match '%[A-Za-z_][A-Za-z0-9_()]*%') {
        $f.Add((New-ZkFinding -CheckId 'T02' -Severity 'High' -AppId $id -AppName $name `
                    -Message 'The uninstall command uses an environment variable. Intune does not expand variables in the uninstall command, so uninstall and supersedence-replace will fail.' `
                    -Evidence $uninstall))
    }
    # T03 interactive helpers are unsupported
    if (($install + ' ' + $uninstall) -match '(?i)serviceui') {
        $f.Add((New-ZkFinding -CheckId 'T03' -Severity 'Medium' -AppId $id -AppName $name `
                    -Message 'The command uses ServiceUI. Microsoft states interactive installs and ServiceUI-style workarounds are not supported.' `
                    -Evidence (($install + ' | ' + $uninstall).Trim(' |'))))
    }

    $rules = @(@(Get-ZkPropertyValue -InputObject $App -Name 'rules') | Where-Object { $null -ne $_ })
    $detection = @($rules | Where-Object { (Get-ZkPropertyValue -InputObject $_ -Name 'ruleType') -eq 'detection' })
    if ($detection.Count -eq 0) {
        $legacy = @(@(Get-ZkPropertyValue -InputObject $App -Name 'detectionRules') | Where-Object { $null -ne $_ })
        $detection = @($legacy)
    }
    foreach ($r in $detection) {
        $type = [string](Get-ZkPropertyValue -InputObject $r -Name '@odata.type')
        # T04 script detection writing to STDERR
        if ($type -match 'PowerShellScript') {
            $b64 = [string](Get-ZkPropertyValue -InputObject $r -Name 'scriptContent')
            $text = ''
            if ($b64) {
                try { $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) }
                catch { Write-Verbose -Message "Could not decode detection script for $name : $($_.Exception.Message)" }
            }
            if ($text -match '(?i)Write-Error|\[Console\]::Error|WriteErrorLine|throw\s') {
                $f.Add((New-ZkFinding -CheckId 'T04' -Severity 'High' -AppId $id -AppName $name `
                            -Message 'The detection script can write to STDERR (Write-Error, throw or Console.Error). Any STDERR output makes Intune report Not installed, even with exit 0 and STDOUT.' `
                            -Evidence (($text -split "`n" | Where-Object { $_ -match '(?i)Write-Error|Console\]::Error|WriteErrorLine|throw\s' } | Select-Object -First 2) -join ' / ').Trim()))
            }
            if ($text -and $text -notmatch '(?i)Write-Output|Write-Host|^\s*["''$]') {
                $f.Add((New-ZkFinding -CheckId 'T04b' -Severity 'Low' -AppId $id -AppName $name `
                            -Message 'The detection script has no obvious STDOUT write. Detection needs exit 0 AND something on STDOUT. Review the script.' `
                            -Evidence 'No Write-Output / Write-Host found'))
            }
        }
        # T05 product code rule pinned to a version
        if ($type -match 'ProductCode') {
            $op = [string](Get-ZkPropertyValue -InputObject $r -Name 'productVersionOperator')
            if ($op -and $op -ne 'notConfigured') {
                $f.Add((New-ZkFinding -CheckId 'T05' -Severity 'Low' -AppId $id -AppName $name `
                            -Message "MSI product-code detection also compares the version ($op). If the app updates itself, detection drifts and Intune reports 0x87D1041C and reinstalls." `
                            -Evidence ("{0} {1} {2}" -f (Get-ZkPropertyValue -InputObject $r -Name 'productCode'), $op, (Get-ZkPropertyValue -InputObject $r -Name 'productVersion'))))
            }
        }
        # T06 32/64-bit view mismatch
        if ($type -match 'FileSystem|Registry') {
            $path = [string](Get-ZkPropertyValue -InputObject $r -Name 'path')
            if (-not $path) { $path = [string](Get-ZkPropertyValue -InputObject $r -Name 'keyPath') }
            $c32 = [bool](Get-ZkPropertyValue -InputObject $r -Name 'check32BitOn64System')
            if ($path -match '(?i)WOW6432Node|Program Files \(x86\)|ProgramFiles\(x86\)') {
                $f.Add((New-ZkFinding -CheckId 'T06' -Severity 'Medium' -AppId $id -AppName $name `
                            -Message ("The detection rule hard-codes a 32-bit location (check32BitOn64System = {0}). Prefer the native path plus the 32-bit switch, so the rule works the same on every client." -f $c32) `
                            -Evidence $path))
            }
            elseif (-not $c32 -and $path -match '(?i)%ProgramFiles%|%CommonProgramFiles%|HKEY_LOCAL_MACHINE\\SOFTWARE|HKLM\\SOFTWARE') {
                $f.Add((New-ZkFinding -CheckId 'T06b' -Severity 'Info' -AppId $id -AppName $name `
                            -Message 'The detection rule reads the 64-bit view (the default). If the installer is 32-bit, it writes to Program Files (x86) or WOW6432Node and this rule misses it (0x87D1041C). Confirm the installer bitness.' `
                            -Evidence $path))
            }
        }
    }

    # T07 user context
    $exp = Get-ZkPropertyValue -InputObject $App -Name 'installExperience'
    $runAs = [string](Get-ZkPropertyValue -InputObject $exp -Name 'runAsAccount')
    if ($runAs -eq 'user') {
        $f.Add((New-ZkFinding -CheckId 'T07' -Severity 'Info' -AppId $id -AppName $name `
                    -Message 'Install context is User. It runs elevated only if the signed-in user is a local admin. Standard users fail when the installer needs admin rights. Test with a standard user.' `
                    -Evidence 'runAsAccount = user'))
    }
    # T08 timeout vs size (heuristic, labelled)
    $maxRun = Get-ZkPropertyValue -InputObject $exp -Name 'maxRunTimeInMinutes'
    $size = Get-ZkPropertyValue -InputObject $App -Name 'size'
    if ($maxRun -and $size -and [int64]$size -gt 2GB -and [int]$maxRun -le 60) {
        $f.Add((New-ZkFinding -CheckId 'T08' -Severity 'Low' -AppId $id -AppName $name `
                    -Message ("Heuristic: package is {0:N1} GB with a {1}-minute install timeout. Installs that run past the timeout are failed by Intune (max 1440)." -f ([int64]$size / 1GB), $maxRun) `
                    -Evidence "maxRunTimeInMinutes = $maxRun"))
    }
    # T09 return codes
    $codes = @(@(Get-ZkPropertyValue -InputObject $App -Name 'returnCodes') | Where-Object { $null -ne $_ })
    if ($codes.Count -gt 0) {
        $has1618Retry = @($codes | Where-Object { [int](Get-ZkPropertyValue -InputObject $_ -Name 'returnCode') -eq 1618 -and (Get-ZkPropertyValue -InputObject $_ -Name 'type') -eq 'retry' }).Count -gt 0
        if (-not $has1618Retry) {
            $f.Add((New-ZkFinding -CheckId 'T09' -Severity 'Medium' -AppId $id -AppName $name `
                        -Message '1618 (another installation in progress) is not mapped to Retry. Field sources report that an unmapped failure code skips the 3 x 5-minute retries and waits about 24 hours.' `
                        -Evidence (($codes | ForEach-Object { '{0}={1}' -f (Get-ZkPropertyValue -InputObject $_ -Name 'returnCode'), (Get-ZkPropertyValue -InputObject $_ -Name 'type') }) -join ', ')))
        }
        $hard = @($codes | Where-Object { (Get-ZkPropertyValue -InputObject $_ -Name 'type') -eq 'hardReboot' })
        if ($hard.Count -gt 0) {
            $f.Add((New-ZkFinding -CheckId 'T09b' -Severity 'Info' -AppId $id -AppName $name `
                        -Message 'One or more return codes are mapped to Hard reboot. A hard-reboot result blocks the next Win32 app on that device until it restarts.' `
                        -Evidence (($hard | ForEach-Object { Get-ZkPropertyValue -InputObject $_ -Name 'returnCode' }) -join ', ')))
        }
    }
    # T15 architecture properties
    $allowed = Get-ZkPropertyValue -InputObject $App -Name 'allowedArchitectures'
    $applicable = Get-ZkPropertyValue -InputObject $App -Name 'applicableArchitectures'
    if ($allowed) {
        $f.Add((New-ZkFinding -CheckId 'T15' -Severity 'Info' -AppId $id -AppName $name `
                    -Message 'allowedArchitectures is set, so Graph reports applicableArchitectures as none. Tools that read only applicableArchitectures will misreport this app.' `
                    -Evidence ("allowed = {0}; applicable = {1}" -f $allowed, $applicable)))
    }
    return $f.ToArray()
}

function Get-ZkRelationshipGraph {
    <#
    .SYNOPSIS
        Builds dependency and supersedence edges from relationship objects. Pure function.
    .PARAMETER Relationship
        Hashtable appId -> array of mobileAppRelationship objects.
    .EXAMPLE
        Get-ZkRelationshipGraph -Relationship $rel
    .EXAMPLE
        (Get-ZkRelationshipGraph -Relationship $rel).Dependencies
    .OUTPUTS
        PSCustomObject with Dependencies and Supersedence edge lists.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [hashtable]$Relationship)
    $dep = New-Object -TypeName System.Collections.Generic.List[object]
    $sup = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($appId in $Relationship.Keys) {
        foreach ($r in @($Relationship[$appId])) {
            if ($null -eq $r) { continue }
            $type = [string](Get-ZkPropertyValue -InputObject $r -Name '@odata.type')
            $targetType = [string](Get-ZkPropertyValue -InputObject $r -Name 'targetType')
            # Only edges where this app is the source ("child" target): the relationship list
            # returns both directions; targetType 'child' means the target is the dependency or
            # the superseded app.
            if ($targetType -and $targetType -ne 'child') { continue }
            $edge = [pscustomobject]@{
                Source     = $appId
                Target     = [string](Get-ZkPropertyValue -InputObject $r -Name 'targetId')
                TargetName = [string](Get-ZkPropertyValue -InputObject $r -Name 'targetDisplayName')
                Kind       = [string](Get-ZkPropertyValue -InputObject $r -Name 'dependencyType')
            }
            if ($type -match 'Dependency') { $dep.Add($edge) }
            elseif ($type -match 'Supersedence') {
                $edge.Kind = [string](Get-ZkPropertyValue -InputObject $r -Name 'supersedenceType')
                $sup.Add($edge)
            }
        }
    }
    [pscustomobject]@{ Dependencies = $dep.ToArray(); Supersedence = $sup.ToArray() }
}

function Test-ZkRelationshipGraph {
    <#
    .SYNOPSIS
        Runs relationship checks T10-T13 and T17 on edge lists. Pure function.
    .PARAMETER Graph
        Output of Get-ZkRelationshipGraph.
    .PARAMETER AssignedAppIds
        App IDs that have at least one assignment.
    .PARAMETER AppNames
        Hashtable appId -> display name.
    .EXAMPLE
        Test-ZkRelationshipGraph -Graph $g -AssignedAppIds $ids -AppNames $names
    .EXAMPLE
        Test-ZkRelationshipGraph -Graph $g -AssignedAppIds @() -AppNames @{}
    .OUTPUTS
        PSCustomObject[] findings
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] $Graph,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$AssignedAppIds,
        [Parameter(Mandatory)] [hashtable]$AppNames
    )
    $f = New-Object -TypeName System.Collections.Generic.List[object]
    $appNameMap = $AppNames
    $nameOf = { param($i) if ($appNameMap.ContainsKey($i)) { $appNameMap[$i] } else { $i } }

    # Undirected component size over dependency edges (Learn counts shared graphs together)
    $adj = @{}
    foreach ($e in @($Graph.Dependencies)) {
        foreach ($pair in @(@($e.Source, $e.Target), @($e.Target, $e.Source))) {
            if (-not $adj.ContainsKey($pair[0])) { $adj[$pair[0]] = New-Object -TypeName System.Collections.Generic.HashSet[string] }
            [void]$adj[$pair[0]].Add($pair[1])
        }
    }
    $seen = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($start in @($adj.Keys)) {
        if ($seen.Contains($start)) { continue }
        $queue = New-Object -TypeName System.Collections.Generic.Queue[string]
        $queue.Enqueue($start); [void]$seen.Add($start); $members = @()
        while ($queue.Count -gt 0) {
            $n = $queue.Dequeue(); $members += $n
            foreach ($m in $adj[$n]) { if ($seen.Add($m)) { $queue.Enqueue($m) } }
        }
        if ($members.Count -gt 100) {
            $f.Add((New-ZkFinding -CheckId 'T10' -Severity 'High' -AppId $start -AppName (& $nameOf $start) `
                        -Message ("Connected dependency graph has {0} apps. Intune caps a dependency graph at 100 and counts every graph that shares an app." -f $members.Count) `
                        -Evidence (($members | Select-Object -First 8 | ForEach-Object { & $nameOf $_ }) -join ', ')))
        }
        elseif ($members.Count -gt 80) {
            $f.Add((New-ZkFinding -CheckId 'T10' -Severity 'Low' -AppId $start -AppName (& $nameOf $start) `
                        -Message ("Connected dependency graph has {0} apps (limit 100, shared apps join graphs)." -f $members.Count) -Evidence ''))
        }
    }

    # Supersedence chain length (directed, follow source -> target)
    $supAdj = @{}
    foreach ($e in @($Graph.Supersedence)) {
        if (-not $supAdj.ContainsKey($e.Source)) { $supAdj[$e.Source] = @() }
        $supAdj[$e.Source] += $e.Target
    }
    $superseded = @($Graph.Supersedence | ForEach-Object { $_.Target })
    foreach ($root in @($supAdj.Keys | Where-Object { $superseded -notcontains $_ })) {
        $nodes = New-Object -TypeName System.Collections.Generic.HashSet[string]
        $stack = New-Object -TypeName System.Collections.Generic.Stack[string]
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $n = $stack.Pop()
            if (-not $nodes.Add($n)) { continue }
            if ($supAdj.ContainsKey($n)) { foreach ($t in $supAdj[$n]) { $stack.Push($t) } }
        }
        if ($nodes.Count -gt 10) {
            $f.Add((New-ZkFinding -CheckId 'T11' -Severity 'High' -AppId $root -AppName (& $nameOf $root) `
                        -Message ("Supersedence chain from this app has {0} nodes. Learn gives 10 (chain) and 11 (graph) as limits. Treat 10 as the ceiling." -f $nodes.Count) -Evidence ''))
        }
        # T12 superseding app must be targeted
        if ($AssignedAppIds -notcontains $root) {
            $f.Add((New-ZkFinding -CheckId 'T12' -Severity 'High' -AppId $root -AppName (& $nameOf $root) `
                        -Message 'This app supersedes other apps but has no assignment. Superseding apps get no automatic targeting and the agent ignores them.' `
                        -Evidence (($supAdj[$root] | ForEach-Object { & $nameOf $_ }) -join ', ')))
        }
    }
    # T13 dependency on an app that is superseded elsewhere
    foreach ($d in @($Graph.Dependencies)) {
        $hit = @($Graph.Supersedence | Where-Object { $_.Target -eq $d.Target })
        foreach ($h in $hit) {
            $f.Add((New-ZkFinding -CheckId 'T13' -Severity 'High' -AppId $d.Source -AppName (& $nameOf $d.Source) `
                        -Message ("Depends on '{0}', which '{1}' supersedes. Learn: 'A depends on B, C supersedes B. A will report a conflict state.'" -f (& $nameOf $d.Target), (& $nameOf $h.Source)) `
                        -Evidence ("dependency {0} -> {1}; supersedence {2} -> {1}" -f $d.Source, $d.Target, $h.Source)))
        }
    }
    # T17 untargeted dependencies don't show install status
    foreach ($d in @($Graph.Dependencies)) {
        if ($AssignedAppIds -notcontains $d.Target -and $d.Kind -eq 'autoInstall') {
            $f.Add((New-ZkFinding -CheckId 'T17' -Severity 'Info' -AppId $d.Target -AppName (& $nameOf $d.Target) `
                        -Message ("Untargeted auto-install dependency of '{0}'. It installs, but only targeted apps show install status, so look on the device for its failures." -f (& $nameOf $d.Source)) -Evidence ''))
        }
    }
    return $f.ToArray()
}

function ConvertTo-ZkHtmlEncoded {
    <#
    .SYNOPSIS
        HTML-encodes a string.
    .PARAMETER Text
        Text to encode.
    .EXAMPLE
        ConvertTo-ZkHtmlEncoded -Text '<a>'
    .EXAMPLE
        'x & y' | ConvertTo-ZkHtmlEncoded
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(ValueFromPipeline)] [AllowNull()] [AllowEmptyString()] [string]$Text)
    process { [System.Net.WebUtility]::HtmlEncode([string]$Text) }
}

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
        [void]$rows.Append('<tr data-sev="' + $c + '" data-st="' + (& $enc $st) + '"><td><span class="st st-' + $c + '" data-status="' + $c + '">' + $label[$c] + '</span></td><td>' + (& $enc $st) + '</td>' + $(if ($hasConf) { '<td>' + $(if ($f.PSObject.Properties['Confidence']) { & $enc $f.Confidence } else { '' }) + '</td>' } else { '' }) + '<td class="c-scope">' + (& $enc $f.Scope) + '</td><td class="c-check">' + (& $enc $f.Check) + '</td><td>' + (& $enc $f.Finding) + '</td><td>' + $evCell + '</td><td>' + $f.NextHtml + '</td></tr>' + "`n")
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
td{padding:9px 10px;border-top:1px solid var(--border);vertical-align:top;word-break:normal;overflow-wrap:break-word}td.c-scope{min-width:110px}td.c-check{min-width:170px}tbody tr:hover{background:var(--surface)}
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

function Export-ZkTenantReport {
    <#
    .SYNOPSIS
        Writes the JSON and HTML tenant reports.
    .PARAMETER Report
        Report object.
    .PARAMETER OutputPath
        Destination folder.
    .PARAMETER KnownCause
        Known-causes database object.
    .PARAMETER NoHtml
        Write only the JSON report.
    .EXAMPLE
        Export-ZkTenantReport -Report $r -OutputPath .\out -KnownCause $db
    .EXAMPLE
        Export-ZkTenantReport -Report $r -OutputPath $env:TEMP -KnownCause $db
    .OUTPUTS
        PSCustomObject with file paths.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Report,
        [Parameter(Mandatory)] [string]$OutputPath,
        [Parameter(Mandatory)] $KnownCause,
        [Parameter()] [switch]$NoHtml
    )
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $json = Join-Path -Path $OutputPath -ChildPath "Kit2-TenantPreCheck-$stamp.json"
    $html = Join-Path -Path $OutputPath -ChildPath "Kit2-TenantPreCheck-$stamp.html"
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $json -Encoding UTF8

    if ($NoHtml) { return [pscustomobject]@{ Json = $json; Html = $null } }
    $e = { param($x) [System.Net.WebUtility]::HtmlEncode([string]$x) }
    $checkInfo = @{}
    foreach ($c in @($KnownCause.tenantChecks)) { $checkInfo[$c.id] = $c }
    $findings = @($Report.Findings | Sort-Object -Property @{ Expression = { @('High', 'Medium', 'Low', 'Info').IndexOf($_.Severity) } }, AppName)
    $dash = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($fi in $findings) {
        $urls = @(); $ct = ''
        if ($checkInfo.ContainsKey($fi.CheckId)) { $urls = @($checkInfo[$fi.CheckId].sources | ForEach-Object { $_.url }); $ct = $checkInfo[$fi.CheckId].title }
        $st2 = switch ($fi.Severity) { 'High' { 'Fail (High)' } 'Medium' { 'Warn (Medium)' } 'Low' { 'Warn (Low)' } default { 'Info' } }
        $dash.Add([pscustomobject]@{ Status = $st2; Confidence = $(if ($fi.Message -match '(?i)heuristic') { 'Heuristic' } else { '' }); Scope = $fi.AppName; Check = ('{0} {1}' -f $fi.CheckId, $ct).Trim(); Finding = $fi.Message; Evidence = $fi.Evidence; NextHtml = (Get-ZkNextStepLink -Url $urls -Code $fi.CheckId) })
    }
    foreach ($a in @($Report.Apps | Sort-Object -Property DisplayName)) {
        $hit = @($findings | Where-Object { ($_.AppId -eq $a.Id -or $_.AppName -eq $a.DisplayName) -and $_.Severity -ne 'Info' })
        if ($hit.Count -eq 0) { $dash.Add([pscustomobject]@{ Status = 'Pass'; Scope = $a.DisplayName; Check = 'All tenant checks'; Finding = 'No warnings or failures for this app.'; Evidence = ''; NextHtml = '<span class="next next-code">None needed</span>' }) }
    }
    $appRows = foreach ($a in @($Report.Apps | Sort-Object -Property DisplayName)) {
        '<tr><td>' + (& $e $a.DisplayName) + '</td><td><code>' + (& $e $a.Id) + '</code></td><td>' + (& $e $a.RunAs) + '</td><td>' + (& $e $a.Assignments) + '</td><td>' + (& $e $a.InstallSummary) + '</td><td>' + (& $e $a.DetectionRuleCount) + '</td></tr>'
    }
    $extra = ''
    if (@($Report.Findings).Count -eq 0) { $extra += '<p>No findings for the apps in scope.</p>' }
    if (@($Report.Errors).Count -gt 0) { $extra += '<h2>Could not read</h2><ul>' + ((@($Report.Errors) | ForEach-Object { '<li>' + (& $e $_) + '</li>' }) -join '') + '</ul>' }
    $extra += '<h2>Apps</h2><div class="tablewrap"><table><thead><tr><th>App</th><th>ID</th><th>Context</th><th>Assignments</th><th>Install summary (devices)</th><th>Detection rules</th></tr></thead><tbody>' + ($appRows -join "`n") + '</tbody></table></div>'
    $doc = ConvertTo-ZkDashboardHtml -Brand 'ZakitPro Win32 App Deployment Doctor' -Title 'Win32 app tenant pre-check' -Subtitle ('Kit 2 v{0} | generated {1} (device local time) | read-only Graph (GET only) | apps checked: {2} | findings: {3} | known-causes {4}' -f $Report.KitVersion, $Report.GeneratedLocal, @($Report.Apps).Count, @($Report.Findings).Count, $KnownCause.version) -Finding $dash.ToArray() -ExtraHtml $extra
    Set-Content -LiteralPath $html -Value $doc -Encoding UTF8
    [pscustomobject]@{ Json = $json; Html = $html }
}

function Invoke-ZkTenantPreCheck {
    <#
    .SYNOPSIS
        Main read-only routine. Separated so tests can mock Graph.
    .PARAMETER AppNameFilter
        Optional name filter.
    .PARAMETER IncludeAgentAppCheck
        Also check the Intune Windows Agent service principal.
    .PARAMETER SkipInstallSummary
        Skip install summaries.
    .EXAMPLE
        Invoke-ZkTenantPreCheck
    .EXAMPLE
        Invoke-ZkTenantPreCheck -AppNameFilter 'Chrome' -SkipInstallSummary
    .OUTPUTS
        PSCustomObject report
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$AppNameFilter,
        [Parameter()] [switch]$IncludeAgentAppCheck,
        [Parameter()] [switch]$SkipInstallSummary
    )
    $list = @(Invoke-ZkGraphGet -Uri "/deviceAppManagement/mobileApps?`$filter=isof('microsoft.graph.win32LobApp')")
    if ($AppNameFilter) { $list = @($list | Where-Object { $_.displayName -like "*$AppNameFilter*" }) }
    Write-Verbose -Message ("Win32 apps in scope: {0}" -f @($list).Count)
    if (@($list).Count -eq 0) {
        $scopeText = if ($AppNameFilter) { "whose name contains '$AppNameFilter'" } else { 'in this tenant' }
        Write-Warning -Message "No Win32 apps found $scopeText. The report will be empty. Check the filter text and that the account can read Intune apps."
    }
    $errors = New-Object -TypeName System.Collections.Generic.List[string]

    $findings = New-Object -TypeName System.Collections.Generic.List[object]
    $apps = New-Object -TypeName System.Collections.Generic.List[object]
    $relationships = @{}
    $assigned = New-Object -TypeName System.Collections.Generic.List[string]
    $names = @{}
    $groupCache = @{}

    foreach ($item in @($list)) {
        try { $app = Invoke-ZkGraphGet -Uri "/deviceAppManagement/mobileApps/$($item.id)" -Single }
        catch {
            $errors.Add(("App {0} ({1}) skipped: {2}" -f $item.displayName, $item.id, $_.Exception.Message))
            Write-Warning -Message $errors[$errors.Count - 1]
            continue
        }
        try {
        $names[[string]$app.id] = [string]$app.displayName
        foreach ($x in (Test-ZkWin32AppDefinition -App $app)) { $findings.Add($x) }

        try { $asg = @(Invoke-ZkGraphGet -Uri "/deviceAppManagement/mobileApps/$($app.id)/assignments") }
        catch { $asg = @(); $errors.Add(("Assignments for {0} not read: {1}" -f $app.displayName, $_.Exception.Message)); Write-Warning -Message $errors[$errors.Count - 1] }
        if ($asg.Count -gt 0) { $assigned.Add([string]$app.id) }
        $asgText = foreach ($a in $asg) {
            $t = Get-ZkPropertyValue -InputObject $a -Name 'target'
            $tt = [string](Get-ZkPropertyValue -InputObject $t -Name '@odata.type')
            $gid = [string](Get-ZkPropertyValue -InputObject $t -Name 'groupId')
            $label = $tt -replace '#microsoft.graph.', '' -replace 'AssignmentTarget', ''
            if ($gid) {
                if (-not $groupCache.ContainsKey($gid)) {
                    try { $groupCache[$gid] = (Invoke-ZkGraphGet -Uri "https://graph.microsoft.com/v1.0/groups/$gid`?`$select=displayName" -Single).displayName }
                    catch { $groupCache[$gid] = $gid; Write-Verbose -Message "Group lookup failed for $gid : $($_.Exception.Message)" }
                }
                $label = "$label`:$($groupCache[$gid])"
            }
            $settings = Get-ZkPropertyValue -InputObject $a -Name 'settings'
            $au = Get-ZkPropertyValue -InputObject (Get-ZkPropertyValue -InputObject $settings -Name 'autoUpdateSettings') -Name 'autoUpdateSupersededAppsState'
            if ($au -eq 'enabled') {
                $findings.Add((New-ZkFinding -CheckId 'T14' -Severity 'Info' -AppId $app.id -AppName $app.displayName `
                            -Message 'Supersedence auto-update is on for an Available assignment. Any later assignment change deletes the auto-update component, and users must be signed in. Allow 8-16 hours.' -Evidence $label))
            }
            '{0} ({1})' -f $a.intent, $label
        }
        try { $relationships[[string]$app.id] = @(Invoke-ZkGraphGet -Uri "/deviceAppManagement/mobileApps/$($app.id)/relationships") }
        catch { $relationships[[string]$app.id] = @(); $errors.Add(("Relationships for {0} not read: {1}" -f $app.displayName, $_.Exception.Message)); Write-Warning -Message $errors[$errors.Count - 1] }

        $summaryText = 'skipped'
        if (-not $SkipInstallSummary) {
            try {
                $s = Invoke-ZkGraphGet -Uri "/deviceAppManagement/mobileApps/$($app.id)/installSummary" -Single
                $summaryText = 'installed {0}, failed {1}, pending {2}, not installed {3}, not applicable {4}' -f $s.installedDeviceCount, $s.failedDeviceCount, $s.pendingInstallDeviceCount, $s.notInstalledDeviceCount, $s.notApplicableDeviceCount
                if ([int]$s.failedDeviceCount -gt 0) {
                    $findings.Add((New-ZkFinding -CheckId 'T16' -Severity 'Medium' -AppId $app.id -AppName $app.displayName `
                                -Message ("{0} device(s) report Failed. Run Invoke-DeviceDiagnostic.ps1 on one of them." -f $s.failedDeviceCount) -Evidence $summaryText))
                }
            }
            catch { $summaryText = 'unavailable'; Write-Warning -Message "Install summary failed for $($app.displayName): $($_.Exception.Message)" }
        }
        $rules = @(@(Get-ZkPropertyValue -InputObject $app -Name 'rules') | Where-Object { $null -ne $_ })
        $det = @($rules | Where-Object { (Get-ZkPropertyValue -InputObject $_ -Name 'ruleType') -eq 'detection' })
        $apps.Add([pscustomobject]@{
                Id                 = [string]$app.id
                DisplayName        = [string]$app.displayName
                DisplayVersion     = [string](Get-ZkPropertyValue -InputObject $app -Name 'displayVersion')
                RunAs              = [string](Get-ZkPropertyValue -InputObject (Get-ZkPropertyValue -InputObject $app -Name 'installExperience') -Name 'runAsAccount')
                InstallCommand     = [string](Get-ZkPropertyValue -InputObject $app -Name 'installCommandLine')
                UninstallCommand   = [string](Get-ZkPropertyValue -InputObject $app -Name 'uninstallCommandLine')
                DetectionRuleCount = $det.Count
                DetectionRules     = $det
                RequirementRules   = @($rules | Where-Object { (Get-ZkPropertyValue -InputObject $_ -Name 'ruleType') -eq 'requirement' })
                ReturnCodes        = @(Get-ZkPropertyValue -InputObject $app -Name 'returnCodes')
                Assignments        = ($asgText -join '; ')
                InstallSummary     = $summaryText
            })
        }
        catch {
            # One odd app object must not stop the scan: record it and carry on with the next app.
            $appLabel = [string](Get-ZkPropertyValue -InputObject $item -Name 'displayName')
            $errors.Add(("App {0} ({1}) could not be evaluated: {2}" -f $appLabel, $item.id, $_.Exception.Message))
            Write-Warning -Message $errors[$errors.Count - 1]
            $findings.Add((New-ZkFinding -CheckId 'T00' -Severity 'Medium' -AppId ([string]$item.id) -AppName $appLabel `
                        -Message 'This app could not be evaluated: its Graph object is missing data the checks expect. Check it in the Intune portal; other apps were checked as normal.' -Evidence $_.Exception.Message))
        }
    }
    $graph = Get-ZkRelationshipGraph -Relationship $relationships
    foreach ($x in (Test-ZkRelationshipGraph -Graph $graph -AssignedAppIds $assigned.ToArray() -AppNames $names)) { $findings.Add($x) }

    if ($IncludeAgentAppCheck) {
        $sp = @(Invoke-ZkGraphGet -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'Microsoft Intune Windows Agent'&`$select=id,appId,displayName,accountEnabled")
        if ($sp.Count -eq 0) {
            $findings.Add((New-ZkFinding -CheckId 'T19' -Severity 'Info' -AppId '' -AppName '(tenant)' -Message "No service principal named 'Microsoft Intune Windows Agent' was found by display name. That is not proof of a problem. Check Entra > Enterprise apps." -Evidence ''))
        }
        foreach ($s in $sp) {
            if (-not [bool]$s.accountEnabled) {
                $findings.Add((New-ZkFinding -CheckId 'T19' -Severity 'High' -AppId '' -AppName '(tenant)' `
                            -Message "The 'Microsoft Intune Windows Agent' enterprise app is disabled. Learn: user-targeted IME payloads stop working. See the guide for Microsoft's documented fix (it is a write action; the kit doesn't do it)." -Evidence ("appId {0}" -f $s.appId)))
            }
        }
    }
    [pscustomobject]@{
        KitVersion     = $script:KitVersion
        GeneratedLocal = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        Scope          = if ($AppNameFilter) { "name contains '$AppNameFilter'" } else { 'all Win32 apps' }
        Apps           = $apps.ToArray()
        Edges          = $graph
        Findings       = @($findings.ToArray() | Sort-Object -Property CheckId, AppId, Message -Unique)
        Errors         = $errors.ToArray()
    }
}

# ---- main ----
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $db = Get-Content -LiteralPath $KnownCausesPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Could not read known-causes.json at '$KnownCausesPath': $($_.Exception.Message)"
    }
    if (-not $SkipConnect) {
        $scopes = @('DeviceManagementApps.Read.All', 'Group.Read.All')
        if ($IncludeAgentAppCheck) { $scopes += 'Application.Read.All' }
        $connect = @{ Scopes = $scopes; NoWelcome = $true }
        if ($TenantId) { $connect['TenantId'] = $TenantId }
        Connect-MgGraph @connect
    }
    $report = Invoke-ZkTenantPreCheck -AppNameFilter $AppNameFilter -IncludeAgentAppCheck:$IncludeAgentAppCheck -SkipInstallSummary:$SkipInstallSummary
    $files = Export-ZkTenantReport -Report $report -OutputPath $OutputPath -KnownCause $db -NoHtml:$NoHtml
    $summary = [pscustomobject]@{
        ReportJson   = $files.Json
        ReportHtml   = $files.Html
        AppCount     = @($report.Apps).Count
        FindingCount = @($report.Findings).Count
    }
    Write-Host ''
    Write-Host ('ZakitPro Kit 2 tenant pre-check v{0} (read-only, GET only)' -f $script:KitVersion)
    Write-Host ('Apps checked: {0} | findings: {1}' -f @($report.Apps).Count, @($report.Findings).Count)
    foreach ($sev in 'High', 'Medium', 'Low', 'Info') {
        $n = @($report.Findings | Where-Object { $_.Severity -eq $sev }).Count
        if ($n -gt 0) { Write-Host ('  {0}: {1}' -f $sev, $n) }
    }
    if (@($report.Errors).Count -gt 0) { Write-Host ('  Could not read {0} item(s); see the report.' -f @($report.Errors).Count) -ForegroundColor Yellow }
    if ($files.Html) { Write-Host ('Report: {0}' -f $files.Html) } else { Write-Host ('Report (JSON only): {0}' -f $files.Json) }
    if ($PassThru) { $summary }
}
