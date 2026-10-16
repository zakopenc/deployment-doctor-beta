#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
<#
.SYNOPSIS
    Read-only tenant pre-flight check for Windows Autopilot (ESP) and Autopilot device preparation.

.DESCRIPTION
    ZakitPro Kit 1 - Deployment Doctor, module M1/M2.
    Reads tenant configuration through Microsoft Graph and reports configuration that is documented
    (Microsoft Learn) or field-reported (cited expert sources) to break deployments, before a device boots.
    Every finding is matched to an entry in known-causes.json (id, cause, fix, sources).

    Checks:
      M2  Intune Provisioning Client service principal, looked up by AppID f1346770-5b25-470b-88bd-d5744ab7952c
      M2  Each Device Prep policy's device group: exists, assigned (not dynamic), not role-assignable,
          owned by the service principal, Intune's own validation result
      M2  Custom Intune roles that appear to carry the enrollment time device membership permission
          (heuristic, see notes), and whether the device group is in any role assignment's scope groups
      M1  Entra 'registering user is added as local administrator' vs Device Prep 'Standard user' policies
      M1  Windows enrollment restrictions blocking personal devices vs corporate identifiers present
      M1  ESP profiles whose blocking apps mix LOB MSI and Win32 apps, or include Microsoft 365 Apps (C2R)
      M1  Device Prep app (25) and script (10) caps; selected apps not assigned to the device group
      M1  Device-context PowerShell scripts that will run during ESP (30-minute timeout signal)

    THIS SCRIPT IS READ-ONLY. It sends only GET requests, plus one documented read action
    (POST .../retrieveEnrollmentTimeDeviceMembershipTarget, which needs only
    DeviceManagementConfiguration.Read.All and changes nothing). It never writes to the tenant.

.PARAMETER OutputPath
    Folder for the HTML and JSON reports. Default: current folder.

.PARAMETER KnownCausesPath
    Path to known-causes.json. Default: ..\data\known-causes.json relative to this script.

.PARAMETER TenantId
    Optional tenant ID or domain to sign in to (for example contoso.onmicrosoft.com).

.PARAMETER SkipConnect
    Use an existing Connect-MgGraph session instead of connecting.

.PARAMETER NoHtml
    Skip the HTML report (JSON and console only).

.PARAMETER PassThru
    Also return the finding objects to the pipeline. Off by default so the console stays clean.

.EXAMPLE
    .\Invoke-TenantPreCheck.ps1 -OutputPath C:\Temp\PreCheck
    Signs in interactively with the read-only scopes and writes TenantPreCheck-<date>.html and .json.

.EXAMPLE
    Connect-MgGraph -Scopes Application.Read.All,GroupMember.Read.All -TenantId contoso.onmicrosoft.com
    .\Invoke-TenantPreCheck.ps1 -SkipConnect -PassThru | Where-Object Result -eq 'Fail'
    Reuses a session you opened yourself. Checks that need missing scopes report 'Not checked'.

.OUTPUTS
    With -PassThru: PSCustomObject[] findings (Id, Module, Check, Result, Detail, KnownCauseIds). Also writes HTML and JSON.

.NOTES
    Name:         Invoke-TenantPreCheck.ps1
    Version:      1.3.0 (2026-10-16)
    Publisher:    ZakitPro - Abderrazak Elbouchikhi (Zak) - hello@zakitpro.com
    Requires:     Windows PowerShell 5.1 or PowerShell 7.x; Microsoft.Graph.Authentication 2.x.
                  An account with read access to Intune and Entra (for example Global Reader + Intune
                  read-only role). Intune license in the tenant.
    Graph scopes (delegated, read-only; each verified on Microsoft Learn 2026-10-15):
                  Application.Read.All                  GET /servicePrincipals
                  GroupMember.Read.All                  GET /groups/{id}, GET /groups/{id}/owners
                  Policy.Read.DeviceConfiguration       GET /beta/policies/deviceRegistrationPolicy
                  DeviceManagementServiceConfig.Read.All GET deviceEnrollmentConfigurations, importedDeviceIdentities
                  DeviceManagementConfiguration.Read.All GET configurationPolicies (+settings), deviceManagementScripts,
                                                        POST retrieveEnrollmentTimeDeviceMembershipTarget (read action)
                  DeviceManagementApps.Read.All         GET mobileApps, mobileApps/{id}/assignments
                  DeviceManagementRBAC.Read.All         GET roleDefinitions, roleAssignments
    Beta endpoints: several Intune and policy endpoints used here are /beta and can change.
    Device Prep setting IDs (enrollment_autopilot_dpp_allowedappids, ..._allowedscriptids, ..._accountype)
                  come from published community examples (ourcloudnetwork.com, cloudflow.be, PSGallery
                  Demo-AutopilotDevicePreparationPolicy), not from Microsoft Learn. Checked 2026-10-15.
    Tested on:    Not tested against a live tenant. Parse-checked and linted with PSScriptAnalyzer only.
    Changelog:    See CHANGELOG.md.
    Disclaimer:   Provided AS IS, without warranty of any kind. Test in a non-production tenant first.
                  You are responsible for running it in your environment.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KnownCausesPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\data\known-causes.json'),

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9.\-]+$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$SkipConnect,

    [Parameter()]
    [switch]$PassThru,

    [Parameter()]
    [switch]$NoHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ProvisioningClientAppId = 'f1346770-5b25-470b-88bd-d5744ab7952c'
$script:RequiredScopes = @(
    'Application.Read.All'
    'GroupMember.Read.All'
    'Policy.Read.DeviceConfiguration'
    'DeviceManagementServiceConfig.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementApps.Read.All'
    'DeviceManagementRBAC.Read.All'
)
$script:Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warn', 'Info', 'NotChecked')][string]$Result,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail,
        [Parameter()][string[]]$Signal = @()
    )
    $script:Findings.Add([PSCustomObject]@{
            Id            = 'F{0:D3}' -f ($script:Findings.Count + 1)
            Module        = $Module
            Check         = $Check
            Result        = $Result
            Detail        = $Detail
            Signals       = $Signal
            KnownCauseIds = @()
        })
}

function Invoke-GraphGet {
    [OutputType([object])]
    <# Read-only GET with paging. Returns all items of a collection, or the single object. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($response.PSObject.Properties.Name -contains 'value') {
            foreach ($v in @($response.value)) { $items.Add($v) }
            $next = if ($response.PSObject.Properties.Name -contains '@odata.nextLink') { $response.'@odata.nextLink' } else { $null }
        }
        else {
            return $response
        }
    }
    return $items.ToArray()
}

function Get-SafeProperty {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $null
}

function Invoke-Check {
    <# Runs one check; a Graph error becomes a NotChecked finding instead of stopping the run. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        & $ScriptBlock
    }
    catch {
        $msg = $_.Exception.Message
        Write-Warning -Message "$Check could not run: $msg"
        Add-Finding -Module $Module -Check $Check -Result 'NotChecked' -Detail "Graph call failed: $msg (missing scope, role, or license?)"
    }
}

# ---------------------------------------------------------------- connect
if (-not $SkipConnect) {
    $connectParams = @{ Scopes = $script:RequiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    try {
        Connect-MgGraph @connectParams
    }
    catch {
        throw "Connect-MgGraph failed: $($_.Exception.Message)"
    }
}
$context = Get-MgContext
if ($null -eq $context) { throw 'No Microsoft Graph session. Run without -SkipConnect, or Connect-MgGraph first.' }
$missing = @($script:RequiredScopes | Where-Object { $context.Scopes -notcontains $_ })
if ($missing.Count -gt 0) {
    Write-Warning -Message "Session is missing scopes: $($missing -join ', '). Related checks will report NotChecked."
}

# ---------------------------------------------------------------- known causes
$knownCauses = @()
if (Test-Path -LiteralPath $KnownCausesPath) {
    $knownCauses = @((Get-Content -LiteralPath $KnownCausesPath -Raw | ConvertFrom-Json).causes)
}
else {
    Write-Warning -Message "known-causes.json not found at $KnownCausesPath. Findings won't be matched to causes."
}

$base = 'https://graph.microsoft.com'
Write-Information -MessageData 'Read-only run: GET requests only, plus one documented read action (POST ...retrieveEnrollmentTimeDeviceMembershipTarget) that returns the Device Prep group and changes nothing.' -InformationAction Continue

# ---------------------------------------------------------------- M2: service principal
Invoke-Check -Module 'M2' -Check 'Intune Provisioning Client service principal' -ScriptBlock {
    $r = @(Invoke-GraphGet -Uri "$base/v1.0/servicePrincipals?`$filter=appId eq '$($script:ProvisioningClientAppId)'&`$select=id,appId,displayName")
    if ($r.Count -eq 0) {
        Add-Finding -Module 'M2' -Check 'Intune Provisioning Client service principal' -Result 'Fail' `
            -Detail "No service principal with AppID $($script:ProvisioningClientAppId)." -Signal 'T_SP_MISSING'
    }
    else {
        Add-Finding -Module 'M2' -Check 'Intune Provisioning Client service principal' -Result 'Pass' `
            -Detail "Found: '$($r[0].displayName)' (object id $($r[0].id))."
        if ($r[0].displayName -ne 'Intune Provisioning Client') {
            Add-Finding -Module 'M2' -Check 'Service principal display name' -Result 'Info' `
                -Detail "Displays as '$($r[0].displayName)'. Match on the AppID, not the name." -Signal 'T_SP_NAME_DIFFERENT'
        }
    }
}

# ---------------------------------------------------------------- Device Prep policies
$dpPolicies = @()
Invoke-Check -Module 'M2' -Check 'Device Prep policies' -ScriptBlock {
    $all = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/configurationPolicies?`$select=id,name,technologies,templateReference,roleScopeTagIds")
    $script:dpPolicies = @($all | Where-Object {
            $tr = Get-SafeProperty -InputObject $_ -Name 'templateReference'
            (Get-SafeProperty -InputObject $tr -Name 'templateFamily') -eq 'enrollmentConfiguration'
        })
    Add-Finding -Module 'M2' -Check 'Device Prep policies' -Result 'Info' `
        -Detail "Found $($script:dpPolicies.Count) policies with templateFamily 'enrollmentConfiguration'."
}

$dpGroupIds = [System.Collections.Generic.List[string]]::new()
$dpStandardUser = $false
foreach ($policy in $dpPolicies) {
    $pName = $policy.name
    # settings: app/script counts and account type
    Invoke-Check -Module 'M1' -Check "Device Prep settings: $pName" -ScriptBlock {
        $settings = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/configurationPolicies/$($policy.id)/settings")
        $appIds = @(); $scriptCount = 0
        foreach ($s in $settings) {
            $inst = Get-SafeProperty -InputObject $s -Name 'settingInstance'
            $defId = [string](Get-SafeProperty -InputObject $inst -Name 'settingDefinitionId')
            $coll = @(Get-SafeProperty -InputObject $inst -Name 'simpleSettingCollectionValue')
            if ($defId -eq 'enrollment_autopilot_dpp_allowedappids') {
                foreach ($v in $coll) {
                    if ($null -eq $v) { continue }
                    try { $appIds += ([string]($v.value | ConvertFrom-Json).id) } catch { Write-Verbose -Message "Unparsed app entry: $($v.value)" }
                }
            }
            elseif ($defId -eq 'enrollment_autopilot_dpp_allowedscriptids') {
                $scriptCount = @($coll | Where-Object { $null -ne $_ }).Count
            }
            elseif ($defId -like 'enrollment_autopilot_dpp_accountype*') {
                $choice = Get-SafeProperty -InputObject $inst -Name 'choiceSettingValue'
                $val = [string](Get-SafeProperty -InputObject $choice -Name 'value')
                if ($val -like '*accountype_1') { $script:dpStandardUser = $true }
            }
        }
        $appResult = if ($appIds.Count -gt 25) { 'Fail' } else { 'Pass' }
        $sig = if ($appIds.Count -gt 25) { @('T_DP_APP_CAP') } else { @() }
        Add-Finding -Module 'M1' -Check "Device Prep app cap: $pName" -Result $appResult -Detail "$($appIds.Count) apps selected (cap 25 since Jan 30, 2026)." -Signal $sig
        $scResult = if ($scriptCount -gt 10) { 'Fail' } else { 'Pass' }
        $sig = if ($scriptCount -gt 10) { @('T_DP_SCRIPT_CAP') } else { @() }
        Add-Finding -Module 'M1' -Check "Device Prep script cap: $pName" -Result $scResult -Detail "$scriptCount scripts selected (cap 10)." -Signal $sig
        $script:currentPolicyAppIds = $appIds
    }

    # device group via documented read action
    $groupId = $null
    Invoke-Check -Module 'M2' -Check "Device group: $pName" -ScriptBlock {
        $r = Invoke-MgGraphRequest -Method POST -Uri "$base/beta/deviceManagement/configurationPolicies/$($policy.id)/retrieveEnrollmentTimeDeviceMembershipTarget" -OutputType PSObject
        $val = Get-SafeProperty -InputObject $r -Name 'value'
        if ($null -eq $val) { $val = $r }
        $statuses = @(Get-SafeProperty -InputObject $val -Name 'enrollmentTimeDeviceMembershipTargetValidationStatuses')
        $statuses = @($statuses | Where-Object { $null -ne $_ })
        if ($statuses.Count -eq 0) {
            Add-Finding -Module 'M2' -Check "Device group: $pName" -Result 'Warn' -Detail 'No device group returned for this policy (automatic-mode policies have none; user-driven policies need one).'
        }
        foreach ($st in $statuses) {
            $script:groupId = $st.targetId
            $dpGroupIds.Add([string]$st.targetId)
            if ($st.validationSucceeded) {
                Add-Finding -Module 'M2' -Check "Intune group validation: $pName" -Result 'Pass' -Detail "Group $($st.targetId) validated by Intune."
            }
            else {
                Add-Finding -Module 'M2' -Check "Intune group validation: $pName" -Result 'Fail' `
                    -Detail "Intune reports group $($st.targetId) invalid: $($st.targetValidationErrorCode)." -Signal 'T_DPGROUP_TARGET_INVALID'
            }
        }
    }
    $thisGroup = $script:groupId
    $script:groupId = $null
    if (-not $thisGroup) { continue }

    Invoke-Check -Module 'M2' -Check "Group properties: $pName" -ScriptBlock {
        $g = $null
        try {
            $g = Invoke-GraphGet -Uri "$base/v1.0/groups/$($thisGroup)?`$select=id,displayName,groupTypes,securityEnabled,isAssignableToRole,membershipRule"
        }
        catch {
            if ($_.Exception.Message -match '404|NotFound|does not exist') {
                Add-Finding -Module 'M2' -Check "Group exists: $pName" -Result 'Fail' -Detail "Group $thisGroup not found (deleted?)." -Signal 'T_DPGROUP_MISSING'
                return
            }
            throw
        }
        if (@($g.groupTypes) -contains 'DynamicMembership') {
            Add-Finding -Module 'M2' -Check "Group type: $($g.displayName)" -Result 'Fail' -Detail 'Group is dynamic. Device Prep needs an assigned (static) security group.' -Signal 'T_DPGROUP_DYNAMIC'
        }
        else {
            Add-Finding -Module 'M2' -Check "Group type: $($g.displayName)" -Result 'Pass' -Detail 'Assigned (static) membership.'
        }
        if ($g.isAssignableToRole -eq $true) {
            Add-Finding -Module 'M2' -Check "Role-assignable: $($g.displayName)" -Result 'Fail' -Detail 'Group is role-assignable. Learn requires role-assignable = No.' -Signal 'T_DPGROUP_ROLEASSIGNABLE'
        }
        else {
            Add-Finding -Module 'M2' -Check "Role-assignable: $($g.displayName)" -Result 'Pass' -Detail 'Not role-assignable.'
        }
        # owners: beta, because v1.0 doesn't list service principal owners yet (Learn note)
        $owners = @(Invoke-GraphGet -Uri "$base/beta/groups/$thisGroup/owners?`$select=id,displayName,appId")
        $spOwner = @($owners | Where-Object { (Get-SafeProperty -InputObject $_ -Name 'appId') -eq $script:ProvisioningClientAppId })
        if ($spOwner.Count -gt 0) {
            Add-Finding -Module 'M2' -Check "SP is owner: $($g.displayName)" -Result 'Pass' -Detail 'Intune Provisioning Client owns the group.'
        }
        else {
            Add-Finding -Module 'M2' -Check "SP is owner: $($g.displayName)" -Result 'Fail' `
                -Detail "Owners: $((@($owners | ForEach-Object { $_.displayName }) -join ', ')). The SP (AppID $($script:ProvisioningClientAppId)) is not an owner." -Signal 'T_DPGROUP_SP_NOT_OWNER'
        }
    }

    # selected apps assigned to the device group?
    $policyApps = @($script:currentPolicyAppIds)
    $script:currentPolicyAppIds = @()
    foreach ($appId in $policyApps) {
        if (-not $appId) { continue }
        Invoke-Check -Module 'M1' -Check "App assigned to device group: $appId" -ScriptBlock {
            $app = Invoke-GraphGet -Uri "$base/beta/deviceAppManagement/mobileApps/$($appId)?`$select=id,displayName"
            $asg = @(Invoke-GraphGet -Uri "$base/beta/deviceAppManagement/mobileApps/$appId/assignments")
            $hit = @($asg | Where-Object { (Get-SafeProperty -InputObject $_.target -Name 'groupId') -eq $thisGroup })
            if ($hit.Count -gt 0) {
                Add-Finding -Module 'M1' -Check "App assigned to device group: $($app.displayName)" -Result 'Pass' -Detail "Assigned to the policy's device group ($($hit[0].intent))."
            }
            else {
                Add-Finding -Module 'M1' -Check "App assigned to device group: $($app.displayName)" -Result 'Fail' `
                    -Detail "Selected in policy '$pName' but not assigned to its device group. Expect 'Skipped'." -Signal 'T_DP_APP_NOT_ASSIGNED_TO_GROUP'
            }
        }
    }
}

# ---------------------------------------------------------------- M1: Entra local admin vs standard user
Invoke-Check -Module 'M1' -Check 'Entra local admin setting vs Device Prep account type' -ScriptBlock {
    $drp = Invoke-GraphGet -Uri "$base/beta/policies/deviceRegistrationPolicy"
    $reg = Get-SafeProperty -InputObject (Get-SafeProperty -InputObject (Get-SafeProperty -InputObject $drp -Name 'azureADJoin') -Name 'localAdmins') -Name 'registeringUsers'
    $type = [string](Get-SafeProperty -InputObject $reg -Name '@odata.type')
    $label = switch -Wildcard ($type) {
        '*allDeviceRegistrationMembership' { 'All' }
        '*enumeratedDeviceRegistrationMembership' { 'Selected' }
        '*noDeviceRegistrationMembership' { 'None' }
        default { "Unknown ($type)" }
    }
    if ($dpStandardUser -and $label -in @('Selected', 'None')) {
        Add-Finding -Module 'M1' -Check 'Entra local admin setting vs Device Prep account type' -Result 'Fail' `
            -Detail "A Device Prep policy uses Standard user and 'Registering user is added as local administrator' = $label. Learn lists this as a known issue (provisioning skipped)." -Signal 'T_DP_STDUSER_ENTRA_LOCALADMIN'
    }
    else {
        Add-Finding -Module 'M1' -Check 'Entra local admin setting vs Device Prep account type' -Result 'Pass' `
            -Detail "Registering user local admin = $label; Standard-user Device Prep policy found: $dpStandardUser."
    }
}

# ---------------------------------------------------------------- M1: enrollment restrictions + ESP
Invoke-Check -Module 'M1' -Check 'Enrollment restrictions and ESP profiles' -ScriptBlock {
    $configs = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/deviceEnrollmentConfigurations")
    $personalBlocked = $false
    $mdmBlocked = @()
    foreach ($c in $configs) {
        $t = [string]$c.'@odata.type'
        if ($t -like '*deviceEnrollmentPlatformRestrictionConfiguration') {
            $pr = Get-SafeProperty -InputObject $c -Name 'platformRestriction'
            if ((Get-SafeProperty -InputObject $c -Name 'platformType') -eq 'windows' -and (Get-SafeProperty -InputObject $pr -Name 'personalDeviceEnrollmentBlocked') -eq $true) { $personalBlocked = $true }
            if ((Get-SafeProperty -InputObject $c -Name 'platformType') -eq 'windows' -and (Get-SafeProperty -InputObject $pr -Name 'platformBlocked') -eq $true) { $mdmBlocked += [string]$c.displayName }
        }
        elseif ($t -like '*deviceEnrollmentPlatformRestrictionsConfiguration') {
            $wr = Get-SafeProperty -InputObject $c -Name 'windowsRestriction'
            if ((Get-SafeProperty -InputObject $wr -Name 'personalDeviceEnrollmentBlocked') -eq $true) { $personalBlocked = $true }
            if ((Get-SafeProperty -InputObject $wr -Name 'platformBlocked') -eq $true) { $mdmBlocked += [string]$c.displayName }
        }
    }
    if ($mdmBlocked.Count -gt 0) {
        Add-Finding -Module 'M1' -Check 'Windows (MDM) platform restriction' -Result 'Fail' `
            -Detail "Windows (MDM) enrollment is blocked in: $($mdmBlocked -join ', '). Learn lists this as a cause of 0x80180014. Check which users each restriction is assigned to." -Signal 'T_WINDOWS_MDM_BLOCKED'
    }
    else {
        Add-Finding -Module 'M1' -Check 'Windows (MDM) platform restriction' -Result 'Pass' -Detail 'No restriction blocks the Windows (MDM) platform.'
    }
    if ($personalBlocked) {
        $ids = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/importedDeviceIdentities?`$top=1")
        if ($ids.Count -eq 0) {
            Add-Finding -Module 'M1' -Check 'Personal enrollment blocked vs corporate identifiers' -Result 'Warn' `
                -Detail 'Personal Windows enrollment is blocked and no corporate identifiers exist. Device Prep devices must be corporate-identified or associated, or enrollment fails (0x80180014).' -Signal 'T_PERSONAL_BLOCKED_NO_CORPID'
        }
        else {
            Add-Finding -Module 'M1' -Check 'Personal enrollment blocked vs corporate identifiers' -Result 'Info' `
                -Detail 'Personal enrollment is blocked; corporate identifiers exist. Confirm each Device Prep device is identified or associated.'
        }
    }
    else {
        Add-Finding -Module 'M1' -Check 'Personal enrollment blocked vs corporate identifiers' -Result 'Pass' -Detail 'No Windows restriction blocking personal devices found.'
    }

    $esps = @($configs | Where-Object { [string]$_.'@odata.type' -like '*windows10EnrollmentCompletionPageConfiguration' })
    if ($esps.Count -gt 0) {
        $apps = @{}
        foreach ($a in @(Invoke-GraphGet -Uri "$base/beta/deviceAppManagement/mobileApps?`$select=id,displayName")) { $apps[$a.id] = $a }
    }
    foreach ($e in $esps) {
        $sel = @(Get-SafeProperty -InputObject $e -Name 'selectedMobileAppIds' | Where-Object { $_ })
        $types = @($sel | ForEach-Object { if ($apps.ContainsKey($_)) { [string]$apps[$_].'@odata.type' } })
        $hasMsi = @($types | Where-Object { $_ -like '*windowsMobileMSI' }).Count -gt 0
        $hasWin32 = @($types | Where-Object { $_ -like '*win32LobApp' }).Count -gt 0
        $hasC2R = @($types | Where-Object { $_ -like '*officeSuiteApp' }).Count -gt 0
        if ($hasMsi -and $hasWin32) {
            Add-Finding -Module 'M1' -Check "ESP LOB/Win32 mix: $($e.displayName)" -Result 'Fail' -Detail 'Blocking apps mix LOB MSI and Win32 apps (TrustedInstaller race).' -Signal 'T_ESP_LOB_WIN32_MIX'
        }
        else {
            Add-Finding -Module 'M1' -Check "ESP LOB/Win32 mix: $($e.displayName)" -Result 'Pass' -Detail "$($sel.Count) blocking apps; no LOB MSI + Win32 mix."
        }
        if ($hasC2R) {
            Add-Finding -Module 'M1' -Check "ESP includes Microsoft 365 Apps: $($e.displayName)" -Result 'Warn' -Detail 'Office C2R is a blocking app. Its Teams Machine-Wide Installer MSI is not tracked by ESP and can collide with Win32 MSI installs.' -Signal 'T_ESP_OFFICE_C2R'
        }
    }
}

# ---------------------------------------------------------------- M1: device scripts (30-minute timeout)
Invoke-Check -Module 'M1' -Check 'Device-context PowerShell scripts' -ScriptBlock {
    $scripts = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/deviceManagementScripts?`$select=id,displayName,runAsAccount")
    $sys = @($scripts | Where-Object { (Get-SafeProperty -InputObject $_ -Name 'runAsAccount') -eq 'system' })
    if ($sys.Count -gt 0) {
        Add-Finding -Module 'M1' -Check 'Device-context PowerShell scripts' -Result 'Info' `
            -Detail "$($sys.Count) system-context scripts: $((@($sys | ForEach-Object { $_.displayName }) -join '; ')). If assigned to devices, they run before Win32 apps in ESP and each can hold ESP up to 30 minutes if it hangs." -Signal 'T_DEVICE_SCRIPTS_PRESENT'
    }
    else {
        Add-Finding -Module 'M1' -Check 'Device-context PowerShell scripts' -Result 'Pass' -Detail 'No system-context platform scripts.'
    }
}

# ---------------------------------------------------------------- M2: RBAC + scope groups
Invoke-Check -Module 'M2' -Check 'RBAC: enrollment time device membership permission' -ScriptBlock {
    $roles = @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/roleDefinitions")
    $custom = @($roles | Where-Object { (Get-SafeProperty -InputObject $_ -Name 'isBuiltIn') -ne $true })
    $etgRoles = @($custom | Where-Object {
            $actions = @($_.rolePermissions | ForEach-Object { $_.resourceActions } | ForEach-Object { $_.allowedResourceActions })
            @($actions | Where-Object { $_ -match 'EnrollmentTime' }).Count -gt 0
        })
    if ($etgRoles.Count -gt 0) {
        Add-Finding -Module 'M2' -Check 'RBAC: enrollment time device membership permission' -Result 'Info' `
            -Detail "Custom roles with an 'EnrollmentTime' action: $((@($etgRoles | ForEach-Object { $_.displayName }) -join '; ')). Built-in Intune Administrator is not listed here."
    }
    else {
        Add-Finding -Module 'M2' -Check 'RBAC: enrollment time device membership permission' -Result 'Warn' `
            -Detail "No custom role contains an action matching 'EnrollmentTime'. Scoped admins who create Device Prep policies need 'Enrollment programs > Enrollment time device membership assignment'. Heuristic match: confirm in Tenant administration > Roles." -Signal 'T_RBAC_ETG_PERMISSION_NOT_FOUND'
    }
    if ($dpGroupIds.Count -gt 0) {
        $scopeGroups = [System.Collections.Generic.HashSet[string]]::new()
        $anyAllDevices = $false
        foreach ($r in $custom) {
            foreach ($ra in @(Invoke-GraphGet -Uri "$base/beta/deviceManagement/roleDefinitions/$($r.id)/roleAssignments")) {
                foreach ($s in @(Get-SafeProperty -InputObject $ra -Name 'resourceScopes')) { if ($s) { [void]$scopeGroups.Add([string]$s) } }
                if ((Get-SafeProperty -InputObject $ra -Name 'scopeType') -in @('allDevices', 'allDevicesAndLicensedUsers')) { $anyAllDevices = $true }
            }
        }
        foreach ($gid in ($dpGroupIds | Select-Object -Unique)) {
            if ($scopeGroups.Contains($gid) -or $anyAllDevices) {
                Add-Finding -Module 'M2' -Check "Scope group: $gid" -Result 'Pass' -Detail 'Device group is in a custom role assignment scope (or a role is scoped to all devices).'
            }
            elseif ($custom.Count -gt 0) {
                Add-Finding -Module 'M2' -Check "Scope group: $gid" -Result 'Warn' `
                    -Detail 'Device group is not a scope group in any custom role assignment. Scoped admins will not see it in the policy wizard.' -Signal 'T_DPGROUP_NOT_IN_SCOPE'
            }
        }
    }
}

# ---------------------------------------------------------------- manual checks (not automatable read-only from sources)
Add-Finding -Module 'M1' -Check 'Policy conflicts (AppLocker CSP in ESP, language GPO, baseline password)' -Result 'Info' `
    -Detail 'Manual: review device-targeted policies against the conflict table on the Autopilot troubleshooting FAQ. Not automated by this script.' -Signal 'T_MANUAL_POLICY_CONFLICT_REVIEW'

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

# ---------------------------------------------------------------- match + report
foreach ($f in $script:Findings) {
    if (@($f.Signals).Count -gt 0) {
        $f.KnownCauseIds = @($knownCauses | Where-Object { @($_.signals | Where-Object { $f.Signals -contains $_ }).Count -gt 0 } | ForEach-Object { $_.id })
    }
}

if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonFile = Join-Path -Path $OutputPath -ChildPath "TenantPreCheck-$stamp.json"
$htmlFile = Join-Path -Path $OutputPath -ChildPath "TenantPreCheck-$stamp.html"
$report = [PSCustomObject]@{
    Tool      = 'ZakitPro Kit 1 Invoke-TenantPreCheck 1.3.0'
    RunAt     = (Get-Date).ToString('o')
    TenantId  = $context.TenantId
    Scopes    = $context.Scopes
    Findings  = $script:Findings
    Causes    = @($knownCauses | Where-Object { $script:Findings.KnownCauseIds -contains $_.id })
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonFile -Encoding UTF8

if (-not $NoHtml) {
$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$rows = foreach ($f in $script:Findings) {
    $urls = @(); $codes = @()
    foreach ($cid in $f.KnownCauseIds) {
        $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1
        $urls += @($c.source_urls); $codes += $cid
    }
    $next = Get-ZkNextStepLink -Url $urls -Code ($codes -join ', ')
    "<tr><td>$(Get-ZkReportBadge -Value $f.Result)</td><td>$(& $enc $f.Id)</td><td>$(& $enc $f.Module)</td><td>$(& $enc $f.Check)</td><td>$(& $enc $f.Detail)</td><td>$(& $enc ($codes -join ', '))</td><td>$next</td></tr>"
}
$cnt = { param($r) @($script:Findings | Where-Object { (ConvertTo-ZkReportStatus -Value $_.Result) -eq $r }).Count }
$html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZakitPro Tenant Pre-Check</title>
<style>$($script:ZkReportCss)</style></head><body>
<h1>Deployment Doctor: tenant pre-check</h1><p class="meta">Run $(& $enc $report.RunAt) &middot; tenant $(& $enc $context.TenantId) &middot; ZakitPro Kit 1 &middot; read-only Graph (GET plus one documented read action)</p>
<div class="warnbox"><b>Read-only, local report.</b> Not tested against a live tenant. Test in non-production first. No data leaves this file.</div>
<p class="summary"><span>$(Get-ZkReportBadge -Value 'Fail') $(& $cnt 'red')</span><span>$(Get-ZkReportBadge -Value 'Warn') $(& $cnt 'yellow')</span><span>$(Get-ZkReportBadge -Value 'Pass') $(& $cnt 'green')</span><span>$(Get-ZkReportBadge -Value 'Info') $(& $cnt 'grey')</span></p>
<table><thead><tr><th>Status</th><th>#</th><th>Module</th><th>Check</th><th>Evidence</th><th>Known cause</th><th>What to do next</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
Set-Content -LiteralPath $htmlFile -Value $html -Encoding UTF8
}
else { $htmlFile = '(skipped: -NoHtml)' }
Write-Information -MessageData "Reports: $htmlFile ; $jsonFile" -InformationAction Continue
if ($PassThru) { $script:Findings }
