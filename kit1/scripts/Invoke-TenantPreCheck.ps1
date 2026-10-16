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
        [Parameter()][string]$ExtraHtml = ''
    )
    $enc = { param($x) [System.Net.WebUtility]::HtmlEncode([string]$x) }
    $label = @{ red = 'Critical'; yellow = 'Warning'; green = 'Passed'; grey = 'Info' }
    $count = @{ red = 0; yellow = 0; green = 0; grey = 0 }
    $statuses = New-Object -TypeName System.Collections.Generic.List[string]
    $rows = New-Object -TypeName System.Text.StringBuilder
    foreach ($f in @($Finding)) {
        $c = ConvertTo-ZkReportStatus -Value ([string]$f.Status)
        $count[$c]++
        $st = [string]$f.Status
        if (-not $statuses.Contains($st)) { $statuses.Add($st) }
        $ev = & $enc $f.Evidence
        $evCell = if ([string]::IsNullOrWhiteSpace([string]$f.Evidence)) { '<span class="muted">None</span>' } else { '<details><summary>Show evidence</summary><pre>' + $ev + '</pre></details><pre class="print-ev">' + $ev + '</pre>' }
        [void]$rows.Append('<tr data-sev="' + $c + '" data-st="' + (& $enc $st) + '"><td><span class="st st-' + $c + '" data-status="' + $c + '">' + $label[$c] + '</span></td><td>' + (& $enc $st) + '</td><td>' + (& $enc $f.Scope) + '</td><td>' + (& $enc $f.Check) + '</td><td>' + (& $enc $f.Finding) + '</td><td>' + $evCell + '</td><td>' + $f.NextHtml + '</td></tr>' + "`n")
    }
    if (@($Finding).Count -eq 0) { [void]$rows.Append('<tr><td colspan="7" class="muted">No checks produced output.</td></tr>') }
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
    [void]$sb.Append('<header class="top"><div><div class="brand">ZakitPro Deployment Doctor</div><h1>' + (& $enc $Title) + '</h1><div class="meta">' + (& $enc $Subtitle) + '</div></div>')
    [void]$sb.Append('<button type="button" id="zk-theme" class="tg hidden-js" aria-label="Toggle dark or light theme">Toggle theme</button></header>')
    [void]$sb.Append('<div class="banner"><b>Read-only, local report.</b> Not tested against a live tenant. Test in non-production first. This file makes no network requests.</div>')
    [void]$sb.Append('<section class="grid" aria-label="Summary"><div class="card scorecard" title="' + (& $enc $legend) + '"><div class="score"><div class="ring ' + $scoreClass + '" aria-label="Health score ' + $score + ' out of 100" data-capped="' + $(if ($capped) { 'true' } else { 'false' }) + '">' + $score + '</div><div><div class="k">Health score</div>' + $scoreNote + '</div></div><div class="legend" id="zk-legend">' + (& $enc $legend) + '</div></div>')
    foreach ($k in 'red', 'yellow', 'green', 'grey') { [void]$sb.Append('<div class="card ' + $k + '"><div class="k">' + $label[$k] + '</div><div class="v">' + $count[$k] + '</div></div>') }
    [void]$sb.Append('</section><h2>Findings</h2>')
    [void]$sb.Append('<div id="zk-filters" class="filters hidden-js" role="search"><label>Search<input id="zk-q" type="search" placeholder="Filter by any text"></label>')
    [void]$sb.Append('<label>Severity<select id="zk-sev"><option value="">All</option><option value="red">Critical</option><option value="yellow">Warning</option><option value="green">Passed</option><option value="grey">Info</option></select></label>')
    [void]$sb.Append('<label>Status<select id="zk-st"><option value="">All</option>' + $stOptions + '</select></label><span id="zk-count" class="muted" aria-live="polite"></span></div>')
    [void]$sb.Append('<div class="tablewrap"><table id="zk-findings"><thead><tr><th>Severity</th><th>Status</th><th>Scope</th><th>Check</th><th>Finding</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>')
    [void]$sb.Append($rows.ToString())
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append($ExtraHtml)
    [void]$sb.Append('<footer>Health score = round(100 x (Passed + 0.5 x Warning) / (Passed + Warning + Critical)); Info and not-checked rows are excluded, and the score is 100 when nothing was scored. If any Critical finding exists, the score is capped at 49 and shown in red. It summarises this run only and is not a security rating. Generated locally by a read-only script; no data leaves this file.</footer>')
    [void]$sb.Append('</div><script>' + $js + '</script></body></html>')
    $sb.ToString()
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
    $dash = foreach ($f in $script:Findings) {
        $urls = @(); $why = @()
        foreach ($cid in @($f.KnownCauseIds)) {
            $c = $knownCauses | Where-Object { $_.id -eq $cid } | Select-Object -First 1
            if ($c) { $urls += @($c.source_urls); $why += ('{0}: {1} Fix: {2}' -f $cid, $c.cause, $c.fix) }
        }
        $ev = [string]$f.Detail
        if ($why.Count -gt 0) { $ev += "`n`n" + ($why -join "`n") }
        [pscustomobject]@{ Status = $f.Result; Scope = $f.Module; Check = ('{0} {1}' -f $f.Id, $f.Check); Finding = $f.Check; Evidence = $ev; NextHtml = (Get-ZkNextStepLink -Url $urls -Code (@($f.KnownCauseIds) -join ', ')) }
    }
    $html = ConvertTo-ZkDashboardHtml -Title 'Tenant pre-check' -Subtitle ('Kit 1 | run {0} | tenant {1} | read-only Graph (GET plus one documented read action)' -f $report.RunAt, $context.TenantId) -Finding @($dash)
    Set-Content -LiteralPath $htmlFile -Value $html -Encoding UTF8
}
else { $htmlFile = '(skipped: -NoHtml)' }
Write-Information -MessageData "Reports: $htmlFile ; $jsonFile" -InformationAction Continue
if ($PassThru) { $script:Findings }
