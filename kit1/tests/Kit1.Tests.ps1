#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# ZakitPro Kit 1 - Pester tests. All external calls are mocked; nothing touches a tenant or device.
BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    $script:Tenant = Join-Path -Path $Root -ChildPath 'scripts/Invoke-TenantPreCheck.ps1'
    $script:Device = Join-Path -Path $Root -ChildPath 'scripts/Invoke-DeviceDiagnostic.ps1'
    $script:Db = Join-Path -Path $Root -ChildPath 'data/known-causes.json'
}

Describe 'Static safety checks' {
    It 'scripts parse without errors' {
        foreach ($f in $Tenant, $Device) {
            $errs = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
            $errs.Count | Should -Be 0
        }
    }
    It 'scripts contain no state-changing registry, service or device cmdlets' {
        $bad = 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Remove-Item\b|Set-Service|Stop-Service|Restart-Computer|Start-ScheduledTask|Unregister-|New-MgServicePrincipal|Remove-Mg|Update-Mg|New-MgGroup'
        foreach ($f in $Tenant, $Device) {
            (Get-Content -LiteralPath $f -Raw) | Should -Not -Match $bad
        }
    }
    It 'tenant script only uses GET, plus the documented retrieve read action' {
        $text = Get-Content -LiteralPath $Tenant -Raw
        $methods = [regex]::Matches($text, '-Method\s+(\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $methods | Should -Be @('GET', 'POST')
        ([regex]::Matches($text, '-Method POST[^\r\n]*')).Value | ForEach-Object { $_ | Should -Match 'retrieveEnrollmentTimeDeviceMembershipTarget' }
    }
    It 'every version string in a script matches its .NOTES version' {
        foreach ($f in $Tenant, $Device) {
            $t = Get-Content -LiteralPath $f -Raw
            $v = [regex]::Match($t, 'Version:\s+(\d+\.\d+\.\d+)').Groups[1].Value
            $all = [regex]::Matches($t, '(?<![\d.])1\.\d+\.\d+(?!\.?\d)') | ForEach-Object Value | Where-Object { $_ -notmatch '^1\.(101|103)\.' } | Sort-Object -Unique
            $all | Should -Be $v -Because $f
        }
    }
    It 'tenant script requests only Read scopes' {
        $text = Get-Content -LiteralPath $Tenant -Raw
        $text | Should -Not -Match "'[A-Za-z.]+ReadWrite[A-Za-z.]*'"
    }
    It 'has zero PSScriptAnalyzer errors or warnings (PSGallery settings)' {
        $r = Invoke-ScriptAnalyzer -Path (Join-Path -Path $Root -ChildPath 'scripts') -Recurse -Settings PSGallery
        @($r | Where-Object { $_.Severity -in 'Error', 'Warning' }).Count | Should -Be 0
    }
}

Describe 'known-causes.json' {
    BeforeAll { $script:Causes = (Get-Content -LiteralPath $Db -Raw | ConvertFrom-Json).causes }
    It 'every entry has the required fields' {
        foreach ($c in $Causes) {
            foreach ($p in 'id', 'symptom', 'signals', 'cause', 'fix', 'source_urls', 'date_checked', 'status') {
                $c.PSObject.Properties.Name | Should -Contain $p
            }
            @($c.source_urls).Count | Should -BeGreaterThan 0
            $c.status | Should -BeIn @('documented', 'field-reported', 'resolved')
            $c.detection | Should -BeIn @('script', 'reminder', 'manual')
            $c.phase | Should -BeIn @('Enrollment', 'DevicePrep', 'ESP-DevicePreparation', 'ESP-DeviceSetup', 'ESP-AccountSetup', 'Report')
            $c.rollback | Should -Not -BeNullOrEmpty
        }
    }
    It 'every signal the scripts emit has a known cause' {
        $text = (Get-Content -LiteralPath $Tenant -Raw) + (Get-Content -LiteralPath $Device -Raw)
        $emitted = [regex]::Matches($text, "'([TD]_[A-Z0-9_]{4,})'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $known = $Causes | ForEach-Object { $_.signals } | Sort-Object -Unique
        foreach ($e in $emitted) { $known | Should -Contain $e -Because "$e needs a KC entry" }
    }
    It 'every signal in the database is emitted by a script (no placeholders)' {
        $text = (Get-Content -LiteralPath $Tenant -Raw) + (Get-Content -LiteralPath $Device -Raw)
        $emitted = [regex]::Matches($text, "'([TD]_[A-Z0-9_]{4,})'") | ForEach-Object { $_.Groups[1].Value }
        foreach ($sg in ($Causes | ForEach-Object { $_.signals })) { $emitted | Should -Contain $sg }
    }
    It 'Documented entries cite Microsoft Learn; reminder-only entries are manual' {
        foreach ($c in ($Causes | Where-Object status -eq 'documented')) { ($c.source_urls -match 'learn\.microsoft\.com').Count | Should -BeGreaterThan 0 -Because $c.id }
        ($Causes | Where-Object id -eq 'KC-022').status | Should -Be 'field-reported'
    }
    It 'detection types are consistent and the README counts match the JSON' {
        foreach ($c in ($Causes | Where-Object detection -eq 'manual')) { @($c.signals).Count | Should -Be 0 -Because "$($c.id) is manual" }
        foreach ($c in ($Causes | Where-Object detection -eq 'reminder')) { foreach ($sg in $c.signals) { $sg | Should -Match '^T_MANUAL_' } }
        ($Causes | Where-Object { $_.id -in 'KC-007', 'KC-008' }).detection | Sort-Object -Unique | Should -Be 'reminder'
        $readme = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..\..\README.md') -Raw
        $m = [regex]::Match($readme, '(\d+) known causes \((\d+) script-detected, (\d+) reminder, (\d+) manual\)')
        $m.Success | Should -BeTrue
        [int]$m.Groups[1].Value | Should -Be @($Causes).Count
        [int]$m.Groups[2].Value | Should -Be @($Causes | Where-Object detection -eq 'script').Count
        [int]$m.Groups[3].Value | Should -Be @($Causes | Where-Object detection -eq 'reminder').Count
        [int]$m.Groups[4].Value | Should -Be @($Causes | Where-Object detection -eq 'manual').Count
    }
    It 'SHA256SUMS.txt matches the shipped files' {
        $root = Join-Path -Path $PSScriptRoot -ChildPath '../..'
        $sums = Join-Path -Path $root -ChildPath 'SHA256SUMS.txt'
        Test-Path -LiteralPath $sums | Should -BeTrue
        foreach ($line in (Get-Content -LiteralPath $sums | Where-Object { $_ })) {
            $hash, $file = $line -split '\s+\*?', 2
            (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path -Path $root -ChildPath $file)).Hash | Should -Be $hash.ToUpper() -Because $file
        }
    }
    It 'ids are unique' {
        ($Causes.id | Sort-Object -Unique).Count | Should -Be $Causes.Count
    }
}

Describe 'Invoke-TenantPreCheck (mocked Graph)' {
    BeforeAll {
        Import-Module Microsoft.Graph.Authentication
        $script:Out = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ('kit1test-' + [guid]::NewGuid())
    }
    It 'reports a missing service principal and writes HTML + JSON without any write call' {
        Mock -CommandName Connect-MgGraph -MockWith { }
        Mock -CommandName Get-MgContext -MockWith { [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000000'; Scopes = @('Application.Read.All') } }
        Mock -CommandName Invoke-MgGraphRequest -MockWith { [PSCustomObject]@{ value = @() } }
        $result = & $Tenant -OutputPath $Out -KnownCausesPath $Db -SkipConnect -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        ($result | Where-Object { $_.Signals -contains 'T_SP_MISSING' }).KnownCauseIds | Should -Contain 'KC-011'
        @(Get-ChildItem -LiteralPath $Out -Filter 'TenantPreCheck-*.html').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $Out -Filter 'TenantPreCheck-*.json').Count | Should -Be 1
        Should -Invoke -CommandName Invoke-MgGraphRequest -ParameterFilter { $Method -notin 'GET', 'POST' } -Times 0
        Should -Invoke -CommandName Connect-MgGraph -Times 0
    }
    It 'flags a dynamic, role-assignable group not owned by the SP' {
        Mock -CommandName Get-MgContext -MockWith { [PSCustomObject]@{ TenantId = 't'; Scopes = @() } }
        Mock -CommandName Invoke-MgGraphRequest -MockWith {
            switch -Regex ($Uri) {
                'servicePrincipals' { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'sp1'; appId = 'f1346770-5b25-470b-88bd-d5744ab7952c'; displayName = 'Intune Autopilot ConfidentialClient' }) } }
                'configurationPolicies\?' { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'p1'; name = 'DP'; templateReference = [PSCustomObject]@{ templateFamily = 'enrollmentConfiguration' } }) } }
                '/settings$' { [PSCustomObject]@{ value = @() } }
                'retrieveEnrollmentTimeDeviceMembershipTarget$' { [PSCustomObject]@{ value = [PSCustomObject]@{ enrollmentTimeDeviceMembershipTargetValidationStatuses = @([PSCustomObject]@{ targetId = 'g1'; validationSucceeded = $true; targetValidationErrorCode = 'none' }) } } }
                '/groups/g1\?' { [PSCustomObject]@{ id = 'g1'; displayName = 'DP-Devices'; groupTypes = @('DynamicMembership'); isAssignableToRole = $true } }
                '/groups/g1/owners' { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'u1'; displayName = 'Admin'; appId = $null }) } }
                default { [PSCustomObject]@{ value = @() } }
            }
        }
        $result = & $Tenant -OutputPath $Out -KnownCausesPath $Db -SkipConnect -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        $sig = @($result | ForEach-Object { $_.Signals })
        $sig | Should -Contain 'T_DPGROUP_DYNAMIC'
        $sig | Should -Contain 'T_DPGROUP_ROLEASSIGNABLE'
        $sig | Should -Contain 'T_DPGROUP_SP_NOT_OWNER'
        $sig | Should -Contain 'T_SP_NAME_DIFFERENT'
    }
    It 'flags a restriction that blocks the Windows (MDM) platform (KC-045)' {
        Mock -CommandName Get-MgContext -MockWith { [PSCustomObject]@{ TenantId = 't'; Scopes = @() } }
        Mock -CommandName Invoke-MgGraphRequest -MockWith {
            switch -Regex ($Uri) {
                'deviceEnrollmentConfigurations' { [PSCustomObject]@{ value = @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'; displayName = 'Block Windows'; platformType = 'windows'; platformRestriction = [PSCustomObject]@{ platformBlocked = $true; personalDeviceEnrollmentBlocked = $false } }) } }
                default { [PSCustomObject]@{ value = @() } }
            }
        }
        $result = & $Tenant -OutputPath $Out -KnownCausesPath $Db -SkipConnect -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        $f = $result | Where-Object { $_.Signals -contains 'T_WINDOWS_MDM_BLOCKED' }
        $f.Result | Should -Be 'Fail'
        $f.KnownCauseIds | Should -Contain 'KC-045'
    }
    It 'rejects an invalid TenantId' {
        { & $Tenant -TenantId 'bad id!' -SkipConnect } | Should -Throw
    }
    AfterAll { Remove-Item -LiteralPath $Out -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Invoke-DeviceDiagnostic (mocked device)' {
    BeforeAll {
        # Linux CI has no CIM/WinEvent cmdlets: define stubs so they can be mocked.
        if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) { function global:Get-CimInstance { param($ClassName, $ErrorAction) } }
        if (-not (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue)) { function global:Get-WinEvent { param($ListLog, $FilterHashtable, $MaxEvents, $ErrorAction) } }
        if (-not (Get-Command -Name Get-Service -ErrorAction SilentlyContinue)) { function global:Get-Service { param($Name, $ErrorAction) } }
        if (-not $env:ProgramData) { $env:ProgramData = [IO.Path]::GetTempPath() }
        $script:Out2 = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ('kit1dev-' + [guid]::NewGuid())
    }
    It 'flags Code Integrity 3033 for IME and missing IME, and matches KC-006' {
        Mock -CommandName Get-CimInstance -MockWith { [PSCustomObject]@{ Caption = 'Windows 11 Enterprise'; BuildNumber = '26100'; LastBootUpTime = (Get-Date) } }
        Mock -CommandName Get-Service -MockWith { $null }
        Mock -CommandName Get-WinEvent -ParameterFilter { $ListLog -like '*CodeIntegrity*' } -MockWith { [PSCustomObject]@{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; RecordCount = 1 } }
        Mock -CommandName Get-WinEvent -ParameterFilter { $ListLog -and $ListLog -notlike '*CodeIntegrity*' } -MockWith { }
        Mock -CommandName Get-WinEvent -ParameterFilter { $FilterHashtable } -MockWith {
            [PSCustomObject]@{ Id = 3033; TimeCreated = (Get-Date); Level = 2; LevelDisplayName = 'Error'; Message = 'Code Integrity determined that a process attempted to load C:\Windows\Installer\MSI1.tmp-\WixToolset.Dtf.WindowsInstaller.dll' }
        }
        $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        ($v | Where-Object Signal -eq 'D_CI3033').KnownCauseIds | Should -Contain 'KC-006'
        ($v | Where-Object Signal -eq 'D_IME_MISSING_CI3033').KnownCauseIds | Should -Contain 'KC-006'
        $rep = Get-ChildItem -LiteralPath $Out2 -Filter 'DeviceDiagnostic-*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        (Get-Content -LiteralPath $rep.FullName -Raw | ConvertFrom-Json).Timeline | Where-Object Source -eq 'CodeIntegrity 3033' | ForEach-Object { $_.Phase | Should -Not -Be 'DevicePreparation' }
        $v.Signal | Should -Not -Contain 'D_IME_MISSING'
        @(Get-ChildItem -LiteralPath $Out2 -Filter 'DeviceDiagnostic-*.json').Count | Should -Be 1
    }
    It 'IME missing with no 3033 evidence points to KC-021, never the App Control cause' {
        Mock -CommandName Get-CimInstance -MockWith { [PSCustomObject]@{ Caption = 'Windows 11'; BuildNumber = '26100'; LastBootUpTime = (Get-Date) } }
        Mock -CommandName Get-Service -MockWith { $null }
        Mock -CommandName Get-WinEvent -MockWith { }
        $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        $m = $v | Where-Object Signal -eq 'D_IME_MISSING'
        $m.KnownCauseIds | Should -Contain 'KC-021'
        @($v | Where-Object { $_.KnownCauseIds -contains 'KC-006' }).Count | Should -Be 0
    }
    Context 'registry-driven verdicts' {
        BeforeAll {
            function script:New-FakeKey {
                param([string]$Name, [string]$PSChildName, [hashtable]$Values)
                $o = [PSCustomObject]@{ Name = $Name; PSChildName = $PSChildName; Vals = $Values }
                $o | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Vals.Keys) }
                $o | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($n) $this.Vals[$n] }
                $o
            }
        }
        BeforeEach {
            Mock -CommandName Get-CimInstance -MockWith { [PSCustomObject]@{ Caption = 'Windows 11'; BuildNumber = '26100'; LastBootUpTime = (Get-Date) } }
            Mock -CommandName Get-Service -MockWith { [PSCustomObject]@{ Status = 'Running' } }
            Mock -CommandName Get-WinEvent -MockWith { }
        }
        It 'does not raise KC-024 on a normal ESP (APv1) device' {
            $esp = 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
            Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -like "$esp*" } -MockWith { $true }
            Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $esp } -MockWith {
                New-FakeKey -Name 'HKEY_LOCAL_MACHINE\x\Device\Setup\Apps\Tracking\Sidecar\Win32App_1' -PSChildName 'Win32App_1' -Values @{ InstallationState = 3 }
            }
            $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            @($v | Where-Object { $_.KnownCauseIds -contains 'KC-024' }).Count | Should -Be 0
            $v.Signal | Should -Not -Contain 'D_ESP_PRESENT_EXPECTED_DP'
        }
        It 'raises KC-024 when Device Prep was expected but ESP ran' {
            $esp = 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
            Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -like "$esp*" } -MockWith { $true }
            Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $esp } -MockWith { }
            $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -ExpectedMode DevicePrep -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            ($v | Where-Object Signal -eq 'D_ESP_PRESENT_EXPECTED_DP').KnownCauseIds | Should -Contain 'KC-024'
        }
        It 'turns a failed phase in Device Prep progress JSON into a Fail verdict (KC-041) with the item name' {
            $root = 'HKLM:\SOFTWARE\Microsoft\Provisioning'
            $json = '{"phases":[{"name":"DeviceSetup","status":"Completed"},{"name":"Apps","status":"Failed","items":[{"displayName":"Contoso VPN","state":"Error","errorCode":"0x80070001"}]}]}'
            Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -eq $root } -MockWith { $true }
            Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $root } -MockWith {
                New-FakeKey -Name 'HKEY_LOCAL_MACHINE\x\DevicePreparation\InitialProvisioning' -PSChildName 'InitialProvisioning' -Values @{ Progress = $json }
            }
            $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            $f = $v | Where-Object Signal -eq 'D_DP_PROGRESS_FAILURE'
            $f.Severity | Should -Be 'Fail'
            $f.KnownCauseIds | Should -Contain 'KC-041'
            $f.Finding | Should -Match 'Contoso VPN'
            $f.Finding | Should -Match '0x80070001'
            $v.Signal | Should -Contain 'D_DP_FOOTPRINT'
        }
        It 'raises no Device Prep failure for healthy progress JSON' {
            $root = 'HKLM:\SOFTWARE\Microsoft\Provisioning'
            # Test data only (not a real sample). Field names OrchestrationContext/PreviousProgress are the ones Patch My PC names.
            $json = '{"OrchestrationContext":"Win32apps","PreviousProgress":"Win32apps","phases":[{"name":"Apps","status":"Completed","errorCode":"0x00000000"}]}'
            Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -eq $root } -MockWith { $true }
            Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $root } -MockWith {
                New-FakeKey -Name 'HKEY_LOCAL_MACHINE\x\InitialProvisioning' -PSChildName 'InitialProvisioning' -Values @{ Progress = $json }
            }
            $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            $v.Signal | Should -Not -Contain 'D_DP_PROGRESS_FAILURE'
            $n = $v | Where-Object Signal -eq 'D_DP_NO_FAILURE_FOUND'
            $n.KnownCauseIds | Should -Contain 'KC-046'
            $n.Finding | Should -Match 'PreviousProgress=Win32apps'
            $rep = Get-ChildItem -LiteralPath $Out2 -Filter 'DeviceDiagnostic-*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
            $tl = (Get-Content -LiteralPath $rep.FullName -Raw | ConvertFrom-Json).Timeline
            @($tl | Where-Object Phase -eq 'DevicePrep').Count | Should -BeGreaterThan 0
            @($tl | Where-Object Phase -eq 'DevicePreparation').Count | Should -Be 0
        }
        It 'prints the fix line for each known cause on the console' {
            Mock -CommandName Get-Service -MockWith { $null }
            $info = & $Device -OutputPath $Out2 -KnownCausesPath $Db -WarningAction SilentlyContinue 6>&1 | Out-String
            $info | Should -Match 'Fix \(KC-021\):'
        }
        It 'writes nothing to the pipeline without -PassThru and never repeats a signal' {
            $out = & $Device -OutputPath $Out2 -KnownCausesPath $Db -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            $out | Should -BeNullOrEmpty
            $v = & $Device -OutputPath $Out2 -KnownCausesPath $Db -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            @($v.Signal | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
        }
    }
    It 'rejects MaxEvents out of range' {
        { & $Device -MaxEvents 1 } | Should -Throw
    }
    AfterAll { Remove-Item -LiteralPath $Out2 -Recurse -Force -ErrorAction SilentlyContinue }
}
