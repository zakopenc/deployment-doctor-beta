#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Unit tests for Invoke-TenantPreCheck.ps1. Graph is mocked; no tenant access.
BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $script:Root -ChildPath 'Invoke-TenantPreCheck.ps1')
    $script:Db = Get-Content -LiteralPath (Join-Path -Path $script:Root -ChildPath 'known-causes.json') -Raw | ConvertFrom-Json
    function New-TestApp {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only; changes no system state.')]
    [CmdletBinding()]

        param([string]$Id, [string]$Name, [string]$Install = 'setup.exe /S', [string]$Uninstall = 'uninstall.exe /S', [object[]]$Rules = @(), [object[]]$Codes = @(), [string]$RunAs = 'system')
        [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.win32LobApp'; id = $Id; displayName = $Name
            installCommandLine = $Install; uninstallCommandLine = $Uninstall; rules = $Rules; returnCodes = $Codes
            installExperience = [pscustomobject]@{ runAsAccount = $RunAs; maxRunTimeInMinutes = 60 }; size = 1000
        }
    }
}

Describe 'Test-ZkWin32AppDefinition' {
    It 'flags 32-bit PowerShell (T01) but not Sysnative' {
        $bad = New-TestApp -Id 'a' -Name 'A' -Install 'powershell.exe -ExecutionPolicy Bypass -File install.ps1'
        $good = New-TestApp -Id 'b' -Name 'B' -Install '%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -File install.ps1'
        @((Test-ZkWin32AppDefinition -App $bad) | ForEach-Object { $_.CheckId }) | Should -Contain 'T01'
        @((Test-ZkWin32AppDefinition -App $good) | ForEach-Object { $_.CheckId }) | Should -Not -Contain 'T01'
    }
    It 'flags env vars in uninstall (T02) and ServiceUI (T03)' {
        $app = New-TestApp -Id 'a' -Name 'A' -Install 'ServiceUI.exe -process:explorer.exe setup.exe' -Uninstall '"%ProgramFiles%\App\uninst.exe" /S'
        $ids = @((Test-ZkWin32AppDefinition -App $app) | ForEach-Object { $_.CheckId })
        $ids | Should -Contain 'T02'; $ids | Should -Contain 'T03'
    }
    It 'flags STDERR in detection scripts (T04)' {
        $script = 'if (Test-Path C:\x) { Write-Output "ok"; exit 0 } else { Write-Error "missing"; exit 1 }'
        $rule = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.win32LobAppPowerShellScriptRule'; ruleType = 'detection'; scriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script)) }
        @(Test-ZkWin32AppDefinition -App (New-TestApp -Id 'a' -Name 'A' -Rules @($rule)) | ForEach-Object { $_.CheckId }) | Should -Contain 'T04'
    }
    It 'flags 1618 not mapped to retry (T09) and hard reboot (T09b)' {
        $codes = @([pscustomobject]@{ returnCode = 0; type = 'success' }, [pscustomobject]@{ returnCode = 1641; type = 'hardReboot' })
        $ids = @(Test-ZkWin32AppDefinition -App (New-TestApp -Id 'a' -Name 'A' -Codes $codes) | ForEach-Object { $_.CheckId })
        $ids | Should -Contain 'T09'; $ids | Should -Contain 'T09b'
    }
    It 'flags hard-coded WOW6432Node (T06)' {
        $rule = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.win32LobAppRegistryRule'; ruleType = 'detection'; keyPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Contoso'; check32BitOn64System = $false }
        @(Test-ZkWin32AppDefinition -App (New-TestApp -Id 'a' -Name 'A' -Rules @($rule)) | ForEach-Object { $_.CheckId }) | Should -Contain 'T06'
    }
    It 'returns no findings for a clean app' {
        $codes = @([pscustomobject]@{ returnCode = 1618; type = 'retry' })
        @(Test-ZkWin32AppDefinition -App (New-TestApp -Id 'a' -Name 'A' -Codes $codes)).Count | Should -Be 0
    }
}

Describe 'Relationship checks' {
    It 'flags dependency on a superseded app (T13) and untargeted superseding app (T12)' {
        $rel = @{
            'A' = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.mobileAppDependency'; targetId = 'B'; targetType = 'child'; dependencyType = 'autoInstall' })
            'C' = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.mobileAppSupersedence'; targetId = 'B'; targetType = 'child'; supersedenceType = 'replace' })
        }
        $g = Get-ZkRelationshipGraph -Relationship $rel
        $ids = @((Test-ZkRelationshipGraph -Graph $g -AssignedAppIds @('A') -AppNames @{ A = 'App A'; B = 'App B'; C = 'App C' }) | ForEach-Object { $_.CheckId })
        $ids | Should -Contain 'T13'; $ids | Should -Contain 'T12'; $ids | Should -Contain 'T17'
    }
    It 'ignores parent-direction edges' {
        $rel = @{ 'B' = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.mobileAppDependency'; targetId = 'A'; targetType = 'parent' }) }
        (Get-ZkRelationshipGraph -Relationship $rel).Dependencies.Count | Should -Be 0
    }
}

Describe 'Invoke-ZkTenantPreCheck with mocked Graph' {
    BeforeAll {
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Method -ne 'GET') { throw 'non-GET call' }
            switch -Regex ($Uri) {
                'mobileApps\?\$filter' { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'app1'; displayName = 'Contoso Viewer' }) } }
                'mobileApps/app1/assignments' { return [pscustomobject]@{ value = @([pscustomobject]@{ intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } }) } }
                'mobileApps/app1/relationships' { return [pscustomobject]@{ value = @() } }
                'mobileApps/app1/installSummary' { return [pscustomobject]@{ installedDeviceCount = 5; failedDeviceCount = 2; pendingInstallDeviceCount = 0; notInstalledDeviceCount = 0; notApplicableDeviceCount = 1 } }
                'mobileApps/app1$' { return (New-TestApp -Id 'app1' -Name 'Contoso Viewer' -Install 'powershell.exe -File i.ps1') }
                'groups/g1' { return [pscustomobject]@{ displayName = 'SG-Contoso' } }
                default { throw "unexpected $Uri" }
            }
        }
    }
    It 'builds a report with findings and resolved group names' {
        $r = Invoke-ZkTenantPreCheck
        @($r.Apps).Count | Should -Be 1
        $r.Apps[0].Assignments | Should -Match 'SG-Contoso'
        @($r.Findings.CheckId) | Should -Contain 'T01'
        @($r.Findings.CheckId) | Should -Contain 'T16'
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Method -ne 'GET' } -Times 0
    }
    It 'exports HTML with sources' {
        $f = Export-ZkTenantReport -Report (Invoke-ZkTenantPreCheck) -OutputPath $TestDrive -KnownCause $script:Db
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Match 'learn.microsoft.com'
    }
}

Describe 'Tenant pre-check: one bad app object does not stop the scan' {
    It 'logs a per-app Warn finding, checks the other apps and still writes a report' {
        Mock Invoke-MgGraphRequest {
            param($Uri)
            switch -Regex ($Uri) {
                'mobileApps\?\$filter' { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'bad1'; displayName = 'Broken App' }, [pscustomobject]@{ id = 'app2'; displayName = 'Fabrikam Agent' }) } }
                'mobileApps/bad1$' { return [pscustomobject]@{ id = 'bad1'; displayName = 'Broken App' } }
                'mobileApps/app2$' { return (New-TestApp -Id 'app2' -Name 'Fabrikam Agent') }
                default { return [pscustomobject]@{ value = @() } }
            }
        }
        Mock Test-ZkWin32AppDefinition -ParameterFilter { $App.id -eq 'bad1' } -MockWith { throw "The property 'rules' cannot be found on this object." }
        $r = Invoke-ZkTenantPreCheck -SkipInstallSummary -WarningAction SilentlyContinue
        @($r.Apps.Id) | Should -Be @('app2')
        $bad = @($r.Findings | Where-Object { $_.CheckId -eq 'T00' })
        $bad.Count | Should -Be 1
        $bad[0].AppId | Should -Be 'bad1'
        $bad[0].Severity | Should -Be 'Medium'
        @($r.Errors) -join ' ' | Should -Match 'Broken App \(bad1\) could not be evaluated'
        $f = Export-ZkTenantReport -Report $r -OutputPath $TestDrive -KnownCause $script:Db
        Test-Path -LiteralPath $f.Html | Should -BeTrue
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Match 'Warn \(Medium\)'
    }
}

Describe 'Tenant pre-check edge cases (mocked Graph)' {
    It 'warns and still exports a report when no Win32 apps exist' {
        Mock Invoke-MgGraphRequest { return [pscustomobject]@{ value = @() } }
        $r = Invoke-ZkTenantPreCheck -AppNameFilter 'Nope' -WarningVariable w -WarningAction SilentlyContinue
        @($r.Apps).Count | Should -Be 0
        ($w -join ' ') | Should -Match 'No Win32 apps found'
        $f = Export-ZkTenantReport -Report $r -OutputPath (Join-Path $TestDrive 'empty\out') -KnownCause $script:Db
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Match 'No findings'
    }
    It 'follows @odata.nextLink paging' {
        Mock Invoke-MgGraphRequest {
            param($Uri)
            if ($Uri -match 'page2') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = '2' }) } }
            return [pscustomobject]@{ value = @([pscustomobject]@{ id = '1' }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/x?page2' }
        }
        @(Invoke-ZkGraphGet -Uri '/x').Count | Should -Be 2
    }
    It 'adds a scope hint to a 403 error' {
        Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: Forbidden (403)' }
        { Invoke-ZkGraphGet -Uri '/x' } | Should -Throw '*read scope*'
    }
    It 'skips an app that cannot be read and records the error' {
        Mock Invoke-MgGraphRequest {
            param($Uri)
            switch -Regex ($Uri) {
                'mobileApps\?\$filter' { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'gone'; displayName = 'Gone App' }) } }
                default { throw 'NotFound (404)' }
            }
        }
        $r = Invoke-ZkTenantPreCheck -WarningAction SilentlyContinue
        @($r.Apps).Count | Should -Be 0
        @($r.Errors).Count | Should -Be 1
        $r.Errors[0] | Should -Match 'Gone App'
    }
    It 'does not duplicate identical findings' {
        Mock Invoke-MgGraphRequest {
            param($Uri)
            $au = [pscustomobject]@{ autoUpdateSettings = [pscustomobject]@{ autoUpdateSupersededAppsState = 'enabled' } }
            switch -Regex ($Uri) {
                'mobileApps\?\$filter' { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'app1'; displayName = 'A' }) } }
                'assignments' { return [pscustomobject]@{ value = @(
                            [pscustomobject]@{ intent = 'available'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }; settings = $au },
                            [pscustomobject]@{ intent = 'available'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }; settings = $au }) } }
                'relationships' { return [pscustomobject]@{ value = @() } }
                'mobileApps/app1$' { return (New-TestApp -Id 'app1' -Name 'A') }
                default { throw "unexpected $Uri" }
            }
        }
        $r = Invoke-ZkTenantPreCheck -SkipInstallSummary
        @($r.Findings | Where-Object { $_.CheckId -eq 'T14' }).Count | Should -Be 1
    }
    It 'writes a JSON report the device diagnostic can read back' {
        Mock Invoke-MgGraphRequest { return [pscustomobject]@{ value = @() } }
        $f = Export-ZkTenantReport -Report (Invoke-ZkTenantPreCheck -WarningAction SilentlyContinue) -OutputPath $TestDrive -KnownCause $script:Db
        $j = Get-Content -LiteralPath $f.Json -Raw -Encoding UTF8 | ConvertFrom-Json
        $j.PSObject.Properties.Name | Should -Contain 'Apps'
        $j.PSObject.Properties.Name | Should -Contain 'Findings'
        $j.KitVersion | Should -Be '1.2.2'
    }
}

Describe 'Tenant script entry point' {
    It 'is quiet on the pipeline by default and returns one object with -PassThru' {
        Mock Invoke-MgGraphRequest { return [pscustomobject]@{ value = @() } }
        $script = Join-Path $script:Root 'Invoke-TenantPreCheck.ps1'
        @(& $script -SkipConnect -OutputPath (Join-Path $TestDrive 'q') -WarningAction SilentlyContinue 6>$null).Count | Should -Be 0
        @(& $script -SkipConnect -OutputPath (Join-Path $TestDrive 'p') -PassThru -WarningAction SilentlyContinue 6>$null).Count | Should -Be 1
    }
}

Describe 'Read-only guarantees' {
    It 'never calls Graph with a write method' {
        $src = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TenantPreCheck.ps1') -Raw
        $src | Should -Not -Match '(?i)-Method\s+(POST|PATCH|PUT|DELETE)'
        $src | Should -Not -Match "(?i)'[A-Za-z.]+ReadWrite[A-Za-z.]*'"
    }
    It 'guard rejects non-GET' {
        { Invoke-ZkGraphGet -Uri '/x' -Method 'POST' } | Should -Throw
    }
}
