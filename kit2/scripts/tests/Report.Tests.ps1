#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Report generation tests for both Kit 2 scripts. Fake, contoso-style data only; no tenant or device access.
BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $script:Root -ChildPath 'Invoke-TenantPreCheck.ps1')
    $script:TenantExport = ${function:Export-ZkTenantReport}
    . (Join-Path -Path $script:Root -ChildPath 'Invoke-DeviceDiagnostic.ps1')
    $script:Db = Get-Content -LiteralPath (Join-Path -Path $script:Root -ChildPath 'known-causes.json') -Raw | ConvertFrom-Json
    $script:Evil = '<script>alert("x")</script><img src="https://evil.example/x.png">'
    function Test-ZkOnlyNextLinkIsExternal {
        param([string]$Html)
        # Any element that could load or point to a remote resource must not exist, except the what-next anchors.
        $Html | Should -Not -Match '(?i)<script'
        $Html | Should -Not -Match '(?i)<link\b'
        $Html | Should -Not -Match '(?i)<img\b'
        $Html | Should -Not -Match '(?i)@import|url\('
        foreach ($m in [regex]::Matches($Html, '(?i)<[^>]*\b(?:src|href)\s*=\s*"(https?:[^"]*)"[^>]*>')) {
            $m.Value | Should -Match '^<a class="next" href="https://learn\.microsoft\.com/' -Because $m.Value
        }
    }
    $script:TenantReport = [pscustomobject]@{
        GeneratedLocal = '2026-01-01 09:00:00 +00:00'; KitVersion = '1.2.0'; Errors = @()
        Apps = @(
            [pscustomobject]@{ DisplayName = 'Contoso Viewer'; Id = 'app-contoso-1'; RunAs = 'system'; Assignments = 'required (group:SG-Contoso)'; InstallSummary = 'installed 5, failed 2'; DetectionRuleCount = 1 },
            [pscustomobject]@{ DisplayName = 'Fabrikam Tool'; Id = 'app-fabrikam-2'; RunAs = 'system'; Assignments = 'required (group:SG-Fabrikam)'; InstallSummary = 'installed 9, failed 0'; DetectionRuleCount = 1 }
        )
        Findings = @(
            [pscustomobject]@{ Severity = 'High'; CheckId = 'T04'; AppId = 'app-contoso-1'; AppName = 'Contoso Viewer'; Message = 'Detection script can write to STDERR.'; Evidence = $script:Evil },
            [pscustomobject]@{ Severity = 'Medium'; CheckId = 'T01'; AppId = 'app-contoso-1'; AppName = 'Contoso Viewer'; Message = '32-bit PowerShell.'; Evidence = 'powershell.exe -File i.ps1' },
            [pscustomobject]@{ Severity = 'Info'; CheckId = 'T10'; AppId = 'app-fabrikam-2'; AppName = 'Fabrikam Tool'; Message = 'Dependency graph size 1.'; Evidence = '1' }
        )
    }
    $script:DeviceReport = [pscustomobject]@{
        Computer = 'CONTOSO-PC01'; GeneratedLocal = '2026-01-01 09:00:00'; KitVersion = '1.2.0'; KnownCausesDb = 'beta'; Ime = $null; LogFiles = @('AppWorkload.log'); RecordCount = 3
        DeviceVerdicts = @()
        Apps = @(
            [pscustomobject]@{ Name = 'Contoso Viewer'; AppId = '00000000-0000-0000-0000-00000000000a'; Signals = @('exit:0', 'detected:false:post'); Unexplained = @(); Context = @(); TenantFindings = @(); DetectionRules = @(); RegistryState = $null
                Verdicts = @([pscustomobject]@{ Confidence = 'High'; Title = 'Detected not installed'; CauseId = 'KC-001'; Matched = $script:Evil; Sources = @([pscustomobject]@{ url = 'https://learn.microsoft.com/en-us/intune/x'; title = 'Learn' }, [pscustomobject]@{ url = 'https://blog.example/y'; title = 'Blog' }) })
                Timeline = @([pscustomobject]@{ Time = '09:00'; Source = 'AppWorkload.log'; Signal = 'exit:0'; Inferred = $false; Type = 1; Message = $script:Evil }) },
            [pscustomobject]@{ Name = 'Fabrikam Tool'; AppId = '00000000-0000-0000-0000-00000000000b'; Signals = @('final:detected'); Verdicts = @(); Unexplained = @(); Context = @(); TenantFindings = @(); DetectionRules = @(); RegistryState = $null; Timeline = @() }
        )
    }
}

Describe 'Kit 2 tenant HTML report' {
    BeforeAll { $script:F = & $script:TenantExport -Report $script:TenantReport -OutputPath (Join-Path $TestDrive 't') -KnownCause $script:Db; $script:H = Get-Content -LiteralPath $script:F.Html -Raw }
    It 'creates one self-contained HTML file with inline CSS and print styles' {
        Test-Path -LiteralPath $script:F.Html | Should -BeTrue
        $script:H | Should -Match '<style>'
        $script:H | Should -Match '@media print'
    }
    It 'has no remote script/link/img and only what-next anchors point outside' { Test-ZkOnlyNextLinkIsExternal -Html $script:H }
    It 'renders red, yellow and green statuses' {
        foreach ($s in 'red', 'yellow', 'green') { $script:H | Should -Match "data-status=`"$s`"" }
    }
    It 'has a what-to-do-next entry per finding' { ([regex]::Matches($script:H, 'class="next"')).Count | Should -BeGreaterOrEqual 3 }
    It 'HTML-escapes evidence' {
        $script:H | Should -Match '&lt;script&gt;alert\(&quot;x&quot;\)&lt;/script&gt;'
        $script:H | Should -Not -Match 'evil\.example/x\.png">'
    }
    It '-NoHtml writes JSON only' {
        $f = & $script:TenantExport -Report $script:TenantReport -OutputPath (Join-Path $TestDrive 'tn') -KnownCause $script:Db -NoHtml
        $f.Html | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'tn') -Filter '*.html').Count | Should -Be 0
        Test-Path -LiteralPath $f.Json | Should -BeTrue
    }
}

Describe 'Kit 2 device HTML report' {
    BeforeAll { $script:F = Export-ZkDeviceReport -Report $script:DeviceReport -OutputPath (Join-Path $TestDrive 'd'); $script:H = Get-Content -LiteralPath $script:F.Html -Raw }
    It 'creates the HTML file with print styles' { Test-Path -LiteralPath $script:F.Html | Should -BeTrue; $script:H | Should -Match '@media print' }
    It 'has no remote script/link/img and drops non-Learn source links' {
        Test-ZkOnlyNextLinkIsExternal -Html $script:H
        $script:H | Should -Not -Match 'blog\.example'
        $script:H | Should -Match 'class="next" href="https://learn\.microsoft\.com/en-us/intune/x"'
    }
    It 'renders red and green statuses' { $script:H | Should -Match 'data-status="red"'; $script:H | Should -Match 'data-status="green"' }
    It 'HTML-escapes evidence and log messages' { $script:H | Should -Match '&lt;script&gt;'; $script:H | Should -Not -Match '<script>' }
    It '-NoHtml writes JSON only' {
        $f = Export-ZkDeviceReport -Report $script:DeviceReport -OutputPath (Join-Path $TestDrive 'dn') -NoHtml
        $f.Html | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'dn') -Filter '*.html').Count | Should -Be 0
    }
}
