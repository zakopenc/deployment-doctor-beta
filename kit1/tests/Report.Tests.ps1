#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Report generation tests for both Kit 1 scripts. Graph and device calls are mocked with fake data.
BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    $script:Tenant = Join-Path -Path $Root -ChildPath 'scripts/Invoke-TenantPreCheck.ps1'
    $script:Device = Join-Path -Path $Root -ChildPath 'scripts/Invoke-DeviceDiagnostic.ps1'
    $script:Db = Join-Path -Path $Root -ChildPath 'data/known-causes.json'
    Import-Module Microsoft.Graph.Authentication
    function Test-ZkDashboard {
        param([string]$Html)
        # Filters and search exist, but are hidden until JS runs; with JS disabled the full table is visible.
        $Html | Should -Match 'id="zk-q"'
        $Html | Should -Match 'id="zk-sev"'
        $Html | Should -Match 'id="zk-st"'
        $Html | Should -Match 'id="zk-filters" class="filters hidden-js"'
        $Html | Should -Not -Match '<tr[^>]*\shidden'
        $Html | Should -Not -Match '(?i)<noscript'
        $Html | Should -Match 'Content-Security-Policy'
        $Html | Should -Match 'prefers-color-scheme:dark'
        $Html | Should -Match 'id="zk-theme"'
        $Html | Should -Match '@media print'
        $Html | Should -Match 'Health score = round'
        $Html | Should -Match 'white-space:nowrap;word-break:keep-all'
        $Html | Should -Match '#zk-findings td:nth-child\(2\)\{min-width:96px'
        $Html | Should -Match 'id="zk-legend">Weighting: Passed = 1, Warning = 0.5, Critical = 0'
        $Html.IndexOf('id="zk-legend"') | Should -BeLessThan $Html.IndexOf('<h2>Findings</h2>')
        $Html | Should -Match 'class="card scorecard" title="Weighting:'
        $Html | Should -Match '<details><summary>Show evidence</summary>'
        $Html | Should -Match 'class="print-ev"'
        $noJs = [regex]::Replace($Html, '(?s)<script>.*?</script>', '')
        ([regex]::Matches($noJs, '<tr data-sev=')).Count | Should -BeGreaterThan 0
        ([regex]::Matches($noJs, '<tr data-sev=')).Count | Should -Be ([regex]::Matches($Html, '<tr data-sev=')).Count
    }
    function Test-ZkOnlyNextLinkIsExternal {
        param([string]$Html)
        $Html | Should -Not -Match '(?i)<script[^>]*\bsrc'
        $Html | Should -Not -Match '(?i)<iframe|<object|<embed|fetch\(|XMLHttpRequest|navigator\.sendBeacon|new WebSocket'
        $Html | Should -Not -Match '(?i)<link\b'
        $Html | Should -Not -Match '(?i)<img\b'
        $Html | Should -Not -Match '(?i)@import|url\('
        foreach ($m in [regex]::Matches($Html, '(?i)<[^>]*\b(?:src|href)\s*=\s*"(https?:[^"]*)"[^>]*>')) {
            $m.Value | Should -Match '^<a class="next" href="https://learn\.microsoft\.com/' -Because $m.Value
        }
    }
    function Use-ZkFakeGraph {
        Mock -CommandName Get-MgContext -MockWith { [PSCustomObject]@{ TenantId = 'contoso.onmicrosoft.com'; Scopes = @() } }
        Mock -CommandName Invoke-MgGraphRequest -MockWith {
            switch -Regex ($Uri) {
                'servicePrincipals' { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'sp1'; appId = 'f1346770-5b25-470b-88bd-d5744ab7952c'; displayName = 'Intune Provisioning Client' }) } }
                'configurationPolicies\?' { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'p1'; name = 'DP <b>Contoso</b>'; templateReference = [PSCustomObject]@{ templateFamily = 'enrollmentConfiguration' } }) } }
                '/settings$' { [PSCustomObject]@{ value = @() } }
                'retrieveEnrollmentTimeDeviceMembershipTarget$' { [PSCustomObject]@{ value = [PSCustomObject]@{ enrollmentTimeDeviceMembershipTargetValidationStatuses = @([PSCustomObject]@{ targetId = 'g1'; validationSucceeded = $true; targetValidationErrorCode = 'none' }) } } }
                '/groups/g1\?' { [PSCustomObject]@{ id = 'g1'; displayName = '<script>alert(1)</script>'; groupTypes = @('DynamicMembership'); isAssignableToRole = $true } }
                '/groups/g1/owners' { [PSCustomObject]@{ value = @() } }
                default { [PSCustomObject]@{ value = @() } }
            }
        }
    }
}

Describe 'Kit 1 tenant HTML report' {
    BeforeEach { $script:Out = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString()) }
    It 'creates one self-contained HTML file with statuses, escaping and what-next links' {
        Use-ZkFakeGraph
        & $Tenant -OutputPath $Out -KnownCausesPath $Db -SkipConnect -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        $f = @(Get-ChildItem -LiteralPath $Out -Filter 'TenantPreCheck-*.html')
        $f.Count | Should -Be 1
        $h = Get-Content -LiteralPath $f[0].FullName -Raw
        $h | Should -Match '@media print'
        Test-ZkOnlyNextLinkIsExternal -Html $h
        Test-ZkDashboard -Html $h
        $h | Should -Match 'data-status="red"'
        $h | Should -Match 'data-status="green"'
        $h | Should -Match 'class="next"'
        $h | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        Should -Invoke -CommandName Invoke-MgGraphRequest -ParameterFilter { $Method -notin 'GET', 'POST' } -Times 0
    }
    It '-NoHtml skips the HTML file but still writes JSON' {
        Use-ZkFakeGraph
        & $Tenant -OutputPath $Out -KnownCausesPath $Db -SkipConnect -NoHtml -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        @(Get-ChildItem -LiteralPath $Out -Filter '*.html').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $Out -Filter '*.json').Count | Should -Be 1
    }
}

Describe 'Kit 1 device HTML report' {
    BeforeAll {
        if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) { function global:Get-CimInstance { param($ClassName, $ErrorAction) } }
        if (-not (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue)) { function global:Get-WinEvent { param($ListLog, $FilterHashtable, $MaxEvents, $ErrorAction) } }
        if (-not (Get-Command -Name Get-Service -ErrorAction SilentlyContinue)) { function global:Get-Service { param($Name, $ErrorAction) } }
        if (-not $env:ProgramData) { $env:ProgramData = [IO.Path]::GetTempPath() }
    }
    BeforeEach {
        $script:Out = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString())
        Mock -CommandName Get-CimInstance -MockWith { [PSCustomObject]@{ Caption = 'Windows 11 <Contoso & Co>'; BuildNumber = '26100'; LastBootUpTime = (Get-Date) } }
        Mock -CommandName Get-Service -MockWith { $null }
        Mock -CommandName Get-WinEvent -MockWith { }
    }
    It 'creates the HTML file with statuses, escaping and no remote resources' {
        & $Device -OutputPath $Out -KnownCausesPath $Db -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        $f = @(Get-ChildItem -LiteralPath $Out -Filter 'DeviceDiagnostic-*.html')
        $f.Count | Should -Be 1
        $h = Get-Content -LiteralPath $f[0].FullName -Raw
        $h | Should -Match '@media print'
        Test-ZkOnlyNextLinkIsExternal -Html $h
        Test-ZkDashboard -Html $h
        $h | Should -Match 'data-status="(red|yellow)"'
        $h | Should -Match '&lt;Contoso &amp; Co&gt;'
    }
    It '-NoHtml skips the HTML file' {
        & $Device -OutputPath $Out -KnownCausesPath $Db -NoHtml -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        @(Get-ChildItem -LiteralPath $Out -Filter '*.html').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $Out -Filter '*.json').Count | Should -Be 1
    }
}
