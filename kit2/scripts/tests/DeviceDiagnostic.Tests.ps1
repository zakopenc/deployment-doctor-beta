#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Unit tests for Invoke-DeviceDiagnostic.ps1. Synthetic fixtures only; no device access.
# Fixture dates are generated relative to today (see TestHelpers.ps1), so these tests do not expire.
BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $script:Root -ChildPath 'Invoke-DeviceDiagnostic.ps1')
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
    $script:Db = Get-Content -LiteralPath (Join-Path -Path $script:Root -ChildPath 'known-causes.json') -Raw | ConvertFrom-Json
    $script:Main = New-ZkTestLogFolder -Destination (Join-Path $TestDrive 'main') -Map @{ 'AppWorkload.log.template' = 'AppWorkload.log'; 'IntuneManagementExtension.log.template' = 'IntuneManagementExtension.log' }
    $script:Healthy = New-ZkTestLogFolder -Destination (Join-Path $TestDrive 'healthy') -Map @{ 'healthy/AppWorkload.log.template' = 'AppWorkload.log' }
    $script:A = '6c1f3d0e-1111-4a2b-9c3d-000000000001'
    $script:B = '6c1f3d0e-2222-4a2b-9c3d-000000000002'
    $script:C = '6c1f3d0e-3333-4a2b-9c3d-000000000003'
    $script:H = '6c1f3d0e-4444-4a2b-9c3d-000000000004'
    function Get-CauseIdList($v) { @(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { $_.CauseId }) }
}

Describe 'ConvertFrom-ZkCmLogText' {
    It 'parses single and multi-line records with 7-digit fractions' {
        $text = Get-Content -LiteralPath (Join-Path $script:Main 'AppWorkload.log') -Raw
        $r = @(ConvertFrom-ZkCmLogText -Text $text -SourceName 'AppWorkload.log')
        $r.Count | Should -Be 10
        ($r | Where-Object { $_.Message -match 'second line' }).Type | Should -Be 3
        $r[0].Time | Should -BeOfType ([datetime])
        $r[0].Time.Date | Should -Be (Get-Date).AddDays(-1).Date
    }
    It 'parses ConfigMgr-style time bias' {
        $line = '<![LOG[x]LOG]!><time="08:06:34.590-060" date="09-02-2016" component="C" context="" type="1" thread="1" file="a.cpp">'
        $r = @(ConvertFrom-ZkCmLogText -Text $line -SourceName 't')
        $r[0].Bias | Should -Be -60
        $r[0].Time.Year | Should -Be 2016
    }
    It 'returns nothing for plain text or an empty string' {
        @(ConvertFrom-ZkCmLogText -Text 'not a cmtrace line' -SourceName 't').Count | Should -Be 0
        @(ConvertFrom-ZkCmLogText -Text '' -SourceName 't').Count | Should -Be 0
    }
    It 'keeps a record whose time cannot be parsed (Time is null)' {
        $line = '<![LOG[odd]LOG]!><time="garbage" date="13-45-2026" component="C" context="" type="1" thread="1" file="">'
        $r = @(ConvertFrom-ZkCmLogText -Text $line -SourceName 't')
        $r.Count | Should -Be 1
        $r[0].Time | Should -BeNullOrEmpty
    }
}

Describe 'Get-ZkLogSignal' {
    It 'reads exit codes' { (Get-ZkLogSignal -Message 'lpExitCode 1618').Value | Should -Be 1618 }
    It 'reads negative exit codes' { (Get-ZkLogSignal -Message 'lpExitCode -2147024891').Value | Should -Be -2147024891 }
    It 'reads detection' { (Get-ZkLogSignal -Message 'applicationDetected: False').Value | Should -Be 'false' }
    It 'flags unmapped codes on the exit signal' {
        $s = Get-ZkLogSignal -Message 'Error with lpExitCode 5 without mapping'
        $s.Kind | Should -Be 'exit'; $s.Unmapped | Should -BeTrue
    }
    It 'accepts the IpExitCode spelling quoted in a field write-up' {
        $s = Get-ZkLogSignal -Message 'Error with IpExitCode: 1602 without mapping'
        $s.Value | Should -Be 1602; $s.Unmapped | Should -BeTrue
    }
    It 'treats a detection-script line with exitCode as detection, not an installer exit' {
        # Line text as quoted by call4cloud (2022).
        $s = Get-ZkLogSignal -Message '[Win32App] Checked Powershell script  exitCode: -1  EnforceSignatureCheck: 0 RunAs32Bit: 0 InstallExRunAs: 0, result of applicationDetected: False'
        $s.Kind | Should -Be 'detected'; $s.Value | Should -Be 'false'
    }
    It 'flags GRS' { (Get-ZkLogSignal -Message '[Win32App][GRSManager] App with id: x is not expired.').Kind | Should -Be 'grs' }
    It 'returns null for noise' { Get-ZkLogSignal -Message 'hello' | Should -BeNullOrEmpty }
}

Describe 'Offline diagnosis on synthetic fixtures' {
    BeforeAll {
        $script:Report = Invoke-ZkDeviceDiagnostic -LogPath $script:Main -DaysBack 14 -KnownCause $script:Db -SkipRegistry
        function Get-App($id) { $script:Report.Apps | Where-Object { $_.AppId -eq $id } }
    }
    It 'finds the apps from log lines' {
        @($script:Report.Apps | ForEach-Object { $_.AppId }) | Should -Contain $script:A
        @($script:Report.Apps | ForEach-Object { $_.AppId }) | Should -Contain $script:B
    }
    It 'gives KC-001 (High) for exit 0 then not detected' {
        $v = @((Get-App $script:A).Verdicts)
        Get-CauseIdList $v | Should -Contain 'KC-001'
        ($v | Where-Object { $_.CauseId -eq 'KC-001' }).Confidence | Should -Be 'High'
    }
    It 'gives KC-003 and KC-004 for unmapped 1618, and not KC-019 or KC-001' {
        $ids = Get-CauseIdList (Get-App $script:B).Verdicts
        $ids | Should -Contain 'KC-003'; $ids | Should -Contain 'KC-004'
        $ids | Should -Not -Contain 'KC-001'; $ids | Should -Not -Contain 'KC-019'
    }
    It 'shows detected-before-install as context, not a verdict (no false KC-002)' {
        $c = Get-App $script:C
        @($c.Verdicts).Count | Should -Be 0
        ($c.Context -join ' ') | Should -Match 'KC-002'
    }
    It 'raises KC-002 for detected-before-install only with -ExpectNewVersion' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Main -DaysBack 14 -KnownCause $script:Db -SkipRegistry -ExpectNewVersion
        Get-CauseIdList ($r.Apps | Where-Object { $_.AppId -eq $script:C }).Verdicts | Should -Contain 'KC-002'
        Get-CauseIdList ($r.Apps | Where-Object { $_.AppId -eq $script:A }).Verdicts | Should -Not -Contain 'KC-002'
    }
    It 'takes the app name from the IME log line when no tenant report is given' {
        (Get-App $script:A).Name | Should -Be 'Contoso Viewer'
        (Get-App $script:B).Name | Should -Be 'Fabrikam Tool'
    }
    It 'leaves no signal unexplained on the fixtures' {
        foreach ($a in @($script:Report.Apps)) { @($a.Unexplained).Count | Should -Be 0 -Because $a.AppId }
    }
    It 'attributes thread-following lines and marks them inferred' {
        @((Get-App $script:A).Timeline | Where-Object { $_.Inferred }).Count | Should -BeGreaterThan 0
    }
    It 'writes JSON and HTML, creating a missing nested output folder' {
        $out = Join-Path $TestDrive 'new\nested\out'
        $files = Export-ZkDeviceReport -Report $script:Report -OutputPath $out
        Test-Path -LiteralPath $files.Json | Should -BeTrue
        (Get-Content -LiteralPath $files.Html -Raw) | Should -Match 'KC-001'
        (Get-Content -LiteralPath $files.Json -Raw | ConvertFrom-Json).KitVersion | Should -Be '1.2.0'
    }
}

Describe 'False positives on a healthy device' {
    It 'gives no verdicts and no unexplained signals for a healthy install with routine GRS lines' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Healthy -DaysBack 30 -KnownCause $script:Db -SkipRegistry
        $h = $r.Apps | Where-Object { $_.AppId -eq $script:H }
        @($h.Verdicts).Count | Should -Be 0
        @($h.Unexplained).Count | Should -Be 0
        @($r.DeviceVerdicts).Count | Should -Be 0
    }
    It 'ignores records older than -DaysBack' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Healthy -DaysBack 30 -KnownCause $script:Db -SkipRegistry
        @(($r.Apps | Where-Object { $_.AppId -eq $script:H }).Signals) | Should -Not -Contain 'exit:1603'
    }
    It 'downgrades an old failure when a later evaluation detected the app' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Healthy -DaysBack 500 -KnownCause $script:Db -SkipRegistry
        $v = @(($r.Apps | Where-Object { $_.AppId -eq $script:H }).Verdicts)
        Get-CauseIdList $v | Should -Contain 'KC-005'
        ($v | Where-Object { $_.CauseId -eq 'KC-005' }).Confidence | Should -Match '^Low'
    }
}

Describe 'Missing or unreadable input' {
    It 'warns and reports KC-021 for a missing log folder' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath (Join-Path $TestDrive 'nothing') -DaysBack 1 -KnownCause $script:Db -SkipRegistry -WarningVariable w -WarningAction SilentlyContinue
        $r.DeviceSignals | Should -Contain 'logs:none'
        Get-CauseIdList $r.DeviceVerdicts | Should -Contain 'KC-021'
        ($w -join ' ') | Should -Match 'Log folder not found'
        @($r.Apps).Count | Should -Be 0
    }
    It 'handles an empty log file' {
        $d = Join-Path $TestDrive 'empty'; $null = New-Item -ItemType Directory -Path $d
        Set-Content -LiteralPath (Join-Path $d 'AppWorkload.log') -Value '' -NoNewline
        $r = Invoke-ZkDeviceDiagnostic -LogPath $d -DaysBack 1 -KnownCause $script:Db -SkipRegistry
        $r.RecordCount | Should -Be 0
        $r.DeviceSignals | Should -Not -Contain 'logs:none'
    }
    It 'reads a log that another process holds open for writing' {
        $d = New-ZkTestLogFolder -Destination (Join-Path $TestDrive 'locked') -Map @{ 'AppWorkload.log.template' = 'AppWorkload.log' }
        $fs = [System.IO.File]::Open((Join-Path $d 'AppWorkload.log'), 'Open', 'ReadWrite', 'Read')
        try { (Get-ZkImeLogRecord -Path $d -DaysBack 14).Records.Count | Should -Be 10 }
        finally { $fs.Dispose() }
    }
}

Describe 'Signal coverage (every signal maps to a KC entry or a defined context)' {
    It 'covers every signal shape the diagnostic can emit' {
        $samples = 'exit:0', 'exit:1641', 'exit:3010', 'exit:success', 'exit:1618', 'exit:1603', 'exit:5', 'exit:-2147024891', 'exit:1602', 'exit:-1',
        'unmapped', 'grs', 'timeout', 'requirement-not-met', 'download-error', 'download', 'cache', 'state', 'policy',
        'detected:true:pre', 'detected:false:pre', 'detected:true:post', 'detected:false:post', 'final:detected',
        'ime:missing', 'ime:stopped', 'ime:old', 'logs:none', 'errorcode:-2016345060',
        'enforcement:1000', 'enforcement:1003', 'enforcement:2000', 'enforcement:2007', 'enforcement:2008', 'enforcement:2009', 'enforcement:3000', 'enforcement:4000',
        'enforcement:5000', 'enforcement:5003', 'enforcement:5999', 'enforcement:6000', 'enforcement:6001', 'enforcement:6002', 'enforcement:6003', 'enforcement:6004', 'enforcement:6005', 'enforcement:1234', 'expect:new-version'
        foreach ($s in $samples) {
            $v = @(Get-ZkVerdict -Signal @($s) -KnownCause $script:Db)
            $cov = Get-ZkSignalCoverage -Signal @($s) -Verdict $v -KnownCause $script:Db
            @($cov.Unexplained).Count | Should -Be 0 -Because "signal '$s' must map to a KC entry or a context meaning"
        }
    }
    It 'maps a registry error code to KC-020' {
        Get-CauseIdList (Get-ZkVerdict -Signal @('errorcode:-2016345060') -KnownCause $script:Db) | Should -Contain 'KC-020'
    }
    It 'does not raise KC-004 for routine GRS lines alone' {
        Get-CauseIdList (Get-ZkVerdict -Signal @('grs') -KnownCause $script:Db) | Should -Not -Contain 'KC-004'
    }
    It 'gives KC-019 for an unlisted failure code only' {
        Get-CauseIdList (Get-ZkVerdict -Signal @('exit:1602') -KnownCause $script:Db) | Should -Contain 'KC-019'
        Get-CauseIdList (Get-ZkVerdict -Signal @('exit:1618') -KnownCause $script:Db) | Should -Not -Contain 'KC-019'
        Get-CauseIdList (Get-ZkVerdict -Signal @('exit:0') -KnownCause $script:Db) | Should -Not -Contain 'KC-019'
    }
}

Describe 'Worked examples and fixtures' {
    It 'uses a correct signed-int32 example for 0x87D1041C' {
        ('{0:X8}' -f -2016345060) | Should -Be '87D1041C'
        [int32]-2016345060 | Should -Be ([int32]([int64]0x87D1041CL - 4294967296))
        [Convert]::ToInt32("87D1041C", 16) | Should -Be -2016345060
        $txt = Get-Content -LiteralPath (Join-Path $script:Root 'known-causes.json') -Raw
        $txt | Should -Match '-2016345060 gives 87D1041C'
    }
    It 'has no hard-coded dates in the log templates (tests must not expire)' {
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures') -Recurse -Filter '*.template') {
            (Get-Content -LiteralPath $f.FullName -Raw) | Should -Not -Match 'date="\d' -Because $f.Name
        }
    }
}

Describe 'Known-causes database integrity' {
    It 'has unique IDs, a detectedBy field, a rollback and dated sources on every entry' {
        $ids = @($script:Db.causes | ForEach-Object { $_.id })
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($c in @($script:Db.causes)) {
            $c.detectedBy | Should -Not -BeNullOrEmpty -Because $c.id
            $c.rollback | Should -Not -BeNullOrEmpty -Because $c.id
            $c.status | Should -BeIn @('Learn-confirmed', 'Multi-source') -Because $c.id
            foreach ($s in @($c.sources)) { $s.dateChecked | Should -Match '^\d{4}-\d{2}-\d{2}$' }
        }
    }
    It 'keeps detectedBy consistent with the matching data' {
        foreach ($c in @($script:Db.causes)) {
            $hasDevice = @($c.deviceSignals.PSObject.Properties).Count -gt 0
            $hasTenant = @($c.tenantChecks).Count -gt 0
            if ($c.detectedBy -match 'Device diagnostic') { $hasDevice | Should -BeTrue -Because "$($c.id) claims the device diagnostic detects it" }
            else { $hasDevice | Should -BeFalse -Because "$($c.id) has device signals but detectedBy doesn't say so" }
            if ($c.detectedBy -match 'tenant pre-check') { $hasTenant | Should -BeTrue -Because $c.id }
            if ($c.detectedBy -match '^Manual') { ($hasDevice -or $hasTenant) | Should -BeFalse -Because $c.id }
        }
    }
    It 'contains every KC ID that the guide cites' {
        $guide = Join-Path (Split-Path $script:Root -Parent) 'guide/src/guide.html'
        if (-not (Test-Path -LiteralPath $guide)) { Set-ItResult -Skipped -Because 'guide source is not shipped in the kit'; return }
        $ids = @($script:Db.causes | ForEach-Object { $_.id })
        foreach ($m in [regex]::Matches((Get-Content -LiteralPath $guide -Raw), 'KC-\d{3}')) { $ids | Should -Contain $m.Value }
    }
    It 'references only tenant checks that exist' {
        $tids = @($script:Db.tenantChecks | ForEach-Object { $_.id })
        foreach ($c in @($script:Db.causes)) { foreach ($t in @($c.tenantChecks)) { $tids | Should -Contain $t -Because $c.id } }
    }
}

Describe 'Tenant report hand-off' {
    It 'adds names, rules and tenant findings from a tenant JSON file' {
        $tenant = [pscustomobject]@{
            Apps     = @([pscustomobject]@{ Id = $script:A.ToUpperInvariant(); DisplayName = 'Contoso Viewer'; DetectionRules = @([pscustomobject]@{ ruleType = 'detection'; path = 'C:\Program Files\Contoso' }); InstallCommand = 'setup.exe /S'; RunAs = 'system' })
            Findings = @([pscustomobject]@{ CheckId = 'T06b'; Severity = 'Low'; AppId = $script:A; AppName = 'Contoso Viewer'; Message = 'x'; Evidence = 'y' })
        }
        $path = Join-Path $TestDrive 'tenant.json'
        $tenant | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        $loaded = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Main -DaysBack 14 -KnownCause $script:Db -SkipRegistry -TenantReport $loaded
        $a = $r.Apps | Where-Object { $_.AppId -eq $script:A }
        $a.Name | Should -Be 'Contoso Viewer'
        @($a.TenantFindings).Count | Should -Be 1
        @($a.DetectionRules).Count | Should -Be 1
    }
    It 'accepts a tenant report with no apps' {
        $r = Invoke-ZkDeviceDiagnostic -LogPath $script:Main -DaysBack 14 -KnownCause $script:Db -SkipRegistry -TenantReport ([pscustomobject]@{ Apps = @(); Findings = @() })
        @($r.Apps).Count | Should -BeGreaterThan 0
    }
}

Describe 'Script entry point' {
    It 'is quiet on the pipeline by default and creates the output folder' {
        $out = Join-Path $TestDrive 'entry\out'
        $res = @(& (Join-Path $script:Root 'Invoke-DeviceDiagnostic.ps1') -LogPath $script:Main -SkipRegistry -OutputPath $out -DaysBack 14 6>$null)
        $res.Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $out -Filter '*.html').Count | Should -Be 1
    }
    It 'returns exactly one summary object with -PassThru' {
        $res = @(& (Join-Path $script:Root 'Invoke-DeviceDiagnostic.ps1') -LogPath $script:Main -SkipRegistry -OutputPath (Join-Path $TestDrive 'pt') -DaysBack 14 -PassThru 6>$null)
        $res.Count | Should -Be 1
        Test-Path -LiteralPath $res[0].ReportHtml | Should -BeTrue
        $res[0].VerdictCount | Should -BeGreaterThan 0
    }
    It 'gives a clear error for a bad tenant report path' {
        { & (Join-Path $script:Root 'Invoke-DeviceDiagnostic.ps1') -LogPath $script:Main -SkipRegistry -OutputPath $TestDrive -TenantReportPath (Join-Path $TestDrive 'nope.json') } | Should -Throw '*tenant report*'
    }
    It 'rejects a malformed AppId' {
        { & (Join-Path $script:Root 'Invoke-DeviceDiagnostic.ps1') -AppId 'not-a-guid' -SkipRegistry -LogPath $TestDrive -OutputPath $TestDrive } | Should -Throw
    }
}

Describe 'Read-only guarantees' {
    It 'contains no registry/service write commands' {
        $src = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-DeviceDiagnostic.ps1') -Raw
        $src | Should -Not -Match '(?i)\b(Set-ItemProperty|New-ItemProperty|Remove-Item|Remove-ItemProperty|Restart-Service|Stop-Service|Start-Service|reg\.exe|Invoke-WebRequest|Invoke-RestMethod)\b'
    }
}
