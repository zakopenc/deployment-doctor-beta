<#
.SYNOPSIS
    Builds docs/sample-report.html from clearly FAKE, contoso-style data using the Kit 2 tenant report renderer.
.DESCRIPTION
    No Graph calls, no tenant. All names and IDs below are invented placeholders.
.EXAMPLE
    pwsh ./docs/New-SampleReport.ps1
#>
[CmdletBinding()]
param()
$root = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path -Path $root -ChildPath 'kit2/scripts/Invoke-TenantPreCheck.ps1')
$db = Get-Content -LiteralPath (Join-Path -Path $root -ChildPath 'kit2/scripts/known-causes.json') -Raw | ConvertFrom-Json
$report = [pscustomobject]@{
    GeneratedLocal = '2026-01-15 09:00:00 (SAMPLE - FAKE DATA)'; KitVersion = '1.2.2'; Errors = @()
    Apps = @(
        [pscustomobject]@{ DisplayName = 'Contoso Viewer (FAKE)'; Id = 'sample-app-0001'; RunAs = 'system'; Assignments = 'required (group:SG-Contoso-Devices)'; InstallSummary = 'installed 41, failed 6, pending 2'; DetectionRuleCount = 1 },
        [pscustomobject]@{ DisplayName = 'Fabrikam Agent (FAKE)'; Id = 'sample-app-0002'; RunAs = 'user'; Assignments = 'required (group:SG-Fabrikam-Users)'; InstallSummary = 'installed 18, failed 0, pending 1'; DetectionRuleCount = 2 },
        [pscustomobject]@{ DisplayName = 'Northwind Reader (FAKE)'; Id = 'sample-app-0003'; RunAs = 'system'; Assignments = 'available (group:SG-Northwind)'; InstallSummary = 'installed 12, failed 0'; DetectionRuleCount = 1 }
    )
    Findings = @(
        [pscustomobject]@{ Severity = 'High'; CheckId = 'T04'; AppId = 'sample-app-0001'; AppName = 'Contoso Viewer (FAKE)'; Message = 'Detection script can write to STDERR, which IME treats as not detected.'; Evidence = 'Write-Error "not found" (line 12 of detect.ps1)' },
        [pscustomobject]@{ Severity = 'Medium'; CheckId = 'T01'; AppId = 'sample-app-0001'; AppName = 'Contoso Viewer (FAKE)'; Message = 'Install command calls powershell.exe without Sysnative, so it runs 32-bit PowerShell.'; Evidence = 'powershell.exe -ExecutionPolicy Bypass -File install.ps1' },
        [pscustomobject]@{ Severity = 'Medium'; CheckId = 'T16'; AppId = 'sample-app-0001'; AppName = 'Contoso Viewer (FAKE)'; Message = '6 device(s) report Failed. Run Invoke-DeviceDiagnostic.ps1 on one of them.'; Evidence = 'installed 41, failed 6, pending 2' },
        [pscustomobject]@{ Severity = 'Medium'; CheckId = 'T07'; AppId = 'sample-app-0002'; AppName = 'Fabrikam Agent (FAKE)'; Message = 'User install context: installs only when a user is signed in.'; Evidence = 'runAsAccount = user' },
        [pscustomobject]@{ Severity = 'Info'; CheckId = 'T10'; AppId = 'sample-app-0003'; AppName = 'Northwind Reader (FAKE)'; Message = 'Dependency graph has 1 app.'; Evidence = 'dependencies: 1' }
    )
}
$f = Export-ZkTenantReport -Report $report -OutputPath (Join-Path -Path $root -ChildPath 'docs/out') -KnownCause $db
Copy-Item -LiteralPath $f.Html -Destination (Join-Path -Path $PSScriptRoot -ChildPath 'sample-report.html') -Force
Remove-Item -LiteralPath (Join-Path -Path $root -ChildPath 'docs/out') -Recurse -Force
