#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
Describe 'PSScriptAnalyzer' {
    BeforeAll {
        $script:Root = Split-Path -Path $PSScriptRoot -Parent
        $script:Scripts = @('Invoke-DeviceDiagnostic.ps1', 'Invoke-TenantPreCheck.ps1') | ForEach-Object { Join-Path -Path $script:Root -ChildPath $_ }
    }
    It 'has zero findings with the PSGallery rule set' {
        @(Invoke-ScriptAnalyzer -Path $script:Root -Recurse -Settings PSGallery).Count | Should -Be 0
    }
    It 'uses only syntax and commands available in Windows PowerShell 5.1 and PowerShell 7' {
        # Compatibility rules with the Windows PowerShell 5.1 (Windows 10 1809) and PowerShell 7.0 profiles
        # that ship with PSScriptAnalyzer.
        $settings = @{
            IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes')
            Rules        = @{
                PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
                PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core') }
                PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
            }
        }
        foreach ($f in $script:Scripts) { @(Invoke-ScriptAnalyzer -Path $f -Settings $settings).Count | Should -Be 0 -Because $f }
    }
    It 'keeps the scripts ASCII-only so Windows PowerShell 5.1 reads them correctly without a BOM' {
        foreach ($f in $script:Scripts) { [System.IO.File]::ReadAllBytes($f) | Where-Object { $_ -gt 127 } | Should -BeNullOrEmpty -Because $f }
    }
}
