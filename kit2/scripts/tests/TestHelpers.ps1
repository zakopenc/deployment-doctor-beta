# Shared helpers for the Kit 2 Pester tests. Builds dated log fixtures relative to today.
function New-ZkTestLogFolder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes test fixtures into Pester TestDrive only.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [hashtable]$Map   # template file name -> output file name
    )
    $fixtures = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    if (-not (Test-Path -LiteralPath $Destination)) { $null = New-Item -ItemType Directory -Path $Destination -Force }
    $d1 = (Get-Date).AddDays(-1).ToString('M-d-yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
    $old = (Get-Date).AddDays(-400).ToString('M-d-yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
    foreach ($k in $Map.Keys) {
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $fixtures -ChildPath $k))
        $text = $text.Replace('{D1}', $d1).Replace('{DOLD}', $old)
        [System.IO.File]::WriteAllText((Join-Path -Path $Destination -ChildPath $Map[$k]), $text)
    }
    return $Destination
}
