[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $BuildDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$expectedTests = @(
    'unittest-bitmap.exe',
    'unittest-hostkeys.exe',
    'unittest-kex.exe',
    'unittest-match.exe',
    'unittest-misc.exe',
    'unittest-sshbuf.exe',
    'unittest-sshkey.exe',
    'unittest-win32compat.exe'
)
$testExecutables = @(Get-ChildItem -Path $BuildDirectory -Recurse -File -Filter 'unittest-*.exe' |
    Sort-Object Name)
$actualNames = @($testExecutables | ForEach-Object Name)
$missingTests = @($expectedTests | Where-Object { $_ -notin $actualNames })
if ($missingTests) {
    throw "Missing upstream unit test executables under '$BuildDirectory': $($missingTests -join ', ')."
}

foreach ($testExecutable in $testExecutables) {
    Write-Host "Running $($testExecutable.Name)"
    Push-Location $testExecutable.DirectoryName
    try {
        & $testExecutable.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "'$($testExecutable.FullName)' failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host "Passed all $($expectedTests.Count) upstream OpenSSH unit test executables."
