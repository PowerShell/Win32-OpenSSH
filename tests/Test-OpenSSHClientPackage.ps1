[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $PackageDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$expectedClientPaths = @(
    'usr/bin/scp.exe',
    'usr/bin/sftp.exe',
    'usr/bin/ssh-add.exe',
    'usr/bin/ssh-agent.exe',
    'usr/bin/ssh-keygen.exe',
    'usr/bin/ssh-keyscan.exe',
    'usr/bin/ssh-pkcs11-helper.exe',
    'usr/bin/ssh-sk-helper.exe',
    'usr/bin/ssh.exe',
    'usr/lib/ssh/sftp-server.exe',
    'usr/lib/ssh/ssh-pkcs11-helper.exe',
    'usr/lib/ssh/ssh-sk-helper.exe'
)
$serverOnlyNames = @(
    'sshd.exe',
    'sshd-auth.exe',
    'sshd-session.exe',
    'ssh-shellhost.exe',
    'install-sshd.ps1',
    'uninstall-sshd.ps1',
    'sshd_config_default',
    'openssh-events.man',
    'moduli'
)

function Get-PEMachine {
    param([Parameter(Mandatory)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' does not have an MZ header."
        }
        $stream.Position = 0x3c
        $stream.Position = $reader.ReadInt32()
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' does not have a PE signature."
        }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

$manifestPath = Join-Path $PackageDirectory 'manifest.json'
if (-not (Test-Path $manifestPath -PathType Leaf)) {
    throw "Package manifest is missing."
}
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

if ($manifest.architecture -ne 'arm64' -or $manifest.machine -ne '0xAA64') {
    throw "Manifest architecture is not ARM64."
}

$replaceEntries = @($manifest.baselineDisposition | Where-Object disposition -eq 'replace')
$removeEntries = @($manifest.baselineDisposition | Where-Object disposition -eq 'remove')
if ($replaceEntries.Count -ne 10 -or $removeEntries.Count -ne 1) {
    throw "Expected 10 replacement paths and one removal path."
}
if ($removeEntries[0].path -ne 'usr/lib/ssh/ssh-keysign.exe') {
    throw "The only removal path must be usr/lib/ssh/ssh-keysign.exe."
}

foreach ($path in $expectedClientPaths) {
    $nativePath = $path.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $fullPath = Join-Path $PackageDirectory $nativePath
    if (-not (Test-Path $fullPath -PathType Leaf)) {
        throw "Expected client file '$path' is missing."
    }
}

$peFiles = @(Get-ChildItem -Path $PackageDirectory -Recurse -File |
    Where-Object Extension -in @('.exe', '.dll'))
if ($peFiles.Count -ne 14) {
    throw "Expected 14 ARM64 PE files (10 baseline replacements, two colocated helpers, and two libcrypto copies), found $($peFiles.Count)."
}
foreach ($file in $peFiles) {
    $machine = Get-PEMachine -Path $file.FullName
    if ($machine -ne 0xAA64) {
        throw "'$($file.FullName)' has machine 0x$($machine.ToString('X4')); expected 0xAA64."
    }
}

$unexpectedServerFiles = Get-ChildItem -Path $PackageDirectory -Recurse -File |
    Where-Object { $serverOnlyNames -contains $_.Name }
if ($unexpectedServerFiles) {
    throw "Server-only files were included: $($unexpectedServerFiles.Name -join ', ')."
}

foreach ($fileEntry in $manifest.files) {
    $nativePath = $fileEntry.path.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $fullPath = Join-Path $PackageDirectory $nativePath
    $actualHash = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $fileEntry.sha256) {
        throw "SHA-256 mismatch for '$($fileEntry.path)'."
    }
}

Write-Host "Validated ARM64 client package: 10 baseline replacements, one removal, 14 ARM64 PE files, no server payload."
