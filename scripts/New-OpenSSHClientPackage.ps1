[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $BuildDirectory,

    [Parameter(Mandatory)]
    [string] $DestinationDirectory,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $SourceRevision,

    [string] $SourceRepository = 'PowerShell/openssh-portable',
    [string] $SourceRef = '',

    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $VcpkgBaseline = '16fa044f80dd984c24deff5b7d0457e64c85a1e0',

    [string] $BuildRepository = '',
    [string] $BuildRevision = '',
    [string] $BuildRun = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$arm64Machine = 0xAA64
$clientFiles = @(
    [pscustomobject]@{ Source = 'scp.exe'; Destination = 'usr/bin/scp.exe' }
    [pscustomobject]@{ Source = 'sftp.exe'; Destination = 'usr/bin/sftp.exe' }
    [pscustomobject]@{ Source = 'ssh-add.exe'; Destination = 'usr/bin/ssh-add.exe' }
    [pscustomobject]@{ Source = 'ssh-agent.exe'; Destination = 'usr/bin/ssh-agent.exe' }
    [pscustomobject]@{ Source = 'ssh-keygen.exe'; Destination = 'usr/bin/ssh-keygen.exe' }
    [pscustomobject]@{ Source = 'ssh-keyscan.exe'; Destination = 'usr/bin/ssh-keyscan.exe' }
    [pscustomobject]@{ Source = 'ssh.exe'; Destination = 'usr/bin/ssh.exe' }
    [pscustomobject]@{ Source = 'sftp-server.exe'; Destination = 'usr/lib/ssh/sftp-server.exe' }
    [pscustomobject]@{ Source = 'ssh-pkcs11-helper.exe'; Destination = 'usr/lib/ssh/ssh-pkcs11-helper.exe' }
    [pscustomobject]@{ Source = 'ssh-sk-helper.exe'; Destination = 'usr/lib/ssh/ssh-sk-helper.exe' }
)
$runtimeFiles = @(
    # The Windows port resolves these helpers beside ssh.exe, while Git for
    # Windows also owns canonical copies under usr/lib/ssh.
    [pscustomobject]@{ Source = 'ssh-pkcs11-helper.exe'; Destination = 'usr/bin/ssh-pkcs11-helper.exe' }
    [pscustomobject]@{ Source = 'ssh-sk-helper.exe'; Destination = 'usr/bin/ssh-sk-helper.exe' }
    [pscustomobject]@{ Source = 'libcrypto.dll'; Destination = 'usr/bin/libcrypto.dll' }
    [pscustomobject]@{ Source = 'libcrypto.dll'; Destination = 'usr/lib/ssh/libcrypto.dll' }
)
$metadataFiles = @('LICENSE.txt', 'NOTICE.txt')
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
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' does not have an MZ header."
        }

        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) {
            throw "'$Path' has an invalid PE header offset."
        }

        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' does not have a PE signature."
        }

        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

function Copy-PayloadFile {
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Mapping
    )

    $sourcePath = Join-Path $BuildDirectory $Mapping.Source
    if (-not (Test-Path $sourcePath -PathType Leaf)) {
        throw "Required client payload '$($Mapping.Source)' is missing from '$BuildDirectory'."
    }

    $machine = Get-PEMachine -Path $sourcePath
    if ($machine -ne $arm64Machine) {
        throw "'$sourcePath' has PE machine 0x$($machine.ToString('X4')); expected ARM64 0xAA64."
    }

    $relativePath = $Mapping.Destination.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $destinationPath = Join-Path $DestinationDirectory $relativePath
    $null = New-Item -ItemType Directory -Path (Split-Path $destinationPath -Parent) -Force
    Copy-Item -Path $sourcePath -Destination $destinationPath -Force

    $item = Get-Item $destinationPath
    return [ordered]@{
        path = $Mapping.Destination
        source = $Mapping.Source
        size = $item.Length
        sha256 = (Get-FileHash -Path $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        machine = '0xAA64'
    }
}

if (Test-Path $DestinationDirectory) {
    Remove-Item -Path $DestinationDirectory -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $DestinationDirectory -Force

$manifestFiles = @()
foreach ($mapping in ($clientFiles + $runtimeFiles)) {
    $manifestFiles += Copy-PayloadFile -Mapping $mapping
}

foreach ($name in $metadataFiles) {
    $sourcePath = Join-Path $BuildDirectory $name
    if (-not (Test-Path $sourcePath -PathType Leaf)) {
        throw "Required package metadata '$name' is missing from '$BuildDirectory'."
    }
    Copy-Item -Path $sourcePath -Destination (Join-Path $DestinationDirectory $name) -Force
}

$unexpectedServerFiles = Get-ChildItem -Path $DestinationDirectory -Recurse -File |
    Where-Object { $serverOnlyNames -contains $_.Name }
if ($unexpectedServerFiles) {
    throw "Server-only files were included: $($unexpectedServerFiles.Name -join ', ')."
}

$baselineDisposition = @()
foreach ($mapping in $clientFiles) {
    $baselineDisposition += [ordered]@{
        path = $mapping.Destination
        disposition = 'replace'
        artifactPath = $mapping.Destination
    }
}
$baselineDisposition += [ordered]@{
    path = 'usr/lib/ssh/ssh-keysign.exe'
    disposition = 'remove'
    reason = 'Win32 OpenSSH does not build ssh-keysign; Windows host-based authentication is unsupported.'
}

$manifest = [ordered]@{
    schemaVersion = 1
    artifact = 'OpenSSH-ARM64-Client'
    architecture = 'arm64'
    machine = '0xAA64'
    source = [ordered]@{
        repository = $SourceRepository
        ref = $SourceRef
        revision = $SourceRevision.ToLowerInvariant()
        vcpkgBaseline = $VcpkgBaseline.ToLowerInvariant()
    }
    build = [ordered]@{
        repository = $BuildRepository
        revision = $BuildRevision
        run = $BuildRun
    }
    files = $manifestFiles
    baselineDisposition = $baselineDisposition
}

$manifestPath = Join-Path $DestinationDirectory 'manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "Created ARM64 client package at '$DestinationDirectory' with $($manifestFiles.Count) PE files."
