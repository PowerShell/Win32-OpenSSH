[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $BuildDirectory,

    [string] $GitExecutable = 'git.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ssh = Join-Path $BuildDirectory 'ssh.exe'
$sshd = Join-Path $BuildDirectory 'sshd.exe'
$sshAdd = Join-Path $BuildDirectory 'ssh-add.exe'
$sshAgent = Join-Path $BuildDirectory 'ssh-agent.exe'
$sshKeygen = Join-Path $BuildDirectory 'ssh-keygen.exe'
$sshKeyscan = Join-Path $BuildDirectory 'ssh-keyscan.exe'
$scp = Join-Path $BuildDirectory 'scp.exe'
$sftp = Join-Path $BuildDirectory 'sftp.exe'
$sftpServer = Join-Path $BuildDirectory 'sftp-server.exe'

foreach ($path in @($ssh, $sshd, $sshAdd, $sshAgent, $sshKeygen, $sshKeyscan, $scp, $sftp, $sftpServer)) {
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "Required smoke-test binary '$path' is missing."
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter()]
        [string[]] $ArgumentList = @(),

        [string] $WorkingDirectory = ''
    )

    if ($WorkingDirectory) {
        Push-Location $WorkingDirectory
    }
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr as error records. Capture
        # diagnostics without treating warnings as failures; the exit code is
        # authoritative for these tools.
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $exitCode.`n$($output -join [Environment]::NewLine)"
        }
        return $output
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Convert-ToSshPath {
    param([Parameter(Mandatory)][string] $Path)
    return ([System.IO.Path]::GetFullPath($Path)).Replace('\', '/')
}

function Set-PrivateKeyAcl {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier] $Owner,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier[]] $FullControl
    )

    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($Owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in $FullControl) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $null = $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

$tempBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$testRoot = Join-Path $tempBase "openssh-arm64-client-$PID"
$profileSshDirectory = Join-Path $env:USERPROFILE '.ssh'
$profileConfig = Join-Path $profileSshDirectory 'config'
$profileConfigBackup = $null
$agentService = $null
$agentServiceCreated = $false
$agentServicePath = $null
$agentServiceStartMode = $null
$agentServiceWasRunning = $false
$sshdService = $null
$sshdServiceCreated = $false
$sshdServicePath = $null
$sshdServiceStartMode = $null
$sshdServiceStartName = $null
$sshdServiceWasRunning = $false
$sshdPrivilegesExisted = $false
$sshdRequiredPrivileges = $null
$sshdLog = $null
$openSshRegistryKeyExisted = $false
$defaultShellExisted = $false
$defaultShell = $null
$succeeded = $false
$oldGitSsh = $env:GIT_SSH
$oldGitSshVariant = $env:GIT_SSH_VARIANT

try {
    $null = New-Item -ItemType Directory -Path $testRoot -Force
    $null = New-Item -ItemType Directory -Path $profileSshDirectory -Force

    if (Test-Path $profileConfig -PathType Leaf) {
        $profileConfigBackup = Join-Path $testRoot 'profile-config.backup'
        Copy-Item $profileConfig $profileConfigBackup -Force
    }

    $hostKey = Join-Path $testRoot 'ssh_host_ed25519_key'
    $clientKey = Join-Path $testRoot 'id_ed25519'
    $rsaKey = Join-Path $testRoot 'id_rsa'
    # Windows PowerShell 5.1 drops empty native arguments, so preserve the
    # explicit empty passphrase through CommandLineToArgvW.
    Invoke-Checked -FilePath $sshKeygen -ArgumentList @('-q', '-t', 'ed25519', '-N', '""', '-f', $hostKey)
    Invoke-Checked -FilePath $sshKeygen -ArgumentList @('-q', '-t', 'ed25519', '-N', '""', '-f', $clientKey)
    Invoke-Checked -FilePath $sshKeygen -ArgumentList @('-q', '-t', 'rsa', '-b', '3072', '-N', '""', '-f', $rsaKey)
    Invoke-Checked -FilePath $sshKeygen -ArgumentList @('-lf', "$rsaKey.pub")

    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    Set-PrivateKeyAcl -Path $hostKey -Owner $administratorsSid -FullControl @($systemSid, $administratorsSid)
    foreach ($privateKey in @($clientKey, $rsaKey)) {
        Set-PrivateKeyAcl -Path $privateKey -Owner $userSid -FullControl @($userSid)
    }

    $authorizedKeys = Join-Path $testRoot 'authorized_keys'
    Copy-Item "$clientKey.pub" $authorizedKeys -Force
    $knownHosts = Join-Path $profileSshDirectory 'known_hosts-arm64-client'
    $port = Get-FreeTcpPort
    $sshdConfig = Join-Path $testRoot 'sshd_config'
    $sshdLog = Join-Path $testRoot 'sshd.log'

    @(
        "Port $port"
        'ListenAddress 127.0.0.1'
        "HostKey `"$hostKey`""
        "AuthorizedKeysFile `"$authorizedKeys`""
        'PubkeyAuthentication yes'
        'PasswordAuthentication no'
        'KbdInteractiveAuthentication no'
        'StrictModes no'
        'AllowTcpForwarding yes'
        'PermitTTY yes'
        "PidFile `"$testRoot\sshd.pid`""
        "Subsystem sftp `"$sftpServer`""
        'LogLevel VERBOSE'
    ) | Set-Content -Path $sshdConfig -Encoding ascii

    Invoke-Checked -FilePath $sshd -ArgumentList @('-t', '-f', $sshdConfig)
    $openSshRegistryPath = 'HKLM:\SOFTWARE\OpenSSH'
    $openSshRegistryKeyExisted = Test-Path $openSshRegistryPath
    $null = New-Item -Path $openSshRegistryPath -Force
    $openSshRegistry = Get-ItemProperty -Path $openSshRegistryPath
    if ($null -ne $openSshRegistry.PSObject.Properties['DefaultShell']) {
        $defaultShellExisted = $true
        $defaultShell = $openSshRegistry.DefaultShell
    }
    Set-ItemProperty -Path $openSshRegistryPath -Name DefaultShell -Value (Join-Path $PSHOME 'powershell.exe')

    $sshdService = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($sshdService) {
        $sshdServicePath = $sshdService.PathName
        $sshdServiceStartMode = $sshdService.StartMode
        $sshdServiceStartName = $sshdService.StartName
        $sshdServiceWasRunning = $sshdService.State -eq 'Running'
        $serviceRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
        $serviceRegistry = Get-ItemProperty -Path $serviceRegistryPath
        if ($null -ne $serviceRegistry.PSObject.Properties['RequiredPrivileges']) {
            $sshdPrivilegesExisted = $true
            $sshdRequiredPrivileges = @($serviceRegistry.RequiredPrivileges)
        }
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
            'config',
            'sshd',
            'binPath=',
            "`"$sshd`" -f `"$sshdConfig`" -E `"$sshdLog`"",
            'start=',
            'demand',
            'obj=',
            'LocalSystem'
        )
    }
    else {
        Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
            'create',
            'sshd',
            'binPath=',
            "`"$sshd`" -f `"$sshdConfig`" -E `"$sshdLog`"",
            'start=',
            'demand',
            'obj=',
            'LocalSystem'
        )
        $sshdServiceCreated = $true
    }
    Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
        'privs',
        'sshd',
        'SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege'
    )
    Start-Service -Name sshd

    $deadline = (Get-Date).AddSeconds(30)
    $listening = $false
    do {
        if ((Get-Service -Name sshd).Status -eq 'Stopped') {
            throw "sshd exited before accepting connections.`n$(Get-Content $sshdLog -Raw -ErrorAction SilentlyContinue)"
        }
        Start-Sleep -Milliseconds 250
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connect = $client.BeginConnect('127.0.0.1', $port, $null, $null)
            $listening = $connect.AsyncWaitHandle.WaitOne(250) -and $client.Connected
        }
        finally {
            $client.Dispose()
        }
    } while (-not $listening -and (Get-Date) -lt $deadline)
    if (-not $listening) {
        throw "sshd did not listen on port $port."
    }

    $keyscanOutput = Invoke-Checked -FilePath $sshKeyscan -ArgumentList @('-p', "$port", '127.0.0.1')
    $keyscanOutput | Where-Object { $_ -and -not $_.StartsWith('#') } |
        Set-Content -Path $knownHosts -Encoding ascii

    @(
        'Host arm64-local'
        '    HostName 127.0.0.1'
        "    Port $port"
        "    User $env:USERNAME"
        "    IdentityFile `"$clientKey`""
        '    IdentitiesOnly yes'
        "    UserKnownHostsFile `"$knownHosts`""
        '    StrictHostKeyChecking yes'
        '    BatchMode yes'
        ''
        'Host arm64-proxy'
        '    HostName 127.0.0.1'
        "    Port $port"
        "    User $env:USERNAME"
        "    IdentityFile `"$clientKey`""
        '    IdentitiesOnly yes'
        "    UserKnownHostsFile `"$knownHosts`""
        '    StrictHostKeyChecking yes'
        '    BatchMode yes'
        "    ProxyCommand `"$ssh`" -F `"$profileConfig`" -W %h:%p arm64-local"
    ) | Set-Content -Path $profileConfig -Encoding ascii

    $resolvedConfig = Invoke-Checked -FilePath $ssh -ArgumentList @('-G', 'arm64-local')
    if (-not ($resolvedConfig -match "^port $port$")) {
        throw 'OpenSSH did not discover the user config file.'
    }

    $directOutput = Invoke-Checked -FilePath $ssh -ArgumentList @('-T', 'arm64-local', 'cmd /c echo ssh-direct-ok')
    if (-not ($directOutput -match 'ssh-direct-ok')) {
        throw 'Direct SSH command did not return expected output.'
    }
    $proxyOutput = Invoke-Checked -FilePath $ssh -ArgumentList @('-T', 'arm64-proxy', 'cmd /c echo ssh-proxy-ok')
    if (-not ($proxyOutput -match 'ssh-proxy-ok')) {
        throw 'ProxyCommand SSH command did not return expected output.'
    }

    $noPtyOutput = Invoke-Checked -FilePath $ssh -ArgumentList @('-T', 'arm64-local', 'cmd /c echo no-pty-ok')
    if (-not ($noPtyOutput -match 'no-pty-ok')) {
        throw 'Non-PTY SSH command did not return expected output.'
    }
    $ptyOutput = Invoke-Checked -FilePath $ssh -ArgumentList @(
        '-tt',
        'arm64-local',
        'cmd /c echo pty-ok'
    )
    $ptyDeadline = (Get-Date).AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 100
        $sshdLogContent = Get-Content $sshdLog -Raw -ErrorAction SilentlyContinue
    } while ($sshdLogContent -notmatch 'Starting session: command on windows-pty' -and (Get-Date) -lt $ptyDeadline)
    if ($sshdLogContent -notmatch 'Starting session: command on windows-pty') {
        throw "sshd did not record a forced Windows PTY session.`n$($ptyOutput -join [Environment]::NewLine)"
    }

    $copySource = Join-Path $testRoot 'scp-source.txt'
    $copyRemote = Join-Path $testRoot 'scp-remote.txt'
    'scp-arm64-ok' | Set-Content -Path $copySource -Encoding ascii
    Invoke-Checked -FilePath $scp -ArgumentList @($copySource, "arm64-local:$(Convert-ToSshPath $copyRemote)")
    if ((Get-Content $copyRemote -Raw).Trim() -ne 'scp-arm64-ok') {
        throw 'scp content verification failed.'
    }

    $sftpSource = Join-Path $testRoot 'sftp-source.txt'
    $sftpRemote = Join-Path $testRoot 'sftp-remote.txt'
    $sftpDownloaded = Join-Path $testRoot 'sftp-downloaded.txt'
    $sftpBatch = Join-Path $testRoot 'sftp.batch'
    'sftp-arm64-ok' | Set-Content -Path $sftpSource -Encoding ascii
    @(
        "put `"$(Convert-ToSshPath $sftpSource)`" `"$(Convert-ToSshPath $sftpRemote)`""
        "get `"$(Convert-ToSshPath $sftpRemote)`" `"$(Convert-ToSshPath $sftpDownloaded)`""
    ) | Set-Content -Path $sftpBatch -Encoding ascii
    Invoke-Checked -FilePath $sftp -ArgumentList @('-b', $sftpBatch, 'arm64-local')
    if ((Get-Content $sftpDownloaded -Raw).Trim() -ne 'sftp-arm64-ok') {
        throw 'sftp content verification failed.'
    }

    $agentService = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'" -ErrorAction SilentlyContinue
    if ($agentService) {
        $agentServicePath = $agentService.PathName
        $agentServiceStartMode = $agentService.StartMode
        $agentServiceWasRunning = $agentService.State -eq 'Running'
        Stop-Service -Name ssh-agent -Force -ErrorAction SilentlyContinue
        Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
            'config',
            'ssh-agent',
            'binPath=',
            "`"$sshAgent`"",
            'start=',
            'demand'
        )
    }
    else {
        Invoke-Checked -FilePath 'sc.exe' -ArgumentList @(
            'create',
            'ssh-agent',
            'binPath=',
            "`"$sshAgent`"",
            'start=',
            'demand'
        )
        $agentServiceCreated = $true
    }
    Start-Service -Name ssh-agent
    Invoke-Checked -FilePath $sshAdd -ArgumentList @($clientKey)
    $agentKeys = Invoke-Checked -FilePath $sshAdd -ArgumentList @('-l')
    if (-not ($agentKeys -match 'ED25519')) {
        throw 'ssh-agent did not retain the ED25519 key.'
    }
    Invoke-Checked -FilePath $sshAdd -ArgumentList @('-D')

    $seedRepository = Join-Path $testRoot 'seed'
    $remoteRepository = Join-Path $testRoot 'remote.git'
    $cloneRepository = Join-Path $testRoot 'clone'
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('init', '-b', 'main', $seedRepository)
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'config', 'user.name', 'ARM64 OpenSSH CI')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'config', 'user.email', 'arm64-openssh-ci@example.invalid')
    'first' | Set-Content -Path (Join-Path $seedRepository 'payload.txt') -Encoding ascii
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'add', 'payload.txt')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'commit', '-m', 'initial')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('init', '--bare', $remoteRepository)
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'remote', 'add', 'origin', $remoteRepository)
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'push', '-u', 'origin', 'main')

    $env:GIT_SSH = $ssh
    $env:GIT_SSH_VARIANT = 'ssh'
    $remoteSshUrl = "arm64-local:$(Convert-ToSshPath $remoteRepository)"
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('clone', $remoteSshUrl, $cloneRepository)

    'second' | Set-Content -Path (Join-Path $seedRepository 'payload.txt') -Encoding ascii
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'add', 'payload.txt')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'commit', '-m', 'update')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $seedRepository, 'push')
    Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $cloneRepository, 'fetch', 'origin')
    $fetchedSubject = Invoke-Checked -FilePath $GitExecutable -ArgumentList @('-C', $cloneRepository, 'log', '-1', '--format=%s', 'origin/main')
    if ($fetchedSubject -ne 'update') {
        throw 'Git-over-SSH fetch did not receive the updated commit.'
    }

    $succeeded = $true
    Write-Host 'Passed ARM64 OpenSSH client smoke tests: keys, config, known_hosts, ProxyCommand, agent, scp, sftp, PTY, and Git clone/fetch.'
}
finally {
    $env:GIT_SSH = $oldGitSsh
    $env:GIT_SSH_VARIANT = $oldGitSshVariant

    Stop-Service -Name ssh-agent -Force -ErrorAction SilentlyContinue
    if ($agentServiceCreated) {
        & sc.exe delete ssh-agent | Out-Null
    }
    elseif ($agentService) {
        & sc.exe config ssh-agent 'binPath=' $agentServicePath | Out-Null
        switch ($agentServiceStartMode) {
            'Auto' { & sc.exe config ssh-agent 'start=' 'auto' | Out-Null }
            'Manual' { & sc.exe config ssh-agent 'start=' 'demand' | Out-Null }
            'Disabled' { & sc.exe config ssh-agent 'start=' 'disabled' | Out-Null }
        }
        if ($agentServiceWasRunning) {
            Start-Service -Name ssh-agent
        }
    }

    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    if ($sshdServiceCreated) {
        & sc.exe delete sshd | Out-Null
    }
    elseif ($sshdService) {
        & sc.exe config sshd 'binPath=' $sshdServicePath 'obj=' $sshdServiceStartName | Out-Null
        switch ($sshdServiceStartMode) {
            'Auto' { & sc.exe config sshd 'start=' 'auto' | Out-Null }
            'Manual' { & sc.exe config sshd 'start=' 'demand' | Out-Null }
            'Disabled' { & sc.exe config sshd 'start=' 'disabled' | Out-Null }
        }
        $serviceRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
        if ($sshdPrivilegesExisted) {
            Set-ItemProperty -Path $serviceRegistryPath -Name RequiredPrivileges -Value $sshdRequiredPrivileges
        }
        else {
            Remove-ItemProperty -Path $serviceRegistryPath -Name RequiredPrivileges -ErrorAction SilentlyContinue
        }
        if ($sshdServiceWasRunning) {
            Start-Service -Name sshd
        }
    }

    $openSshRegistryPath = 'HKLM:\SOFTWARE\OpenSSH'
    if ($defaultShellExisted) {
        Set-ItemProperty -Path $openSshRegistryPath -Name DefaultShell -Value $defaultShell
    }
    else {
        Remove-ItemProperty -Path $openSshRegistryPath -Name DefaultShell -ErrorAction SilentlyContinue
    }
    if (-not $openSshRegistryKeyExisted) {
        Remove-Item -Path $openSshRegistryPath -Force -ErrorAction SilentlyContinue
    }

    if (-not $succeeded -and $sshdLog -and (Test-Path $sshdLog) -and $env:GITHUB_WORKSPACE) {
        $smokeLogDirectory = Join-Path $env:GITHUB_WORKSPACE 'smoke-logs'
        $null = New-Item -ItemType Directory -Path $smokeLogDirectory -Force
        Copy-Item $sshdLog (Join-Path $smokeLogDirectory 'sshd.log') -Force
    }

    if ($profileConfigBackup) {
        Copy-Item $profileConfigBackup $profileConfig -Force
    }
    else {
        Remove-Item $profileConfig -Force -ErrorAction SilentlyContinue
    }
    Remove-Item (Join-Path $profileSshDirectory 'known_hosts-arm64-client') -Force -ErrorAction SilentlyContinue
    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
