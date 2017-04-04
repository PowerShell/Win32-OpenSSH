#Abstract layer
Enum MachineRole {
    Client
    Server
}

Enum Protocol
{
    WSMAN
    SSH
}

Enum PlatformType {
    Windows
    Linux
    OSX
}

function Set-Platform {
    # Use the .NET Core APIs to determine the current platform; if a runtime
    # exception is thrown, we are on FullCLR, not .NET Core.
    try {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]
        $OSPlatform = [System.Runtime.InteropServices.OSPlatform]
        
        $IsLinux = $Runtime::IsOSPlatform($OSPlatform::Linux)
        $IsOSX = $Runtime::IsOSPlatform($OSPlatform::OSX)
        $IsWindows = $Runtime::IsOSPlatform($OSPlatform::Windows)
    } catch {    
        try {            
            $IsLinux = $false
            $IsOSX = $false
            $IsWindows = $true
        }
        catch { }
    }
    if($IsOSX) {
        [PlatformType]::OSX
    } elseif($IsLinux) {
        [PlatformType]::Linux
    } else {        
        [PlatformType]::Windows    
    }
}

function Is-CoreCLR {
    # Use the .NET Core APIs to determine the current platform; if a runtime
    # exception is thrown, we are on FullCLR, not .NET Core.
    try {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]        
        $IsCoreCLR = $true        
    } catch {    
        try {
            $IsCoreCLR = $false            
        }
        catch { }
    }
    if($IsCoreCLR)
    {
        $true
    }
    $false
}

Class Machine
{
    [string] $MachineName = "localhost"
    [MachineRole] $Role = [MachineRole]::Client
    [PlatformType] $Platform
    [boolean] $IsCoreCLR

    #Members on server role
    [string []] $PublicHostKeyPaths
    [string []] $PrivateHostKeyPaths
    [string] $ssouser = "sshtest_ssouser"
    [string] $passwduser = "sshtest_passwduser"
    [string] $passwduser_pw = "P@ssw0rd_1"
    [string] $localAdminAuthorizedKeyPath
    [string] $sshdConfigFile = (join-path $PSScriptRoot "sshd_config")
    [string] $backupFileName = (join-path $PSScriptRoot "sshd_backup")
    [System.Security.SecureString] $password
    $preLatfpSetting
    [string] $localUserprofilePath

    #Members on client role
    [string []] $clientPrivateKeyPaths
    [string []] $clientPublicKeyPaths
    [string] $ClientKeyDirectory
    [string] $knownHostOfCurrentUser    
    [string] $OpenSSHdir = $PSScriptRoot
    [string] $ToolsPath = "$env:ProgramData\chocolatey\lib\sysinternals\tools"    

    Machine() {
        $this.Platform = Set-Platform        
        $this.IsCoreCLR = Is-CoreCLR
        #$this.InitializeClient()
        #$this.InitializeServer()
    }

    Machine ([MachineRole] $r) {
        $this.Platform = Set-Platform        
        $this.IsCoreCLR = Is-CoreCLR
        $this.Role = $r
        #if($this.Role -eq [MachineRole]::Client) {
        #    $this.InitializeClient()
        #} else {
        #    $this.InitializeServer()
        #}        
    }    

    [void] InitializeClient() {
        $this.ClientKeyDirectory = join-path $PSScriptRoot "clientkeys"
        if(-not (Test-path $this.ClientKeyDirectory -PathType Container))
        {
            New-Item -Path $this.ClientKeyDirectory -ItemType Directory -Force -ErrorAction silentlycontinue
        }

        Remove-Item -Path "$($this.ClientKeyDirectory)\*" -Force -ea silentlycontinue        

        $this.knownHostOfCurrentUser = join-path ($env:USERPROFILE) ".ssh/known_hosts"

        if ($this.Platform -eq [PlatformType]::Windows)
        {
            $this.ToolsPath = "$env:ProgramData\chocolatey\lib\sysinternals\tools"
            #download pstools
            if ( -not (Test-Path (join-path $($this.ToolsPath) "psexec.exe" ))) {
	            $this.DownloadPStools()
            }
        }
        
    }

    [void] InitializeServer() {
        if ($this.Platform -eq [PlatformType]::Windows)
        {
            #Start-Service sshd
            #load the profile to create the profile folder
            $this.SetLocalAccountTokenFilterPolicy(1)
        }

        $this.password = ConvertTo-SecureString -String $this.localAdminPassword -AsPlainText -Force
        $this.AddAdminUser($this.localAdminUserName, $this.password)
        
        $this.SetupServerRemoting([Protocol]::WSMAN)
        $this.localUserprofilePath = $this.GetUserProfileLocation($this)
        $sshPath = join-path $($this.localUserprofilePath)  ".ssh"
        if(-not (Test-path $sshPath -PathType Container))
        {
            New-Item -Path $sshPath -ItemType Directory -Force -ErrorAction silentlycontinue
        }
        $this.localAdminAuthorizedKeyPath = join-path $($this.localUserprofilePath)  ".ssh/authorized_keys"
        Remove-Item -Path $($this.localAdminAuthorizedKeyPath) -Force -ea silentlycontinue
    }

    [void] SetupClient([Machine] $server) {
        #add the host keys known host on client
        
        if( -not (Test-Path $($this.knownHostOfCurrentUser ) ) )
        {
            $null = New-item -path $($this.knownHostOfCurrentUser) -force
        }
        foreach($keypath in $server.PublicHostKeyPaths)
        {
            $this.SetKeys($($server.MachineName), $keypath,  $($this.knownHostOfCurrentUser))
        }
    }

    [void] SetupSingleSignon([string] $identifyFile) {
        .\ssh-add.exe $identifyFile
    }

    [void] CleanupSingleSignon([string] $identifyFile) {
        .\ssh-add.exe -d $identifyFile
    }

    [void] AddItemInSSHDConfig([string] $key, [string] $value) {
        if ( $this.Platform -eq [PlatformType]::Windows ) {
                Get-Content $this.sshdConfigFile | % {
                    if($_.StartsWith($key)) {
                        "#$_"
                    }
                    else {$_}
                } | Set-Content $this.sshdConfigFile
            Add-Content -Path $this.sshdConfigFile -Value "`r`n$key $value"

            Restart-Service sshd
        } else {               
        }
    }

    [void] BackupSSHDConfig() {
        if ( $this.Platform -eq [PlatformType]::Windows ) {
            if(Test-path $this.backupFileName) {
                Remove-Item -Path $this.backupFileName -Force
            }

            Copy-Item $this.sshdConfigFile $this.backupFileName -Force
        }
    }

    [void] RestoreSSHDConfig() {
        if ( $this.Platform -eq [PlatformType]::Windows ) {
            Copy-Item $this.backupFileName $this.sshdConfigFile  -Force
            Remove-Item -Path $this.backupFileName -Force
            Restart-Service sshd
        }
    }

    [void] SetupServerRemoting([Protocol] $protocol) {
        if ($this.Platform -eq [PlatformType]::Windows)
        {
            switch($protocol )
            {
                ([Protocol]::SSH) {
                    $env:Path = "$env:Path;$PSScriptRoot"
                    Restart-Service sshd
                }
                ([Protocol]::WSMAN) {
                    if( (Get-ComputerInfo).osproductType -notcontains 'Server' )
                        {
                            Enable-PSRemoting -Force
                        }
                }
                default {
                }
            }
        }
    }    

    [void] SetupServer([Machine] $client) {
        if( -not (Test-Path $($this.localAdminAuthorizedKeyPath ) ) )
        {
            $null = New-item -path $($this.localAdminAuthorizedKeyPath) -force
        }
        
        foreach($publicKeyPath in $client.clientPublicKeyPaths)
        {
            $this.SetKeys($null, $publicKeyPath, $($this.localAdminAuthorizedKeyPath))
        }        
        # Provide Read Access to NT Service\sshd
        $acl = get-acl $($this.localAdminAuthorizedKeyPath)
        $ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("NT Service\sshd", "Read", "Allow")
        $acl.SetAccessRule($ar)
        Set-Acl  $($this.localAdminAuthorizedKeyPath) $acl
    }

    [void] CleanupServer() {
        $sshPath = split-path $this.localAdminAuthorizedKeyPath -Parent
        if(Test-Path $sshPath -PathType Container )
        {
            Remove-item -path $sshPath -force -Recurse
        }

        if ( $this.Platform -eq [PlatformType]::Windows )
        {
            $this.CleanupLocalAccountTokenFilterPolicy()
        }
    }

    [void] CleanupClient() {                
        Remove-item -path $($this.ClientKeyDirectory) -force -Recurse -ea silentlycontinue
        $sshPath = split-path $this.knownHostOfCurrentUser -Parent
        if(Test-Path $sshPath -PathType Container )
        {
            Remove-item -path $sshPath -force -Recurse
        }
        $this.CleanupPasswordSetting()
    }

    [void] RunCmd($Str) {        
        if ($this.Platform -eq [PlatformType]::Windows)
        {
            cmd /c $Str
        }
    }

    [void] AddLocalUser($UserName, $password) {
        $a = Get-LocalUser -Name $UserName -ErrorAction Ignore
        if ($a -eq $null)
        {
            $pass = ConvertTo-SecureString -String $this.localAdminPassword -AsPlainText -Force
            $a = New-LocalUser -Name $UserName -Password $pass -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword                
        }
    }

    [void] AddLocalGroup($groupName) {
        $g = Get-LocalGroup -Name $groupName -ErrorAction Ignore
        if ($g -eq $null)
        {                
            $g = New-LocalGroup -Name $groupName
        }
    }

    [void] AddUserToLocalGroup($UserName, $password, $groupName) {        
        if ( $this.Platform -eq [PlatformType]::Windows ) {
            $this.AddLocalUser($UserName, $password)
            $this.AddLocalGroup($groupName)

            if((Get-LocalGroupMember -Name $groupName -Member $UserName -ErrorAction Ignore ) -eq $null)
            {
                Add-LocalGroupMember -Name $groupName -Member $UserName
            }
        } else {    
            #Todo add local user and add it to a user group on linux
        }
    }

    [void] RemoveUserFromLocalGroup($UserName, $groupName) {        
        if ( $this.Platform -eq [PlatformType]::Windows ) {
            if((Get-LocalGroupMember -Name $groupName -Member $UserName -ErrorAction Ignore ) -eq $null)
            {
                Remove-LocalGroupMember -Name $groupName -Member $UserName
            }
        } else {    
            #Todo add local user and add it to a user group on linux
        }
    }

    [void] ClenaupLocalGroup($groupName) {
        $g = Get-LocalGroup -Name $groupName -ErrorAction Ignore
        if ($g -eq $null)
        {                
            $g | Remove-LocalGroup
        }
    }

    [void] AddAdminUser($UserName, $password) {        
        if ( $this.Platform -eq [PlatformType]::Windows ) {
            $a = Get-LocalUser -Name $UserName -ErrorAction Ignore
            if ($a -eq $null)
            {                
                $a = New-LocalUser -Name $UserName -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword                
            }

            if((Get-LocalGroupMember -SID s-1-5-32-544 -Member $a -ErrorAction Ignore ) -eq $null)
            {
                Add-LocalGroupMember -SID s-1-5-32-544 -Member $a
            }
        } else {    
            #Todo add local user and add it to a administrators on linux             
        }
    }

    [void] AddPasswordSetting([string] $pass) {
        if ($this.Platform -eq [PlatformType]::Windows) {
            if (-not($env:DISPLAY)) {$env:DISPLAY=1}
            $env:SSH_ASKPASS="$($env:ComSpec) /c echo $pass"
        }
    }

    [void] CleanupPasswordSetting() {
        if ($this.Platform -eq [PlatformType]::Windows -and (Test-Path env:SSH_ASKPASS))
        {
            if ($env:DISPLAY -eq 1) {Remove-Item env:\DISPLAY}
            remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
        }
    }

    #Set LocalAccountTokenFilterPolicy
    [void] SetLocalAccountTokenFilterPolicy($setting) {        
        $path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\system"
        #load the profile to create the profile folder
        $this.preLatfpSetting = get-ItemProperty -Path $path -Name LocalAccountTokenFilterPolicy -ErrorAction Ignore
        if( $this.preLatfpSetting -eq $null)
        {
            New-ItemProperty -Path $path -Name LocalAccountTokenFilterPolicy -Value $setting -PropertyType DWord
        }
        else
        {
            Set-ItemProperty -Path $path -Name LocalAccountTokenFilterPolicy -Value $setting
        }    
    }

    [void] CleanupLocalAccountTokenFilterPolicy() {    
        if($this.preLatfpSetting -eq $null)
        {
            Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\system -Name LocalAccountTokenFilterPolicy -Force -ErrorAction SilentlyContinue
        }
        else
        {
            Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\system -Name LocalAccountTokenFilterPolicy -Value $this.preLatfpSetting.LocalAccountTokenFilterPolicy
        }
    }

    [void] SecureHostKeys([string[]] $keys) {
        if ( $this.Platform -eq [PlatformType]::Windows )
        {            
            #TODO: Remove the path to OpenSSHDir from the string link
            #Secure host-keys with psexec 
            foreach($key in $keys) {              
	            & "$($this.ToolsPath)\psexec" -accepteula -nobanner -i -s -w $($this.OpenSSHdir) cmd.exe /c "ssh-add.exe $key"
            }
        }
    }

    [void] CleanupHostKeys() {
        if ( $this.Platform -eq [PlatformType]::Windows )
        {
            & "$($this.ToolsPath)\psexec" -accepteula -nobanner -i -s -w $($this.OpenSSHdir) cmd.exe /c "ssh-add.exe -D"
        }
    }

    [string] GetUserProfileLocation([Machine] $remote ) {        
        #load the profile to create the profile folder        
        $pscreds = [System.Management.Automation.PSCredential]::new($($remote.MachineName) + "\" + $($remote.localAdminUserName), $($remote.password))
        $ret = Invoke-Command -Credential $pscreds -ComputerName $($remote.MachineName) -command {$env:userprofile}
        return $ret
    }

    [void] UnzipFile($argVar, $targetondisk ) {    
	    $shell_app=new-object -com shell.application
	    $zip_file = $shell_app.namespace($argVar)
	    Write-Host "Uncompressing zip file to $($targetondisk)" -ForegroundColor Cyan
	    $destination = $shell_app.namespace($targetondisk)
	    $destination.Copyhere($zip_file.items(), 0x10)
	    $shell_app = $null
    }

    #this does not work when "using module"; works fine when import the module
    [void] DownloadPStools()
     {
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
        $newMachineEnvironmentPath = $machinePath
        # Install chocolatey
        $chocolateyPath = "$env:AllUsersProfile\chocolatey\bin"
        if(Get-Command "choco" -ErrorAction SilentlyContinue)
        {
            Write-Information -MessageData "Chocolatey is already installed. Skipping installation."
        }
        else
        {
            Write-Information -MessageData  "Chocolatey not present. Installing chocolatey."
            Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))

            if (-not ($machinePath.ToLower().Contains($chocolateyPath.ToLower())))
            {
                Write-Information -MessageData "Adding $chocolateyPath to Path environment variable"
                $newMachineEnvironmentPath += ";$chocolateyPath"
                $env:Path += ";$chocolateyPath"
            }
            else
            {
                Write-Information -MessageData "$chocolateyPath already present in Path environment variable"
            }
        }

        if ( -not (Test-Path $($this.ToolsPath) ) ) {
            Write-Information -MessageData "sysinternals not present. Installing sysinternals."
            choco install sysinternals -y            
        }
        else
        {
            Write-Information -MessageData "sysinternals present. Skipping installation."
        }	    
    }

    [void] SetKeys($Hostnames, $keyPath, $Path) {
        if($Hostnames -ne $null)
        {
            foreach ($hostname in $Hostnames)
            {                
                ($hostname + " " + (Get-Content $keyPath)) | Out-File -Append $Path -Encoding ascii
            }
        }
        else
        {
            Get-Content $keyPath | Out-File -Append $Path -Encoding ascii
        }
    } 
}
