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

Class Machine
{
    [string] $MachineName = $env:COMPUTERNAME
    [MachineRole] $Role = [MachineRole]::Client

    #Members on server role
    [string []] $PublicHostKeyPaths
    [string []] $PrivateHostKeyPaths
    [string] $localAdminUserName = "localadmin"
    [string] $localAdminPassword = "Bull_dog1"
    [string] $localAdminAuthorizedKeyPath
    [System.Security.SecureString] $password
    $preLatfpSetting
    $localUserprofilePath

    #Members on client role
    [string []] $clientPrivateKeyPaths
    [string []] $clientPublicKeyPaths
    [string] $ClientKeyDirectory
    [string] $knownHostOfCurrentUser    
    [string] $OpenSSHdir = $PSScriptRoot
    [string] $ToolsPath = "$PSScriptRoot\pstools"

    Machine() {
        $IsWindows = $this.IsWindows()
        $this.InitializeClient()
        $this.InitializeServer()
    }

    Machine ([MachineRole] $r) {
        $IsWindows = $this.IsWindows()
        $this.Role = $r
        if($this.Role -eq [MachineRole]::Client) {
            $this.InitializeClient()
        } else {
            $this.InitializeServer()
        }        
    }    

    [void] InitializeClient() {
        $this.ClientKeyDirectory = join-path ($env:USERPROFILE) ".ssh"
        Remove-Item -Path "$($this.ClientKeyDirectory)\*" -Force -ea silentlycontinue

        $this.knownHostOfCurrentUser = join-path ($env:USERPROFILE) ".ssh/known_hosts"

        if ($this.IsWindows)
        {
            $this.ToolsPath = "$PSScriptRoot\pstools"
            #download pstools
	        $this.DownloadPStools("https://download.sysinternals.com/files/PSTools.zip", $PSScriptRoot)
        }
        
        foreach($key in @("rsa","dsa","ecdsa","ed25519"))
        {
            $keyPath = "$($this.ClientKeyDirectory)\id_$key"
            $this.clientPrivateKeyPaths += $keyPath
            $this.clientPublicKeyPaths += "$keyPath.pub"
            $str = ".\ssh-keygen -t $key -P """" -f $keyPath"
            $this.RunCmd($str)
            
        }
    }

    [void] InitializeServer() {
        if ($this.IsWindows)
        {
            #Start-Service sshd
            #load the profile to create the profile folder
            $this.SetLocalAccountTokenFilterPolicy(1)
        }

        $this.password = ConvertTo-SecureString -String $this.localAdminPassword -AsPlainText -Force
        $this.AddAdminUser($this.localAdminUserName, $this.password)
        
        $this.localUserprofilePath = $this.GetUserProfileLocation($this)
        $this.localAdminAuthorizedKeyPath = join-path $($this.localUserprofilePath)  ".ssh/authorized_keys"
        Remove-Item -Path $($this.localAdminAuthorizedKeyPath) -Force -ea silentlycontinue

        #Generate all host keys
        .\ssh-keygen -A
        $this.PublicHostKeyPaths = @("$psscriptroot\ssh_host_rsa_key.pub","$psscriptroot\ssh_host_dsa_key.pub","$psscriptroot\ssh_host_ecdsa_key.pub","$psscriptroot\ssh_host_ed25519_key.pub")
        $this.PrivateHostKeyPaths = @("$psscriptroot\ssh_host_rsa_key","$psscriptroot\ssh_host_dsa_key","$psscriptroot\ssh_host_ecdsa_key","$psscriptroot\ssh_host_ed25519_key")
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

    [void] SetupServerRemoting([Protocol] $protocol) {
        if ($this.IsWindows)
        {
            switch($protocol )
            {
                ([Protocol]::SSH) {
                    $env:Path = "$env:Path;$PSScriptRoot"
                    Restart-Service sshd
                }
                ([Protocol]::WSMAN) {
                    Enable-PSRemoting -Force
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
    }

    [void] CleanupServer() {        
        Remove-Item -Path $this.localAdminAuthorizedKeyPath -Force -ea silentlycontinue
        if ($this.IsWindows)
        {
            $this.CleanupLocalAccountTokenFilterPolicy()
        }
    }

    [void] CleanupClient() {
        Remove-Item -Path "$this.clientKeyPath\*" -Force -ea silentlycontinue
    }

    [bool] IsWindows() {     
        return $env:OS.contains("Windows")    
    }

    [void] RunCmd($Str) {        
        if ($this.IsWindows())
        {
            cmd /c $Str
        }
    }

    [void] AddAdminUser($UserName, $password) {        
        if ($this.IsWindows) {
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
            #Todo add local user and add it to administrators group on linux
            #Todo: get $localUserprofilePath    
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
        if ($this.IsWindows)
        {            
            #TODO: Remove the path to OpenSSHDir from the string link
            #Secure host-keys with psexec 
            foreach($key in $keys) {              
	            & "$($this.ToolsPath)\psexec" -accepteula -nobanner -i -s -w $($this.OpenSSHdir) cmd.exe /c "ssh-add.exe $key"
            }
        }
    }

    [void] CleanupHostKeys() {
        if ($this.IsWindows)
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

    [void] DownloadPStools ( [string]$URL, [string]$DestDir)
     {
            
        if ( -not (Test-Path $($this.ToolsPath) ) ) {
            New-Item -ItemType Directory -Force -Path $($this.ToolsPath) | out-null
        }
	    $parsed = Split-Path $URL -Leaf
        $psexecZipFile = Join-Path $DestDir $parsed

	    if ( -not (Test-Path $psexecZipFile) ) {
            start-bitstransfer -Destination $DestDir $URL
        }
            
	    if ( -not (Test-Path "$($this.ToolsPath)\psexec.exe")) {                
            $this.UnzipFile($psexecZipFile, $this.ToolsPath)
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
