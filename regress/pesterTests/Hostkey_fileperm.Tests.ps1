If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "hostkey_fileperm"
Describe "Tests for host keys file permission" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        
        $logName = "sshdlog.txt"
        $port = 47003
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $script:logNum = 0
        Remove-Item -Path (Join-Path $testDir "*$logName") -Force -ErrorAction SilentlyContinue        
        $platform = Get-Platform
        $skip = ($platform -eq [PlatformType]::Windows) -and ($PSVersionTable.PSVersion.Major -le 2)
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }
    }

    AfterEach { $tI++ }
    AfterAll {
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }

    Context "$tC - Host key files permission" {
        BeforeAll {
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
            $objUserSid = Get-UserSID -User $ssouser
            $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)
            
            $hostKeyFilePath = join-path $testDir hostkeyFilePermTest_ed25519_key
            if(Test-path $hostKeyFilePath -PathType Leaf) {
                Repair-SshdHostKeyPermission -filepath $hostKeyFilePath -confirm:$false
            }
            Remove-Item -path "$hostKeyFilePath*" -Force -ErrorAction SilentlyContinue
            ssh-keygen.exe -t ed25519 -f $hostKeyFilePath -P `"`"
            Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
            $tI=1
            
            function WaitForValidation
            {
                param([string]$logPath, [int]$length)
                $num = 0
                while((-not (Test-Path $logPath -PathType leaf)) -or ((Get-item $logPath).Length -lt $length) -and ($num++ -lt 4))
                {
                    Start-Sleep -Milliseconds 1000
                }
                Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
                
                $num = 0
                while ([string]::IsNullorEmpty($(Get-Content $logPath -ErrorAction SilentlyContinue | Out-String)) -and ($num++ -lt 4))
                {
                    Start-Sleep -Milliseconds 1000
                }
            }
        }

        BeforeEach {
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }

        AfterAll {
            if(Test-path $hostKeyFilePath -PathType Leaf) {
                Repair-SshdHostKeyPermission -filepath $hostKeyFilePath -confirm:$false
            }
            $tC++
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups and running process can access to public key file)" {            
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
        
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 600            

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
            
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups and pwd user has explicit ACE)" {            
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $everyOneSid -confirm:$false

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 600         

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by system and running process can access to public key file)" -skip:$skip {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Set-FilePermission -Filepath $hostKeyFilePath -UserSid $adminsSid -Action Delete
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Set-FilePermission -Filepath "$hostKeyFilePath.pub" -UserSid $adminsSid -Action Delete
            
            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 600

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-negative (other account can access private key file)" {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $objUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $everyOneSid -confirm:$false
            
            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 1100

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_private: bad permissions"            
        }

        It "$tC.$tI-Host keys-negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $objUserSid -FullAccessNeeded $systemSid,$adminsSid,$objUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $everyOneSid -confirm:$false

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 1100

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_private: bad permissions"
        }

        It "$tC.$tI-Host keys-negative (the running process does not have read access to public key)" -skip:$skip {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -confirm:$false            
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $systemSid -FullAccessNeeded $systemSid -confirm:$false
            Set-FilePermission -Filepath "$hostKeyFilePath.pub" -UserSid $adminsSid -Action Delete

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            WaitForValidation -LogPath $logPath -Length 1100

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_public: Permission denied"
        }
    }
}
