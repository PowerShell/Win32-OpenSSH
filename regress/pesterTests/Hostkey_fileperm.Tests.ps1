Import-Module $PSScriptRoot\CommonUtils.psm1 -Force -DisableNameChecking
$tC = 1
$tI = 0
$suite = "hostkey_fileperm"
Describe "Tests for host keys file permission" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
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
        Remove-Item -Path (Join-Path $testDir "*$logName") -Force -ErrorAction ignore
    }

    AfterEach { $tI++ }

    Context "$tC - Host key files permission" {
        BeforeAll {
            $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
            $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
            
            $hostKeyFilePath = join-path $testDir hostkeyFilePermTest_ed25519_key
            if(Test-path $hostKeyFilePath -PathType Leaf) {
                Set-FileOwnerAndACL -filepath $hostKeyFilePath
            }
            if(Test-path "$hostKeyFilePath.pub" -PathType Leaf){
                Set-FileOwnerAndACL -filepath "$hostKeyFilePath.pub"
            }
            Remove-Item -path "$hostKeyFilePath*" -Force -ErrorAction Ignore
            ssh-keygen.exe -t ed25519 -f $hostKeyFilePath -P `"`"
            Get-Process -Name sshd | Where-Object {$_.SI -ne 0} | Stop-process
            $tI=1
        }

        BeforeEach {
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }

        AfterAll {
            if(Test-path $hostKeyFilePath -PathType Leaf){
                Adjust-UserKeyFileACL -Filepath $hostKeyFilePath -Owner $systemAccount
            }
            if(Test-path "$hostKeyFilePath.pub" -PathType Leaf){
                Adjust-UserKeyFileACL -Filepath "$hostKeyFilePath.pub" -Owner $systemAccount
            }
            $tC++
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups and running process can access to public key file)" {
            Set-FileOwnerAndACL -Filepath $hostKeyFilePath -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $systemAccount -Perms "FullControl"
            
            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $everyOne -Perms "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups and pwd user has explicit ACE)" {
            Set-FileOwnerAndACL -Filepath $hostKeyFilePath -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $currentUser -Perms "Read"
            
            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $everyOne -Perms "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 2 } }            

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by system and running process can access to public key file)" {               
            Set-FileOwnerAndACL -Filepath $hostKeyFilePath -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $adminAccount -Perms "Read"

            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $adminAccount -Perms "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }
            

            #validate file content does not contain unprotected info.
            $logPath | Should Not Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-negative (other account can access private key file)" {
            Set-FileOwnerAndACL -Filepath $hostKeyFilePath -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $adminAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $objUser -Perms "Read"
            
            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $everyOne -Perms "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_private: bad permissions"            
        }

        It "$tC.$tI-Host keys-negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $hostKeyFilePath -Owner $objUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $adminAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $systemAccount -Perms "FullControl"
            
            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $everyOne -Perms "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_private: bad permissions"
        }

        It "$tC.$tI-Host keys-negative (the running process does not have read access to public key)" {
            #setup to have ssouser as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $hostKeyFilePath -Owner $systemAccount -OwnerPerms "FullControl"            
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $adminAccount -Perms "Read"

            Set-FileOwnerAndACL -Filepath "$hostKeyFilePath.pub" -Owner $systemAccount -OwnerPerms "FullControl"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-h $hostKeyFilePath", "-E $logPath") -NoNewWindow
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }

            #validate file content contains unprotected info.
            $logPath | Should Contain "key_load_public: Permission denied"
        }
    }
}
