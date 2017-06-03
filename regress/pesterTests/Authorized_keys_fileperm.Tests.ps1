Import-Module $PSScriptRoot\CommonUtils.psm1 -Force -DisableNameChecking
$tC = 1
$tI = 0
$suite = "authorized_keys_fileperm"
Describe "Tests for authorized_keys file permission" -Tags "CI" {
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

        $fileName = "test.txt"
        $logName = "sshdlog.txt"
        $server = $OpenSSHTestInfo["Target"]
        $port = 47003
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $PwdUser = $OpenSSHTestInfo["PasswdUser"]
        $ssouserProfile = $OpenSSHTestInfo["SSOUserProfile"]
        Remove-Item -Path (Join-Path $testDir "*$fileName") -Force -ErrorAction ignore
    }

    AfterEach { $tI++ }

    Context "Authorized key file permission" {
        BeforeAll {
            $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
            $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))

            $ssouserSSHProfilePath = Join-Path $ssouserProfile .testssh
            if(-not (Test-Path $ssouserSSHProfilePath -PathType Container)) {
                New-Item $ssouserSSHProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
            }
            $authorizedkeyPath = Join-Path $ssouserProfile .testssh\authorized_keys
            $Source = Join-Path $ssouserProfile .ssh\authorized_keys
            $testknownhosts = Join-path $PSScriptRoot testdata\test_known_hosts
            Copy-Item $Source $ssouserSSHProfilePath -Force -ErrorAction Stop

            Adjust-UserKeyFileACL -Filepath $authorizedkeyPath -Owner $objUser -OwnerPerms "Read, Write"

            Get-Process -Name sshd | Where-Object {$_.SI -ne 0} | Stop-process
            #add wrong password so ssh does not prompt password if failed with authorized keys
            Add-PasswordSetting -Pass "WrongPass"
            $tI=1
        }

        AfterAll {
            if(Test-Path $authorizedkeyPath) {
                Adjust-UserKeyFileACL -Filepath $authorizedkeyPath -Owner $objUser -OwnerPerms "Read, Write"
                Remove-Item $authorizedkeyPath -Force -ErrorAction Ignore
            }
            if(Test-Path $ssouserSSHProfilePath) {            
                Remove-Item $ssouserSSHProfilePath -Force -ErrorAction Ignore -Recurse
            }
            Remove-PasswordSetting
            $tC++
        }

        BeforeEach {
            $filePath = Join-Path $testDir "$tC.$tI.$fileName"            
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }       

        It "$tC.$tI-authorized_keys-positive(pwd user is the owner and running process can access to the file)" {
            #setup to have ssouser as owner and grant ssouser read and write, admins group, and local system full control            
            Adjust-UserKeyFileACL -Filepath $authorizedkeyPath -Owner $objUser -OwnerPerms "Read, Write"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts" echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by local system)" {
            #setup to have system as owner and grant it full control            
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $adminAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $objUser -Perms "Read, Write"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd does not have explict ACE)" {
            #setup to have admin group as owner and grant it full control
            
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"            

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd have explict ACE)" {
            #setup to have admin group as owner and grant it full control
            
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $objUser -Perms "Read, Write"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other admin user)" {
            #setup to have current user (admin user) as owner and grant it full control
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $currentUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $adminAccount -Perms "FullControl"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            $matches = Get-Content $filePath | Select-String -pattern "^Permission denied"
            $matches.Count | Should BeGreaterThan 2
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-negative(other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $objUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $adminAccount -Perms "FullControl"

            #add $PwdUser to access the file authorized_keys
            $objPwdUser = New-Object System.Security.Principal.NTAccount($PwdUser)
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $objPwdUser -Perm "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            $matches = Get-Content $filePath | Select-String -pattern "^Permission denied"
            $matches.Count | Should BeGreaterThan 2
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other non-admin user)" {
            #setup to have PwdUser as owner and grant it full control
            $objPwdUser = New-Object System.Security.Principal.NTAccount($PwdUser)
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -owner $objPwdUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $adminAccount -Perms "FullControl"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $FilePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            $matches = Get-Content $filePath | Select-String -pattern "^Permission denied"
            $matches.Count | Should BeGreaterThan 2
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }  
        }
        It "$tC.$tI-authorized_keys-negative(the running process does not have read access to the authorized_keys)" {
            #setup to have ssouser as owner and grant it full control            
            Set-FileOwnerAndACL -Filepath $authorizedkeyPath -Owner $objUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $systemAccount -Perms "FullControl"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $matches = Get-Content $filePath | Select-String -pattern "^Permission denied"
            $matches.Count | Should BeGreaterThan 2
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } } 
        }
    }
}
