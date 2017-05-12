Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Describe "Tests for authorized_keys file permission" -Tags "CI" {
    BeforeAll {    
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\authorized_keys_fileperm"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName
        $logName = "log.txt"
        $logPath = Join-Path $testDir $logName
        $server = $OpenSSHTestInfo["Target"]
        $port = 47003
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $PwdUser = $OpenSSHTestInfo["PasswdUser"]
        $ssouserProfile = $OpenSSHTestInfo["SSOUserProfile"]
        $script:logNum = 0

        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {         
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore            
        }        

        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterEach {        
        if( $OpenSSHTestInfo["DebugMode"])
        {
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedagent$script:logNum.log" -Force -ErrorAction ignore            
            Copy-Item $logPath "$($script:logNum)$($logPath)" -Force -ErrorAction ignore
            Clear-Content $logPath -Force -ErrorAction ignore                    
            $script:logNum++
                    
            # clear the ssh-agent so that next testcase will get fresh logs.
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore            
        }
    }

    Context "Authorized key file permission" {
        BeforeAll {            
            $ssouserSSHProfilePath = Join-Path $ssouserProfile .testssh
            if(-not (Test-Path $ssouserSSHProfilePath -PathType Container)) {
                New-Item $ssouserSSHProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
            }
            $authorizedkeyPath = Join-Path $ssouserProfile .testssh\authorized_keys
            $Source = Join-Path $ssouserProfile .ssh\authorized_keys
            $testknownhosts = Join-path $PSScriptRoot testdata\test_known_hosts
            if(Test-Path $authorizedkeyPath) {
                Set-SecureFileACL -filepath $authorizedkeyPath
            }
            Copy-Item $Source $ssouserSSHProfilePath -Force -ErrorAction Stop            

            Remove-Item $filePath -Force -ErrorAction Ignore
            Get-Process -Name sshd | Where-Object {$_.SI -ne 0} | Stop-process
            #add wrong password so ssh does not prompt password if failed with authorized keys
            Add-PasswordSetting -Pass "WrongPass"
        }

        AfterAll {
            if(Test-Path $authorizedkeyPath) {
                Set-SecureFileACL -filepath $authorizedkeyPath
                Remove-Item $authorizedkeyPath -Force -ErrorAction Ignore
            }
            if(Test-Path $ssouserSSHProfilePath) {            
                Remove-Item $ssouserSSHProfilePath -Force -ErrorAction Ignore
            }
            Remove-PasswordSetting
        }

        AfterEach {
            Remove-Item -Path $filePath -Force -ErrorAction ignore            
        }

        It 'Authorized key file -- positive (authorized_keys is owned by current user and running process can access to the file)' {
            #setup to have current user (admin user) as owner and grant it full control
            Set-SecureFileACL -filepath $authorizedkeyPath

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It 'Authorized key file -- positive (Secured file and sshd can access to the file)' {
            #setup to have ssouser as owner and grant it full control
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath $authorizedkeyPath -Owner $objUser

            #add running process account Read access the file authorized_keys
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $currentUser -Perm "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            $o | Should Be "1234"
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It 'Authorized key file -- negative (other account can access private key file)' {
            #setup to have current user as owner and grant it full control
            Set-SecureFileACL -filepath $authorizedkeyPath
            #add $PwdUser to access the file authorized_keys
            $objPwdUser = New-Object System.Security.Principal.NTAccount($PwdUser)
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $objPwdUser -Perm "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            $matches = Get-Content $filePath | Select-String -pattern "Permission denied"
            $matches.Count | Should Not Be 0
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }            
        }

        It 'Authorized key file -- negative (the authorized_keys has wrong owner)' {
            #setup to have ssouser as owner and grant it full control
            $objPwdUser = New-Object System.Security.Principal.NTAccount($PwdUser)
            Set-SecureFileACL -filepath $authorizedkeyPath -owner $objPwdUser

            #add current user full access the file authorized_keys
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            Add-PermissionToFileACL -FilePath $authorizedkeyPath -User $currentUser -Perm "FullControl"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            $matches = Get-Content $filePath | Select-String -pattern "Permission denied"
            $matches.Count | Should Not Be 0
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } }  
        }
        It 'Authorized key file -- negative (the running process does not have read access to the authorized_keys)' {
            #setup to have ssouser as owner and grant it full control
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath $authorizedkeyPath -Owner $objUser

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-o `"AuthorizedKeysFile .testssh/authorized_keys`"", "-E $logPath") -NoNewWindow
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $matches = Get-Content $filePath | Select-String -pattern "Permission denied"
            $matches.Count | Should Not Be 0
            
            #Cleanup
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Start-sleep 1; Stop-Process $_; Start-sleep 1 } } 
        }
    }
}
