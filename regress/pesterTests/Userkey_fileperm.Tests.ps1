Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Describe "Tests for user Key file permission" -Tags "Scenario" {
    BeforeAll {    
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\usertkey_fileperm"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $pubKeyUser = $OpenSSHTestInfo["PubKeyUser"]
        $pubKeyUserProfile = $OpenSSHTestInfo["PubKeyUserProfile"]
        $server = $OpenSSHTestInfo["Target"]
        $keyFileName = "sshtest_userPermTestkey_ed25519"
        $keyFilePath = Join-Path $testDir $keyFileName
        Remove-Item -path "$keyFilePath*" -Force -ErrorAction Ignore
        ssh-keygen.exe -t ed25519 -f $keyFilePath -P `"`" 
        $userName = "$env:USERNAME@$env:USERDOMAIN"
        if(Test-Path $keyFilePath) {
            Set-SecureFileACL -filepath $keyFilePath
        }
        #add wrong password so ssh does not prompt password if failed with authorized keys
        Add-PasswordSetting -Pass "WrongPass"
    }

    AfterAll {
        Remove-PasswordSetting
    }

    <# comment the test out since ssh-add have impact on 
    existing default test environment.
    Context "ssh-add key files" {
        BeforeEach {
            ssh-add -D 2>&1 > $fileName
        }

        AfterEach {
            ssh-add -D 2>&1 > $fileName
            if(Test-Path $keyFilePath) {
                Set-SecureFileACL -filepath $keyFilePath
            }            
        }

        It 'ssh-add positive (Secured private key owned by current user)' {
            #setup to have current user as owner and grant it full control        
            Set-SecureFileACL -filepath $keyFilePath
            ssh-add $keyFilePath 2>&1 > $fileName
            $LASTEXITCODE | Should Be 0
            $o = ssh-add -l
            $matches = $o | Select-String -pattern "no identities"
            $matches.Count | Should Be 0

            $matches = $o | Select-String -pattern $userName
            $matches.Count | Should Be 1
        }

        It 'ssh-add positive (Secured private key owned by Administrators group)' {
            #setup to have local admin group as owner and grant it full control
            $objAdmin = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
            Set-SecureFileACL -filepath $keyFilePath -Owner $objAdmin
            ssh-add $keyFilePath 2>&1 > $fileName
            $LASTEXITCODE | Should Be 0
            $o = ssh-add -l
            $matches = $o | Select-String -pattern "no identities"
            $matches.Count | Should Be 0

            $matches = $o | Select-String -pattern $userName
            $matches.Count | Should Be 1
        }
        
        It 'ssh-add -- negative (other account can access private key file)' {
            #setup to have current user as owner and grant it full control        
            Set-SecureFileACL -filepath $keyFilePath            

            #add ssouser to access the private key
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Add-PermissionToFileACL -FilePath $keyFilePath -User $objUser -Perm "Read"

            ssh-add $keyFilePath 2>&1 > $fileName
            $LASTEXITCODE | Should Not Be 0
            $o = ssh-add -l
            $matches = $o | Select-String -pattern "no identities"
            $matches.Count | Should Be 1
        }

        It 'ssh-add -- negative (the private key has wrong owner)' {
            #setup to have ssouser as owner and grant it full control
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath $keyFilePath -owner $objUser
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            Add-PermissionToFileACL -FilePath $keyFilePath -User $currentUser -Perm "FullControl"

            ssh-add $keyFilePath 2>&1 > $fileName
            $LASTEXITCODE | Should Not Be 0
            $o = ssh-add -l
            $matches = $o | Select-String -pattern "no identities"
            $matches.Count | Should Be 1
        }
    }#>

    Context "ssh with private key file" {
        BeforeAll {
            $pubKeyUserProfilePath = Join-Path $pubKeyUserProfile .ssh
            if(-not (Test-Path $pubKeyUserProfilePath -PathType Container)) {
                New-Item $pubKeyUserProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
            }
            Set-SecureFileACL -filepath $keyFilePath
            $testAuthorizedKeyPath = Join-Path $pubKeyUserProfilePath authorized_keys
            Copy-Item "$keyFilePath.pub" $testAuthorizedKeyPath -Force -ErrorAction SilentlyContinue
            Add-PermissionToFileACL -FilePath $testAuthorizedKeyPath -User "NT Service\sshd" -Perm "Read"
            Remove-Item -Path $filePath -Force -ErrorAction ignore
        }
        AfterAll {
            if(Test-Path $testAuthorizedKeyPath) {
                Set-SecureFileACL -filepath $testAuthorizedKeyPath
                Remove-Item $testAuthorizedKeyPath -Force -ErrorAction Ignore
            }
            if(Test-Path $pubKeyUserProfilePath) {            
                Remove-Item $pubKeyUserProfilePath -Force -ErrorAction Ignore
            }
        }

        AfterEach {
            if(Test-Path $keyFilePath) {
                Set-SecureFileACL -filepath $keyFilePath
            }

            Remove-Item -Path $filePath -Force -ErrorAction ignore
        }

        It 'ssh with private key file -- positive (Secured private key owned by current user)' {
            Set-SecureFileACL -filepath $keyFilePath
            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It 'ssh with private key file -- positive (Secured private key owned by Administrators group)' {
            #setup to have local admin group as owner and grant it full control
            $objAdmin = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
            Set-SecureFileACL -filepath $keyFilePath -Owner $objAdmin

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }
        
        It 'ssh with private key file -- negative (other account can access private key file)' {
            #setup to have current user as owner and grant it full control        
            Set-SecureFileACL -filepath $keyFilePath            

            #add ssouser to access the private key
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Add-PermissionToFileACL -FilePath $keyFilePath -User $objUser -Perm "Read"

            #Run
            $o = ssh -p $port -i $keyFilePath -E $filePath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $matches = Get-Content $filePath | Select-String -pattern "UNPROTECTED PRIVATE KEY FILE!"
            $matches.Count | Should Be 1
        }

        It 'ssh with private key file -- (the private key has wrong owner)' {
            #setup to have ssouser as owner and grant it full control
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath $keyFilePath -owner $objUser

            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            Add-PermissionToFileACL -FilePath $keyFilePath -User $currentUser -Perm "FullControl"

            $o = ssh -p $port -i $keyFilePath -E $filePath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $matches = Get-Content $filePath | Select-String -pattern "UNPROTECTED PRIVATE KEY FILE!"
            $matches.Count | Should Be 1
        }
    }
}
