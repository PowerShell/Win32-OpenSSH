Import-Module $PSScriptRoot\CommonUtils.psm1 -Force -DisableNameChecking

$tC = 1
$tI = 0
$suite = "userkey_fileperm"

Describe "Tests for user Key file permission" -Tags "CI" {
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

        $logName = "log.txt"
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $pubKeyUser = $OpenSSHTestInfo["PubKeyUser"]
        $pubKeyUserProfile = $OpenSSHTestInfo["PubKeyUserProfile"]
        $server = $OpenSSHTestInfo["Target"]
        $userName = "$env:USERNAME@$env:USERDOMAIN"
        $keypassphrase = "testpassword"

        $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
        $adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
        $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
        $pubKeyUserAccount = New-Object System.Security.Principal.NTAccount($pubKeyUser)
        $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
        $everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
                
        Add-PasswordSetting -Pass $keypassphrase
    }

    AfterAll {
        Remove-PasswordSetting
    }
    BeforeEach {
        $logPath = Join-Path $testDir "$tC.$tI.$logName"
    }

    AfterEach {$tI++;}    

    Context "$tC-ssh with private key file" {
        BeforeAll {            
            $keyFileName = "sshtest_userPermTestkey_ed25519"
            $keyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$keyFilePath*" -Force -ErrorAction Ignore
            ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase 

            $pubKeyUserProfilePath = Join-Path $pubKeyUserProfile .ssh
            if(-not (Test-Path $pubKeyUserProfilePath -PathType Container)) {
                New-Item $pubKeyUserProfilePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            
            $testAuthorizedKeyPath = Join-Path $pubKeyUserProfilePath authorized_keys
            Copy-Item "$keyFilePath.pub" $testAuthorizedKeyPath -Force -ErrorAction SilentlyContinue
            Adjust-UserKeyFileACL -FilePath $testAuthorizedKeyPath -Owner $pubKeyUserAccount -OwnerPerms "Read, Write"
            Add-PermissionToFileACL -FilePath $testAuthorizedKeyPath -User "NT Service\sshd" -Perm "Read"
            $tI=1
        }
        AfterAll {
            if(Test-Path $testAuthorizedKeyPath) {                
                Remove-Item $testAuthorizedKeyPath -Force -ErrorAction Ignore
            }
            if(Test-Path $pubKeyUserProfilePath) {            
                Remove-Item $pubKeyUserProfilePath -Recurse -Force -ErrorAction Ignore
            }
            $tC++
        }        

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by current user)" {
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $currentUser -OwnerPerms "Read, Write"
            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $adminsAccount -OwnerPerms "FullControl"

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $adminsAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $keyFilePath -User $currentUser -Perm "Read"

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by local system)" {
            #setup to have local system as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $keyFilePath -User $adminsAccount -Perm "Read"

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }
        
        It "$tC.$tI-ssh with private key file -- negative(other account can access private key file)" {
            #setup to have current user as owner and grant it full control        
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $currentUser -OwnerPerms "Read, Write"

            #add ssouser to access the private key            
            Add-PermissionToFileACL -FilePath $keyFilePath -User $objUser -Perm "Read"

            #Run
            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-ssh with private key file -- negative(the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control            
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $objUser -OwnerPerms "Read, Write"            
            Add-PermissionToFileACL -FilePath $keyFilePath -User $adminsAccount -Perm "FullControl"

            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }
    }
}
