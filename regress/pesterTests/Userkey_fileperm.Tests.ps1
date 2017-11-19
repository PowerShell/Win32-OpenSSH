If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force

$tC = 1
$tI = 0
$suite = "userkey_fileperm"

Describe "Tests for user Key file permission" -Tags "CI" {
    BeforeAll {    
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to setup test environment."
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
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
        $objUserSid = Get-UserSID -User $ssouser
        $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)        
        $pubKeyUserAccountSid = Get-UserSID -User $pubKeyUser        
                
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
            Remove-Item -path "$keyFilePath*" -Force -ErrorAction SilentlyContinue
            if($OpenSSHTestInfo["NoLibreSSL"])
            {
                    ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase -Z aes128-ctr
            }
            else
            {
                ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase 
            }

            $pubKeyUserProfilePath = Join-Path $pubKeyUserProfile .ssh
            if(-not (Test-Path $pubKeyUserProfilePath -PathType Container)) {
                New-Item $pubKeyUserProfilePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            
            $testAuthorizedKeyPath = Join-Path $pubKeyUserProfilePath authorized_keys
            Copy-Item "$keyFilePath.pub" $testAuthorizedKeyPath -Force -ErrorAction SilentlyContinue
            Repair-AuthorizedKeyPermission -FilePath $testAuthorizedKeyPath -confirm:$false
            $tI=1
        }
        AfterAll {
            if(Test-Path $testAuthorizedKeyPath) {                
                Remove-Item $testAuthorizedKeyPath -Force -ErrorAction SilentlyContinue
            }
            if(Test-Path $pubKeyUserProfilePath) {            
                Remove-Item $pubKeyUserProfilePath -Recurse -Force -ErrorAction SilentlyContinue
            }
            $tC++
        }        

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by current user)" {
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            
            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $currentUserSid -confirm:$false

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by local system)" {
            #setup to have local system as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $systemSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh -p $port -i $keyFilePath $pubKeyUser@$server echo 1234
            $o | Should Be "1234"
        }
        
        It "$tC.$tI-ssh with private key file -- negative(other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $currentUser,$adminsSid,$systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            #Run
            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-ssh with private key file -- negative(the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $objUserSid -FullAccessNeeded $objUserSid,$adminsSid,$systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }
    }
}
