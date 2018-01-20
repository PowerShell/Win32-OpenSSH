If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "keyutils"

Describe "E2E scenarios for ssh key management" -Tags "CI" {
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

        $keypassphrase = "testpassword"
        $NoLibreSSL = $OpenSSHTestInfo["NoLibreSSL"]
        if($NoLibreSSL)
        {
            $keytypes = @("ed25519")                
        }
        else
        {
            $keytypes = @("rsa","dsa","ecdsa","ed25519")            
        }
        
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
        $objUserSid = Get-UserSID -User $ssouser
        $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)

        #only validate owner and ACEs of the file
        function ValidateKeyFile {
            param(
                [string]$FilePath,
                [bool]$IsHostKey = $true
            )

            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            $currentOwnerSid.Equals($currentUserSid) | Should Be $true
            $myACL.Access | Should Not Be $null
            
            $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
            $ReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
    
            if($FilePath.EndsWith(".pub")) {
                if ($IsHostKey) {
                    $myACL.Access.Count | Should Be 3
                    $identities = @($systemSid, $adminsSid, $currentUserSid)
                }
                else {
                    $myACL.Access.Count | Should Be 4
                    $identities = @($systemSid, $adminsSid, $currentUserSid, $everyoneSid)
                }
            }
            else {
                $myACL.Access.Count | Should Be 3
                $identities = @($systemSid, $adminsSid, $currentUserSid)
            }

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true           

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FullControlPerm
                        break;
                    }

                    $currentUserSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadWriteAccessPerm
                        break;
                    }
                    $everyoneSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadAccessPerm
                        break;
                    }
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}    

    Context "$tC -ssh-keygen all key types" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - Keygen -A" {
            Push-Location $testDir
            remove-item ssh_host_*_key* -ErrorAction SilentlyContinue
            ssh-keygen -A
            Pop-Location
            
            Get-ChildItem (join-path $testDir ssh_host_*_key) | % {
                ValidateKeyFile -FilePath $_.FullName
            }

            Get-ChildItem (join-path $testDir ssh_host_*_key.pub) | % {
                ValidateKeyFile -FilePath $_.FullName
            }            
        }

        It "$tC.$tI - Keygen -t -f" {
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                remove-item $keyPath -ErrorAction SilentlyContinue
                if($OpenSSHTestInfo["NoLibreSSL"])
                {
                    ssh-keygen -t $type -P $keypassphrase -f $keyPath -Z aes128-ctr
                }
                else
                {
                    ssh-keygen -t $type -P $keypassphrase -f $keyPath
                }                
                ValidateKeyFile -FilePath $keyPath
                ValidateKeyFile -FilePath "$keyPath.pub" -IsHostKey $false
            }
        }
    }

    # This uses keys generated in above context
    Context "$tC -ssh-add test cases" {
        BeforeAll {
            $tI=1
            function WaitForStatus
            {
                param([string]$ServiceName, [string]$Status)
                while((((Get-Service $ServiceName).Status) -ine $Status) -and ($num++ -lt 4))
                {
                    Start-Sleep -Milliseconds 1000
                }
            }
        }
        AfterAll{$tC++}

        # Executing ssh-agent will start agent service
        # This is to support typical Unix scenarios where 
        # running ssh-agent will setup the agent for current session
        It "$tC.$tI - ssh-agent starts agent service" {
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent -Force
            }

            (Get-Service ssh-agent).Status | Should Be "Stopped"

            ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"

            (Get-Service ssh-agent).Status | Should Be "Running"
        }

        It "$tC.$tI - ssh-add - add and remove all key types" {
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase

            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
                iex "cmd /c `"ssh-add $keyPath < $nullFile 2> nul `""
            }

            #remove SSH_ASKPASS
            Remove-PasswordSetting

            #ensure added keys are listed
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonAdd.txt")
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            }

            #delete added keys
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                iex "cmd /c `"ssh-add -d $keyPath 2> nul `""
            }

            #check keys are deleted
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonDelete.txt")

            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
            }            
        }        
    }

    Context "$tC-ssh-add key files with different file perms" {
        BeforeAll {
            $keyFileName = "sshadd_userPermTestkey_ed25519"
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
            
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase
            $tI=1
        }
        BeforeEach {
            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
        }
        AfterEach {
            if(Test-Path $keyFilePath) {
                Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false
            }            
        }

        AfterAll {
            #remove SSH_ASKPASS
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-  ssh-add - positive (Secured private key owned by current user)" {
            #setup to have current user as owner and grant it full control                    
            Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul"
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control            
            Repair-FilePermission -FilePath $keyFilePath -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $adminsSid -FullAccessNeeded $currentUserSid,$adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by local system group)" {
            #setup to have local admin group as owner and grant it full control            
            Repair-FilePermission -FilePath $keyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }
        
        It "$tC.$tI-  ssh-add - negative (other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $currentUserSid,$adminsSid, $systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }

        It "$tC.$tI - ssh-add - negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $objUserSid -FullAccessNeeded $objUserSid,$adminsSid, $systemSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }
    }
		
    Context "$tC - ssh-keyscan test cases" {
        BeforeAll {            
            $tI=1
            $port = $OpenSSHTestInfo["Port"]
            Remove-item (join-path $testDir "$tC.$tI.out.txt") -force -ErrorAction SilentlyContinue
        }
        BeforeEach {
            $outputFile = join-path $testDir "$tC.$tI.out.txt"
        }
        AfterAll{$tC++}

		It "$tC.$tI - ssh-keyscan with default arguments" -Skip:$NoLibreSSL {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

        It "$tC.$tI - ssh-keyscan with -p" -Skip:$NoLibreSSL {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f" -Skip:$NoLibreSSL {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f -t" -Skip:$NoLibreSSL {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt -t rsa,dsa 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}
	}
}
