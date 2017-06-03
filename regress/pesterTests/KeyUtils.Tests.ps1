Import-Module $PSScriptRoot\CommonUtils.psm1 -Force -DisableNameChecking
$tC = 1
$tI = 0
$suite = "keyutils"

Describe "E2E scenarios for ssh key management" -Tags "CI" {
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

        $keypassphrase = "testpassword"
        $keytypes = @("rsa","dsa","ecdsa","ed25519")
        
        $ssouser = $OpenSSHTestInfo["SSOUser"]

        $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
        $adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")            
        $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
        $everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
        $objUser = New-Object System.Security.Principal.NTAccount($ssouser)

        #only validate owner and ACEs of the file
        function ValidateKeyFile {
            param([string]$FilePath)

            $myACL = Get-ACL $FilePath
            $myACL.Owner.Equals($currentUser.Value) | Should Be $true
            $myACL.Access | Should Not Be $null
            if($FilePath.EndsWith(".pub")) {
                $myACL.Access.Count | Should Be 4
                $identities = @($systemAccount.Value, $adminsAccount.Value, $currentUser.Value, $everyone.Value)
            }
            else {
                $myACL.Access.Count | Should Be 3
                $identities = @($systemAccount.Value, $adminsAccount.Value, $currentUser.Value)
            }

            foreach ($a in $myACL.Access) {
                $a.IdentityReference.Value -in $identities | Should Be $true           

                switch ($a.IdentityReference.Value)
                {
                    {$_ -in @($systemAccount.Value, $adminsAccount.Value)}
                    {
                        $a.FileSystemRights | Should Be "FullControl"
                        break;
                    }

                    $currentUser.Value
                    {
                        $a.FileSystemRights | Should Be "Write, Read, Synchronize"
                        break;
                    }
                    $everyone.Value
                    {
                        $a.FileSystemRights | Should Be "Read, Synchronize"
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
                remove-item $keyPath -ErrorAction ignore             
                ssh-keygen -t $type -P $keypassphrase -f $keyPath
                ValidateKeyFile -FilePath $keyPath
                ValidateKeyFile -FilePath "$keyPath.pub"
            }
        }
    }

    # This uses keys generated in above context
    Context "$tC -ssh-add test cases" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        # Executing ssh-agent will start agent service
        # This is to support typical Unix scenarios where 
        # running ssh-agent will setup the agent for current session
        It "$tC.$tI - ssh-agent starts agent service and sshd depends on ssh-agent" {
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent -Force
            }

            (Get-Service ssh-agent).Status | Should Be "Stopped"
            (Get-Service sshd).Status | Should Be "Stopped"

            ssh-agent

            (Get-Service ssh-agent).Status | Should Be "Running"

            Stop-Service ssh-agent -Force

            (Get-Service ssh-agent).Status | Should Be "Stopped"
            (Get-Service sshd).Status | Should Be "Stopped"

            # this should automatically start both the services
            Start-Service sshd
            (Get-Service ssh-agent).Status | Should Be "Running"
            (Get-Service sshd).Status | Should Be "Running"
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
                ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
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
                ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
            }            
        }        
    }

    Context "$tC-ssh-add key files with different file perms" {
        BeforeAll {
            $keyFileName = "sshadd_userPermTestkey_ed25519"
            $keyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$keyFilePath*" -Force -ErrorAction Ignore
            ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase
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
                Adjust-UserKeyFileACL -FilePath $keyFilePath -Owner $currentUser -OwnerPerms "Read, Write"
            }            
        }

        AfterAll {
            #remove SSH_ASKPASS
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-  ssh-add - positive (Secured private key owned by current user)" {
            #setup to have current user as owner and grant it full control        
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $currentUser -OwnerPerms "FullControl"

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul"
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $adminsAccount -OwnerPerms "FullControl"

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $adminsAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $keyFilePath -User $currentUser -Perm "Read, Write"

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by local system group)" {
            #setup to have local admin group as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $keyFilePath -User $adminsAccount -Perm "FullControl"

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }
        
        It "$tC.$tI-  ssh-add - negative (other account can access private key file)" {
            #setup to have current user as owner and grant it full control        
            Set-FileOwnerAndACL -FilePath $keyFilePath -Owner $currentUser -OwnerPerms "FullControl"         

            #add ssouser to access the private key            
            Add-PermissionToFileACL -FilePath $keyFilePath -User $objUser -Perm "Read"

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }

        It "$tC.$tI - ssh-add - negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Set-FileOwnerAndACL -FilePath $keyFilePath -owner $objUser -OwnerPerms "Read, Write"
            Add-PermissionToFileACL -FilePath $keyFilePath -User $adminsAccount -Perm "FullControl"

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]            
            ($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }
    }
		
    Context "$tC - ssh-keyscan test cases" {
        BeforeAll {
            $tI=1
            $port = $OpenSSHTestInfo["Port"]
            Remove-item (join-path $testDir "$tC.$tI.out.txt") -force -ErrorAction Ignore
        }
        BeforeEach {
            $outputFile = join-path $testDir "$tC.$tI.out.txt"
        }
        AfterAll{$tC++}

		It "$tC.$tI - ssh-keyscan with default arguments" {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

        It "$tC.$tI - ssh-keyscan with -p" {
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f" {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f -t" {
			Set-Content -Path tmp.txt -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f tmp.txt -t rsa,dsa 2>&1 > $outputFile"
			$outputFile | Should Contain '.*ssh-rsa.*'
		}
	}
}
