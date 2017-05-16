$tC = 1
$tI = 0
$suite = "keyutils"

Describe "E2E scenarios for ssh key management" -Tags "Scenario" {
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
        #only validate owner and ACE of the file
        function ValidKeyFile {
            param($Path)

            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL = Get-ACL $Path
            $myACL.Owner.Equals($currentUser.Value) | Should Be $true
            $myACL.Access | Should Not Be $null
            $myACL.Access.Count | Should Be 1
            
            $myACL.Access[0].IdentityReference.Equals($currentUser) | Should Be $true
            $myACL.Access[0].AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
            $myACL.Access[0].FileSystemRights | Should Be ([System.Security.AccessControl.FileSystemRights]::FullControl)
            $myACL.Access[0].IsInherited | Should Be $false
            $myACL.Access[0].InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
            $myACL.Access[0].PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)            
        }
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}    

    Context "$tC - ssh-keygen all key types" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - Keygen -A" {
            $cd = (pwd).Path
            cd $testDir
            remove-item ssh_host_*_key* -ErrorAction SilentlyContinue
            ssh-keygen -A
            
            Get-ChildItem ssh_host_*_key | % {
                ValidKeyFile -Path $_.FullName
            }

            Get-ChildItem ssh_host_*_key.pub | % {
                ValidKeyFile -Path $_.FullName
            }
            cd $cd
        }

        It "$tC.$tI - Keygen -t -f" {
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                remove-item $keyPath -ErrorAction SilentlyContinue             
                ssh-keygen -t $type -P $keypassphrase -f $keyPath
                ValidKeyFile -Path $keyPath
                ValidKeyFile -Path "$keyPath.pub"
            }
        }
    }

    # This uses keys generated in above context
    Context "$tC - ssh-add test cases" {
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
            if (-not($env:DISPLAY)) { $env:DISPLAY = 1 }
            $env:SSH_ASKPASS="$($env:ComSpec) /c echo $($keypassphrase)"

            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
                iex "cmd /c `"ssh-add $keyPath < $nullFile 2> nul `""
            }

            #remove SSH_ASKPASS
            if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
            remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue

            #ensure added keys are listed
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonAdd.txt")
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                ($allkeys | foreach {$_.Contains($pubkeyraw)}).Contains($true) | Should Be $true               
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
                if ($allkeys.Count -eq 1) {
                    $allkeys.Contains($pubkeyraw) | Should Be $false
                }
                else { 
                    ($allkeys | foreach {$_.Contains($pubkeyraw)}).Contains($true) | Should Be $false  
                }

            }
            
        }
        
    }
}
