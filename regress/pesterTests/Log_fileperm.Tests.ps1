$tC = 1
$tI = 0
$suite = "log_fileperm"

Describe "Tests for log file permission" -Tags "CI" {
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
        $port = 47003
        $logName = "log.txt"

        $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
        $adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
        $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))

        Remove-Item (Join-Path $testDir "*$logName") -Force -ErrorAction Ignore

        #only validate owner and ACEs of the file
        function ValiLogFilePerm {
            param([string]$FilePath)

            $myACL = Get-ACL $FilePath
            $myACL.Owner.Equals($currentUser.Value) | Should Be $true
            $myACL.Access | Should Not Be $null
            $myACL.Access.Count | Should Be 3
            $identities = @($systemAccount.Value, $adminsAccount.Value, $currentUser.Value)            

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
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }
    }

    BeforeEach {
        $logPath = Join-Path $testDir "$tC.$tI.$logName"
    }

    AfterEach {$tI++;} 

    Context "$tC-SSHD -E Log file permission" {
        BeforeAll {            
            Get-Process -Name sshd | Where-Object {$_.SI -ne 0} | Stop-process
            $tI=1
        }
        
        AfterAll {
            $tC++
        }

        It "$tC.$tI-SSHD -E Log file permission" {
            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-E $logPath") -NoNewWindow
            Start-sleep 1; 
            ValiLogFilePerm -FilePath $logPath
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Stop-Process $_; Start-sleep 1 } }
        }
    }
}