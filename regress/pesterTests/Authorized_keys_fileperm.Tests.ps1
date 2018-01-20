If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Import-Module OpenSSHUtils -Force
$tC = 1
$tI = 0
$suite = "authorized_keys_fileperm"
Describe "Tests for authorized_keys file permission" -Tags "CI" {
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

        $fileName = "test.txt"
        $logName = "sshdlog.txt"
        $server = $OpenSSHTestInfo["Target"]
        $port = 47003
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $PwdUser = $OpenSSHTestInfo["PasswdUser"]
        $ssouserProfile = $OpenSSHTestInfo["SSOUserProfile"]
        Remove-Item -Path (Join-Path $testDir "*$fileName") -Force -ErrorAction SilentlyContinue
        $platform = Get-Platform
        $skip = ($platform -eq [PlatformType]::Windows) -and ($PSVersionTable.PSVersion.Major -le 2)
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }

        $Taskfolder = "\OpenSSHTestTasks\"
        $Taskname = "StartTestDaemon"
        
        function Start-SSHD-TestDaemon
        {
            param([string] $Arguments)
            $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']

            $ac = New-ScheduledTaskAction -Execute (join-path $opensshbinpath "sshd") -WorkingDirectory $opensshbinpath -Argument $Arguments
            $task = Register-ScheduledTask -TaskName $Taskname -User system -Action $ac -TaskPath $Taskfolder -Force
            Start-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname
        }

        function Stop-SSHD-TestDaemon
        {
            Stop-ScheduledTask -TaskPath $Taskfolder -TaskName $Taskname
            #stop-scheduledTask does not wait for worker process to end. Kill it if still running. Logic below assume sshd service is running
            $svcpid = ((tasklist /svc | select-string -Pattern ".+sshd").ToString() -split "\s+")[1]
            (gps sshd).id | foreach { if ((-not($_ -eq $svcpid))) {Stop-Process $_ -Force} }
        }
    }

    AfterEach { $tI++ }
    
    AfterAll {
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }

    Context "Authorized key file permission" {
        BeforeAll {
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
            $objUserSid = Get-UserSID -User $ssouser

            $ssouserSSHProfilePath = Join-Path $ssouserProfile .testssh
            if(-not (Test-Path $ssouserSSHProfilePath -PathType Container)) {
                New-Item $ssouserSSHProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
            }
            $authorizedkeyPath = Join-Path $ssouserProfile .testssh\authorized_keys
            $Source = Join-Path $ssouserProfile .ssh\authorized_keys
            $testknownhosts = Join-path $PSScriptRoot testdata\test_known_hosts
            Copy-Item $Source $ssouserSSHProfilePath -Force -ErrorAction Stop

            Repair-AuthorizedKeyPermission -Filepath $authorizedkeyPath -confirm:$false

            Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
            #add wrong password so ssh does not prompt password if failed with authorized keys
            Add-PasswordSetting -Pass "WrongPass"
            $tI=1
        }

        AfterAll {
            Repair-AuthorizedKeyPermission -Filepath $authorizedkeyPath -confirm:$false
            if(Test-Path $authorizedkeyPath) {
                Repair-AuthorizedKeyPermission -Filepath $authorizedkeyPath -confirm:$false
                Remove-Item $authorizedkeyPath -Force -ErrorAction SilentlyContinue
            }
            if(Test-Path $ssouserSSHProfilePath) {            
                Remove-Item $ssouserSSHProfilePath -Force -ErrorAction SilentlyContinue -Recurse
            }
            Remove-PasswordSetting
            $tC++
        }

        BeforeEach {
            $filePath = Join-Path $testDir "$tC.$tI.$fileName"            
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
            Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
        }       

        It "$tC.$tI-authorized_keys-positive(pwd user is the owner and running process can access to the file)" {
            #setup to have ssouser as owner and grant ssouser read and write, admins group, and local system full control            
            Repair-FilePermission -Filepath $authorizedkeyPath -Owners $objUserSid -FullAccessNeeded  $adminsSid,$systemSid,$objUserSid -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts" echo 1234
            Stop-SSHD-TestDaemon
            $o | Should Be "1234"
            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by local system)" {
            #setup to have system as owner and grant it full control            
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $systemSid -FullAccessNeeded  $adminsSid,$systemSid,$objUserSid -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            Stop-SSHD-TestDaemon
            $o | Should Be "1234"
            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd does not have explict ACE)" {
            #setup to have admin group as owner and grant it full control            
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            Stop-SSHD-TestDaemon
            $o | Should Be "1234"
            
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd have explict ACE)" {
            #setup to have admin group as owner and grant it full control
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid,$objUserSid -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            $o = ssh -p $port $ssouser@$server -o "UserKnownHostsFile $testknownhosts"  echo 1234
            Stop-SSHD-TestDaemon
            $o | Should Be "1234"
            
        }

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other admin user)" {
            #setup to have current user (admin user) as owner and grant it full control
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $currentUserSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHD-TestDaemon
            $logPath | Should Contain "Authentication refused."
        }

        It "$tC.$tI-authorized_keys-negative(other account can access private key file)" {
            #setup to have current user as owner and grant it full control            
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $objUserSid -FullAccessNeeded $adminsSid,$systemSid,$objUserSid -confirm:$false

            #add $PwdUser to access the file authorized_keys
            $objPwdUserSid = Get-UserSid -User $PwdUser
            Set-FilePermission -FilePath $authorizedkeyPath -User $objPwdUserSid -Perm "Read"

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            ssh -p $port -E $filePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHD-TestDaemon
            $logPath | Should Contain "Authentication refused."
        }

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other non-admin user)" {
            #setup to have PwdUser as owner and grant it full control            
            $objPwdUserSid = Get-UserSid -User $PwdUser
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $objPwdUserSid -FullAccessNeeded $adminsSid,$systemSid,$objPwdUser -confirm:$false

            #Run
            Start-SSHD-TestDaemon -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $logPath"
            ssh -p $port -E $FilePath -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHD-TestDaemon
            $logPath | Should Contain "Authentication refused."            
        }
    }
}
