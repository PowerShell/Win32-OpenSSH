Import-Module $PSScriptRoot\CommonUtils.psm1 -Force -DisableNameChecking
$tC = 1
$tI = 0
$suite = "authorized_keys_fileperm"
Describe "Tests for ssh config" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        if(-not (Test-Path $OpenSSHTestInfo["TestDataPath"]))
        {
            $null = New-Item $OpenSSHTestInfo["TestDataPath"] -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $logName = "testlog.txt"

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]

        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {         
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore         
            Remove-Item -Path (Join-Path $testDir "*log*.log") -Force -ErrorAction ignore
        }
        
        Remove-Item -Path (Join-Path $testDir "*logName") -Force -ErrorAction ignore
    }

    AfterEach {        
        if( $OpenSSHTestInfo["DebugMode"])
        {
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" "$testDir\agentlog$tC.$tI.log" -Force -ErrorAction ignore
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" "$testDir\sshdlog$tC.$tI.log" -Force -ErrorAction ignore
                    
            #Clear the ssh-agent, sshd logs so that next testcase will get fresh logs.
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore
        }
        $tI++
    }

    Context "$tC-User SSHConfig--ReadConfig" {
        BeforeAll {
            $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
            $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))

            $userConfigFile = Join-Path $home ".ssh\config"
            if( -not (Test-path $userConfigFile) ) {
                Copy-item "$PSScriptRoot\testdata\ssh_config" $userConfigFile -force
            }
            $oldACL = Get-ACL $userConfigFile
            $tI=1
        }

        BeforeEach {
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }

        AfterEach {
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }

        AfterAll {
            $tC++
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (current logon user is the owner)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $currentUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $adminAccount -Perms "FullControl"

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (local system is the owner)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $systemAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $adminAccount -Perms "FullControl"

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has no explict ACE)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $systemAccount -Perms "FullControl"

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has explict ACE)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $adminAccount -OwnerPerms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $currentUser -Perms "Read, Write"

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig negative (wrong owner)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $ssouser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $adminAccount -Perms "FullControl"

            #Run
            cmd /c "ssh test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            Get-Content $logPath | Should Match "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig negative (others has permission)" {
            #setup
            Set-FileOwnerAndACL -Filepath $userConfigFile -Owner $currentUser -OwnerPerms "Read","Write"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $systemAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $adminAccount -Perms "FullControl"
            Add-PermissionToFileACL -FilePath $userConfigFile -User $objUser -Perms "Read"

            #Run
            cmd /c "ssh test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            Get-Content $logPath | Should Match "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }
    }
}
