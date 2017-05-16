Describe "Tests for ssh config" -Tags "Scenario" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        if(-not (Test-Path $OpenSSHTestInfo["TestDataPath"]))
        {
            $null = New-Item $OpenSSHTestInfo["TestDataPath"] -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\cfginclude"
        $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName
        $logName = "log.txt"
        $logPath = Join-Path $testDir $logName

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $script:logNum = 0

        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {         
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore         
        }
        Remove-Item -Path $filePath -Force -ErrorAction ignore

        function Set-SecureFileACL 
        {
            [CmdletBinding()]
            param(
                [string]$FilePath,
                [System.Security.Principal.NTAccount]$Owner = $null,
                [System.Security.AccessControl.FileSystemAccessRule]$ACE = $null
                )

            $myACL = Get-ACL -Path $FilePath
            $myACL.SetAccessRuleProtection($True, $True)
            Set-Acl -Path $FilePath -AclObject $myACL

            $myACL = Get-ACL $FilePath
            if($owner -ne $null)
            {
                $myACL.SetOwner($Owner)
            }
    
            if($myACL.Access) 
            {        
                $myACL.Access | % {
                    if (($_ -ne $null) -and ($_.IdentityReference.Value -ine "BUILTIN\Administrators") -and 
                    ($_.IdentityReference.Value -ine "NT AUTHORITY\SYSTEM") -and 
                    ($_.IdentityReference.Value -ine "$(whoami)"))
                    {
                        if(-not ($myACL.RemoveAccessRule($_)))
                        {
                            throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                        }
                    }
                }
            }
            if($ACE -ne $null)
            {            
                $myACL.AddAccessRule($ACE)
            }

            Set-Acl -Path $FilePath -AclObject $myACL
        }
    }

    AfterAll {
        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterEach {        
        if( $OpenSSHTestInfo["DebugMode"])
        {
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedagent$script:logNum.log" -Force -ErrorAction ignore
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedsshd$script:logNum.log" -Force -ErrorAction ignore
            Copy-Item $logPath "$($script:logNum)$($logPath)" -Force -ErrorAction ignore
            Clear-Content $logPath -Force -ErrorAction ignore                    
            $script:logNum++
                    
            # clear the ssh-agent, sshd logs so that next testcase will get fresh logs.
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore
        }
        Remove-Item -Path $filePath -Force -ErrorAction ignore        
    }

    Context "User SSHConfig -- ReadConfig" {
        BeforeAll {
            $userConfigFile = Join-Path $home ".ssh\config"
            Copy-item "$PSScriptRoot\testdata\ssh_config" $userConfigFile -force
            $oldACL = Get-ACL $userConfigFile
        }
        AfterEach {
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }

        AfterAll {        
            Remove-Item -Path $userConfigFile -Force -ErrorAction ignore
        }

        It 'User SSHConfig -- ReadConfig (admin user is the owner)' {
            #setup
            Set-SecureFileACL -filepath $userConfigFile

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str
            $LASTEXITCODE | Should Be 0

            #validate file content.
            Get-Content $filePath | Should be $env:COMPUTERNAME 
            
            #clean up
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }
        It 'User SSHConfig -- ReadConfig (wrong owner)' {
            #setup
            Set-SecureFileACL -filepath $userConfigFile -owner $ssouser

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str

            #clean up
            $LASTEXITCODE | Should Not Be 0        
        }

        It 'User SSHConfig -- ReadConfig (wrong permission)' {
            #setup            
            $owner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))

            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($objUser, "Read, Write", "None", "None", "Allow")
             Set-SecureFileACL -filepath $userConfigFile -owner $owner -Ace $objACE

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str

            #clean up
            $LASTEXITCODE | Should Not Be 0        
        }
    }
}
