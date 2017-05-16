#todo: -i -q -v -l -c -C
#todo: -S -F -V -e
$tC = 1
$tI = 0
$suite = "sshclient"
        
Describe "E2E scenarios for ssh client" -Tags "CI" {
    BeforeAll {        
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        <#$testData = @(
            @{
                Title = 'Simple logon no option';                
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = ""
            },
            @{
                Title = 'Simple logon using -C -l option'
                LogonStr = $server.MachineName
                Options = "-C -l $($server.localAdminUserName)"
            }
        )
        
        $testData1 = @(
            @{
                Title = "logon using -i -q option"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile -q'
            },
            @{
                Title = "logon using -i option"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile'
            },
            @{
                Title = "logon using -i -c  option"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile -c aes256-ctr'
            },
             -V does not redirect to file
            @{
                Title = "logon using -i -V option"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile -V'
                SkipVerification = $true
            },
            @{
                Title = 'logon using -i -l option'
                LogonStr = $server.MachineName
                Options = '-i $identifyFile -l $($server.localAdminUserName)'
            }
        )#>
        
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}

    Context "$tC - Basic Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - test version" {
            iex "cmd /c `"ssh -V 2> $stderrFile`""
            $stderrFile | Should Contain "OpenSSH_"
        }

        It "$tC.$tI - test help" {
            iex "cmd /c `"ssh -? 2> $stderrFile`""
            $stderrFile | Should Contain "usage: ssh"
        }
        
        It "$tC.$tI - remote echo command" {
            iex "$sshDefaultCmd echo 1234" | Should Be "1234"
        }

    }

    Context "$tC - exit code (exit-status.sh)" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - various exit codes" {
            foreach ($i in (0,1,4,5,44)) {
                ssh -p $port $ssouser@$server exit $i
                $LASTEXITCODE | Should Be $i
            }            
        }
    }

    Context "$tC - Redirection Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - stdout to file" {
            ssh test_target powershell get-process > $stdoutFile
            $stdoutFile | Should Contain "ProcessName"
        }

        It "$tC.$tI - stdout to PS object" {
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        <#It "$tC.$tI - stdin from PS object" {
            #if input redirection doesn't work, this would hang
            0 | ssh -p $port $ssouser@$server pause
            $true | Should Be $true
        }#>
    }

    Context "$tC - cmdline parameters" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - verbose to file (-v -E)" {
            $o = ssh -v -E $logFile test_target echo 1234
            $o | Should Be "1234"
            #TODO - checks below are very inefficient (time taking). 
            $logFile | Should Contain "OpenSSH_"
            $logFile | Should Contain "Exit Status 0"
        }


        It "$tC.$tI - cipher options (-c)" {
            #bad cipher
            iex "cmd /c `"ssh -c bad_cipher test_target echo 1234 2>$stderrFile`""
            $stderrFile | Should Contain "Unknown cipher type"
            #good cipher, ensure cipher is used from debug logs
            $o = ssh -c aes256-ctr  -v -E $logFile test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should Contain "kex: server->client cipher: aes256-ctr"
            $logFile | Should Contain "kex: client->server cipher: aes256-ctr"
        }

        It "$tC.$tI - ssh_config (-F)" {
            #ensure -F is working by pointing to a bad configuration
            $badConfigFile = Join-Path $testDir "$tC.$tI.bad_ssh_config"
            "bad_config_line" | Set-Content $badConfigFile
            iex "cmd /c `"ssh -F $badConfigFile test_target echo 1234 2>$stderrFile`""
            $stderrFile | Should Contain "bad_ssh_config"
            $stderrFile | Should Contain "bad_config_line"
            $stderrFile | Should Contain "bad configuration options"

            #try with a proper configuration file. Put it on a unicode path with unicode content
            #so we can test the Unicode support simultaneously
            $goodConfigFile = Join-Path $testDir "$tC.$tI.Очень_хорошо_ssh_config"
            "#this is a Unicode comment because it contains русский язык" | Set-Content $goodConfigFile -Encoding UTF8
            "Host myhost" | Add-Content $goodConfigFile
            "    HostName $server" | Add-Content $goodConfigFile
            "    Port $port" | Add-Content $goodConfigFile
            "    User $ssouser" | Add-Content $goodConfigFile
            $o = ssh -F $goodConfigFile myhost echo 1234
            $o | Should Be "1234"          
        }

        It "$tC.$tI - IP options - (-4) (-6)" {
            # TODO - this test assumes target is localhost. 
            # make it work independent of target
            #-4
            $o = ssh -4 -v -E $logFile test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should Contain "[127.0.0.1]"
            #-4
            $o = ssh -6 -v -E $logFile test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should Contain "[::1]"            
        }
    }


    
    <#Context "Key is not secured in ssh-agent on server" {
        BeforeAll {            
            $identifyFile = $client.clientPrivateKeyPaths[0]
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }
        
        AfterEach {
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }
        
        It '<Title>' -TestCases:$testData1 {
            param([string]$Title, $LogonStr, $Options, $SkipVerification = $false)
           
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\ssh $($Options) $($LogonStr) hostname > $filePath")
           $client.RunCmd($str)
           #validate file content.
           Get-Content $filePath | Should be $server.MachineName           
        }
    }
    
    Context "Key is secured in ssh-agent" {
        BeforeAll {
            $server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }

        AfterAll {            
            $Server.CleanupHostKeys()
        }
        
        AfterEach {
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }
        
        It '<Title>' -TestCases:$testData1 {
            param([string]$Title, $LogonStr, $Options, $SkipVerification = $false)
           
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\ssh $Options $LogonStr hostname > $filePath")
           $client.RunCmd($str)
           #validate file content.           
           Get-Content $filePath | Should be $server.MachineName           
        }
    }
    
    Context "Single signon on client and keys secured in ssh-agent on server" {
        BeforeAll {
            $Server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            #setup single signon
            .\ssh-add.exe $identifyFile
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }

        AfterAll {
            $Server.CleanupHostKeys()

            #cleanup single signon
            .\ssh-add.exe -D
        }
        
        AfterEach {
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }

        It '<Title>' -TestCases:$testData {
            param([string]$Title, $LogonStr, $Options)
           
           $str = ".\ssh $($Options) $($LogonStr) hostname > $filePath"
           $client.RunCmd($str)
           #validate file content.           
           Get-Content $filePath | Should be $server.MachineName           
        }
    }
    Context "password authentication" {
        BeforeAll {
            $client.AddPasswordSetting($server.localAdminPassword)
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }

        AfterAll {
            $client.CleanupPasswordSetting()
        }

        AfterEach {
            Remove-Item -Path $filePath -Force -ea silentlycontinue
        }

        It '<Title>' -TestCases:$testData {
            param([string]$Title, $LogonStr, $Options)
           
           $str = ".\ssh $($Options) $($LogonStr) hostname > $filePath"
           $client.RunCmd($str)
           #validate file content.           
           Get-Content $filePath | Should be $server.MachineName           
        }
    }#>
}
