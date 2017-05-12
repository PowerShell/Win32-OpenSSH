#todo: -i -q -v -l -c -C
#todo: -S -F -V -e
$tC = 1
$tI = 0
        
Describe "ssh client tests" -Tags "CI" {
    BeforeAll {        
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        if(-not (Test-Path $OpenSSHTestInfo["TestDataPath"]))
        {
            $null = New-Item $OpenSSHTestInfo["TestDataPath"] -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $sshCmdDefault = "ssh -p $port $($ssouser)@$($server)"

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] "ssh"
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $testData = @(
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
            <# -V does not redirect to file
            @{
                Title = "logon using -i -V option"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile -V'
                SkipVerification = $true
            },#>
            @{
                Title = 'logon using -i -l option'
                LogonStr = $server.MachineName
                Options = '-i $identifyFile -l $($server.localAdminUserName)'
            }
        )
        
    }

    BeforeEach {
        $tI++;
        $tFile=Join-Path $testDir "$tC.$tI.txt"
    }        

    Context "$tC - Basic Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - test version" {
            iex "cmd /c `"ssh -V 2> $tFile`""
            $tFile | Should Contain "OpenSSH_"
        }

        It "$tC.$tI - test help" {
            iex "cmd /c `"ssh -? 2> $tFile`""
            $tFile | Should Contain "usage: ssh"
        }
        
        It "$tC.$tI - remote echo command" {
            iex "$sshDefaultCmd echo 1234" | Should Be "1234"
        }

        It "$tC.$tI - exit code" {
            ssh -p $port $ssouser@$server exit 0
            $LASTEXITCODE | Should Be 0
            ssh -p $port $ssouser@$server exit 21
            $LASTEXITCODE | Should Be 21
        }
    }

    Context "$tC - Redirection Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - stdout to file" {
            iex "$sshDefaultCmd powershell get-process > $tFile"
            $tFile | Should Contain "ProcessName"
        }

        It "$tC.$tI - stdout to PS object" {
            $o = iex "$sshDefaultCmd echo 1234"
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

        It "$tC.$tI - verbose to file" {
            $logFile = Join-Path $testDir "$tC.$tI.log.txt"
            $o = ssh -p $port -v -E $logFile $ssouser@$server echo 1234
            $o | Should Be "1234"
            #TODO - checks below are very inefficient (time taking). 
            $logFile | Should Contain "OpenSSH_"
            $logFile | Should Contain "Exit Status 0"
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
