#covered -i -q -v -l -c -C
#todo: -S -F -V -e
Describe "Tests for ssh command" -Tags "Scenario" {
    BeforeAll {        
        $fileName = "test.txt"
        $filePath = Join-Path ${TestDrive} $fileName

        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)

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

    AfterAll {
        $client.CleanupClient()
        $server.CleanupServer()
    }

    Context "Key is not secured in ssh-agent on server" {
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
    }
}
