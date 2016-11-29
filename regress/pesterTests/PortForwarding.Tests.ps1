using module .\PlatformAbstractLayer.psm1

Describe "Tests for portforwarding" -Tags "CI" {
    BeforeAll {        
        $fileName = "test.txt"
        $filePath = Join-Path ${TestDrive} $fileName

        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)

        $server.SecureHostKeys($server.PrivateHostKeyPaths)
        $server.SetupServerRemoting([Protocol]::WSMAN)
        #setup single signon
        .\ssh-add.exe $client.clientPrivateKeyPaths[0]
        Remove-Item -Path $filePath -Force -ea silentlycontinue

        $testData = @(
            @{
                Title = "Local port forwarding"
                Options = "-L 5432:127.0.0.1:47001"
                Port = 5432

            },
            @{
                Title = "Remote port forwarding"
                Options = "-R 5432:127.0.0.1:47001"
                Port = 5432
            }
        )      
    }

    AfterAll {
        #cleanup single signon
        .\ssh-add.exe -D
        $Server.CleanupHostKeys()
        $client.CleanupClient()
        $server.CleanupServer()
    }

    AfterEach {
        Remove-Item -Path $filePath -Force -ea silentlycontinue
    }

    It '<Title>' -TestCases:$testData {
        param([string]$Title, $Options, $port)
           
        $str = ".\ssh $($Options) $($server.localAdminUserName)@$($server.MachineName) powershell.exe Test-WSMan -computer 127.0.0.1 -port $port > $filePath"
        $client.RunCmd($str)
        #validate file content.           
        $content = Get-Content $filePath
        $content -like "wsmid*" | Should Not Be $null
    }
        
}
