
Describe "Tests for portforwarding" -Tags "CI" {
    BeforeAll {

        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        $fileName = "test.txt"
        $filePath = Join-Path ${TestDrive} $fileName
        $logName = "log.txt"
        $logPath = Join-Path ${TestDrive} $logName        
        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]

        $testData = @(
            @{
                Title = "Local port forwarding"
                Options = "-L 5432:127.0.0.1:47001"
                FwdedPort = 5432

            },
            @{
                Title = "Remote port forwarding"
                Options = "-R 5432:127.0.0.1:47001"
                FwdedPort = 5432
            }
        )      
    }

    AfterEach {
        Remove-Item -Path $filePath -Force -ea silentlycontinue
        Remove-Item -Path $logPath -Force -ea silentlycontinue
    }

    It '<Title>' -TestCases:$testData {
        param([string]$Title, $Options, $FwdedPort)
         
        $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) powershell.exe Test-WSMan -computer 127.0.0.1 -port $FwdedPort > $filePath"
        # TODO - move this to PAL
        cmd /c $str
        #validate file content.           
        $content = Get-Content $filePath
        $content -like "wsmid*" | Should Not Be $null
    }
        
}
