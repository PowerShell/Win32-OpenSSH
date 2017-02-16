using module .\PlatformAbstractLayer.psm1

Describe "SFTP Testcases" -Tags "CI" {
    BeforeAll {
        $rootDirectory = $TestDrive
        
        $outputFileName = "output.txt"
        $batchFileName = "sftp-batchcmds.txt"
        $outputFilePath = Join-Path $rootDirectory $outputFileName
        $batchFilePath = Join-Path $rootDirectory $batchFileName
        
        $tempFileName = "tempFile.txt"
        $tempFilePath = Join-Path $rootDirectory $tempFileName
        
        $tempUnicodeFileName = "tempFile_язык.txt"
        $tempUnicodeFilePath = Join-Path $rootDirectory $tempUnicodeFileName
        
        $clientDirectory = Join-Path $rootDirectory 'client_dir'
        $serverDirectory = Join-Path $rootDirectory 'server_dir'
        
        $null = New-Item $clientDirectory -ItemType directory -Force
        $null = New-Item $serverDirectory -ItemType directory -Force
        $null = New-Item $batchFilePath -ItemType file -Force
        $null = New-Item $outputFilePath -ItemType file -Force
        $null = New-Item $tempFilePath -ItemType file -Force -value "temp file data"
        $null = New-Item $tempUnicodeFilePath -ItemType file -Force -value "temp file data"
        
        $expectedOutputDelimiter = "#DL$"
        
        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)
        
        $testData1 = @(
             @{
                title = "put, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "put $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
			
             },
             @{
                title = "get, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "get $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mput, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mput $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
             },
             @{
                title = "mget, ls for non-unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mget $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mkdir, cd, pwd for non-unicode directory names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "cd $serverdirectory
                            mkdir server_test_dir
                            cd server_test_dir
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir")
             },
             @{
                Title = "lmkdir, lcd, lpwd for non-unicode directory names"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile'
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir
                            lcd client_test_dir
                            lpwd"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir")
             },
             @{
                title = "put, ls for unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "put $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)			
             },
             @{
                title = "get, ls for unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "get $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mput, ls for unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mput $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)
             },
             @{
                title = "mget, ls for unicode file names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "mget $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mkdir, cd, pwd for unicode directory names"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile'
                commands = "cd $serverdirectory
                            mkdir server_test_dir_язык
                            cd server_test_dir_язык
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir_язык")
             },
             @{
                Title = "lmkdir, lcd, lpwd for unicode directory names"
                LogonStr = "$($server.localAdminUserName)@$($server.MachineName)"
                Options = '-i $identifyFile'
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir_язык
                            lcd client_test_dir_язык
                            lpwd
                            lls $clientDirectory"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir_язык")
             }
        )
        
        $testData2 = @(
            @{
                title = "rm, rmdir, rename for unicode file, directory"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile -b $batchFilePath'
                
                tmpFileName1 = $tempUnicodeFileName
                tmpFilePath1 = $tempUnicodeFilePath
                tmpFileName2 = "tempfile_язык_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_язык_2.txt")

                tmpDirectoryName1 = "test_dir_язык_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_язык_1")
                tmpDirectoryName2 = "test_dir_язык_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_язык_2")
            },
            @{
                title = "rm, rmdir, rename for non-unicode file, directory"
                logonstr = "$($server.localadminusername)@$($server.machinename)"
                options = '-i $identifyfile -b $batchFilePath'
                
                tmpFileName1 = $tempFileName
                tmpFilePath1 = $tempFilePath
                tmpFileName2 = "tempfile_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_2.txt")

                tmpDirectoryName1 = "test_dir_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_1")
                tmpDirectoryName2 = "test_dir_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_2")
            }
        )
    }

    AfterAll {
        $client.CleanupClient()
        $server.CleanupServer()
    }

    Context "Single signon" {
        BeforeAll {
            $Server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            .\ssh-add.exe $identifyFile #setup single signon            
        }
        AfterAll {
            $Server.CleanupHostKeys()
            .\ssh-add.exe -D #cleanup single signon
            
            Get-Item $rootDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }

        BeforeEach {
           Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
           Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
           Remove-Item $batchFilePath
           Remove-Item $outputFilePath
        }
        
        It '<Title>' -TestCases:$testData1 {
           param([string]$Title, $LogonStr, $Options, $Commands, $ExpectedOutput, $SkipVerification = $false)
           
           Set-Content $batchFilePath -Encoding UTF8 -value $Commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) -b $batchFilePath $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)

           #validate file content.
           $($ExpectedOutput).split($expectedOutputDelimiter) | foreach {
              Test-Path ($_) | Should be $true
           }
        }
        
        It '<Title>' -TestCases:$testData2 {
           param([string]$Title, $LogonStr, $Options, $tmpFileName1, $tmpFilePath1, $tmpFileName2, $tmpFilePath2, $tmpDirectoryName1, $tmpDirectoryPath1, $tmpDirectoryName2, $tmpDirectoryPath2, $SkipVerification = $false)
           
           #rm (remove file)
           $commands = "mkdir $tmpDirectoryPath1
                        put $tmpFilePath1 $tmpDirectoryPath1
                        ls $tmpDirectoryPath1"
           Set-Content $batchFilePath  -Encoding UTF8 -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $true
           
           $commands = "rm $tmpDirectoryPath1\*
                        ls $tmpDirectoryPath1
                        pwd
                       "
           Set-Content $batchFilePath  -Encoding UTF8 -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $false
           
           #rename file
           Remove-Item $outputFilePath
           Copy-Item $tmpFilePath1 -destination $tmpDirectoryPath1
           $commands = "rename $tmpDirectoryPath1\$tmpFileName1 $tmpDirectoryPath1\$tmpFileName2
                        ls $tmpDirectoryPath1
                        pwd"
           Set-Content $batchFilePath -Encoding UTF8 -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           Test-Path (join-path $tmpDirectoryPath1 $tmpFileName2) | Should be $true
           
           #rename directory
           Remove-Item $outputFilePath
           $commands = "rm $tmpDirectoryPath1\*
                        rename $tmpDirectoryPath1 $tmpDirectoryPath2
                        ls $serverDirectory"
           Set-Content $batchFilePath -Encoding UTF8 -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           Test-Path $tmpDirectoryPath2 | Should be $true
           
           #rmdir (remove directory)
           Remove-Item $outputFilePath
           $commands = "rmdir $tmpDirectoryPath2
                        ls $serverDirectory"
           Set-Content $batchFilePath -Encoding UTF8 -value $commands
           $str = $ExecutionContext.InvokeCommand.ExpandString(".\sftp $($Options) $($LogonStr) > $outputFilePath")
           $client.RunCmd($str)
           Test-Path $tmpDirectoryPath2 | Should be $false
        }
    }
}
