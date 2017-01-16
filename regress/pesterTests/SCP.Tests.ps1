using module .\PlatformAbstractLayer.psm1

#covered -i -p -q -r -v -c -S -C
#todo: -F, -l and -P should be tested over the network
Describe "Tests for scp command" -Tags "CI" {
    BeforeAll {        
        $fileName1 = "test.txt"
        $fileName2 = "test2.txt"
        $SourceDirName = "SourceDir"
        $SourceDir = Join-Path ${TestDrive} $SourceDirName
        $SourceFilePath = Join-Path $SourceDir $fileName1
        $DestinationDir = Join-Path ${TestDrive} "DestDir"
        $DestinationFilePath = Join-Path $DestinationDir $fileName1        
        $NestedSourceDir= Join-Path $SourceDir "nested"
        $NestedSourceFilePath = Join-Path $NestedSourceDir $fileName2
        $null = New-Item $SourceDir -ItemType directory -Force
        $null = New-Item $NestedSourceDir -ItemType directory -Force
        $null = New-item -path $SourceFilePath -force
        $null = New-item -path $NestedSourceFilePath -force
        "Test content111" | Set-content -Path $SourceFilePath
        "Test content in nested dir" | Set-content -Path $NestedSourceFilePath
        $null = New-Item $DestinationDir -ItemType directory -Force
        
        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)

        $testData = @(
            @{
                Title = 'Simple copy local file to local file'
                Source = $SourceFilePath                   
                Destination = $DestinationFilePath
            },
            @{
                Title = 'Simple copy local file to remote file'
                Source = $SourceFilePath
                Destination = "$($server.localAdminUserName)@$($server.MachineName):$DestinationFilePath"
            },
            @{
                Title = 'Simple copy remote file to local file'
                Source = "$($server.localAdminUserName)@$($server.MachineName):$SourceFilePath"
                Destination = $DestinationFilePath                    
            },            
            @{
                Title = 'Simple copy local file to local dir'
                Source = $SourceFilePath
                Destination = $DestinationDir
            },
            @{
                Title = 'simple copy local file to remote dir'         
                Source = $SourceFilePath
                Destination = "$($server.localAdminUserName)@$($server.MachineName):$DestinationDir"
            },
            @{
                Title = 'simple copy remote file to local dir'
                Source = "$($server.localAdminUserName)@$($server.MachineName):$SourceFilePath"
                Destination = $DestinationDir
            }
        )

        $testData1 = @(
            @{
                Title = 'copy from local dir to remote dir'
                Source = $sourceDir
                Destination = "$($server.localAdminUserName)@$($server.MachineName):$DestinationDir"
            },
            @{
                Title = 'copy from local dir to local dir'
                Source = $sourceDir
                Destination = $DestinationDir
            },
            @{
                Title = 'copy from remote dir to local dir'            
                Source = "$($server.localAdminUserName)@$($server.MachineName):$sourceDir"
                Destination = $DestinationDir
            }
        )
    }
    AfterAll {

        $client.CleanupClient()
        $server.CleanupServer()

        Get-Item $SourceDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-Item $DestinationDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    BeforeAll {
        $null = New-Item $DestinationDir -ItemType directory -Force
    }

    AfterEach {
        Get-ChildItem $DestinationDir -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    <#Context "SCP usage" {
        It 'SCP usage' {
            #TODO: usage output does not redirect to file
        }
    }#>       
    
    Context "Key is Secured in ssh-agent on server" {
        BeforeAll {
            $Server.SecureHostKeys($server.PrivateHostKeyPaths)
            $privateKeyFile = $client.clientPrivateKeyPaths[0]            
        }

        AfterAll {
            $Server.CleanupHostKeys()
        }
        
        It 'File copy with -i option and private key: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)                        
            .\scp -i $privateKeyFile $Source $Destination
            #validate file content. DestPath is the path to the file.
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0            
            $equal | Should Be $true            
        }        

        It 'Directory recursive copy with -i option and private key: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)               

            .\scp -r -i $privateKeyFile $Source $Destination
            
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true

            
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
        }        
    }
    
    Context "Single signon with keys -p -v -c option Secured in ssh-agent" {
        BeforeAll {        
            $Server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            #setup single signon
            .\ssh-add.exe $identifyFile
        }

        AfterAll {
            $Server.CleanupHostKeys()

            #cleanup single signon
            .\ssh-add.exe -D
        }        

        It 'File copy with -S option (positive)' {
            .\scp -S .\ssh.exe $SourceFilePath "$($server.localAdminUserName)@$($server.MachineName):$DestinationFilePath"
            #validate file content. DestPath is the path to the file.
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
        }

        It 'File copy with -p -c -v option: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)

            .\scp -p -c aes128-ctr -v -C $Source $Destination
            #validate file content. DestPath is the path to the file.
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true            
        }
                
        It 'Directory recursive copy with -r -p -v option: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)
            .\scp -r -p -c aes128-ctr -v $Source $Destination
            
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true            
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
        }
    }
   
   Context "Private key authentication with -i -C -q options. host keys are not secured on server" {
        BeforeAll {
            $identifyFile = $client.clientPrivateKeyPaths[0]
        }
        
        It 'File copy with -i -C -q options: <Title> ' -TestCases:$testData{
            param([string]$Title, $Source, $Destination)

            .\scp -i $identifyFile -C -q $Source $Destination
            #validate file content. DestPath is the path to the file.
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
        }

        It 'Directory recursive copy with -i -C -r and -q options: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)               

            .\scp -i $identifyFile -C -r -q $Source $Destination
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
            $equal | Should Be $true          
        }
    }

    Context "Password authentication" {
        BeforeAll {
            $client.AddPasswordSetting($server.localAdminPassword)
        }

        AfterAll {
            $client.CleanupPasswordSetting()
        }
        
        It 'File copy with -p options: <Title> ' -TestCases:$testData {
            param([string]$Title, $Source, $Destination)

            .\scp -p $Source $Destination            
            #validate file content. DestPath is the path to the file.
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
        }

        It 'Directory recursive copy with -p and -v options: <Title> ' -TestCases:$testData1 {
            param([string]$Title, $Source, $Destination)               

            .\scp -r -p $Source $Destination            
            $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true
                        
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length, LastWriteTime.DateTime).Length -eq 0
            $equal | Should Be $true          
        }
    }
}   
