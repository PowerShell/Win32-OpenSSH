Describe "Tests for powershell over ssh" -Tags "Scenario" {
    BeforeAll {
        $defaultParamValues = $PSDefaultParameterValues.Clone()
        #Skip on windows powershell. this feature only supported in powershell core from git
	#due to known issue, these tests need to be disabled.
        #if ($psversiontable.GitCommitId -eq $null)
        if ($true)
        {
            $PSDefaultParameterValues["It:Skip"] = $true
        }
        
        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)
        $server.SetupServerRemoting([Protocol]::SSH)
    }
    AfterAll {
        $global:PSDefaultParameterValues = $defaultParamValues
        $client.CleanupClient()
        $server.CleanupServer()
    }

    Context "Key based authentication with KeyFilePath. Key is Secured in ssh-agenton server" {
        BeforeAll {
            $server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
        }

        AfterAll {
            $server.CleanupHostKeys()
        }        
        It 'Key is Secured in ssh-agenton server' {
            $session = New-PSSession -HostName $server.MachineName -UserName $server.localAdminUserName -KeyFilePath $identifyFile
            #$pscreds = [System.Management.Automation.PSCredential]::new($($server.MachineName) + "\" + $($server.localAdminUserName), $($server.password))
            #$session = New-PSSession -Credential $pscreds -ComputerName $($server.MachineName)
            $ret = Invoke-Command $session -command {$env:computername}
            $ret | Should be $server.MachineName
        }
    }

    #this context only run on windows
    Context "Single signon and host keys are secured in ssh-agent" {
        BeforeAll {        
            $server.SecureHostKeys($server.PrivateHostKeyPaths)
            $identifyFile = $client.clientPrivateKeyPaths[0]
            #setup single signon
            .\ssh-add.exe $identifyFile
        }

        AfterAll {
            $server.CleanupHostKeys()

            #cleanup single signon
            .\ssh-add.exe -D
        }
        
        It 'Single signon and host keys are secured in ssh-agent' {
            #$session = New-PSSession -HostName $server.MachineName -UserName $server.localAdminUserName
            $pscreds = [System.Management.Automation.PSCredential]::new($($server.MachineName) + "\" + $($server.localAdminUserName), $($server.password))
            $session = New-PSSession -Credential $pscreds -ComputerName $($server.MachineName)
            $ret = Invoke-Command $session -command {$env:computername}
            $ret | Should be $server.MachineName
        }
    }    
   
   Context "Key based authentication with KeyFilePath. Host keys are not secured on server" {
        BeforeAll {
            $identifyFile = $client.clientPrivateKeyPaths[0]
        }
        
        It 'Key based authentication with KeyFilePath. Host keys are not secured on server' {
            $session = New-PSSession -HostName $server.MachineName -UserName $server.localAdminUserName -KeyFilePath $identifyFile
            #$pscreds = [System.Management.Automation.PSCredential]::new($($server.MachineName) + "\" + $($server.localAdminUserName), $($server.password))
            #$session = New-PSSession -Credential $pscreds -ComputerName $($server.MachineName)
            $ret = Invoke-Command $session -command {$env:computername}
            $ret | Should be $server.MachineName
        }
    }    
}   

