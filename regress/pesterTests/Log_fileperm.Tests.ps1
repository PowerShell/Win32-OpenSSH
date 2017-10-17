If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "log_fileperm"

Describe "Tests for log file permission" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $port = 47003
        $logName = "log.txt"        
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"        

        Remove-Item (Join-Path $testDir "*$logName") -Force -ErrorAction SilentlyContinue
        
        $platform = Get-Platform
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }

        #only validate owner and ACEs of the file
        function ValidateLogFilePerm {
            param([string]$FilePath)
            
            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            $currentOwnerSid.Equals($currentUserSid) | Should Be $true
            $myACL.Access | Should Not Be $null            

            $ReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
            
            $myACL.Access.Count | Should Be 3
            $identities = @($systemSid, $adminsSid, $currentUserSid)            

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true           

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FullControlPerm
                        break;
                    }
                    $currentUserSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadWriteAccessPerm
                        break;
                    }
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }
    }

    BeforeEach {
        $logPath = Join-Path $testDir "$tC.$tI.$logName"
    }

    AfterEach {$tI++;}
    AfterAll {
        if(($platform -eq [PlatformType]::Windows) -and ($psversiontable.BuildVersion.Major -le 6))
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }

    Context "$tC-SSHD -E Log file permission" {
        BeforeAll {            
            Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
            $tI=1
        }
        
        AfterAll {
            $tC++
        }

        It "$tC.$tI-SSHD -E Log file permission" {
            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-E $logPath") -NoNewWindow
            Start-sleep 1; 
            ValidateLogFilePerm -FilePath $logPath
            Get-Process -Name sshd  -ErrorAction SilentlyContinue | Where-Object {$_.SessionID -ne 0} | Stop-process -force -ErrorAction SilentlyContinue
        }
    }
}