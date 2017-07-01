Describe "Tests of sshd_config" -Tags "Scenario" {
    BeforeAll {
        $fileName = "test.txt"
        $filePath = Join-Path ${TestDrive} $fileName

        [Machine] $client = [Machine]::new([MachineRole]::Client)
        [Machine] $server = [Machine]::new([MachineRole]::Server)
        $client.SetupClient($server)
        $server.SetupServer($client)
    }

    AfterAll {
        $client.CleanupClient()
        $server.CleanupServer()
    }

<#
    Settings in the sshd_config:

    DenyUsers denyuser1 denyu*2 denyuse?3, 
    AllowUsers allowuser1 allowu*r2 allow?se?3 allowuser4 localuser1 localu*r2 loc?lu?er3 localadmin
    DenyGroups denygroup1 denygr*p2 deny?rou?3
    AllowGroups allowgroup1 allowg*2 allowg?ou?3 Adm*
#>
     Context "Tests of AllowGroups, AllowUsers, DenyUsers, DenyGroups" {
        BeforeAll {            
            Remove-Item -Path $filePath -Force -ea silentlycontinue
            $password = "Bull_dog1"

            $allowUser1 = "allowuser1"
            $allowUser2 = "allowuser2"
            $allowUser3 = "allowuser3"
            $allowUser4 = "allowuser4"

            $denyUser1 = "denyuser1"
            $denyUser2 = "denyuser2"
            $denyUser3 = "denyuser3"

            $localuser1 = "localuser1"
            $localuser2 = "localuser2"
            $localuser3 = "localuser3"

            $allowGroup1 = "allowgroup1"
            $allowGroup2 = "allowgroup2"
            $allowGroup3 = "allowgroup3"

            $denyGroup1 = "denygroup1"
            $denyGroup2 = "denygroup2"
            $denyGroup3 = "denygroup3"
            $client.AddPasswordSetting($password)
        }        
        AfterEach {
            Remove-Item -Path $filePath -Force -ea SilentlyContinue
        }

        AfterAll {
            $client.CleanupPasswordSetting()
        }

        It 'User with full name in the list of AllowUsers' {
           $server.AddUserToLocalGroup($allowUser1, $password, $allowGroup1)
           
           $client.RunCmd(".\ssh $($allowUser1)@$($server.MachineName) hostname > $filePath")
           Get-Content $filePath | Should be $server.MachineName
           $server.RemoveUserFromLocalGroup($allowUser1, $allowGroup1)
        }

        It 'User with * wildcard' {
           $server.AddUserToLocalGroup($allowUser2, $password, $allowGroup1)
           
           $client.RunCmd(".\ssh $($allowUser2)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Be 0
           Get-Content $filePath | Should be $server.MachineName
           $server.RemoveUserFromLocalGroup($allowUser2, $allowGroup1)
        }

        It 'User with ? wildcard' {
           $server.AddUserToLocalGroup($allowUser3, $password, $allowGroup1)
           
           $client.RunCmd(".\ssh $($allowUser3)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Be 0
           Get-Content $filePath | Should be $server.MachineName
           $server.RemoveUserFromLocalGroup($allowUser3, $allowGroup1)
        }

        It 'User with full name in the list of AllowUsers but not in any AllowGroups' {
           $server.AddLocalUser($allowUser4, $password)
           
           $client.RunCmd(".\ssh $($allowUser4)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty
        }

        It 'User with full name in the list of DenyUsers' {           
           $server.AddUserToLocalGroup($denyUser1, $password, $allowGroup1)

           $client.RunCmd(".\ssh $($denyUser1)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty

           $server.RemoveUserFromLocalGroup($denyUser1, $allowGroup1)
        }

        It 'User with * wildcard in the list of DenyUsers' {
           $server.AddUserToLocalGroup($denyUser2, $password, $allowGroup1)

           $str = ".\ssh $($denyUser2)@$($server.MachineName) hostname > $filePath"
           $client.RunCmd(".\ssh $($denyUser2)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty

           $server.RemoveUserFromLocalGroup($denyUser2, $allowGroup1)
        }

        It 'User with ? wildcard in the list of DenyUsers' {
           $server.AddUserToLocalGroup($denyUser3, $password, $allowGroup1)
           
           $client.RunCmd(".\ssh $($denyUser3)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty

           $server.RemoveUserFromLocalGroup($denyUser3, $allowGroup1)
        }

        It 'User is listed in the list of AllowUsers but also in a full name DenyGroups and AllowGroups' {
           $server.AddUserToLocalGroup($localuser1, $password, $allowGroup1)
           $server.AddUserToLocalGroup($localuser1, $password, $denyGroup1)
           
           $client.RunCmd(".\ssh $($localuser1)@$($server.MachineName) hostname > $filePath")

           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty


           $server.RemoveUserFromLocalGroup($localuser1, $allowGroup1)
           $server.RemoveUserFromLocalGroup($localuser1, $denyGroup1)
        }

        It 'User is listed in the list of AllowUsers but also in a wildcard * DenyGroups' {           
           $server.AddUserToLocalGroup($localuser2, $password, $denyGroup2)
                      
           $client.RunCmd(".\ssh $($localuser2)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty

           $server.RemoveUserFromLocalGroup($localuser2, $denyGroup2)
        }

        It 'User is listed in the list of AllowUsers but also in a wildcard ? DenyGroups' {           
           $server.AddUserToLocalGroup($localuser3, $password, $denyGroup3)
                      
           $client.RunCmd(".\ssh $($localuser3)@$($server.MachineName) hostname > $filePath")
           $LASTEXITCODE | Should Not Be 0
           Get-Content $filePath | Should BeNullOrEmpty

           $server.RemoveUserFromLocalGroup($localuser3, $denyGroup3)
        }
    }
}
