$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"

$ntrights = "ntrights.exe -u `"NT SERVICE\SSHD`" +r SeAssignPrimaryTokenPrivilege"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1> null
}

New-Service -Name ssh-agent -BinaryPathName $sshagentpath -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName $sshdpath -Description "SSH Deamon" -StartupType Manual -DependsOn ssh-agent | Out-Null
sc.exe config sshd obj= "NT SERVICE\SSHD"

Push-Location
cd $scriptdir
cmd.exe /c $ntrights
Pop-Location
Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"

