# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency
# @bingbing8 - removed secedit.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$sshdir = Join-Path $env:ProgramData "\ssh"
$logsdir = Join-Path $sshdir "logs"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1>$null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>$null
}

New-Service -Name ssh-agent -BinaryPathName `"$sshagentpath`" -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName `"$sshdpath`" -Description "SSH Daemon" -StartupType Manual | Out-Null

#create the ssh config folder and set its permissions
if(-not (test-path $sshdir -PathType Container))
{
    $null = New-Item $sshdir -ItemType Directory -Force -ErrorAction Stop
}
$acl = Get-Acl -Path $sshdir
# following SDDL implies 
# - owner - built in Administrators
# - disabled inheritance
# - Full access to System
# - Full access to built in Administrators
$acl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)")
Set-Acl -Path $sshdir -AclObject $acl

# create logs folder and set its permissions
if(-not (test-path $logsdir -PathType Container))
{
    $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
}
$acl = Get-Acl -Path $logsdir
# following SDDL implies 
# - owner - built in Administrators
# - disabled inheritance
# - Full access to System
# - Full access to built in Administrators
$acl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
Set-Acl -Path $logsdir -AclObject $acl

#copy sshd_config_default to $sshdir\sshd_config
$sshdconfigpath = Join-Path $sshdir "sshd_config"
$sshddefaultconfigpath = Join-Path $scriptdir "sshd_config_default"
if(-not (test-path $sshdconfigpath -PathType Leaf))
{
    $null = Copy-Item $sshddefaultconfigpath -Destination $sshdconfigpath  -ErrorAction Stop
}

Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
