param ([switch]$Quiet)
Import-Module $PSScriptRoot\OpenSSHUtils.psm1 -Force -DisableNameChecking

#check sshd config file
$sshdConfigPath = join-path $PSScriptRoot "sshd_config"
if(Test-Path $sshdConfigPath -PathType Leaf)
{
    Fix-HostSSHDConfigPermissions -FilePath $sshdConfigPath @psBoundParameters
}
else
{
    Write-host "$FilePath does not exist"  -ForegroundColor Yellow
}
 
#check host keys
<#$result = 'n'
if (-not $Quiet) {
    Do
    {                
        $input = Read-Host -Prompt "Did you register host private keys with ssh-agent? [Yes] Y; [No] N"    
    } until ($input -match "^(y(es)?|N(o)?)$")
    $result = $Matches[0]
}

if($result.ToLower().Startswith('n'))
{
    $warning = @"
To keep the host private keys secure, it is recommended to register them with ssh-agent following
steps in link https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH.
If you choose not to register the keys with ssh-agent, please grant sshd read access to the private host keys after run this script.
"@
    Write-Warning $warning
    Write-Host " "
}#>

Get-ChildItem $PSScriptRoot\ssh_host_*_key -ErrorAction Ignore | % {    
    Fix-HostKeyPermissions -FilePath $_.FullName @psBoundParameters
}


#check authorized_keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"  -ErrorAction Ignore | % {
    $userProfilePath = Get-ItemPropertyValue $_.pspath -Name ProfileImagePath -ErrorAction Ignore
    $filePath = Join-Path $userProfilePath .ssh\authorized_keys
    if(Test-Path $filePath -PathType Leaf)
    {
        Fix-AuthorizedKeyPermissions -FilePath $filePath @psBoundParameters
    }
}

Write-Host "   Done."
Write-Host " "
