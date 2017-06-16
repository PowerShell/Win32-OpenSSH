[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param ()
Set-StrictMode -Version 2.0
If (!(Test-Path variable:PSScriptRoot)) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition}
Import-Module $PSScriptRoot\OpenSSHUtils -Force

#check sshd config file
$sshdConfigPath = join-path $PSScriptRoot "sshd_config"
if(Test-Path $sshdConfigPath -PathType Leaf)
{
    Repair-SshdConfigPermission -FilePath $sshdConfigPath @psBoundParameters
}
else
{
    Write-host "$FilePath does not exist"  -ForegroundColor Yellow
}
 
#check host keys
<#
$warning = @"
To keep the host private keys secure, it is recommended to register them with ssh-agent following
steps in link https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH.
If you choose not to register the keys with ssh-agent, please grant sshd read access to the private host keys after run this script.
"@
$prompt = "Did you register host private keys with ssh-agent?"
$description = "Grant sshd read access to the private host keys"

if($pscmdlet.ShouldProcess($description, $prompt, $warning))
{
    $warning = @"
To keep the host private keys secure, it is recommended to register them with ssh-agent following
steps in link https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH.
If you choose not to register the keys with ssh-agent, please grant sshd read access to the private host keys after run this script.
"@
    Write-Warning $warning
    Write-Host " "
}#>

Get-ChildItem $PSScriptRoot\ssh_host_*_key -ErrorAction SilentlyContinue | % {    
    Repair-SshdHostKeyPermission -FilePath $_.FullName @psBoundParameters
}


#check authorized_keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"  -ErrorAction SilentlyContinue | % {
    $properties =  Get-ItemProperty $_.pspath  -ErrorAction SilentlyContinue
    $userProfilePath = ""
    if($properties)
    {
        $userProfilePath =  $properties.ProfileImagePath
    }
    $filePath = Join-Path $userProfilePath .ssh\authorized_keys
    if(Test-Path $filePath -PathType Leaf)
    {
        Repair-AuthorizedKeyPermission -FilePath $filePath @psBoundParameters
    }
}

Write-Host "   Done."
Write-Host " "
