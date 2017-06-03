param ([switch]$Quiet)
Import-Module $PSScriptRoot\OpenSSHUtils.psm1 -Force -DisableNameChecking

if(Test-Path ~\.ssh\config -PathType Leaf)
{
    Fix-UserSSHConfigPermissions -FilePath ~\.ssh\config @psBoundParameters
}

Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa" -ErrorAction Ignore | % {
    Fix-UserKeyPermissions -FilePath $_.FullName @psBoundParameters
}

Write-Host "   Done."
Write-Host " "
