[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param ()
Set-StrictMode -Version 2.0
If (!(Test-Path variable:PSScriptRoot)) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition}

Import-Module $PSScriptRoot\OpenSSHUtils -Force

if(Test-Path ~\.ssh\config -PathType Leaf)
{
    Repair-UserSshConfigPermission -FilePath ~\.ssh\config @psBoundParameters
}

Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa" -ErrorAction SilentlyContinue | % {
    Repair-UserKeyPermission -FilePath $_.FullName @psBoundParameters
}

Write-Host "   Done."
Write-Host " "
