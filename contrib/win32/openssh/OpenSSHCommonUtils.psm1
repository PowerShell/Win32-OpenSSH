If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHUtils -Force
<#
.Synopsis
    Finds the root of the git repository

.Outputs
    A System.IO.DirectoryInfo for the location of the root if root is found; otherwise, script root.

.Inputs
    None
#>
function Get-RepositoryRoot
{    
    $start = $currentDir = (Get-Item -Path $PSScriptRoot)
    while ($null -ne $currentDir.Parent)
    {
        $path = Join-Path -Path $currentDir.FullName -ChildPath '.git'
        if (Test-Path -Path $path)
        {
            return $currentDir
        }
        $currentDir = $currentDir.Parent
    }
    return $start
}

<#
.Synopsis
    add a file permission to an account

.Outputs
    N/A

.Inputs
    FilePath - The path to the file    
    User - account name
    Perms - The permission to grant.
#>
function Add-PermissionToFileACL
{
        param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [parameter(Mandatory=$true)]
        [System.Security.Principal.NTAccount] $User,
        [parameter(Mandatory=$true)]
        [System.Security.AccessControl.FileSystemRights[]]$Perms
    )    

    $myACL = Get-ACL $FilePath
        
    if($Perms)
    {
        $Perms | % { 
            $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($User, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($userACE)
        }
    }    
    Enable-Privilege SeRestorePrivilege | out-null
    Set-Acl -Path $FilePath -AclObject $myACL
}

Export-ModuleMember -Function Get-RepositoryRoot, Add-PermissionToFileACL