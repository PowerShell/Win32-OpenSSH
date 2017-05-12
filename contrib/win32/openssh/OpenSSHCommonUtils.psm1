<#
.Synopsis
    Finds the root of the git repository

.Outputs
    A System.IO.DirectoryInfo for the location of the root.

.Inputs
    None

.Notes
    FileNotFoundException is thrown if the current directory does not contain a CMakeLists.txt file.
#>
function Get-RepositoryRoot
{
    $currentDir = (Get-Item -Path $PSCommandPath).Directory

    while ($null -ne $currentDir.Parent)
    {
        $path = Join-Path -Path $currentDir.FullName -ChildPath '.git'
        if (Test-Path -Path $path)
        {
            return $currentDir
        }
        $currentDir = $currentDir.Parent
    }

    throw new-object System.IO.DirectoryNotFoundException("Could not find the root of the GIT repository")
}

<#
.Synopsis
    Sets the Secure File ACL. 
    1. Removed all user acl except Administrators group, system, and current user
    2. whether or not take the owner

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
    takeowner - if want to take the ownership
#>
function Cleanup-SecureFileACL 
{
    [CmdletBinding()]
    param([string]$FilePath, [System.Security.Principal.NTAccount] $Owner)

    $myACL = Get-ACL $filePath
    $myACL.SetAccessRuleProtection($True, $True)
    Set-Acl -Path $filePath -AclObject $myACL

    $myACL = Get-ACL $filePath
    if($owner -ne $null)
    {        
        $myACL.SetOwner($owner)
    }
    
    if($myACL.Access) 
    {        
        $myACL.Access | % {
            if (($_ -ne $null) -and ($_.IdentityReference.Value -ine "BUILTIN\Administrators") -and 
            ($_.IdentityReference.Value -ine "NT AUTHORITY\SYSTEM") -and 
            ($_.IdentityReference.Value -ine "$(whoami)"))
            {
                if(-not ($myACL.RemoveAccessRule($_)))
                {
                    throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                }
            }
        }
    }

    Set-Acl -Path $filePath -AclObject $myACL
}

<#
.Synopsis
    add a file permission to an account

.Outputs
    N/A

.Inputs
    FilePath - The path to the file    
    User - account name
    Perm - The permission to grant.
#>
function Add-PermissionToFileACL 
{
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $User,
        [System.Security.AccessControl.FileSystemRights]$Perm
    )    

    $myACL = Get-ACL $filePath
        
    $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($User, $perm, "None", "None", "Allow") 
    $myACL.AddAccessRule($objACE)    

    Set-Acl -Path $filePath -AclObject $myACL
}

Export-ModuleMember -Function Get-RepositoryRoot, Add-PermissionToFileACL, Cleanup-SecureFileACL 