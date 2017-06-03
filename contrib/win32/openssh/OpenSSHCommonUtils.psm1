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
    Set owner of the file to by LOCALSYSTEM account
    Set private host key be fully controlled by LOCALSYSTEM and Administrators
    Set public host key be fully controlled by LOCALSYSTEM and Administrators, read access by everyone

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
#>
function Adjust-HostKeyFileACL
{
        param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $myACL = Get-ACL $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $FilePath -AclObject $myACL

    $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
    $everyoneAccount = New-Object System.Security.Principal.NTAccount("EveryOne")
    $myACL = Get-ACL $FilePath

    $myACL.SetOwner($systemAccount)

    if($myACL.Access) 
    {        
        $myACL.Access | % {
            if(-not ($myACL.RemoveAccessRule($_)))
            {
                throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
            }
        }
    }    

    $adminACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($adminAccount, "FullControl", "None", "None", "Allow") 
    $myACL.AddAccessRule($adminACE)

    $systemACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($systemAccount, "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($systemACE)

    if($FilePath.EndsWith(".pub"))
    {
        $everyoneAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("Everyone", "Read", "None", "None", "Allow")
        $myACL.AddAccessRule($everyoneAce)
    }

    Set-Acl -Path $FilePath -AclObject $myACL
}

<#
.Synopsis
    Set owner of the user key file
    Set ACL to have private user key be fully controlled by LOCALSYSTEM and Administrators, Read, write access by owner
    Set public user key be fully controlled by LOCALSYSTEM and Administrators, Read, write access by owner, read access by everyone

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
    Owner - owner of the file
    OwnerPerms - the permissions grant to the owner
#>
function Adjust-UserKeyFileACL
{
    param (
    [parameter(Mandatory=$true)]
    [string]$FilePath,
    [System.Security.Principal.NTAccount] $Owner = $null,
    [System.Security.AccessControl.FileSystemRights[]] $OwnerPerms = $null
    )

    $myACL = Get-ACL $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $FilePath -AclObject $myACL

    $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
    $everyoneAccount = New-Object System.Security.Principal.NTAccount("EveryOne")
    $myACL = Get-ACL $FilePath

    $actualOwner = $null
    if($Owner -eq $null)
    {
        $actualOwner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
    }
    else
    {
        $actualOwner = $Owner
    }

    $myACL.SetOwner($actualOwner)

    if($myACL.Access) 
    {        
        $myACL.Access | % {
            if(-not ($myACL.RemoveAccessRule($_)))
            {
                throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
            }
        }
    }    

    $adminACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($adminAccount, "FullControl", "None", "None", "Allow") 
    $myACL.AddAccessRule($adminACE)

    $systemACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($systemAccount, "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($systemACE)

    if($OwnerPerms)
    {
        $OwnerPerms | % { 
            $ownerACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($actualOwner, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($ownerACE)
        }
    }

    if($FilePath.EndsWith(".pub"))
    {
        $everyoneAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("Everyone", "Read", "None", "None", "Allow")
        $myACL.AddAccessRule($everyoneAce)
    }
    
    Set-Acl -Path $FilePath -AclObject $myACL
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

    Set-Acl -Path $FilePath -AclObject $myACL
}

Export-ModuleMember -Function Get-RepositoryRoot, Add-PermissionToFileACL, Adjust-HostKeyFileACL, Adjust-UserKeyFileACL