Enum PlatformType {
    Windows
    Linux
    OSX
}

function Get-Platform {
    # Use the .NET Core APIs to determine the current platform; if a runtime
    # exception is thrown, we are on FullCLR, not .NET Core.
    try {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]
        $OSPlatform = [System.Runtime.InteropServices.OSPlatform]
        
        $IsLinux = $Runtime::IsOSPlatform($OSPlatform::Linux)
        $IsOSX = $Runtime::IsOSPlatform($OSPlatform::OSX)
        $IsWindows = $Runtime::IsOSPlatform($OSPlatform::Windows)
    } catch {    
        try {            
            $IsLinux = $false
            $IsOSX = $false
            $IsWindows = $true
        }
        catch { }
    }
    if($IsOSX) {
        [PlatformType]::OSX
    } elseif($IsLinux) {
        [PlatformType]::Linux
    } else {        
        [PlatformType]::Windows    
    }
}

<#
.Synopsis
    user key should be owned by current user account
    private key can be accessed only by the file owner, localsystem and Administrators
    public user key can be accessed by only file owner, localsystem and Administrators and read by everyone

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
    Owner - The file owner
    OwnerPerms - The permissions grant to owner
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

    if(-not ($actualOwner.Equals($adminAccount)) -and (-not $actualOwner.Equals($systemAccount)) -and $OwnerPerms)
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

function Set-FileOwnerAndACL
{            
    param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount]$Owner = $null,
        [System.Security.AccessControl.FileSystemRights[]] $OwnerPerms = @("Read", "Write")
        )

    $myACL = Get-ACL -Path $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $FilePath -AclObject $myACL

    $myACL = Get-ACL $FilePath
    $actualOwner = $null
    if($owner -eq $null)
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

    if($OwnerPerms)
    {
        $OwnerPerms | % { 
            $ownerACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($actualOwner, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($ownerACE)
        }
    }

    Set-Acl -Path $FilePath -AclObject $myACL
}
        
function Add-PermissionToFileACL 
{    
    param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $User,
        [System.Security.AccessControl.FileSystemRights[]]$Perms,
        [System.Security.AccessControl.AccessControlType] $AccessType = "Allow"
    )    

    $myACL = Get-ACL $FilePath

    if($Perms)
    {
        $Perms | % { 
            $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($User, $_, "None", "None", $AccessType)
            $myACL.AddAccessRule($userACE)
        }
    }   

    Set-Acl -Path $FilePath -AclObject $myACL
}

function Add-PasswordSetting 
{
    param([string] $pass)
    $platform = Get-Platform
    if ($platform -eq [PlatformType]::Windows) {
        if (-not($env:DISPLAY)) {$env:DISPLAY = 1}
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo $pass"
    }
}

function Remove-PasswordSetting
{
    if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
    Remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
}