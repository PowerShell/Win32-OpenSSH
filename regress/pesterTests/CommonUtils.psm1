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

function Set-SecureFileACL 
{            
    param(
        [string]$FilePath,
        [System.Security.Principal.NTAccount]$Owner = $null
        )

    $myACL = Get-ACL -Path $FilePath
    $myACL.SetAccessRuleProtection($True, $True)
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

    $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($actualOwner, "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($objACE)

    Set-Acl -Path $FilePath -AclObject $myACL
}
        
function Add-PermissionToFileACL 
{    
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