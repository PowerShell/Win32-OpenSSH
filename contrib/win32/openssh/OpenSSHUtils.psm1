$systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
$adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")            
$currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
$everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
$sshdAccount = New-Object System.Security.Principal.NTAccount("NT SERVICE","sshd")

<#
    .Synopsis
    Fix-HostSSHDConfigPermissions
    fix the file owner and permissions of sshd_config
#>
function Fix-HostSSHDConfigPermissions
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [switch] $Quiet)

        Fix-FilePermissions -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount @psBoundParameters
}

<#
    .Synopsis
    Fix-HostKeyPermissions
    fix the file owner and permissions of host private and public key
    -FilePath: The path of the private host key
#>
function Fix-HostKeyPermissions
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [switch] $Quiet)
        $parameters = $PSBoundParameters
        if($parameters["FilePath"].EndsWith(".pub"))
        {
            $parameters["FilePath"] = $parameters["FilePath"].Replace(".pub", "")
        }
        Fix-FilePermissions -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount @psBoundParameters
        
        $parameters["FilePath"] += ".pub"
        Fix-FilePermissions -Owners $systemAccount,$adminsAccount -ReadAccessOK $everyone -ReadAccessNeeded $sshdAccount @parameters
}

<#
    .Synopsis
    Fix-AuthorizedKeyPermissions
    fix the file owner and permissions of authorized_keys
#>
function Fix-AuthorizedKeyPermissions
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [switch] $Quiet)        

        if(-not (Test-Path $FilePath -PathType Leaf))
        {
            Write-host "$FilePath not found" -ForegroundColor Yellow
            return
        }
        $fullPath = (Resolve-Path $FilePath).Path
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profileItem = Get-ChildItem $profileListPath  -ErrorAction Ignore | ? { 
            $fullPath.ToLower().Contains((Get-ItemPropertyValue $_.PSPath -Name ProfileImagePath -ErrorAction Ignore).Tolower())
        }
        if($profileItem)
        {
            $userSid = $profileItem.PSChildName
            $account = Get-UserAccount -UserSid $userSid
            Fix-FilePermissions -Owners $account,$adminsAccount,$systemAccount -AnyAccessOK $account -ReadAccessNeeded $sshdAccount @psBoundParameters
        }
        else
        {
            Write-host "$fullPath is not in the profile folder of any user. Skip checking..." -ForegroundColor Yellow
        }
}

<#
    .Synopsis
    Fix-UserKeyPermissions
    fix the file owner and permissions of user config
    -FilePath: The path of the private user key
#>
function Fix-UserKeyPermissions
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [switch] $Quiet)

        $parameters = $PSBoundParameters
        if($parameters["FilePath"].EndsWith(".pub"))
        {
            $parameters["FilePath"] = $parameters["FilePath"].Replace(".pub", "")
        }
        Fix-FilePermissions -Owners $currentUser, $adminsAccount,$systemAccount -AnyAccessOK $currentUser @psBoundParameters
        
        $parameters["FilePath"] += ".pub"
        Fix-FilePermissions -Owners $currentUser, $adminsAccount,$systemAccount -AnyAccessOK $currentUser -ReadAccessOK $everyone @parameters
}

<#
    .Synopsis
    Fix-UserSSHConfigPermissions
    fix the file owner and permissions of user config
#>
function Fix-UserSSHConfigPermissions
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [switch] $Quiet)
        Fix-FilePermissions -Owners $currentUser,$adminsAccount,$systemAccount -AnyAccessOK $currentUser @psBoundParameters
}

<#
    .Synopsis
    Fix-FilePermissionInternal
    Only validate owner and ACEs of the file
#>
function Fix-FilePermissions
{
    param (        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $AnyAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessNeeded,
        [switch] $Quiet
    )

    if(-not (Test-Path $FilePath -PathType Leaf))
    {
        Write-host "$FilePath not found" -ForegroundColor Yellow
        return
    }
    
    Write-host "  [*] $FilePath"
    $return = Fix-FilePermissionInternal @PSBoundParameters

    if($return -contains $true) 
    {
        #Write-host "Re-check the health of file $FilePath"
        Fix-FilePermissionInternal @PSBoundParameters
    }
}

<#
    .Synopsis
    Fix-FilePermissionInternal
#>
function Fix-FilePermissionInternal {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $AnyAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessNeeded,
        [switch] $Quiet
    )

    $acl = Get-Acl $FilePath
    $needChange = $false
    $health = $true
    if ($Quiet)
    {
        $result = 'Y'
    }
    
    if(-not $Owners.Contains([System.Security.Principal.NTAccount]$($acl.Owner)))
    {
        if (-not $Quiet) {
            $warning = "Current owner: '$($acl.Owner)'. '$($Owners[0])' should own $FilePath."
            Do {
                Write-Warning $warning
                $input = Read-Host -Prompt "Shall I set the file owner? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }        
            } until ($input -match "^(y(es)?|N(o)?)$")
            $result = $Matches[0]
        }        

        if($result.ToLower().Startswith('y'))
        {
            $needChange = $true
            $acl.SetOwner($Owners[0])
            Write-Host "'$($Owners[0])' now owns $FilePath. " -ForegroundColor Green
        }
        else
        {
            $health = $false
            Write-Host "The owner is still set to '$($acl.Owner)'." -ForegroundColor Yellow
        }
    }

    $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

    #system and admin groups can have any access to the file; plus the account in the AnyAccessOK list
    $realAnyAccessOKList = $AnyAccessOK + @($systemAccount, $adminsAccount)

    #if accounts in the ReadAccessNeeded already part of dacl, they are okay; need to make sure they have read access only
    $realReadAcessOKList = $ReadAccessOK + $ReadAccessNeeded

    #this is orginal list requested by the user, the account will be removed from the list if they already part of the dacl
    $realReadAccessNeeded = $ReadAccessNeeded

    foreach($a in $acl.Access)
    {
        if(($realAnyAccessOKList -ne $null) -and $realAnyAccessOKList.Contains($a.IdentityReference))
        {
            #ignore those accounts listed in the AnyAccessOK list.
        }
        #If everyone is in the ReadAccessOK list, any user can have read access;
        # below block make sure they are granted Read access only
        elseif($realReadAcessOKList -and (($realReadAcessOKList.Contains($everyone)) -or `
             ($realReadAcessOKList.Contains($a.IdentityReference))))
        {
            if($realReadAccessNeeded -and ($a.IdentityReference.Equals($everyone)))
            {
                $realReadAccessNeeded.Clear()
            }
            elseif($realReadAccessNeeded -and $realReadAccessNeeded.Contains($a.IdentityReference))
            {
                    $realReadAccessNeeded = $realReadAccessNeeded | ? { -not $_.Equals($a.IdentityReference) }
            }

            if (-not ($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -or `
            (-not (([System.UInt32]$a.FileSystemRights.value__) -band (-bnot $ReadAccessPerm))))
            {
                continue;
            }

            $warning = "'$($a.IdentityReference)' has the following access to $($FilePath): '$($a.FileSystemRights)'." 
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Set-Acl -Path $FilePath -AclObject $acl     
                }

                $message = @"
$warning
Need to remove inheritance to fix it.
"@                

                return Remove-RuleProtection -FilePath $FilePath -Message $message -Quiet:$Quiet
            }
            
            if (-not $Quiet) {
                Do {
                        Write-Warning $warning
                        $input = Read-Host -Prompt "Shall I make it Read only? [Yes] Y; [No] N (default is `"Y`")"
                        if([string]::IsNullOrEmpty($input))
                        {
                            $input = 'Y'
                        }
                    
                    } until ($input -match "^(y(es)?|N(o)?)$")
                $result = $Matches[0]
            }

            if($result.ToLower().Startswith('y'))
            {   
                $needChange = $true
                $sshAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
                    ($a.IdentityReference, "Read", "None", "None", "Allow")
                $acl.SetAccessRule($sshAce)
                Write-Host "'$($a.IdentityReference)' now has Read access to $FilePath. "  -ForegroundColor Green
            }
            else
            {
                $health = $false
                Write-Host "'$($a.IdentityReference)' still has these access to $($FilePath): '$($a.FileSystemRights)'." -ForegroundColor Yellow
            }
          }
        #other than AnyAccessOK and ReadAccessOK list, if any other account is allowed, they should be removed from the dacl
        elseif($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow))
        {
            
            $warning = "'$($a.IdentityReference)' should not have access to '$FilePath'. " 
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Set-Acl -Path $FilePath -AclObject $acl     
                }
                $message = @"
$warning
Need to remove inheritance to fix it.
"@                
                return Remove-RuleProtection -FilePath $FilePath -Message $message -Quiet:$Quiet
            }
            if (-not $Quiet) {
                Do {            
                    Write-Warning $warning
                    $input = Read-Host -Prompt "Shall I remove this access? [Yes] Y; [No] N (default is `"Y`")"
                    if([string]::IsNullOrEmpty($input))
                    {
                        $input = 'Y'
                    }        
                } until ($input -match "^(y(es)?|N(o)?)$")
                $result = $Matches[0]
            }
        
            if($result.ToLower().Startswith('y'))
            {   
                $needChange = $true
                if(-not ($acl.RemoveAccessRule($a)))
                {
                    throw "failed to remove access of $($a.IdentityReference) rule to file $FilePath"
                }
                else
                {
                    Write-Host "'$($a.IdentityReference)' has no more access to $FilePath." -ForegroundColor Green
                }
            }
            else
            {
                $health = $false
                Write-Host "'$($a.IdentityReference)' still has access to $FilePath." -ForegroundColor Yellow
            }
        }    
    }

    #This is the real account list we need to add read access to the file
    if($realReadAccessNeeded)
    {
        $realReadAccessNeeded | % {
            if([string]::IsNullOrEmpty((Get-UserSID -User $_)))
            {
                Write-Warning "'$_' needs Read access to $FilePath', but it does not exit on the machine."
            }
            else
            {
                if (-not $Quiet) {
                    $warning = "'$_' needs Read access to $FilePath'."
                    Do {
                        Write-Warning $warning
                        $input = Read-Host -Prompt "Shall I make the above change? [Yes] Y; [No] N (default is `"Y`")"
                        if([string]::IsNullOrEmpty($input))
                        {
                            $input = 'Y'
                        }        
                    } until ($input -match "^(y(es)?|N(o)?)$")
                    $result = $Matches[0]
                }
        
                if($result.ToLower().Startswith('y'))
                {
                    $needChange = $true
                    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($_, "Read", "None", "None", "Allow")
                    $acl.AddAccessRule($ace)
                    Write-Host "'$_' now has Read access to $FilePath. " -ForegroundColor Green
                }
                else
                {
                    $health = $false
                    Write-Host "'$_' does not have Read access to $FilePath." -ForegroundColor Yellow
                }
            }
        }
    }

    if($needChange)    
    {
        Set-Acl -Path $FilePath -AclObject $acl     
    }
    if($health)
    {
        if ($needChange) 
        {
            Write-Host "      fixed permissions" -ForegroundColor Yellow
        }
        else 
        {
            Write-Host "      looks good"  -ForegroundColor Green
        }
    }
    Write-host " "
}

<#
    .Synopsis
    Remove-RuleProtection
#>
function Remove-RuleProtection
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$Message,
        [switch] $Quiet
    )
    if (-not $Quiet) {
        Do 
        {
            Write-Warning $Message
            $input = Read-Host -Prompt "Shall I remove the inheritace? [Yes] Y; [No] N (default is `"Y`")"
            if([string]::IsNullOrEmpty($input))
            {
                $input = 'Y'
            }                  
        } until ($input -match "^(y(es)?|N(o)?)$")
        $result = $Matches[0]
    }

    if($result.ToLower().Startswith('y'))
    {   
        $acl = Get-ACL $FilePath
        $acl.SetAccessRuleProtection($True, $True)
        Set-Acl -Path $FilePath -AclObject $acl
        Write-Host "inheritance is removed from $FilePath. "  -ForegroundColor Green
        return $true
    }
    else
    {        
        Write-Host "inheritance is not removed from $FilePath. Skip Checking FilePath."  -ForegroundColor Yellow
        return $false
    }
}
<#
    .Synopsis
    Get-UserAccount
#>
function Get-UserAccount
{
    param
        (   [parameter(Mandatory=$true)]      
            [string]$UserSid
        )
    try
    {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSid) 
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
        $objUser
    }
    catch {
    }
}

<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{
    param ([System.Security.Principal.NTAccount]$User)    
    try
    {
        $strSID = $User.Translate([System.Security.Principal.SecurityIdentifier])
        $strSID.Value
    }
    catch {
    }
}


Export-ModuleMember -Function Fix-HostSSHDConfigPermissions, Fix-HostKeyPermissions, Fix-AuthorizedKeyPermissions, Fix-UserKeyPermissions, Fix-UserSSHConfigPermissions
