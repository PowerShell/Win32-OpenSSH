# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$logsdir = Join-Path $scriptdir "logs"

$sshdAccount = "NT SERVICE\SSHD"

#Idea borrowed from http://sqldbamusings.blogspot.com/2012/03/powershell-adding-accounts-to-local.html
function Add-Privilege
{
    param(
    [string] $Account,
    
    [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeServiceLogonRight")]
    [string] $Privilege
    )

    #Get $Account SID
    $account_sid = $null
    try 
    {
	    $ntprincipal = new-object System.Security.Principal.NTAccount "$Account"
	    $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
	    $account_sid = $sid.Value.ToString()
    } 
    catch 
    {
	    Throw 'Unable to resolve '+ $Account
    }

    #Prepare policy settings file to be applied
    $settings_to_export = [System.IO.Path]::GetTempFileName()
    "[Unicode]" | Set-Content $settings_to_export -Encoding Unicode
    "Unicode=yes" | Add-Content $settings_to_export -Force -WhatIf:$false
    "[Version]"  | Add-Content $settings_to_export -Force -WhatIf:$false
    "signature=`"`$CHICAGO`$`"" | Add-Content $settings_to_export -Force -WhatIf:$false
    "Revision=1" | Add-Content $settings_to_export -Force -WhatIf:$false
    "[Privilege Rights]" | Add-Content $settings_to_export -Force -WhatIf:$false

    #Get Current policy settings
    $imported_settings = [System.IO.Path]::GetTempFileName()
    secedit.exe /export /areas USER_RIGHTS /cfg "$($imported_settings)" > $null 

    if (-not(Test-Path $imported_settings)) {
        Throw "Unable to import current security policy settings"
    }

    #find current assigned accounts to $Privilege and add it to $settings_to_export
    $current_settings = Get-Content $imported_settings -Encoding Unicode
    $existing_setting = $null
    foreach ($setting in $current_settings) {
        if ($setting -like "$Privilege`*") {
            $existing_setting = $setting
        }            
    }

    #Add $account_sid to list
    if ($existing_setting -eq $null) {
        $Privilege + " = *" + $account_sid | Add-Content $settings_to_export -Force -WhatIf:$false
    }
    else
    {
        $existing_setting + ",*" + $account_sid | Add-Content $settings_to_export -Force -WhatIf:$false
    }

    #export
    secedit.exe /configure /db "secedit.sdb" /cfg "$($settings_to_export)" /areas USER_RIGHTS > $null 

}


if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1> null
}

New-Service -Name ssh-agent -BinaryPathName $sshagentpath -Description "SSH Agent" -StartupType Manual | Out-Null
cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'

New-Service -Name sshd -BinaryPathName $sshdpath -Description "SSH Daemon" -StartupType Manual -DependsOn ssh-agent | Out-Null
sc.exe config sshd obj= $sshdAccount
sc.exe privs sshd SeAssignPrimaryTokenPrivilege

Add-Privilege -Account $sshdAccount -Privilege SeAssignPrimaryTokenPrivilege

if(-not (test-path $logsdir -PathType Container))
{
    $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
}
$rights = [System.Security.AccessControl.FileSystemRights]"Read, Write"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sshdAccount, $rights, "ContainerInherit,ObjectInherit", "None", "Allow")
$acl = Get-Acl -Path $logsdir
$Acl.SetAccessRule($accessRule)
Set-Acl -Path $logsdir -AclObject $acl
Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
