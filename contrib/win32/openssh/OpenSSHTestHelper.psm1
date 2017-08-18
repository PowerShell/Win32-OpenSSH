$ErrorActionPreference = 'Stop'
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -Force
Import-Module $PSScriptRoot\OpenSSHUtils -Force

[System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
# test environment parameters initialized with defaults
$E2ETestResultsFileName = "E2ETestResults.xml"
$UnitTestResultsFileName = "UnitTestResults.txt"
$TestSetupLogFileName = "TestSetupLog.txt"
$SSOUser = "sshtest_ssouser"
$PubKeyUser = "sshtest_pubkeyuser"
$PasswdUser = "sshtest_passwduser"
$OpenSSHTestAccountsPassword = "P@ssw0rd_1"
$OpenSSHTestAccounts = $Script:SSOUser, $Script:PubKeyUser, $Script:PasswdUser

$Script:TestDataPath = "$env:SystemDrive\OpenSSHTests"
$Script:E2ETestResultsFile = Join-Path $TestDataPath $E2ETestResultsFileName
$Script:UnitTestResultsFile = Join-Path $TestDataPath $UnitTestResultsFileName
$Script:TestSetupLogFile = Join-Path $TestDataPath $TestSetupLogFileName
$Script:E2ETestDirectory = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
$Script:WindowsInBox = $false
$Script:EnableAppVerifier = $true
$Script:PostmortemDebugging = $false

<#
    .Synopsis
    Set-OpenSSHTestEnvironment
    TODO - split these steps into client and server side 
#>
function Set-OpenSSHTestEnvironment
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param
    (   
        [string] $OpenSSHBinPath,
        [string] $TestDataPath = "$env:SystemDrive\OpenSSHTests",        
        [Boolean] $DebugMode = $false,
        [Switch] $NoAppVerifier,
        [Switch] $PostmortemDebugging
    )
    
    if($PSBoundParameters.ContainsKey("Verbose"))
    {
        $verboseInfo =  ($PSBoundParameters['Verbose']).IsPresent
    }
    
    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
    $Script:TestDataPath = $TestDataPath;
    $Script:E2ETestResultsFile = Join-Path $TestDataPath "E2ETestResults.xml"
    $Script:UnitTestResultsFile = Join-Path $TestDataPath "UnitTestResults.txt"
    $Script:TestSetupLogFile = Join-Path $TestDataPath "TestSetupLog.txt"
    $Script:UnitTestDirectory = Get-UnitTestDirectory
    $Script:EnableAppVerifier = -not ($NoAppVerifier.IsPresent)
    if($Script:EnableAppVerifier)
    {
        $Script:PostmortemDebugging = $PostmortemDebugging.IsPresent
    }

    $Global:OpenSSHTestInfo = @{        
        "Target"= "localhost";                                 # test listener name
        "Port"= "47002";                                       # test listener port
        "SSOUser"= $SSOUser;                                   # test user with single sign on capability
        "PubKeyUser"= $PubKeyUser;                             # test user to be used with explicit key for key auth
        "PasswdUser"= $PasswdUser;                             # common password for all test accounts
        "TestAccountPW"= $OpenSSHTestAccountsPassword;         # common password for all test accounts
        "TestDataPath" = $TestDataPath;                    # openssh tests path
        "TestSetupLogFile" = $Script:TestSetupLogFile;         # openssh test setup log file
        "E2ETestResultsFile" = $Script:E2ETestResultsFile;     # openssh E2E test results file
        "UnitTestResultsFile" = $Script:UnitTestResultsFile;   # openssh unittest test results file
        "E2ETestDirectory" = $Script:E2ETestDirectory          # the directory of E2E tests
        "UnitTestDirectory" = $Script:UnitTestDirectory        # the directory of unit tests
        "DebugMode" = $DebugMode                               # run openssh E2E in debug mode
        "EnableAppVerifier" = $Script:EnableAppVerifier
        "PostmortemDebugging" = $Script:PostmortemDebugging
        }
        
    #if user does not set path, pick it up
    if([string]::IsNullOrEmpty($OpenSSHBinPath))
    {
        $sshcmd = get-command ssh.exe -ErrorAction SilentlyContinue       
        if($sshcmd -eq $null)
        {
            Throw "Cannot find ssh.exe. Please specify -OpenSSHBinPath to the OpenSSH installed location."
        }
        else
        {
            $dirToCheck = split-path $sshcmd.Path
            $description = "Pick up ssh.exe from $dirToCheck."
            $prompt = "Are you sure you want to pick up ssh.exe from $($dirToCheck)?"           
            $caption = "Found ssh.exe from $dirToCheck"
            if(-not $pscmdlet.ShouldProcess($description, $prompt, $caption))
            {
                Write-Host "User decided not to pick up ssh.exe from $dirToCheck. Please specify -OpenSSHBinPath to the OpenSSH installed location."
                return
            }
            $script:OpenSSHBinPath = $dirToCheck
        }        
    }
    else
    {        
        if (-not (Test-Path (Join-Path $OpenSSHBinPath ssh.exe) -PathType Leaf))
        {
            Throw "Cannot find OpenSSH binaries under $OpenSSHBinPath. Please specify -OpenSSHBinPath to the OpenSSH installed location"
        }
        else
        {
            $script:OpenSSHBinPath = $OpenSSHBinPath
        }
    }

    $Global:OpenSSHTestInfo.Add("OpenSSHBinPath", $script:OpenSSHBinPath)
    if (-not ($env:Path.ToLower().Contains($script:OpenSSHBinPath.ToLower())))
    {
        $env:Path = "$($script:OpenSSHBinPath);$($env:path)"
    }

    $acl = get-acl (join-path $script:OpenSSHBinPath "ssh.exe")
    
    if($acl.Owner -ieq "NT SERVICE\TrustedInstaller")
    {
        $Script:WindowsInBox = $true
        $Global:OpenSSHTestInfo.Add("WindowsInBox", $true)
    }

    $description = @"
WARNING: Following changes will be made to OpenSSH configuration
   - sshd_config will be backed up as sshd_config.ori
   - will be replaced with a test sshd_config
   - $HOME\.ssh\known_hosts will be backed up as known_hosts.ori
   - will be replaced with a test known_hosts
   - $HOME\.ssh\config will be backed up as config.ori
   - will be replaced with a test config
   - sshd test listener will be on port 47002
   - $HOME\.ssh\known_hosts will be modified with test host key entry
   - test accounts - ssouser, pubkeyuser, and passwduser will be added
   - Setup single signon for ssouser
   - To cleanup - Run Clear-OpenSSHTestEnvironment
"@  
    
    $prompt = "Are you sure you want to perform the above operations?"
    $caption = $description
    if(-not $pscmdlet.ShouldProcess($description, $prompt, $caption))
    {
        Write-Host "User decided not to make the changes."
        return
    }

    Install-OpenSSHTestDependencies

    if(-not (Test-path $TestDataPath -PathType Container))
    {
       New-Item -ItemType Directory -Path $TestDataPath -Force -ErrorAction SilentlyContinue | out-null
    }

    #Backup existing OpenSSH configuration
    $backupConfigPath = Join-Path $script:OpenSSHBinPath sshd_config.ori
    if (-not (Test-Path $backupConfigPath -PathType Leaf)) {
        Copy-Item (Join-Path $script:OpenSSHBinPath sshd_config) $backupConfigPath -Force
    }
    $targetsshdConfig = Join-Path $script:OpenSSHBinPath sshd_config
    # copy new sshd_config
    if($Script:WindowsInBox -and (Test-Path $targetsshdConfig))
    {
        $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
        Add-PermissionToFileACL -FilePath $targetsshdConfig -User $currentUser -Perm "Read,Write"
    }
    
    Copy-Item (Join-Path $Script:E2ETestDirectory sshd_config) $targetsshdConfig -Force
    
    Start-Service ssh-agent

    #copy sshtest keys
    Copy-Item "$($Script:E2ETestDirectory)\sshtest*hostkey*" $script:OpenSSHBinPath -Force    
    Get-ChildItem "$($script:OpenSSHBinPath)\sshtest*hostkey*"| % {
        #workaround for the cariggage new line added by git before copy them
        $filePath = "$($_.FullName)"
        $con = (Get-Content $filePath | Out-String).Replace("`r`n","`n")
        Set-Content -Path $filePath -Value "$con"
        if (-not ($_.Name.EndsWith(".pub")))
        {
            Repair-SshdHostKeyPermission -FilePath $_.FullName -confirm:$false
            if($psversiontable.BuildVersion.Major -gt 6)
            {                
                #register private key with agent
                ssh-add-hostkey.ps1 $_.FullName
            }
        }        
    }

    Restart-Service sshd -Force
   
    #Backup existing known_hosts and replace with test version
    #TODO - account for custom known_hosts locations
    $dotSshDirectoryPath = Join-Path $home .ssh
    $knowHostsFilePath = Join-Path $dotSshDirectoryPath known_hosts
    if(-not (Test-Path $dotSshDirectoryPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $dotSshDirectoryPath -Force -ErrorAction SilentlyContinue | out-null
    }
    if ((Test-Path $knowHostsFilePath -PathType Leaf) -and (-not (Test-Path (Join-Path $dotSshDirectoryPath known_hosts.ori) -PathType Leaf))) {
        Copy-Item $knowHostsFilePath (Join-Path $dotSshDirectoryPath known_hosts.ori) -Force
    }
    Copy-Item (Join-Path $Script:E2ETestDirectory known_hosts) $knowHostsFilePath -Force

    $sshConfigFilePath = Join-Path $dotSshDirectoryPath config
    if ((Test-Path $sshConfigFilePath -PathType Leaf) -and (-not (Test-Path (Join-Path $dotSshDirectoryPath config.ori) -PathType Leaf))) {
        Copy-Item $sshConfigFilePath (Join-Path $dotSshDirectoryPath config.ori) -Force
    }
    Copy-Item (Join-Path $Script:E2ETestDirectory ssh_config) $sshConfigFilePath -Force
    Repair-UserSshConfigPermission -FilePath $sshConfigFilePath -confirm:$false

    # create test accounts
    #TODO - this is Windows specific. Need to be in PAL
    foreach ($user in $OpenSSHTestAccounts)
    {
        try
        {
            $objUser = New-Object System.Security.Principal.NTAccount($user)
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch
        {
            #only add the local user when it does not exists on the machine        
            net user $user $Script:OpenSSHTestAccountsPassword /ADD 2>&1 >> $Script:TestSetupLogFile
        }        
    }

    #setup single sign on for ssouser
    $ssouserProfile = Get-LocalUserProfile -User $SSOUser
    $Global:OpenSSHTestInfo.Add("SSOUserProfile", $ssouserProfile)
    $Global:OpenSSHTestInfo.Add("PubKeyUserProfile", (Get-LocalUserProfile -User $PubKeyUser))

    New-Item -ItemType Directory -Path (Join-Path $ssouserProfile .ssh) -Force -ErrorAction SilentlyContinue  | out-null
    $authorizedKeyPath = Join-Path $ssouserProfile .ssh\authorized_keys
    $testPubKeyPath = Join-Path $Script:E2ETestDirectory sshtest_userssokey_ed25519.pub
    Copy-Item $testPubKeyPath $authorizedKeyPath -Force -ErrorAction SilentlyContinue
    Repair-AuthorizedKeyPermission -FilePath $authorizedKeyPath -confirm:$false
    
    $testPriKeypath = Join-Path $Script:E2ETestDirectory sshtest_userssokey_ed25519
    $con = (Get-Content $testPriKeypath | Out-String).Replace("`r`n","`n")
    Set-Content -Path $testPriKeypath -Value "$con"
    cmd /c "ssh-add -D 2>&1 >> $Script:TestSetupLogFile"
    Repair-UserKeyPermission -FilePath $testPriKeypath -confirm:$false
    cmd /c "ssh-add $testPriKeypath 2>&1 >> $Script:TestSetupLogFile"

    #Enable AppVerifier
    if($EnableAppVerifier)
    {        
        # clear all applications in application verifier first
        &  $env:windir\System32\appverif.exe -disable * -for *  | out-null
        Get-ChildItem "$($script:OpenSSHBinPath)\*.exe" | % {
            & $env:windir\System32\appverif.exe -verify $_.Name  | out-null
        }

        if($Script:PostmortemDebugging -and (Test-path $Script:WindbgPath))
        {            
            # enable Postmortem debugger            
            New-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -Type String -Value "`"$Script:WindbgPath`" -p %ld -e %ld -g" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Auto -Type String -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    Backup-OpenSSHTestInfo
}
#TODO - this is Windows specific. Need to be in PAL
function Get-LocalUserProfile
{
    param([string]$User)
    $sid = Get-UserSID -User $User
    $userProfileRegistry = Join-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $sid
    if (-not (Test-Path $userProfileRegistry) ) {        
        #create profile
        if (-not($env:DISPLAY)) { $env:DISPLAY = 1 }
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo $($OpenSSHTestAccountsPassword)"
        $ret = ssh -p 47002 "$User@localhost" echo %userprofile%
        if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
        remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
    }   
    
    (Get-ItemProperty -Path $userProfileRegistry -Name 'ProfileImagePath').ProfileImagePath    
}


<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Pester for running the tests  
#>
function Install-OpenSSHTestDependencies
{
    [CmdletBinding()]
    param ()
    
    #$isOpenSSHUtilsAvailable = Get-Module 'OpenSSHUtils' -ListAvailable
    #if (-not ($isOpenSSHUtilsAvailable))
    #{      
        Write-Log -Message "Installing Module OpenSSHUtils..."
        Install-OpenSSHUtilsModule -SourceDir $PSScriptRoot
    #}
    Import-Module OpensshUtils -Force

    if($Script:WindowsInBox)
    {
        return
    }

    # Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Write-Log -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $Script:TestSetupLogFile
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {      
        Write-Log -Message "Installing Pester..." 
        choco install Pester -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }

    if($Script:PostmortemDebugging -or (($OpenSSHTestInfo -ne $null) -and ($OpenSSHTestInfo["PostmortemDebugging"])))
    {
        $folderName = "x86"
        $pathroot = $env:ProgramFiles
        if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
        {
            $folderName = "x64"
            $pathroot = ${env:ProgramFiles(x86)}
        }
        $Script:WindbgPath = "$pathroot\Windows Kits\8.1\Debuggers\$folderName\windbg.exe"
        if(-not (Test-Path $Script:WindbgPath))
        {
            $Script:WindbgPath = "$pathroot\Windows Kits\10\Debuggers\$folderName\windbg.exe"
            if(-not (Test-Path $Script:WindbgPath))
            {
                choco install windbg -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
            }            
        }        
    }

    if(($Script:EnableAppVerifier -or (($OpenSSHTestInfo -ne $null) -and ($OpenSSHTestInfo["EnableAppVerifier"]))) -and (-not (Test-path $env:windir\System32\appverif.exe)))
    {
        choco install appverifier -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
    }
}

function Install-OpenSSHUtilsModule
{
    [CmdletBinding()]
    param(   
        [string]$TargetDir = (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\OpenSSHUtils"),
        [string]$SourceDir)
    
    $manifestFile = Join-Path -Path $SourceDir -ChildPath OpenSSHUtils.psd1   
    $moduleFile    = Join-Path -Path $SourceDir -ChildPath OpenSSHUtils.psm1
    $targetDirectory = $TargetDir
    $manifest = Test-ModuleManifest -Path $manifestFile -WarningAction SilentlyContinue -ErrorAction Stop
    if ($PSVersionTable.PSVersion.Major -ge 5)
    {   
        $targetDirectory = Join-Path -Path $targetDir -ChildPath $manifest.Version.ToString()
    }
    
    $modulePath = Join-Path -Path $env:ProgramFiles -ChildPath WindowsPowerShell\Modules
    if(-not (Test-Path "$targetDirectory" -PathType Container))
    {
        New-Item -ItemType Directory -Path "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    }
    Copy-item "$manifestFile" -Destination "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    Copy-item "$moduleFile" -Destination "$targetDirectory" -Force -ErrorAction SilentlyContinue | out-null
    
    if ($PSVersionTable.PSVersion.Major -lt 4)
    {
        $modulePaths = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') -split ';'
        if ($modulePaths -notcontains $modulePath)
        {
            Write-Verbose -Message "Adding '$modulePath' to PSModulePath."

            $modulePaths = @(
                $modulePath
                $modulePaths
            )

            $newModulePath = $modulePaths -join ';'

            [Environment]::SetEnvironmentVariable('PSModulePath', $newModulePath, 'Machine')
            $env:PSModulePath += ";$modulePath"
        }
    }
}

function Uninstall-OpenSSHUtilsModule
{
    [CmdletBinding()]
    param([string]$TargetDir = (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\OpenSSHUtils"))    
    
    if(Test-Path $TargetDir -PathType Container)
    {
        Remove-item $TargetDir -Recurse -Force -ErrorAction SilentlyContinue | out-null
    }    
}

<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{
    param
        (             
            [string]$Domain,            
            [string]$User
        )
    if([string]::IsNullOrEmpty($Domain))
    {
        $objUser = New-Object System.Security.Principal.NTAccount($User)        
    }
    else
    {
        $objUser = New-Object System.Security.Principal.NTAccount($Domain, $User)
    }
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

<#
    .Synopsis
    Clear-OpenSSHTestEnvironment
#>
function Clear-OpenSSHTestEnvironment
{   
    if($Global:OpenSSHTestInfo -eq $null) {
        throw "OpenSSHTestInfo is not set. Did you run Set-OpenSShTestEnvironment?"
    }

    $sshBinPath = $Global:OpenSSHTestInfo["OpenSSHBinPath"]

    # .exe - Windows specific. TODO - PAL 
    if (-not (Test-Path (Join-Path $sshBinPath ssh.exe) -PathType Leaf))
    {
        Throw "Cannot find OpenSSH binaries under $script:OpenSSHBinPath. "
    }
    
    #unregister test host keys from agent
    Get-ChildItem "$sshBinPath\sshtest*hostkey*.pub"| % {
        ssh-add-hostkey.ps1 -Delete_key $_.FullName
    }

    if($Global:OpenSSHTestInfo["EnableAppVerifier"] -and (Test-path $env:windir\System32\appverif.exe))
    {
        # clear all applications in application verifier
        &  $env:windir\System32\appverif.exe -disable * -for * | out-null
    }

    if($Global:OpenSSHTestInfo["PostmortemDebugging"])
    {
        Remove-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger -ErrorAction SilentlyContinue -Force | Out-Null
        Remove-ItemProperty "HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Auto -ErrorAction SilentlyContinue -Force | Out-Null
    }
    
    Remove-Item $sshBinPath\sshtest*hostkey* -Force -ErrorAction SilentlyContinue    
    #Restore sshd_config
    $backupConfigPath = Join-Path $sshBinPath sshd_config.ori
    if (Test-Path $backupConfigPath -PathType Leaf) {        
        Copy-Item $backupConfigPath (Join-Path $sshBinPath sshd_config) -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $sshBinPath sshd_config.ori) -Force -ErrorAction SilentlyContinue
        Restart-Service sshd
    }
    
    #Restore known_hosts
    $originKnowHostsPath = Join-Path $home .ssh\known_hosts.ori
    if (Test-Path $originKnowHostsPath)
    {
        Copy-Item $originKnowHostsPath (Join-Path $home .ssh\known_hosts) -Force -ErrorAction SilentlyContinue
        Remove-Item $originKnowHostsPath -Force -ErrorAction SilentlyContinue
    }

    #Restore ssh_config
    $originConfigPath = Join-Path $home .ssh\config.ori
    if (Test-Path $originConfigPath)
    {
        Copy-Item $originConfigPath (Join-Path $home .ssh\config) -Force -ErrorAction SilentlyContinue
        Remove-Item $originConfigPath -Force -ErrorAction SilentlyContinue
    }

    #Delete accounts
    foreach ($user in $OpenSSHTestAccounts)
    {
        net user $user /delete
    }
    
    # remove registered keys    
    cmd /c "ssh-add -d (Join-Path $Script:E2ETestDirectory sshtest_userssokey_ed25519) 2>&1 >> $Script:TestSetupLogFile"

    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }
    
    $isOpenSSHUtilsAvailable = Get-Module 'OpenSSHUtils' -ListAvailable
    if ($isOpenSSHUtilsAvailable)
    {      
        Write-Log -Message "Uninstalling Module OpenSSHUtils..."
        Uninstall-OpenSSHUtilsModule
    }
}

<#
    .Synopsis
    Get-UnitTestDirectory.
#>
function Get-UnitTestDirectory
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    [string] $platform = $env:PROCESSOR_ARCHITECTURE
    if(-not [String]::IsNullOrEmpty($NativeHostArch))
    {
        $folderName = $NativeHostArch
        if($NativeHostArch -eq 'x86')
        {
            $folderName = "Win32"
        }
    }
    else
    {
        if($platform -ieq "AMD64")
        {
            $folderName = "x64"
        }
        else
        {
            $folderName = "Win32"
        }
    }

    if([String]::IsNullOrEmpty($Configuration))
    {
        if( $folderName -ieq "Win32" )
        {
            $RealConfiguration = "Debug"
        }
        else
        {
            $RealConfiguration = "Release"
        }
    }
    else
    {
        $RealConfiguration = $Configuration
    }    
    $unitTestdir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"
    $unitTestDir
}

<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Invoke-OpenSSHE2ETest
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('CI', 'Scenario')]
        [string]$pri = "CI")
    # Discover all CI tests and run them.
    Import-Module pester -force -global
    Push-Location $Script:E2ETestDirectory
    Write-Log -Message "Running OpenSSH E2E tests..."    
    $testFolders = @(Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique)
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:E2ETestResultsFile -Tag $pri -PassThru
    Pop-Location
}

<#
    .Synopsis
    Run openssh unit tests.
#>
function Invoke-OpenSSHUnitTest
{     
    # Discover all CI tests and run them.
    if([string]::Isnullorempty($Script:UnitTestDirectory))
    {
        $Script:UnitTestDirectory = $OpenSSHTestInfo["UnitTestDirectory"]
    }
    Push-Location $Script:UnitTestDirectory
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $Script:UnitTestResultsFile)
    {
        $null = Remove-Item -Path $Script:UnitTestResultsFile -Force -ErrorAction SilentlyContinue
    }
    $testFolders = Get-ChildItem -filter unittest-*.exe -Recurse -Exclude unittest-sshkey.exe,unittest-kex.exe |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique
    $testfailed = $false
    if ($testFolders -ne $null)
    {
        $testFolders | % {            
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            $unittestFilePath = join-path $_ $unittestFile
            $Error.clear()
            $LASTEXITCODE=0
            if(Test-Path $unittestFilePath -pathtype leaf)
            {
                Push-Location $_
                Write-Log "Running OpenSSH unit $unittestFile ..."
                & "$unittestFilePath" >> $Script:UnitTestResultsFile
                Pop-Location
            }
            
            $errorCode = $LASTEXITCODE
            if ($errorCode -ne 0)
            {
                $testfailed = $true
                $errorMessage = "$_ test failed for OpenSSH.`nExitCode: $errorCode. Detail test log is at $($Script:UnitTestResultsFile)."
                Write-Warning $errorMessage                         
            }            
        }
    }
    Pop-Location
    $testfailed
}

function Backup-OpenSSHTestInfo
{
    param
    (    
        [string] $BackupFile = $null
    )

    if ($Global:OpenSSHTestInfo -eq $null) {
        Throw "`$OpenSSHTestInfo is null. Did you run Set-OpenSSHTestEnvironment yet?"
    }
    
    $testInfo = $Global:OpenSSHTestInfo
    
    if ([String]::IsNullOrEmpty($BackupFile)) {
        $BackupFile = Join-Path $testInfo["TestDataPath"] "OpenSSHTestInfo_backup.txt"
    }
    
    $null | Set-Content $BackupFile

    foreach ($key in $testInfo.Keys) {
        $value = $testInfo[$key]
        Add-Content $BackupFile "$key,$value"
    }
}

function Restore-OpenSSHTestInfo
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $BackupFile
    )

    if($Global:OpenSSHTestInfo -ne $null)
    {
        $Global:OpenSSHTestInfo.Clear()
        $Global:OpenSSHTestInfo = $null
    }

    $Global:OpenSSHTestInfo = @{}

    $entries = Get-Content $BackupFile

    foreach ($entry in $entries) {
        $data = $entry.Split(",")
        $Global:OpenSSHTestInfo[$data[0]] = $data[1] 
    }
}

<#
    Write-Log 
#>
function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    if(-not (Test-Path (Split-Path $Script:TestSetupLogFile) -PathType Container))
    {
        $null = New-Item -ItemType Directory -Path (Split-Path $Script:TestSetupLogFile) -Force -ErrorAction SilentlyContinue | out-null
    }
    if (-not ([string]::IsNullOrEmpty($Script:TestSetupLogFile)))
    {
        Add-Content -Path $Script:TestSetupLogFile -Value $Message
    }  
}

Export-ModuleMember -Function Set-OpenSSHTestEnvironment, Clear-OpenSSHTestEnvironment, Invoke-OpenSSHUnitTest, Invoke-OpenSSHE2ETest, Backup-OpenSSHTestInfo, Restore-OpenSSHTestInfo
