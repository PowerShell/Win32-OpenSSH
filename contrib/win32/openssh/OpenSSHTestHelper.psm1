$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -DisableNameChecking

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
   
<#
    .Synopsis
    Setup-OpenSSHTestEnvironment
    TODO - split these steps into client and server side 
#>
function Setup-OpenSSHTestEnvironment
{
    [CmdletBinding()]
    param
    (    
        [switch] $Quiet,
        [string] $OpenSSHBinPath,
        [string] $TestDataPath = "$env:SystemDrive\OpenSSHTests",
        [Boolean] $DebugMode = $false
    )
    
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
        }
        
    #if user does not set path, pick it up
    if([string]::IsNullOrEmpty($OpenSSHBinPath))
    {
        $sshcmd = get-command ssh.exe -ErrorAction Ignore        
        if($sshcmd -eq $null)
        {
            Throw "Cannot find ssh.exe. Please specify -OpenSSHBinPath to the OpenSSH installed location."
        }
        elseif($Quiet)
        {
            $dirToCheck = split-path $sshcmd.Path
            $script:OpenSSHBinPath = $dirToCheck
        }
        else
        {
            $dirToCheck = split-path $sshcmd.Path
            $message = "Do you want to test openssh installed at $($dirToCheck)? [Yes] Y; [No] N (default is `"Y`")"
            $response = Read-Host -Prompt $message
            if( ($response -eq "") -or ($response -ieq "Y") -or ($response -ieq "Yes") )
            {
                $script:OpenSSHBinPath = $dirToCheck
            }
            elseif( ($response -ieq "N") -or ($response -ieq "No") )
            {
                Write-Host "User decided not to pick up ssh.exe from $dirToCheck. Please specify -OpenSSHBinPath to the OpenSSH installed location."
                return
            }
            else
            {
                Throw "User entered invalid option ($response). Please specify -OpenSSHBinPath to the OpenSSH installed location"
            }
        }        
    }
    else
    {        
        if (-not (Test-Path (Join-Path $OpenSSHBinPath ssh.exe) -PathType Leaf))
        {
            Throw "Cannot find OpenSSH binaries under $OpenSSHBinPath. Please specify -OpenSSHBinPathto the OpenSSH installed location"
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

    $warning = @"
WARNING: Following changes will be made to OpenSSH configuration
   - sshd_config will be backed up as sshd_config.ori
   - will be replaced with a test sshd_config
   - $HOME\.ssh\known_hosts will be backed up as known_hosts.ori
   - will be replaced with a test known_hosts
   - sshd test listener will be on port 47002
   - $HOME\.ssh\known_hosts will be modified with test host key entry
   - test accounts - ssouser, pubkeyuser, and passwduser will be added
   - Setup single signon for ssouser
   - To cleanup - Run Cleanup-OpenSSHTestEnvironment
"@

    if (-not $Quiet) {
        Write-Warning $warning
        $continue = Read-Host -Prompt "Do you want to continue with the above changes? [Yes] Y; [No] N (default is `"Y`")"
        if( ($continue -ieq "N") -or ($continue -ieq "No") )
        {
            Write-Host "User decided not to make the changes."
            return
        }
        elseif(($continue -ne "") -and ($continue -ine "Y") -and ($continue -ine "Yes"))        
        {
            Throw "User entered invalid option ($continue). Exit now."
        }
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
    
    # copy new sshd_config
    Copy-Item (Join-Path $Script:E2ETestDirectory sshd_config) (Join-Path $script:OpenSSHBinPath sshd_config) -Force
    
    #workaround for the cariggage new line added by git before copy them
    Get-ChildItem "$($Script:E2ETestDirectory)\sshtest_*key*" | % {
        (Get-Content $_.FullName -Raw).Replace("`r`n","`n") | Set-Content $_.FullName -Force
    }

    #copy sshtest keys
    Copy-Item "$($Script:E2ETestDirectory)\sshtest*hostkey*" $script:OpenSSHBinPath -Force
    $owner = New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, $env:USERNAME)
    Get-ChildItem "$($script:OpenSSHBinPath)\sshtest*hostkey*" -Exclude *.pub | % {
        Cleanup-SecureFileACL -FilePath $_.FullName -Owner $owner
        Add-PermissionToFileACL -FilePath $_.FullName -User "NT Service\sshd" -Perm "Read"
    }
    Restart-Service sshd -Force
   
    #Backup existing known_hosts and replace with test version
    #TODO - account for custom known_hosts locations
    $knowHostsDirectoryPath = Join-Path $home .ssh
    $knowHostsFilePath = Join-Path $knowHostsDirectoryPath known_hosts
    if(-not (Test-Path $knowHostsDirectoryPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $knowHostsDirectoryPath -Force -ErrorAction SilentlyContinue | out-null
    }
    if ((Test-Path $knowHostsFilePath -PathType Leaf) -and (-not (Test-Path (Join-Path $knowHostsDirectoryPath known_hosts.ori) -PathType Leaf))) {
        Copy-Item $knowHostsFilePath (Join-Path $knowHostsDirectoryPath known_hosts.ori) -Force
    }
    Copy-Item (Join-Path $Script:E2ETestDirectory known_hosts) $knowHostsFilePath -Force

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
    Add-PermissionToFileACL -FilePath $authorizedKeyPath -User "NT Service\sshd" -Perm "Read"
    $testPriKeypath = Join-Path $Script:E2ETestDirectory sshtest_userssokey_ed25519
    Cleanup-SecureFileACL -FilePath $testPriKeypath -owner $owner
    cmd /c "ssh-add $testPriKeypath 2>&1 >> $Script:TestSetupLogFile"
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
      2) sysinternals required by the tests on windows.
#>
function Install-OpenSSHTestDependencies
{
    [CmdletBinding()]
    param ()

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

    if ( -not (Test-Path "$env:ProgramData\chocolatey\lib\sysinternals\tools" ) ) {        
        Write-Log -Message "sysinternals not present. Installing sysinternals."
        choco install sysinternals -y --force --limitoutput 2>&1 >> $Script:TestSetupLogFile
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
    Cleanup-OpenSSHTestEnvironment
#>
function Cleanup-OpenSSHTestEnvironment
{    
    # .exe - Windows specific. TODO - PAL 
    if (-not (Test-Path (Join-Path $script:OpenSSHBinPath ssh.exe) -PathType Leaf))
    {
        Throw "Cannot find OpenSSH binaries under $script:OpenSSHBinPath. "
    }

    #Restore sshd_config
    $backupConfigPath = Join-Path $Script:OpenSSHBinPath sshd_config.ori
    if (Test-Path $backupConfigPath -PathType Leaf) {        
        Copy-Item $backupConfigPath (Join-Path $Script:OpenSSHBinPath sshd_config) -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $Script:OpenSSHBinPath sshd_config.ori) -Force -ErrorAction SilentlyContinue
        Remove-Item $Script:OpenSSHBinPath\sshtest*hostkey* -Force -ErrorAction SilentlyContinue
        Restart-Service sshd
    }
    
    #Restore known_hosts
    $originKnowHostsPath = Join-Path $home .ssh\known_hosts.ori
    if (Test-Path $originKnowHostsPath)
    {
        Copy-Item $originKnowHostsPath (Join-Path $home .ssh\known_hosts) -Force -ErrorAction SilentlyContinue
        Remove-Item $originKnowHostsPath -Force -ErrorAction SilentlyContinue
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
function Run-OpenSSHE2ETest
{     
   # Discover all CI tests and run them.
    Push-Location $Script:E2ETestDirectory
    Write-Log -Message "Running OpenSSH E2E tests..."    
    $testFolders = Get-ChildItem *.tests.ps1 -Recurse -Exclude SSHDConfig.tests.ps1, SSH.Tests.ps1 | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:E2ETestResultsFile -Tag 'CI'
    Pop-Location
}

<#
    .Synopsis
    Run openssh unit tests.
#>
function Run-OpenSSHUnitTest
{     
    # Discover all CI tests and run them.
    Push-Location $Script:UnitTestDirectory
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $Script:UnitTestResultsFile)    
    {
        $null = Remove-Item -Path $Script:UnitTestResultsFile -Force -ErrorAction SilentlyContinue
    }
    $testFolders = Get-ChildItem unittest-*.exe -Recurse -Exclude unittest-sshkey.exe,unittest-kex.exe |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique
    $testfailed = $false
    if ($testFolders -ne $null)
    {
        $testFolders | % {
            Push-Location $_
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            Write-log "Running OpenSSH unit $unittestFile ..."
            & .\$unittestFile >> $Script:UnitTestResultsFile
            
            $errorCode = $LASTEXITCODE
            if ($errorCode -ne 0)
            {
                $testfailed = $true
                $errorMessage = "$($_.FullName) test failed for OpenSSH.`nExitCode: $errorCode. Detail test log is at $($Script:UnitTestResultsFile)."
                Write-Warning $errorMessage                         
            }
            Pop-Location
        }
    }
    Pop-Location
    $testfailed
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

Export-ModuleMember -Function Setup-OpenSSHTestEnvironment, Cleanup-OpenSSHTestEnvironment, Run-OpenSSHUnitTest, Run-OpenSSHE2ETest
