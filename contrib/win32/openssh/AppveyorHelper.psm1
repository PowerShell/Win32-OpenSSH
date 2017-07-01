$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -Force
Import-Module $PSScriptRoot\OpenSSHBuildHelper.psm1 -Force
Import-Module $PSScriptRoot\OpenSSHTestHelper.psm1 -Force

$repoRoot = Get-RepositoryRoot
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

# Write the build message
Function Write-BuildMessage
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,
        $Category,
        [string]  $Details)

    if($env:AppVeyor)
    {
        Add-AppveyorMessage @PSBoundParameters
    }

    # write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

# Sets a build variable
Function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    if($env:AppVeyor -and (Get-Command Set-AppveyorBuildVariable -ErrorAction Ignore) -ne $null)
    {
        Set-AppveyorBuildVariable @PSBoundParameters
    }
    elseif($env:AppVeyor)
    {
        appveyor SetVariable -Name $Name -Value $Value
    } 
    else
    {
        Set-Item env:$Name -Value $Value
    }
}

# Emulates running all of AppVeyor but locally
# should not be used on AppVeyor
function Invoke-AppVeyorFull
{
    param(
        [switch] $APPVEYOR_SCHEDULED_BUILD,
        [switch] $CleanRepo
    )
    if($CleanRepo)
    {
        Clear-PSRepo
    }

    if($env:APPVEYOR)
    {
        throw "This function is to simulate appveyor, but not to be run from appveyor!"
    }

    if($APPVEYOR_SCHEDULED_BUILD)
    {
        $env:APPVEYOR_SCHEDULED_BUILD = 'True'
    }
    try {        
        Invoke-AppVeyorBuild
        Install-OpenSSH
        Set-OpenSSHTestEnvironment -confirm:$false
        Invoke-OpenSSHTests
        Publish-Artifact
    }
    finally {
        if($APPVEYOR_SCHEDULED_BUILD -and $env:APPVEYOR_SCHEDULED_BUILD)
        {
            Remove-Item env:APPVEYOR_SCHEDULED_BUILD
        }
    }
}

# Implements the AppVeyor 'build_script' step
function Invoke-AppVeyorBuild
{
      Set-BuildVariable TestPassed True
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x64
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x86
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
}

<#
    .Synopsis
    Adds a build log to the list of published artifacts.
    .Description
    If a build log exists, it is renamed to reflect the associated CLR runtime then added to the list of
    artifacts to publish.  If it doesn't exist, a warning is written and the file is skipped.
    The rename is needed since publishing overwrites the artifact if it already exists.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter buildLog
    The build log file produced by the build.    
#>
function Add-BuildLog
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $buildLog
    )

    if (Test-Path -Path $buildLog)
    {   
        $null = $artifacts.Add($buildLog)
    }
    else
    {
        Write-Warning "Skip publishing build log. $buildLog does not exist"
    }
}

<#
    .Synopsis
    Deploy all required files to a location and install the binaries
#>
function Install-OpenSSH
{
    [CmdletBinding()]
    param
    ( 
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = "",

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if ($NativeHostArch -eq "") 
    {
        $NativeHostArch = 'x64'
        if ($env:PROCESSOR_ARCHITECTURE  -eq 'x86') {
            $NativeHostArch = 'x86'
        }
    }

    Start-OpenSSHPackage -NativeHostArch $NativeHostArch -Configuration $Configuration -DestinationPath $OpenSSHDir

    Push-Location $OpenSSHDir 
    & "$OpenSSHDir\install-sshd.ps1"
    & "$OpenSSHDir\ssh-keygen.exe" -A    
    & "$OpenSSHDir\FixHostFilePermissions.ps1" -Confirm:$false

    #machine will be reboot after Install-openssh anyway
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath
    if (-not ($machinePath.ToLower().Contains($OpenSSHDir.ToLower())))
    {
        $newMachineEnvironmentPath = "$OpenSSHDir;$newMachineEnvironmentPath"
        $env:Path = "$OpenSSHDir;$env:Path"
    }
    # Update machine environment path
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }
    
    Set-Service sshd -StartupType Automatic 
    Set-Service ssh-agent -StartupType Automatic

    Pop-Location
    Write-BuildMessage -Message "OpenSSH installed!" -Category Information
}

<#
    .Synopsis
    uninstalled sshd
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param
    ( 
        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if (-not (Test-Path $OpenSSHDir -PathType Container))
    {
        return
    }

    Push-Location $OpenSSHDir
    if((Get-Service ssh-agent -ErrorAction SilentlyContinue) -ne $null) {
        Stop-Service ssh-agent -Force
    }
    & "$OpenSSHDir\uninstall-sshd.ps1"
        
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath
    if ($machinePath.ToLower().Contains($OpenSSHDir.ToLower()))
    {        
        $newMachineEnvironmentPath = $newMachineEnvironmentPath.Replace("$OpenSSHDir;", '')
        $env:Path = $env:Path.Replace("$OpenSSHDir;", '')
    }
    
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }
    
    Pop-Location
    Remove-Item -Path $OpenSSHDir -Recurse -Force -ErrorAction SilentlyContinue    
}

<#
    .Synopsis
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter FileToAdd
    Path to the file
#>
function Add-Artifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )        
    
    if ([string]::IsNullOrEmpty($FileToAdd) -or (-not (Test-Path $FileToAdd -PathType Leaf)) )
    {            
        Write-Host "Skip publishing package artifacts. $FileToAdd does not exist"
    }    
    else
    {
        $null = $artifacts.Add($FileToAdd)
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = new-object System.Collections.ArrayList
    
    # Get the build.log file for each build configuration        
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x64)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x86)

    if($Global:OpenSSHTestInfo)
    {
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["UnitTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["E2ETestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["TestSetupLogFile"]
    }
    
    foreach ($artifact in $artifacts)
    {
        Write-Host "Publishing $artifact as Appveyor artifact"
        Push-AppveyorArtifact $artifact -ErrorAction Continue
    }
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Invoke-OpenSSHTests
{
    Write-Host "Start running unit tests"
    $unitTestFailed = Invoke-OpenSSHUnitTest

    if($unitTestFailed)
    {
        Write-Host "At least one of the unit tests failed!" -ForegroundColor Yellow
        Write-BuildMessage "At least one of the unit tests failed!" -Category Error
        Set-BuildVariable TestPassed False
    }
    else
    {
        Write-Host "All Unit tests passed!"
        Write-BuildMessage -Message "All Unit tests passed!" -Category Information    
    }
    # Run all E2E tests.
    Invoke-OpenSSHE2ETest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["E2ETestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable TestPassed False
    }
    $xml = [xml](Get-Content $OpenSSHTestInfo["E2ETestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["E2ETestResultsFile"])."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
    }
}

<#
      .Synopsis
      upload OpenSSH pester test results.
#>
function Publish-OpenSSHTestResults
{ 
    if ($env:APPVEYOR_JOB_ID)
    {
        $resultFile = Resolve-Path $Global:OpenSSHTestInfo["E2ETestResultsFile"] -ErrorAction Ignore
        if( (Test-Path $Global:OpenSSHTestInfo["E2ETestResultsFile"]) -and $resultFile)
        {
            (New-Object 'System.Net.WebClient').UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", $resultFile)
             Write-BuildMessage -Message "Test results uploaded!" -Category Information
        }
    }

    if ($env:DebugMode)
    {
        Remove-Item $env:DebugMode
    }
    
    if($env:TestPassed -ieq 'True')
    {
        Write-BuildMessage -Message "The checkin validation success!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation failed!" -Category Error
        throw "The checkin validation failed!"
    }
}
