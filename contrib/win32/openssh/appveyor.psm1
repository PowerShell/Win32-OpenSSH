$ErrorActionPreference = 'Stop'
Import-Module $PSScriptRoot\build.psm1 -Force -DisableNameChecking
$repoRoot = Get-RepositoryRoot
$script:logFile = join-path $repoRoot.FullName "appveyor.log"
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

<#
    Called by Write-BuildMsg to write to the build log, if it exists. 
#>
function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    # write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:logFile)))
    {
        Add-Content -Path $script:logFile -Value $Message
    }  
}

# Sets a build variable
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
        Install-TestDependencies
        Run-OpenSSHTests
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
      Start-SSHBuild -Configuration Release -NativeHostArch x64
      Start-SSHBuild -Configuration Debug -NativeHostArch x86
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
}

<#
    .Synopsis
    This function invokes msiexec.exe to install PSCore on the AppVeyor build machine
#>
function Invoke-MSIEXEC
{
  [CmdletBinding()]  
  param(
    [Parameter(Mandatory=$true)]
    [string] $InstallFile
  )
    
    Write-Log -Message "Installing $InstallFile..."
    $arguments = @(
    "/i"
    "`"$InstallFile`""
    "/qn"
    "/norestart"
    )
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 0){
        Write-Log -Message "$InstallFile has been successfully installed."
    }
    else {
        Write-Log -Message "installer exit code  $($process.ExitCode) for file  $($InstallFile)"        
    }
  
  return $process.ExitCode
}

<#
    .Synopsis
    This function installs PSCore MSI on the AppVeyor build machine
#>
function Install-PSCoreFromGithub
{
  $downloadLocation = Download-PSCoreMSI    
  
  Write-Log -Message "Installing PSCore ..."
  if(-not [string]::IsNullOrEmpty($downloadLocation))
  {
    $processExitCode = Invoke-MSIEXEC -InstallFile $downloadLocation
    Write-Log -Message "Process exitcode: $processExitCode"
  }
}

<#
    .Synopsis
    Retuns MSI location for PSCore for Win10, Windows 8.1 and 2012 R2
#>
function Get-PSCoreMSIDownloadURL
{
  $osversion = [String][Environment]::OSVersion.Version
  
  if($osversion.StartsWith("6"))
  {
      if ($($env:PROCESSOR_ARCHITECTURE).Contains('64'))
      {
        return 'https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.14/PowerShell_6.0.0.14-alpha.14-win81-x64.msi'
      }
      else
      {
        return 'https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.14/PowerShell_6.0.0.14-alpha.14-win7-x86.msi'
      }
  }
  elseif ($osversion.Contains("10.0"))
  {
    if ($($env:PROCESSOR_ARCHITECTURE).Contains('64'))
      {
        return 'https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.14/PowerShell_6.0.0.14-alpha.14-win10-x64.msi'
      }
      else
      {        
        return 'https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.14/PowerShell_6.0.0.14-alpha.14-win7-x86.msi'
      }
  }
}

<#
    .Synopsis
    This functions downloads MSI and returns the path where the file is downloaded.
#>
function Download-PSCoreMSI
{
    $url = Get-PSCoreMSIDownloadURL
    if([string]::IsNullOrEmpty($url))
    {        
        Write-Log -Message "url is empty"
        return ''
    }
    $parsed = $url.Substring($url.LastIndexOf("/") + 1)
    if(-not (Test-path "$env:SystemDrive\PScore" -PathType Container))
    {
        $null = New-Item -ItemType Directory -Force -Path "$env:SystemDrive\PScore" | out-null 
    }
    $downloadLocation = "$env:SystemDrive\PScore\$parsed"
    if(-not (Test-path $downloadLocation -PathType Leaf))
    {
        Invoke-WebRequest -Uri $url -OutFile $downloadLocation -ErrorVariable v
    }

    if ($v)
    {
        Write-BuildMessage -Message "Failed to download PSCore MSI package from $url" -Category Error
        throw "Failed to download PSCore MSI package from $url"
    }
    else
    {
        return $downloadLocation
    }
}

<#
      .SYNOPSIS
      This function installs the tools required by our tests
      1) Pester for running the tests  
      2) sysinternals required by the tests on windows.
  #>
function Install-TestDependencies
{
    [CmdletBinding()]
    param ()

    # Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Write-Log -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $script:logFile
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {      
      Write-Log -Message "Installing Pester..." 
      choco install Pester -y --force --limitoutput 2>&1 >> $script:logFile
    }

    if ( -not (Test-Path "$env:ProgramData\chocolatey\lib\sysinternals\tools" ) ) {        
        Write-Log -Message "sysinternals not present. Installing sysinternals."
        choco install sysinternals -y --force --limitoutput 2>&1 >> $script:logFile
    }
    <#if ( (-not (Test-Path "${env:ProgramFiles(x86)}\Windows Kits\8.1\Debuggers\" )) -and (-not (Test-Path "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\" ))) {        
        Write-Log -Message "debugger not present. Installing windbg."
        choco install windbg --force  --limitoutput -y 2>&1 >> $script:logFile
    }#>
    Install-PSCoreFromGithub
    $psCorePath = GetLocalPSCorePath
    Set-BuildVariable -Name psPath -Value $psCorePath
    Write-BuildMessage -Message "All testDependencies installed!" -Category Information
}

<#
    .Synopsis
    Get the path to the installed powershell score
#>
function GetLocalPSCorePath {
    $psPath = Get-ChildItem "$env:ProgramFiles\PowerShell\*\powershell.exe" -Recurse -ErrorAction SilentlyContinue
    if($psPath.Count -eq 0)
    {
        ""
    }
    else
    {
        $psPath[-1].FullName		
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
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    Build-Win32OpenSSHPackage @PSBoundParameters

    Push-Location $OpenSSHDir 
    & ( "$OpenSSHDir\install-sshd.ps1") 
    .\ssh-keygen.exe -A
    Start-Service ssh-agent
    &( "$OpenSSHDir\install-sshlsa.ps1")

    Set-Service sshd -StartupType Automatic 
    Set-Service ssh-agent -StartupType Automatic
    Start-Service sshd

    Pop-Location
	Write-BuildMessage -Message "OpenSSH installed!" -Category Information
}

<#
    .Synopsis
    uninstalled sshd and sshla
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )    

    Push-Location $OpenSSHDir
    
    Stop-Service sshd    
    &( "$OpenSSHDir\uninstall-sshd.ps1")
    &( "$OpenSSHDir\uninstall-sshlsa.ps1")
    Pop-Location
}

<#
    .Synopsis
    Deploy all required files to build a package and create zip file.
#>
function Build-Win32OpenSSHPackage
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHDir = "$env:SystemDrive\OpenSSH",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $OpenSSHDir -PathType Container))
    {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force -ErrorAction Stop
    }

    [string] $platform = $env:PROCESSOR_ARCHITECTURE    
    if(-not [String]::IsNullOrEmpty($NativeHostArch))
    {
        $folderName = $NativeHostArch
        if($NativeHostArch -ieq 'x86')
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

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.exe,*.dll -Exclude *unittest*.* -Force -ErrorAction Stop
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "contrib\win32\openssh"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.ps1,sshd_config -Exclude AnalyzeCodeDiff.ps1 -Force -ErrorAction Stop
        
    $packageName = "rktools.2003"
    $rktoolsPath = "${env:ProgramFiles(x86)}\Windows Resource Kits\Tools\ntrights.exe"
    if (-not (Test-Path -Path $rktoolsPath))
    {        
        Write-Log -Message "$packageName not present. Installing $packageName."
        choco install $packageName -y --force 2>&1 >> $script:logFile
        if (-not (Test-Path -Path $rktoolsPath))
        {
            choco install $packageName -y --force 2>&1 >> $script:logFile
            if (-not (Test-Path -Path $rktoolsPath))
            {
                Write-BuildMessage "Installation dependencies: failed to download $packageName. try again please." -Category Error
                throw "failed to download $packageName"
            }
        }
    }

    Copy-Item -Path $rktoolsPath -Destination $OpenSSHDir -Force -ErrorAction Stop

    $packageFolder = $env:SystemDrive
    if ($env:APPVEYOR_BUILD_FOLDER)
    {
        $packageFolder = $env:APPVEYOR_BUILD_FOLDER
    }

    $package = "$packageFolder\Win32OpenSSH$RealConfiguration$folderName.zip"
    $allPackage = "$packageFolder\Win32OpenSSH*.zip"
    if (Test-Path $allPackage)
    {
        Remove-Item -Path $allPackage -Force -ErrorAction SilentlyContinue
    }

    Add-Type -assemblyname System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OpenSSHDir, $package)
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Deploy-OpenSSHTests
{
    [CmdletBinding()]
    param
    (    
        [string] $OpenSSHTestDir = "$env:SystemDrive\OpenSSH",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = ""
    )

    if (-not (Test-Path -Path $OpenSSHTestDir -PathType Container))
    {
        $null = New-Item -Path $OpenSSHTestDir -ItemType Directory -Force -ErrorAction Stop
    }

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
    

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    #copy all pester tests
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "regress\pesterTests"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHTestDir -Include *.ps1,*.psm1, sshd_config -Force -ErrorAction Stop
    #copy all unit tests.
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "bin\$folderName\$RealConfiguration"
    Copy-Item -Path "$sourceDir\unittest-*" -Destination $OpenSSHTestDir -Force -ErrorAction Stop
    #restart the service to use the test copy of sshd_config
    Restart-Service sshd
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
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter packageFile
    Path to the package
#>
function Add-Artifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )    
    
    $files = Get-ChildItem -Path $FileToAdd -ErrorAction Ignore
    if ($files -ne $null)
    {        
        $files | % {
            $null = $artifacts.Add($_.FullName)             
         }
    }
    else
    {
        Write-Log -Message "Skip publishing package artifacts. $FileToAdd does not exist"
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = [System.Collections.ArrayList]::new()
    
    $packageFolder = $env:SystemDrive
    if ($env:APPVEYOR_BUILD_FOLDER)
    {
        $packageFolder = $env:APPVEYOR_BUILD_FOLDER
    }

    Add-Artifact  -artifacts $artifacts -FileToAdd "$packageFolder\Win32OpenSSH*.zip"
    Add-Artifact  -artifacts $artifacts -FileToAdd "$env:SystemDrive\OpenSSH\UnitTestResults.txt"
    Add-Artifact  -artifacts $artifacts -FileToAdd "$env:SystemDrive\OpenSSH\TestError.txt"

    # Get the build.log file for each build configuration        
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName)

    Add-Artifact  -artifacts $artifacts -FileToAdd "$script:logFile"
    Add-Artifact  -artifacts $artifacts -FileToAdd "$script:messageFile"

    foreach ($artifact in $artifacts)
    {
        Write-Log -Message "Publishing $artifact as Appveyor artifact"
        # NOTE: attempt to publish subsequent artifacts even if the current one fails
        Push-AppveyorArtifact $artifact -ErrorAction "Continue"
    }
}

<#
    .Synopsis
    Run OpenSSH pester tests.
#>
function Run-OpenSSHPesterTest
{
    param($testRoot = "$env:SystemDrive\OpenSSH", 
        $outputXml = "$env:SystemDrive\OpenSSH\TestResults.xml")
     
   # Discover all CI tests and run them.
    Push-Location $testRoot
    Write-Log -Message "Running OpenSSH Pester tests..."    
    $testFolders = Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique
    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $outputXml -Tag 'CI'
    Pop-Location
}

function Check-PesterTestResult
{
    param($outputXml = "$env:SystemDrive\OpenSSH\TestResults.xml")
    if (-not (Test-Path $outputXml))
    {
        Write-Warning "$($xml.'test-results'.failures) tests in regress\pesterTests failed"
        Write-BuildMessage -Message "Test result file $outputXml not found after tests." -Category Error
        Set-BuildVariable TestPassed False
    }
    $xml = [xml](Get-Content -raw $outputXml)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at TestResults.xml."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
        $Error| Out-File "$testInstallFolder\TestError.txt" -Append
    }
}

<#
    .Synopsis
    Run unit tests.
#>
function Run-OpenSSHUnitTest
{
    param($testRoot = "$env:SystemDrive\OpenSSH",
         $unitTestOutputFile = "$env:SystemDrive\OpenSSH\UnitTestResults.txt")
     
   # Discover all CI tests and run them.
    Push-Location $testRoot
    Write-Log -Message "Running OpenSSH unit tests..."
    if (Test-Path $unitTestOutputFile)    
    {
        Remove-Item -Path $unitTestOutputFile -Force -ErrorAction SilentlyContinue
    }

    $unitTestFiles = Get-ChildItem -Path "$testRoot\unittest*.exe" -Exclude unittest-kex.exe,unittest-hostkeys.exe
    $testfailed = $false
    if ($unitTestFiles -ne $null)
    {        
        $unitTestFiles | % {
            Write-Output "Running OpenSSH unit $($_.FullName)..."
            & $_.FullName >> $unitTestOutputFile
            $errorCode = $LASTEXITCODE
            if ($errorCode -ne 0)
            {
                $testfailed = $true
                $errorMessage = "$($_.FullName) test failed for OpenSSH.`nExitCode: $errorCode. Detail test log is at UnitTestResults.txt."
                Write-Warning $errorMessage
                Write-BuildMessage -Message $errorMessage -Category Error
                Set-BuildVariable TestPassed False
            }
        }
        if(-not $testfailed)
        {
            Write-BuildMessage -Message "All Unit tests passed!" -Category Information
        }
    }
    Pop-Location
}

<#
      .Synopsis
      Runs the tests for this repo

      .Parameter testResultsFile
      The name of the xml file to write pester results.
      The default value is '.\testResults.xml'

      .Example
      .\RunTests.ps1 
      Runs the tests and creates the default 'testResults.xml'
  #>
function Run-OpenSSHTests
{  
  [CmdletBinding()]
  param
  (    
      [string] $testResultsFile = "$env:SystemDrive\OpenSSH\TestResults.xml",
      [string] $unitTestResultsFile = "$env:SystemDrive\OpenSSH\UnitTestResults.txt",
      [string] $testInstallFolder = "$env:SystemDrive\OpenSSH"
  )  

  Deploy-OpenSSHTests -OpenSSHTestDir $testInstallFolder
  Run-OpenSSHUnitTest -testRoot $testInstallFolder -unitTestOutputFile $unitTestResultsFile
  # Run all pester tests.
  Run-OpenSSHPesterTest -testRoot $testInstallFolder -outputXml $testResultsFile
}

function Upload-OpenSSHTestResults
{  
    [CmdletBinding()]
    param
    (    
        [string] $testResultsFile = "$env:SystemDrive\OpenSSH\TestResults.xml"
    )
  
    if ($env:APPVEYOR_JOB_ID)
    {
        $resultFile = Resolve-Path $testResultsFile -ErrorAction Ignore
        if($resultFile)
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
        Write-BuildMessage -Message "The checkin validation success!"
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation failed!" -Category Error
        throw "The checkin validation failed!"
    }
}

Export-ModuleMember -Function Set-BuildVariable, Invoke-AppVeyorBuild, Install-OpenSSH, Install-TestDependencies, GetLocalPSCorePath, Upload-OpenSSHTestResults, Run-OpenSSHTests, Publish-Artifact, Start-SSHBuild, Deploy-OpenSSHTests, Run-OpenSSHUnitTest,Run-OpenSSHPesterTest,Check-PesterTestResult
