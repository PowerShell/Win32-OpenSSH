
Set-StrictMode -Version Latest
[string] $script:platform = $env:PROCESSOR_ARCHITECTURE
[string] $script:vcPath = $null
[System.IO.DirectoryInfo] $script:OpenSSHRoot = $null
[bool] $script:Verbose = $false
[string] $script:BuildLogFile = $null

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
    if (-not ([string]::IsNullOrEmpty($script:BuildLogFile)))
    {
        Add-Content -Path $script:BuildLogFile -Value $Message
    }  
}

<#
.Synopsis
    Writes a build message.
.Parameter Message
    The message to write.
.Parameter AsInfo
    Writes a user message using Write-Information.
.Parameter AsVerbose
    Writes a message using Write-Verbose and to the build log if -Verbose was specified to Start-DscBuild.
.Parameter AsWarning
    Writes a message using Write-Warning and to the build log.
.Parameter AsError
    Writes a message using Write-Error and to the build log.
.Parameter Silent
    Writes the message only to the log.
.Parameter ErrorAction
    Determines if the script is terminated when errors are written.
    This parameter is ignored when -Silent is specified.
.Example
    Write-BuildMsg -AsInfo 'Starting the build'
    Writes an informational message to the log and to the user
.Example
    Write-BuildMsg -AsError 'Terminating build' -Silent
    Writes an error message only to the log
.Example
    Write-BuildMsg -AsError 'Terminating build' -ErrorAction Stop
    Writes an error message to the log and the user and terminates the build.
.Example
    Write-BuildMsg -AsInfo 'Nuget is already installed' -Silent:(-not $script:Verbose)
    Writes an informational message to the log. If -Verbose was specified, also
    writes to message to the user.
#>
function Write-BuildMsg
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter(ParameterSetName='Info')]
        [switch] $AsInfo,

        [Parameter(ParameterSetName='Verbose')]
        [switch] $AsVerbose,

        [Parameter(ParameterSetName='Warning')]
        [switch] $AsWarning,

        [Parameter(ParameterSetName='Error')]
        [switch] $AsError,

        [switch] $Silent
    )

    if ($AsVerbose)
    {
        if ($script:Verbose)
        {
            Write-Log -Message "VERBOSE: $message"
            if (-not $Silent)
            {
                Write-Verbose -Message $message -Verbose
            }
        }
        return
    }

    if ($AsInfo)
    {
        Write-Log -Message "INFO: $message"
        if (-not $Silent)
        {
            Write-Information -MessageData $message -InformationAction Continue
        }
        return
    }

    if ($AsWarning)
    {
        Write-Log -Message "WARNING: $message"
        if (-not $Silent)
        {
            Write-Warning -Message $message
        }
        return
    }

    if ($AsError)
    {
        Write-Log -Message "ERROR: $message"
        if (-not $Silent)
        {
            Write-Error -Message $message
        }
        return
    }

    # if we reached here, no output type switch was specified.
    Write-BuildMsg -AsError -ErrorAction Stop -Message 'Write-BuildMsg was called without selecting an output type.'
}

<#
.Synopsis
    Verifies all tools and dependencies required for building Open SSH are installed on the machine.
#>
function Start-SSHBootstrap
{
    Set-StrictMode -Version Latest
    Write-BuildMsg -AsInfo -Message "Checking tools and dependencies"

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath

    # NOTE: Unless -Verbose is specified, most informational output will only go to the log file.
    [bool] $silent = -not $script:Verbose

    # Install chocolatey
    $chocolateyPath = "$env:AllUsersProfile\chocolatey\bin"
    if(Get-Command "choco" -ErrorAction SilentlyContinue)
    {
        Write-BuildMsg -AsVerbose -Message "Chocolatey is already installed. Skipping installation." -Silent:$silent
    }
    else
    {
        Write-BuildMsg -AsInfo -Message "Chocolatey not present. Installing chocolatey."
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))

        if (-not ($machinePath.ToLower().Contains($chocolateyPath.ToLower())))
        {
            Write-BuildMsg -AsVerbose -Message "Adding $chocolateyPath to Path environment variable"
            $newMachineEnvironmentPath += ";$chocolateyPath"
            $env:Path += ";$chocolateyPath"
        }
        else
        {
            Write-BuildMsg -AsVerbose -Message "$chocolateyPath already present in Path environment variable"
        }
    }

    # Add git\cmd to the path
    $gitCmdPath = "$env:ProgramFiles\git\cmd"
    if (-not ($machinePath.ToLower().Contains($gitCmdPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $gitCmdPath to Path environment variable"
        $newMachineEnvironmentPath = "$gitCmdPath;$newMachineEnvironmentPath"
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$gitCmdPath already present in Path environment variable" -Silent:$silent
    }

    $nativeMSBuildPath = "${env:ProgramFiles(x86)}\MSBuild\14.0\bin"
    if($script:platform -ieq "AMD64")
    {
        $nativeMSBuildPath += "\amd64"
    }

    if (-not ($machinePath.ToLower().Contains($nativeMSBuildPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $nativeMSBuildPath to Path environment variable"
        $newMachineEnvironmentPath += ";$nativeMSBuildPath"
        $env:Path += ";$nativeMSBuildPath"
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$nativeMSBuildPath already present in Path environment variable" -Silent:$silent
    }

    # Update machine environment path
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }

    # install nasm
    $packageName = "nasm"
    $nasmPath = "${env:ProgramFiles(x86)}\NASM"

    if (-not (Test-Path -Path $nasmPath -PathType Container))
    {
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName."        
        choco install $packageName -y --force  --execution-timeout 10000 
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$packageName present. Skipping installation." -Silent:$silent
    }

    # Install Visual Studio 2015 Community
    $packageName = "VisualStudio2015Community"
    $VSPackageInstalled = Get-ItemProperty "HKLM:\software\WOW6432Node\Microsoft\VisualStudio\14.0\setup\vs" -ErrorAction SilentlyContinue

    if ($null -eq $VSPackageInstalled)
    {
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName." 
        $adminFilePath = "$script:OpenSSHRoot\contrib\win32\openssh\VSWithBuildTools.xml"
        choco install $packageName -packageParameters "--AdminFile $adminFilePath" -y --force  --execution-timeout 10000
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$packageName present. Skipping installation." -Silent:$silent
    }

    # Install Windows 8.1 SDK
    $packageName = "windows-sdk-8.1"
    $sdkPath = "C:\Program Files (x86)\Windows Kits\8.1\bin\x86\register_app.vbs"

    if (-not (Test-Path -Path $sdkPath))
    {
        Write-BuildMsg -AsInfo  -Message "Windows 8.1 SDK not present. Installing $packageName."
        choco install $packageName -y --force
    }
    else
    {
        Write-BuildMsg -AsInfo -Message "$packageName present. Skipping installation." -Silent:$silent
    }

    # Require restarting PowerShell session
    if ($null -eq $VSPackageInstalled)
    {
        Write-Host "To apply changes, please close this PowerShell window, open a new one and call Start-SSHBuild or Start-DscBootstrap again." -ForegroundColor Black -BackgroundColor Yellow
        Write-Host -NoNewLine 'Press any key to close this PowerShell window...' -ForegroundColor Black -BackgroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }

    # Ensure the VS C toolset is installed
    if ($null -eq $env:VS140COMNTOOLS)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Cannot find Visual Studio 2015 Environment variable VS140COMNTOOlS"
    }

    $item = Get-Item(Join-Path -Path $env:VS140COMNTOOLS -ChildPath '../../vc')

    $script:vcPath = $item.FullName
    Write-BuildMsg -AsVerbose -Message "vcPath: $script:vcPath"
    if ((Test-Path -Path "$script:vcPath\vcvarsall.bat") -eq $false)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Could not find Visual Studio vcvarsall.bat at" + $script:vcPath
    }
}

function Start-SSHBuild
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "Debug"
    )
    Set-StrictMode -Version Latest
    $script:BuildLogFile = $null

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot

    # Get openssh-portable root    
    $script:OpenSSHRoot = Get-Item -Path $repositoryRoot.FullName

    if($PSBoundParameters.ContainsKey("Verbose"))
    {
        $script:Verbose =  ($PSBoundParameters['Verbose']).IsPresent
    }    

    $script:BuildLogFile = Get-BuildLogFile -root $repositoryRoot.FullName -Configuration $Configuration -NativeHostArch $NativeHostArch
    if (Test-Path -Path $script:BuildLogFile)
    {
        Remove-Item -Path $script:BuildLogFile
    }

    Write-BuildMsg -AsInfo -Message "Starting Open SSH build."
    Write-BuildMsg -AsInfo -Message "Build Log: $($script:BuildLogFile)"

    Start-SSHBootstrap
    $msbuildCmd = "msbuild.exe"
    $solutionFile = Get-SolutionFile -root $repositoryRoot.FullName
    $cmdMsg = @("${solutionFile}", "/p:Platform=${NativeHostArch}", "/p:Configuration=${Configuration}", "/fl", "/flp:LogFile=${script:BuildLogFile}`;Append`;Verbosity=diagnostic")

    Write-Information -MessageData $msbuildCmd
    Write-Information -MessageData $cmdMsg    
    
    & $msbuildCmd $cmdMsg
    $errorCode = $LASTEXITCODE

    if ($errorCode -ne 0)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Build failed for OpenSSH.`nExitCode: $error"
    }

    Write-BuildMsg -AsVerbose -Message "Finished Open SSH build."
}

function Get-BuildLogFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.IO.DirectoryInfo] $root,

        [ValidateSet('x86', 'x64')]
        [string]$NativeHostArch = "x64",
                
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "Debug"
        
    )    
    return Join-Path -Path $root -ChildPath "contrib\win32\openssh\OpenSSH$($Configuration)$($NativeHostArch).log"    
}

function Get-SolutionFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.IO.DirectoryInfo] $root        
    )    
    return Join-Path -Path $root -ChildPath "contrib\win32\openssh\Win32-OpenSSH.sln"    
}

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
    Set-StrictMode -Version Latest
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

Export-ModuleMember -Function Start-SSHBuild, Get-RepositoryRoot, Get-BuildLogFile