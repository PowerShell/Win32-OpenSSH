Set-StrictMode -Version Latest

Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -force -DisableNameChecking
[string] $script:platform = $env:PROCESSOR_ARCHITECTURE
[string] $script:vcPath = $null
[System.IO.DirectoryInfo] $script:OpenSSHRoot = $null
[System.IO.DirectoryInfo] $script:gitRoot = $null
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
function Start-OpenSSHBootstrap
{    
    [bool] $silent = -not $script:Verbose

    Set-StrictMode -Version Latest
    Write-BuildMsg -AsInfo -Message "Checking tools and dependencies" -Silent:$silent

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath   

    # Install chocolatey
    $chocolateyPath = "$env:AllUsersProfile\chocolatey\bin"
    if(Get-Command "choco" -ErrorAction SilentlyContinue)
    {
        Write-BuildMsg -AsVerbose -Message "Chocolatey is already installed. Skipping installation." -Silent:$silent
    }
    else
    {
        Write-BuildMsg -AsInfo -Message "Chocolatey not present. Installing chocolatey." -Silent:$silent
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $script:BuildLogFile
    }

    # Add git\cmd to the path
    $gitCmdPath = "$env:ProgramFiles\git\cmd"
    if (-not ($machinePath.ToLower().Contains($gitCmdPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $gitCmdPath to Path environment variable" -Silent:$silent
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
        Write-BuildMsg -AsVerbose -Message "Adding $nativeMSBuildPath to Path environment variable" -Silent:$silent
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
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName." -Silent:$silent
        choco install $packageName -y --force --limitoutput --execution-timeout 10000 2>&1 >> $script:BuildLogFile
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
        choco install $packageName -packageParameters "--AdminFile $adminFilePath" -y --force --limitoutput --execution-timeout 10000 2>&1 >> $script:BuildLogFile
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$packageName present. Skipping installation." -Silent:$silent
    }

    # Install Windows 8.1 SDK
    $packageName = "windows-sdk-8.1"
    $sdkPath = "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x86\register_app.vbs"

    if (-not (Test-Path -Path $sdkPath))
    {
        Write-BuildMsg -AsInfo  -Message "Windows 8.1 SDK not present. Installing $packageName."
        choco install $packageName -y --limitoutput --force 2>&1 >> $script:BuildLogFile
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
    Write-BuildMsg -AsVerbose -Message "vcPath: $script:vcPath" -Silent:$silent
    if ((Test-Path -Path "$script:vcPath\vcvarsall.bat") -eq $false)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Could not find Visual Studio vcvarsall.bat at$script:vcPath, which means some required develop kits are missing on the machine." 
    }
}

function Clone-Win32OpenSSH
{    
    [bool] $silent = -not $script:Verbose

    $win32OpenSSHPath = join-path $script:gitRoot "Win32-OpenSSH"
    if (-not (Test-Path -Path $win32OpenSSHPath -PathType Container))
    {
        Write-BuildMsg -AsInfo -Message "clone repo Win32-OpenSSH" -Silent:$silent
        Push-Location $gitRoot
        git clone -q --recursive https://github.com/PowerShell/Win32-OpenSSH.git $win32OpenSSHPath
        Pop-Location
    }
    Write-BuildMsg -AsInfo -Message "pull latest from repo Win32-OpenSSH" -Silent:$silent
    Push-Location $win32OpenSSHPath
	git fetch -q origin
    git checkout -qf L1-Prod        
    Pop-Location
}

function Copy-OpenSSLSDK
{    
    [bool] $silent = -not $script:Verbose

    $sourcePath  = Join-Path $script:gitRoot "Win32-OpenSSH\contrib\win32\openssh\OpenSSLSDK"
    Write-BuildMsg -AsInfo -Message "copying $sourcePath" -Silent:$silent
    Copy-Item -Container -Path $sourcePath -Destination $PSScriptRoot -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable e
    if($e -ne $null)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Copy OpenSSL from $sourcePath failed "
    }
}

function Package-OpenSSH
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "Release"
    )

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot
    $repositoryRoot = Get-Item -Path $repositoryRoot.FullName
    $folderName = $NativeHostArch
    if($NativeHostArch -ieq 'x86')
    {
        $folderName = "Win32"
    }
    $buildDir = Join-Path $repositoryRoot ("bin\" + $folderName + "\" + $Configuration)
    $payload = "sshd.exe", "ssh.exe", "ssh-agent.exe", "ssh-add.exe", "sftp.exe"
    $payload += "sftp-server.exe", "scp.exe", "ssh-lsa.dll", "ssh-shellhost.exe", "ssh-keygen.exe" 
    $payload += "sshd_config", "install-sshd.ps1", "uninstall-sshd.ps1"
    $payload += "install-sshlsa.ps1", "uninstall-sshlsa.ps1"

    $packageName = "OpenSSH-Win64"
    if ($NativeHostArch -eq 'x86') {
        $packageName = "OpenSSH-Win32"
    }

    $packageDir = Join-Path $buildDir $packageName
    Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $packageDir -Type Directory | Out-Null
    
    $symbolsDir = Join-Path $buildDir ($packageName + '_Symbols')
    Remove-Item $symbolsDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $symbolsDir -Type Directory | Out-Null
       
    foreach ($file in $payload) {
        if ((-not(Test-Path (Join-Path $buildDir $file)))) {
            Throw "Cannot find $file under $buildDir. Did you run Build-OpenSSH?"
        }
        Copy-Item (Join-Path $buildDir $file) $packageDir
        if ($file.EndsWith(".exe")) {
            $pdb = $file.Replace(".exe", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir
        }
        if ($file.EndsWith(".dll")) {
            $pdb = $file.Replace(".dll", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir
        }
    }

    Remove-Item ($packageDir + '.zip') -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path $packageDir -DestinationPath ($packageDir + '.zip')
    Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue

    Remove-Item ($symbolsDir + '.zip') -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path $symbolsDir -DestinationPath ($symbolsDir + '.zip')
    Remove-Item $symbolsDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Build-OpenSSH
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "Release"
    )
    Set-StrictMode -Version Latest
    $script:BuildLogFile = $null

    [System.IO.DirectoryInfo] $repositoryRoot = Get-RepositoryRoot

    # Get openssh-portable root    
    $script:OpenSSHRoot = Get-Item -Path $repositoryRoot.FullName
	$script:gitRoot = split-path $script:OpenSSHRoot

    if($PSBoundParameters.ContainsKey("Verbose"))
    {
        $script:Verbose =  ($PSBoundParameters['Verbose']).IsPresent
    }
    [bool] $silent = -not $script:Verbose

    $script:BuildLogFile = Get-BuildLogFile -root $repositoryRoot.FullName -Configuration $Configuration -NativeHostArch $NativeHostArch
    if (Test-Path -Path $script:BuildLogFile)
    {
        Remove-Item -Path $script:BuildLogFile -force
    }
    
    Write-BuildMsg -AsInfo -Message "Starting Open SSH build; Build Log: $($script:BuildLogFile)"

    Start-OpenSSHBootstrap

    Clone-Win32OpenSSH
    Copy-OpenSSLSDK
    $msbuildCmd = "msbuild.exe"
    $solutionFile = Get-SolutionFile -root $repositoryRoot.FullName
    $cmdMsg = @("${solutionFile}", "/p:Platform=${NativeHostArch}", "/p:Configuration=${Configuration}", "/m", "/noconlog", "/nologo", "/fl", "/flp:LogFile=${script:BuildLogFile}`;Append`;Verbosity=diagnostic")

    & $msbuildCmd $cmdMsg
    $errorCode = $LASTEXITCODE

    if ($errorCode -ne 0)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Build failed for OpenSSH.`nExitCode: $error."
    }    

    Write-BuildMsg -AsInfo -Message "SSH build passed." -Silent:$silent
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
        [string]$Configuration = "Release"
        
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
    Deploy all required files to build a package and create zip file.
#>
function Deploy-Win32OpenSSHBinaries
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",
        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = "",
        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
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
    if((Get-Service ssh-agent -ErrorAction Ignore) -ne $null) {
        Stop-Service ssh-agent -Force
    }
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.exe,*.dll -Exclude *unittest*.* -Force -ErrorAction Stop
    $sourceDir = Join-Path $repositoryRoot.FullName -ChildPath "contrib\win32\openssh"
    Copy-Item -Path "$sourceDir\*" -Destination $OpenSSHDir -Include *.ps1,sshd_config -Exclude AnalyzeCodeDiff.ps1 -Force -ErrorAction Stop
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
        [ValidateSet('Debug', 'Release', '')]
        [string]$Configuration = "",

        [ValidateSet('x86', 'x64', '')]
        [string]$NativeHostArch = "",

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    Deploy-Win32OpenSSHBinaries @PSBoundParameters

    Push-Location $OpenSSHDir 
    & ( "$OpenSSHDir\install-sshd.ps1") 
    .\ssh-keygen.exe -A
    & ( "$OpenSSHDir\install-sshlsa.ps1")

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
    Start-Service sshd

    Pop-Location
    Write-Log -Message "OpenSSH installed!"
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
        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    Push-Location $OpenSSHDir
    if((Get-Service ssh-agent -ErrorAction Ignore) -ne $null) {
        Stop-Service ssh-agent -Force
    }
    &( "$OpenSSHDir\uninstall-sshd.ps1")
    &( "$OpenSSHDir\uninstall-sshlsa.ps1")
        
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath
    if ($machinePath.ToLower().Contains($OpenSSHDir.ToLower()))
    {        
        $newMachineEnvironmentPath.Replace("$OpenSSHDir;", '')
        $env:Path = $env:Path.Replace("$OpenSSHDir;", '')
    }

    # Update machine environment path
    # machine will be reboot after Uninstall-OpenSSH
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }

    Pop-Location
}


Export-ModuleMember -Function Build-OpenSSH, Get-BuildLogFile, Install-OpenSSH, UnInstall-OpenSSH, Package-OpenSSH
