Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHCommonUtils.psm1 -Force

[string] $script:vcPath = $null
[System.IO.DirectoryInfo] $script:OpenSSHRoot = $null
[System.IO.DirectoryInfo] $script:gitRoot = $null
[bool] $script:Verbose = $false
[string] $script:BuildLogFile = $null
[string] $script:libreSSLSDKStr = "LibreSSLSDK"
[string] $script:win32OpenSSHPath = $null
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

    if($PSBoundParameters.ContainsKey("AsVerbose"))
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

    if($PSBoundParameters.ContainsKey("AsInfo"))    
    {
        Write-Log -Message "INFO: $message"
        if (-not $Silent)
        {
            if(Get-Command "Write-Information" -ErrorAction SilentlyContinue )
            {
                Write-Information -MessageData $message -InformationAction Continue
            }
            else
            {
                Write-Verbose -Message $message -Verbose
            }
        }
        return
    }

    if($PSBoundParameters.ContainsKey("AsWarning"))
    {
        Write-Log -Message "WARNING: $message"
        if (-not $Silent)
        {
            Write-Warning -Message $message
        }
        return
    }

    if($PSBoundParameters.ContainsKey("AsError"))
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
    param(
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [switch]$OneCore)

    [bool] $silent = -not $script:Verbose
    Write-BuildMsg -AsInfo -Message "Checking tools and dependencies" -Silent:$silent

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
    $newMachineEnvironmentPath = $machinePath   

    # Install chocolatey
    $chocolateyPath = "$env:AllUsersProfile\chocolatey\bin"
    if(Get-Command choco -ErrorAction SilentlyContinue)
    {
        Write-BuildMsg -AsVerbose -Message "Chocolatey is already installed. Skipping installation." -Silent:$silent
    }
    else
    {
        Write-BuildMsg -AsInfo -Message "Chocolatey not present. Installing chocolatey." -Silent:$silent
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 >> $script:BuildLogFile
    }

    if (-not ($machinePath.ToLower().Contains($chocolateyPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $chocolateyPath to Path environment variable" -Silent:$silent
        $newMachineEnvironmentPath = "$chocolateyPath;$newMachineEnvironmentPath"
        if(-not ($env:Path.ToLower().Contains($chocolateyPath.ToLower())))
        {
            $env:Path = "$chocolateyPath;$env:Path"
        }
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$chocolateyPath already present in Path environment variable" -Silent:$silent
    }

    # Add git\cmd to the path
    $gitCmdPath = "$env:ProgramFiles\git\cmd"
    if (-not ($machinePath.ToLower().Contains($gitCmdPath.ToLower())))
    {
        Write-BuildMsg -AsVerbose -Message "Adding $gitCmdPath to Path environment variable" -Silent:$silent
        $newMachineEnvironmentPath = "$gitCmdPath;$newMachineEnvironmentPath"
        if(-not ($env:Path.ToLower().Contains($gitCmdPath.ToLower())))
        {
            $env:Path = "$gitCmdPath;$env:Path"
        }
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message "$gitCmdPath already present in Path environment variable" -Silent:$silent
    }

    $VS2015Path = Get-VS2015BuildToolPath
    $VS2017Path = Get-VS2017BuildToolPath

    # Update machine environment path
    if ($newMachineEnvironmentPath -ne $machinePath)
    {
        [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
    }    

    $vcVars = "${env:ProgramFiles(x86)}\Microsoft Visual Studio 14.0\Common7\Tools\vsvars32.bat"
    $sdkPath = "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x86\register_app.vbs"    
    #use vs2017 build tool if exists
    if($VS2017Path -ne $null)
    {
        If (-not (Test-Path $sdkPath))
        {
            $packageName = "windows-sdk-8.1"
            Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
            choco install $packageName -y --force --limitoutput --execution-timeout 10000 2>&1 >> $script:BuildLogFile
        }

        if(-not (Test-Path $VcVars))
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "VC++ 2015.3 v140 toolset are not installed."   
        }
    }
    elseIf (($VS2015Path -eq $null) -or (-not (Test-Path $VcVars)) -or (-not (Test-Path $sdkPath))) {
        $packageName = "vcbuildtools"
        Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
        choco install $packageName -ia "/InstallSelectableItems VisualCppBuildTools_ATLMFC_SDK;VisualCppBuildTools_NETFX_SDK;Win81SDK_CppBuildSKUV1" -y --force --limitoutput --execution-timeout 10000 2>&1 >> $script:BuildLogFile
        $errorCode = $LASTEXITCODE
        if ($errorCode -eq 3010)
        {
            Write-Host "The recent package changes indicate a reboot is necessary. please reboot the machine, open a new powershell window and call Start-SSHBuild or Start-OpenSSHBootstrap again." -ForegroundColor Black -BackgroundColor Yellow
            Do {
                $input = Read-Host -Prompt "Reboot the machine? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }
            } until ($input -match "^(y(es)?|N(o)?)$")
            [string]$ret = $Matches[0]
            if ($ret.ToLower().Startswith('y'))
            {
                Write-BuildMsg -AsWarning -Message "restarting machine ..."
                Restart-Computer -Force
                exit
            }
            else
            {
                Write-BuildMsg -AsError -ErrorAction Stop -Message "User choose not to restart the machine to apply the changes."
            }
        }
        elseif($errorCode -ne 0)
        {
            Write-BuildMsg -AsError -ErrorAction Stop -Message "$packageName installation failed with error code $errorCode."
        }
    }
    else
    {
        Write-BuildMsg -AsVerbose -Message 'VC++ 2015 Build Tools already present.'
    }

    if($NativeHostArch.ToLower().Startswith('arm') -and ($VS2017Path -eq $null))
    {
        
        #todo, install vs 2017 build tools
        Write-BuildMsg -AsError -ErrorAction Stop -Message "The required msbuild 15.0 is not installed on the machine."
    }

    if($OneCore -or ($NativeHostArch.ToLower().Startswith('arm')))
    {
        $win10sdk = Get-Windows10SDKVersion
        if($win10sdk -eq $null)
        {
            $packageName = "windows-sdk-10.1"
            Write-BuildMsg -AsInfo -Message "$packageName not present. Installing $packageName ..."
            choco install $packageName --force --limitoutput --execution-timeout 10000 2>&1 >> $script:BuildLogFile
        }
    }

    # Ensure the VS C toolset is installed
    if ($null -eq $env:VS140COMNTOOLS)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Cannot find Visual Studio 2015 Environment variable VS140COMNTOOlS."
    }

    $item = Get-Item(Join-Path -Path $env:VS140COMNTOOLS -ChildPath '../../vc')

    $script:vcPath = $item.FullName
    Write-BuildMsg -AsVerbose -Message "vcPath: $script:vcPath" -Silent:$silent
    if ((Test-Path -Path "$script:vcPath\vcvarsall.bat") -eq $false)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Could not find Visual Studio vcvarsall.bat at $script:vcPath, which means some required develop kits are missing on the machine." 
    }
}

function Get-Win32OpenSSHRepo
{
    [bool] $silent = -not $script:Verbose

    if (-not (Test-Path -Path $script:win32OpenSSHPath -PathType Container))
    {
        Write-BuildMsg -AsInfo -Message "clone repo Win32-OpenSSH" -Silent:$silent
        Push-Location $gitRoot
        git clone -q --recursive https://github.com/PowerShell/Win32-OpenSSH.git $script:win32OpenSSHPath
        Pop-Location
    }
    
    Write-BuildMsg -AsInfo -Message "pull latest from repo Win32-OpenSSH" -Silent:$silent
    Push-Location $script:win32OpenSSHPath
    git fetch -q origin
    git checkout -qf L1-Prod
    Pop-Location
}

function Remove-Win32OpenSSHRepo
{
    Remove-Item -Path $script:win32OpenSSHPath -Recurse -Force -ErrorAction SilentlyContinue
}

function Copy-LibreSSLSDK
{
    [bool] $silent = -not $script:Verbose

    $sourcePath  = Join-Path $script:win32OpenSSHPath "contrib\win32\openssh\LibreSSLSDK"
    Write-BuildMsg -AsInfo -Message "copying $sourcePath" -Silent:$silent
    Copy-Item -Container -Path $sourcePath -Destination $PSScriptRoot -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable e
    if($e -ne $null)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Copy LibreSSLSDK from $sourcePath to $PSScriptRoot failed."
    }
}

function Start-OpenSSHPackage
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        # Copy payload to DestinationPath instead of packaging
        [string]$DestinationPath = "",
        [switch]$NoOpenSSL
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
    $payload += "sftp-server.exe", "scp.exe", "ssh-shellhost.exe", "ssh-keygen.exe", "ssh-keyscan.exe" 
    $payload += "sshd_config_default", "install-sshd.ps1", "uninstall-sshd.ps1"
    $payload +="FixHostFilePermissions.ps1", "FixUserFilePermissions.ps1", "OpenSSHUtils.psm1", "OpenSSHUtils.psd1"

    $packageName = "OpenSSH-Win64"
    if ($NativeHostArch -ieq 'x86') {
        $packageName = "OpenSSH-Win32"
    }
    elseif ($NativeHostArch -ieq 'arm64') {
        $packageName = "OpenSSH-ARM64"
    }
    elseif ($NativeHostArch -ieq 'arm') {
        $packageName = "OpenSSH-ARM"
    }

    while((($service = Get-Service ssh-agent -ErrorAction SilentlyContinue) -ne $null) -and ($service.Status -ine 'Stopped'))
    {        
        Stop-Service ssh-agent -Force
        #sleep to wait the servicelog file write        
        Start-Sleep 5
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
        Copy-Item (Join-Path $buildDir $file) $packageDir -Force
        if ($file.EndsWith(".exe")) {
            $pdb = $file.Replace(".exe", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir -Force
        }
        if ($file.EndsWith(".dll")) {
            $pdb = $file.Replace(".dll", ".pdb")
            Copy-Item (Join-Path $buildDir $pdb) $symbolsDir -Force
        }
    }

    #copy libcrypto dll
    $libreSSLSDKPath = Join-Path $PSScriptRoot $script:libreSSLSDKStr
    if (-not $NoOpenSSL.IsPresent) 
    {        
        Copy-Item -Path $(Join-Path $libreSSLSDKPath "$NativeHostArch\libcrypto.dll") -Destination $packageDir -Force -ErrorAction Stop
    }    

    if ($DestinationPath -ne "") {
        if (Test-Path $DestinationPath) {            
            Remove-Item $DestinationPath\* -Force -Recurse -ErrorAction SilentlyContinue
        }
        else {
            New-Item -ItemType Directory $DestinationPath -Force | Out-Null
        }
        Copy-Item -Path $packageDir\* -Destination $DestinationPath -Force -Recurse
        Write-BuildMsg -AsInfo -Message "Copied payload to $DestinationPath."
    }
    else {
        Remove-Item ($packageDir + '.zip') -Force -ErrorAction SilentlyContinue
        if(get-command Compress-Archive -ErrorAction SilentlyContinue)
        {
            Compress-Archive -Path $packageDir -DestinationPath ($packageDir + '.zip')
            Write-BuildMsg -AsInfo -Message "Packaged Payload - '$packageDir.zip'"
        }
        else
        {
            Write-BuildMsg -AsInfo -Message "Packaged Payload not compressed."
        }
    }
    Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue
    
    if ($DestinationPath -ne "") {
        Copy-Item -Path $symbolsDir\* -Destination $DestinationPath -Force -Recurse
        Write-BuildMsg -AsInfo -Message "Copied symbols to $DestinationPath"
    }
    else {
        Remove-Item ($symbolsDir + '.zip') -Force -ErrorAction SilentlyContinue
        if(get-command Compress-Archive -ErrorAction SilentlyContinue)
        {
            Compress-Archive -Path $symbolsDir -DestinationPath ($symbolsDir + '.zip')
            Write-BuildMsg -AsInfo -Message "Packaged Symbols - '$symbolsDir.zip'"
        }
        else
        {
               Write-BuildMsg -AsInfo -Message "Packaged Symbols not compressed."
        }
    }
    Remove-Item $symbolsDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Start-OpenSSHBuild
{
    [CmdletBinding(SupportsShouldProcess=$false)]    
    param
    (        
        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release",

        [switch]$NoOpenSSL,

        [switch]$OneCore
    )    
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
    
    Write-BuildMsg -AsInfo -Message "Starting Open SSH build; Build Log: $($script:BuildLogFile)."

    Start-OpenSSHBootstrap -OneCore:$OneCore

    $script:win32OpenSSHPath = join-path $script:gitRoot "Win32-OpenSSH"
    if (-not (Test-Path (Join-Path $PSScriptRoot LibreSSLSDK)))
    {
        Get-Win32OpenSSHRepo
        Copy-LibreSSLSDK
        Remove-Win32OpenSSHRepo
    }

    $PathTargets = Join-Path $PSScriptRoot paths.targets
    if ($NoOpenSSL) 
    {        
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.UseOpenSSL = 'false'
        $xml.Project.PropertyGroup.SSLLib = [string]::Empty
        $xml.Save($PathTargets)
        $f = Join-Path $PSScriptRoot config.h.vs
        (Get-Content $f).Replace('#define WITH_OPENSSL 1','') | Set-Content $f
        (Get-Content $f).Replace('#define OPENSSL_HAS_ECC 1','') | Set-Content $f
        (Get-Content $f).Replace('#define OPENSSL_HAS_NISTP521 1','') | Set-Content $f
    }
    
    if($NativeHostArch.ToLower().Startswith('arm'))
    {
        $win10SDKVer = Get-Windows10SDKVersion
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.WindowsSDKVersion = $win10SDKVer.ToString()
        $arch = $NativeHostArch.ToUpper()
        $nodeName = "WindowsSDKDesktop$($arch)Support"
        $node = $xml.Project.PropertyGroup.ChildNodes | where {$_.Name -eq $nodeName}
        if($node -eq $null)
        {
            $newElement =$xml.CreateElement($nodeName, $xml.Project.xmlns)
            $newNode = $xml.Project.PropertyGroup.AppendChild($newElement)
            $null = $newNode.AppendChild($xml.CreateTextNode("true"))
        } 
        else
        {
            $node.InnerText = "true"
        }
        $xml.Save($PathTargets)
    }

    if($OneCore)
    {
        $win10SDKVer = Get-Windows10SDKVersion
        [XML]$xml = Get-Content $PathTargets
        $xml.Project.PropertyGroup.WindowsSDKVersion = $win10SDKVer.ToString()
        $xml.Project.PropertyGroup.AdditionalDependentLibs = 'onecore.lib'
        $xml.Project.PropertyGroup.MinimalCoreWin = 'true'
        
        #Use onecore libcrypto binaries
        $xml.Project.PropertyGroup."LibreSSL-x86-Path" = '$(SolutionDir)\LibreSSLSDK\onecore\x86\'
        $xml.Project.PropertyGroup."LibreSSL-x64-Path" = '$(SolutionDir)\LibreSSLSDK\onecore\x64\'
        $xml.Project.PropertyGroup."LibreSSL-arm-Path" = '$(SolutionDir)\LibreSSLSDK\onecore\arm\'
        $xml.Project.PropertyGroup."LibreSSL-arm64-Path" = '$(SolutionDir)\LibreSSLSDK\onecore\arm64\'
        
        $xml.Save($PathTargets)
    }
    
    $solutionFile = Get-SolutionFile -root $repositoryRoot.FullName
    $cmdMsg = @("${solutionFile}", "/t:Rebuild", "/p:Platform=${NativeHostArch}", "/p:Configuration=${Configuration}", "/m", "/nologo", "/fl", "/flp:LogFile=${script:BuildLogFile}`;Append`;Verbosity=diagnostic")    
    if($silent)
    {
        $cmdMsg += "/noconlog"
    }
    
    $msbuildCmd = Get-VS2017BuildToolPath
    if($msbuildCmd -eq $null)
    {
        $msbuildCmd = Get-VS2015BuildToolPath
    }

    & "$msbuildCmd" $cmdMsg
    $errorCode = $LASTEXITCODE

    if ($errorCode -ne 0)
    {
        Write-BuildMsg -AsError -ErrorAction Stop -Message "Build failed for OpenSSH.`nExitCode: $error."
    }    

    Write-BuildMsg -AsInfo -Message "SSH build successful."
}

function Get-VS2017BuildToolPath
{
    $searchPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\*\MSBuild\15.0\Bin"
    if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
    {
        $searchPath += "\amd64"
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "MSBuild.exe" -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
   return $toolAvailable[0].FullName
}

function Get-VS2015BuildToolPath
{
    $searchPath = "${env:ProgramFiles(x86)}\MSBuild\14.0\Bin"
    if($env:PROCESSOR_ARCHITECTURE -ieq "AMD64")
    {
        $searchPath += "\amd64"
    }
    $toolAvailable = @()
    $toolAvailable += Get-ChildItem -path $searchPath\* -Filter "MSBuild.exe" -ErrorAction SilentlyContinue
    if($toolAvailable.count -eq 0)
    {
        return $null
    }
   return $toolAvailable[0].FullName
}

function Get-Windows10SDKVersion
{   
   ## Search for latest windows sdk available on the machine
   $windowsSDKPath = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib"
   $minSDKVersion = [version]"10.0.14393.0"
   $versionsAvailable = @()
   $versionsAvailable += Get-ChildItem $windowsSDKPath | ? {$_.Name.StartsWith("10.")} | % {$version = [version]$_.Name; if($version.CompareTo($minSDKVersion) -ge 0) {$version}}
   if(0 -eq $versionsAvailable.count)
   {
        return $null
   }
   $versionsAvailable = $versionsAvailable | Sort-Object -Descending
   return $versionsAvailable[0]
}

function Get-BuildLogFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.IO.DirectoryInfo] $root,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",
                
        [ValidateSet('Debug', 'Release')]
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



Export-ModuleMember -Function Start-OpenSSHBuild, Get-BuildLogFile, Start-OpenSSHPackage
