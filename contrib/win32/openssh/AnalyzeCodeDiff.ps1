Set-StrictMode -Version Latest
$Win32Macro = 'WIN32_FIXME'
$sourceRoot = 'C:\openssh\Win32-OpenSSH'

[int]$g_code = 0
[int]$g_win32 = 0
[int]$g_unix = 0

function AnalyzeFile($file, [bool]$log)
{
    $file = Join-Path $sourceRoot $file
    if ($log) {    Write-Host -ForegroundColor Gray $file }
    $content = Get-Content $file
    [int]$commentlines = 0    #comments
    [int]$emptylines = 0      #emptylines
    [int]$code = 0            #all code lines
    [int]$win32 = 0           #win32 only lines
    [int]$win32substituted = 0#lines in win32 block that have a corresponding Unix block (#ifdef with #else)
    [int]$unix = 0;           #unix only lines
    [int]$unixsubstituted = 0 #lines in unix block that have a corresponding Win32 block (#ifdef with #else)
    [int]$total = 0           
    [int]$nestedmacros = 0    #tracks nested macro blocks inside a win32 or a unix block
    [bool]$incommentblock = $false
    [bool]$inWin32block = $false
    [bool]$inUnixblock = $false    
    [int]$currentblockcode = 0
    [bool]$insubstitutedblock = $false


    foreach ($linestr in $content)
    {
        $total++
       $line = [String]$linestr
       $line = $line.Trim()
       #skip if line is empty
       if ($line.Length -gt 0)
       {
          if ($incommentblock) 
          {
            $commentlines++
            if ($line.EndsWith('*/')) {$incommentblock = $false}
          }
          else
          {
             if ($line.StartsWith('//')) {$commentlines++}
             elseif ($line.StartsWith('/*')) 
             {
                if (!($line.EndsWith('*/'))) { $incommentblock = $true }
                $commentlines++
             }            
             else 
             {
                $code++
                if ($inWin32block)
                {
                    $win32++
                    $currentblockcode++
                    #keep skipping inner #ifdefs
                    if ($line.StartsWith('#ifdef')) {$nestedmacros++}

                    if ($line.EndsWith('#endif') -or $line.EndsWith('#else'))
                    {
                        if ($nestedmacros -eq 0) 
                        {
                            $inWin32block = $false
                            if ($line.EndsWith('#else')) 
                            {
                                $inUnixblock = $true
                                $insubstitutedblock = $true
                                $win32substituted += $currentblockcode
                            }
                            elseif ($insubstitutedblock)
                            {
                                $win32substituted += $currentblockcode
                                $insubstitutedblock = $false
                            }
                            $currentblockcode = 0
                        }
                        else
                        {
                            if ($line.EndsWith('#endif')) {$nestedmacros--}                           
                        }
                    }
                }
                elseif ($inUnixblock)
                {
                    $unix++
                    $currentblockcode++
                    #keep skipping inner #ifdefs
                    if ($line.StartsWith('#ifdef')) {$nestedmacros++}

                    if ($line.EndsWith('#endif') -or $line.EndsWith('#else'))
                    {
                        if ($nestedmacros -eq 0) 
                        {
                            $inUnixblock = $false
                            if ($line.EndsWith('#else')) 
                            {
                                $inWin32block = $true
                                $insubstitutedblock = $true
                                $unixsubstituted += $currentblockcode
                            }
                            elseif ($insubstitutedblock)
                            {
                                $unixsubstituted += $currentblockcode
                                $insubstitutedblock = $false
                            }

                            $currentblockcode = 0
                        }
                        else
                        {
                            if ($line.EndsWith('#endif')) {$nestedmacros--}                           
                        }
                    }
                }
                else
                {
                    if ($line.StartsWith('#ifdef') -and $line.Contains($Win32Macro))
                    {
                        $inWin32block = $true
                        $currentblockcode = 0
                    }
                    if ($line.StartsWith('#ifndef') -and $line.Contains($Win32Macro))
                    {
                        $inUnixblock = $true
                        $currentblockcode = 0;
                    }
                }
                
             }
          }
       }
       else {$emptylines++}
    }
    
    if ($log) 
    {
        Write-Host -ForegroundColor Yellow "  Comments " $commentlines
        Write-Host -ForegroundColor Green  "  Blank    " $emptylines
        Write-Host -ForegroundColor Cyan        "  Code     " $code
        Write-Host -ForegroundColor DarkMagenta "  Total    " $total "  check("($commentlines+$emptylines+$code)")"
        Write-Host -ForegroundColor Cyan        "  Win32    " $win32    
        Write-Host -ForegroundColor Cyan        "  Unix     " $unix
        Write-Host -ForegroundColor Cyan        "  Win32sub " $win32substituted 
        Write-Host -ForegroundColor Cyan        "  Unixsub  " $unixsubstituted
    }

    $global:g_code += $code
    $global:g_win32 += $win32
    $global:g_unix += $unix

}


function AnalyzeProject($project, [bool]$log)
{
    if ($log) {        Write-Host "Project: " $project}
    $projectName = $project
    $projectroot = Join-Path $sourceRoot 'contrib\win32\openssh'
    $project = Join-Path $projectroot $project
    $project = $project + '.vcxproj'

    $global:g_code = 0
    $global:g_win32 = 0
    $global:g_unix = 0

    $c = Get-Content $project
    foreach ($ln in $c){
        $l = [String]$ln
        $l = $l.Trim()

        if ($l.StartsWith('<ClCompile Include="$(OpenSSH-Src-Path)'))
        {
            $l = $l.Replace('<ClCompile Include="$(OpenSSH-Src-Path)','')  
            $l = $l.Substring(0, $l.IndexOf('"'))
            AnalyzeFile $l $log
        }
    }

    if ($log) 
    {
        Write-Host "  Total Code     " $global:g_code
        Write-Host "  Win32 Code     " $global:g_win32
        Write-Host "  Unix  Code     " $global:g_unix
    }

    Write-Host $projectName "   "  (100 - ($global:g_unix*100/($global:g_code - $global:g_win32))) "%"

}


AnalyzeProject libssh
AnalyzeProject scp
AnalyzeProject sftp
AnalyzeProject sftp-server
AnalyzeProject ssh
AnalyzeProject ssh-add
AnalyzeProject ssh-agent
AnalyzeProject sshd