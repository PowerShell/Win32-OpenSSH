$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
}

New-Service -Name sshd -BinaryPathName $sshdpath -Description "SSH Deamon" -StartupType Manual | Out-Null
Write-Host -ForegroundColor Green "sshd successfully installed"
