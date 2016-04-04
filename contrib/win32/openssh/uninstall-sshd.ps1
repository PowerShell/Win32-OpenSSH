if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
   Write-Host -ForegroundColor Green "sshd successfully uninstalled"
}
else {
    Write-Host -ForegroundColor Yellow "sshd service is not installed"
}

