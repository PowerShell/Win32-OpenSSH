if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1> null
   Write-Host -ForegroundColor Green "sshd successfully uninstalled"
}
else {
    Write-Host -ForegroundColor Yellow "sshd service is not installed"
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>null
   Write-Host -ForegroundColor Green "ssh-agent successfully uninstalled"
}
else {
    Write-Host -ForegroundColor Yellow "ssh-agent service is not installed"
}



