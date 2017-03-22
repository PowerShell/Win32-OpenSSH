Please answer the following

"OpenSSH for Windows" version?
 ((Get-Item (Get-Command sshd).Source).VersionInfo.FileVersion) 

OS details?
 ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion\" -Name ProductName).ProductName) 

What is failing?

Expected output?

Actual output?
