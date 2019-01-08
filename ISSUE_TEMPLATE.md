**Troubleshooting steps**
https://github.com/PowerShell/Win32-OpenSSH/wiki/Troubleshooting-Steps


**Terminal issue? please go through wiki**
https://github.com/PowerShell/Win32-OpenSSH/wiki/TTY-PTY-support-in-Windows-OpenSSH

Please answer the following

**"OpenSSH for Windows" version**
 `((Get-Item (Get-Command sshd).Source).VersionInfo.FileVersion)`
 
**Server OperatingSystem**
 `((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion\" -Name ProductName).ProductName)`

**Client OperatingSystem**

**What is failing**

**Expected output**

**Actual output**
