Please answer the following

**If it is a terminal issue then please go through https://github.com/PowerShell/Win32-OpenSSH/wiki/TTY-PTY-support-in-Windows-OpenSSH before filling an issue**

**"OpenSSH for Windows" version**
 `((Get-Item (Get-Command sshd).Source).VersionInfo.FileVersion)`
 
**Server OperatingSystem**
 `((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows nt\CurrentVersion\" -Name ProductName).ProductName)`

**Client OperatingSystem**

**What is failing**

**Expected output**

**Actual output**
