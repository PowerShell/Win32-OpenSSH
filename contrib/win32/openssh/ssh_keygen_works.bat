@pushd \Windows\System32\OpenSSH\
@echo.
@ssh-keygen -A
@echo Your ssh host keys:
@echo.
@dir ssh_host_*_key /B/S
@echo.


@:echo Some of them might have the wrong permissions, so that sshd is producing
@:echo error messages in \Windows\System32\OpenSSH\Logs\sshd.log that look like
@:echo this:
@:echo.
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: @         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: Permissions for './ssh_host_ed25519_key' are too open.
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: It is required that your private key files are NOT accessible by others.
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: This private key will be ignored.
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: key_load_private: bad permissions
@:echo #\Windows\System32\OpenSSH\Logs\sshd.log# error: Could not load host key: ./ssh_host_ed25519_key
@:echo.
@:echo This is because you trusted Microsoft's version of ssh-keygen.exe to set
@:echo the correct permissions on host key files that it generates! That software
@:echo is not reliable. See:
@:echo.
@:echo https://github.com/PowerShell/Win32-OpenSSH/issues/1007
@:echo.
@:echo Here are the permissions on your ssh host keys:
@:echo.

@echo Existing permissions:
@echo.
@icacls ssh_host_*_key /Q|findstr /v "^Success"
@echo.

@:echo They should look like this:
@:echo.
@:echo # ssh_host_ed25519_key NT SERVICE\sshd:(R)
@:echo #                      NT AUTHORITY\SYSTEM:(F)
@:echo #                      BUILTIN\Administrators:(F)
@:echo.
@:echo And not like this (which is how ssh-keygen leaves them):
@:echo.
@:echo # doesnt_work_key BUILTIN\Administrators:(F)
@:echo #                 NT AUTHORITY\SYSTEM:(F)
@:echo #                 %COMPUTERNAME%\%USERNAME%:(R,W)
@:echo.


@echo I will try to fix your permissions.
@icacls ssh_host_*_key /grant "NT Service\sshd":(R)        >NUL
@icacls ssh_host_*_key /remove "%COMPUTERNAME%\%USERNAME%" >NUL
@icacls ssh_host_*_key /inheritance:r                      >NUL
@icacls ssh_host_*_key /grant "BUILTIN\Administrators:(F)" >NUL
@icacls ssh_host_*_key /grant "NT AUTHORITY\SYSTEM:(F)"    >NUL
@echo.

@echo Modified permissions:
@echo.
@icacls ssh_host_*_key /Q|findstr /v "^Success"

@echo Please patch ssh-keygen.exe!
@popd