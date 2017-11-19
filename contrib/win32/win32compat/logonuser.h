/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support logon user call on Win32 based operating systems.
*
*/

#ifndef LOGONUSER_H
#define LOGONUSER_H

BOOL
LogonUserExExWHelper(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID *, PVOID *, LPDWORD, PQUOTA_LIMITS);

#endif
