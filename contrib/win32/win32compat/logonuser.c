/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support logon user call on Win32 based operating systems.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Windows.h>
#include "debug.h"

/* Define the function prototype */
typedef BOOL(WINAPI *LogonUserExExWType)(wchar_t*, wchar_t*, wchar_t*, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID, PVOID, LPDWORD, PQUOTA_LIMITS);
static HMODULE hMod = NULL;
static LogonUserExExWType func = NULL;

/*
* The function uses LoadLibrary and GetProcAddress to access
* LogonUserExExW function from sspicli.dll.
*/
BOOL
LogonUserExExWHelper(wchar_t *user_name, wchar_t *domain, wchar_t *password, DWORD logon_type,
	DWORD logon_provider, PTOKEN_GROUPS token_groups, PHANDLE token, PSID *logon_sid, 
	PVOID *profile_buffer, LPDWORD profile_length, PQUOTA_LIMITS quota_limits)
{
	wchar_t sspicli_dll_path[MAX_PATH + 1] = { 0, };
	wchar_t advapi32_dll_path[MAX_PATH + 1] = { 0, };
	wchar_t system32_path[MAX_PATH + 1] = { 0, };
	
	if (!GetSystemDirectoryW(system32_path, _countof(system32_path))) {
		debug3("GetSystemDirectory failed with error %d", GetLastError());
		return FALSE;
	}
	wcsncpy_s(sspicli_dll_path, _countof(sspicli_dll_path), system32_path, wcsnlen(system32_path, _countof(system32_path)) + 1);
	wcscat_s(sspicli_dll_path, _countof(sspicli_dll_path), L"\\sspicli.dll");
	wcsncpy_s(advapi32_dll_path, _countof(advapi32_dll_path), system32_path, wcsnlen(system32_path, _countof(system32_path)) + 1);
	wcscat_s(advapi32_dll_path, _countof(advapi32_dll_path), L"\\advapi32.dll");	

	if (hMod == NULL) {
		hMod = LoadLibraryW(sspicli_dll_path);
		if (hMod == NULL)
			debug3("Failed to retrieve the module handle of sspicli.dll with error %d", GetLastError());
	}

	if (hMod == NULL)
		hMod = LoadLibraryW(advapi32_dll_path);

	if (hMod == NULL) {
		debug3("Failed to retrieve the module handle of advapi32.dll with error %d", GetLastError());
		return FALSE;
	}	

	if (func == NULL)
		func = (LogonUserExExWType)GetProcAddress(hMod, "LogonUserExExW");

	if (func == NULL) {
		debug3("GetProcAddress of LogonUserExExW failed with error $d.", GetLastError());
		return FALSE;
	}
	
	return func(user_name, domain, password, logon_type, logon_provider,
			token_groups, token, logon_sid, profile_buffer, profile_length, quota_limits);	
}