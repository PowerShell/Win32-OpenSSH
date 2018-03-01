/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* wmain entry for sshd. 
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
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

/* disable inclusion of compatability defitnitions in CRT headers */
#define __STDC__ 1
#include <Windows.h>
#include <wchar.h>
#include <Lm.h>
#include <sddl.h>

#include "inc\utf.h"
#include "misc_internal.h"

int main(int, char **);
extern HANDLE main_thread;

int scm_start_service(DWORD, LPWSTR*);

SERVICE_TABLE_ENTRYW dispatch_table[] =
{
	{ L"sshd", (LPSERVICE_MAIN_FUNCTIONW)scm_start_service },
	{ NULL, NULL }
};
static SERVICE_STATUS_HANDLE service_status_handle;
static SERVICE_STATUS service_status;


static VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	service_status.dwCurrentState = dwCurrentState;
	service_status.dwWin32ExitCode = dwWin32ExitCode;
	service_status.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		service_status.dwControlsAccepted = 0;
	else
		service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
		service_status.dwCheckPoint = 0;
	else
		service_status.dwCheckPoint = 1;

	SetServiceStatus(service_status_handle, &service_status);
}

BOOL WINAPI native_sig_handler(DWORD);
static VOID WINAPI service_handler(DWORD dwControl)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP: {
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 500);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		/* TOTO - GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0); doesn't seem to be invoking 
		 * signal handler (native_sig_handler) when sshd runs as service 
		 * So calling the signal handler directly to interrupt the deamon's main thread
		 * This is being called after reporting SERVICE_STOPPED because main thread does a exit()
		 * as part of handling Crtl+c
		 */
		native_sig_handler(CTRL_C_EVENT);
		return;
	}
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	ReportSvcStatus(service_status.dwCurrentState, NO_ERROR, 0);
}

#define SSH_HOSTKEY_GEN_CMDLINE L"ssh-keygen -A"
static void 
generate_host_keys()
{
	TOKEN_USER* info = NULL;
	DWORD info_len = 0, dwError = 0;
	HANDLE proc_token = NULL;
	UUID uuid;
	RPC_CWSTR rpc_str;
	USER_INFO_1 ui;
	NET_API_STATUS nStatus;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t cmdline[MAX_PATH];

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &proc_token) == FALSE ||
	    GetTokenInformation(proc_token, TokenUser, NULL, 0, &info_len) == TRUE ||
	    (info = (TOKEN_USER*)malloc(info_len)) == NULL ||
	    GetTokenInformation(proc_token, TokenUser, info, info_len, &info_len) == FALSE)
		goto cleanup;

	if (IsWellKnownSid(info->User.Sid, WinLocalSystemSid)) {
		/* create sshd account if it does not exist */
		UuidCreate(&uuid);
		UuidToStringW(&uuid, (RPC_WSTR*)&rpc_str);
		ui.usri1_name = L"sshd";
		ui.usri1_password = (LPWSTR)rpc_str;
		ui.usri1_priv = USER_PRIV_USER;
		ui.usri1_home_dir = NULL;
		ui.usri1_comment = NULL;
		ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
		ui.usri1_script_path = NULL;

		NetUserAdd(NULL, 1, (LPBYTE)&ui, &dwError);
		RpcStringFreeW((RPC_WSTR*)&rpc_str);

		/* create host keys if they dont already exist */
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(STARTUPINFOW);
		ZeroMemory(&pi, sizeof(pi));
		memcpy(cmdline, SSH_HOSTKEY_GEN_CMDLINE, wcslen(SSH_HOSTKEY_GEN_CMDLINE) * 2 + 2);
		if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
			WaitForSingleObject(pi.hProcess, INFINITE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
	}
cleanup:
	if (proc_token)
		CloseHandle(proc_token);
	if (info)
		free(info);
}

/*
* 1) Create %programdata%\ssh - Administrator group(F), system(F), authorized users(RX).
* 2) Create %programdata%\ssh\logs - Administrator group(F), system(F)
* 3) copy <binary_location>\sshd_config_default to %programdata%\ssh\sshd_config
*/
static void 
create_prgdata_ssh_folder()
{
	/* create ssh cfg folder */
	char ssh_cfg_dir[PATH_MAX] = { 0, };
	strcpy_s(ssh_cfg_dir, _countof(ssh_cfg_dir), get_program_data_path());
	strcat_s(ssh_cfg_dir, _countof(ssh_cfg_dir), "\\ssh");
	if (create_directory_withsddl(ssh_cfg_dir, "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)") < 0) {
		printf("failed to create %s", ssh_cfg_dir);
		exit(255);
	}

	/* create logs folder */
	char logs_dir[PATH_MAX] = { 0, };
	strcat_s(logs_dir, _countof(logs_dir), ssh_cfg_dir);
	strcat_s(logs_dir, _countof(logs_dir), "\\logs");
	if (create_directory_withsddl(logs_dir, "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") < 0) {
		printf("failed to create %s", logs_dir);
		exit(255);
	}

	/* COPY sshd_config_default to %programData%\openssh\sshd_config */
	char sshd_config_path[PATH_MAX] = { 0, };
	strcat_s(sshd_config_path, _countof(sshd_config_path), ssh_cfg_dir);
	strcat_s(sshd_config_path, _countof(sshd_config_path), "\\sshd_config");
	struct stat st;
	if (stat(sshd_config_path, &st) < 0) {
		char sshd_config_default_path[PATH_MAX] = { 0, };
		strcat_s(sshd_config_default_path, _countof(sshd_config_default_path), w32_programdir());
		strcat_s(sshd_config_default_path, _countof(sshd_config_default_path), "\\sshd_config_default");

		if (copy_file(sshd_config_default_path, sshd_config_path) < 0) {
			printf("Failed to copy %s to %s, error:%d", sshd_config_default_path, sshd_config_path, GetLastError());
			exit(255);
		}
	}
}

/* Create HKLM\Software\OpenSSH windows registry key */
static void
create_openssh_registry_key()
{
	HKEY ssh_registry_root = NULL;
	wchar_t* sddl_str;
	SECURITY_ATTRIBUTES sa;
	int r;

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);

	/*
	* SDDL - FullAcess to System and Builtin/Admins and restricted access to Authenticated users
	* 0x12019b - FILE_GENERIC_READ/WRITE minus FILE_CREATE_PIPE_INSTANCE
	*/
	sddl_str = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)";
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_str, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) {
		printf("cannot convert sddl ERROR:%d", GetLastError());
		return;
	}

	if ((r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SSH_REGISTRY_ROOT, 0, 0, 0, KEY_WRITE, &sa, &ssh_registry_root, 0)) == ERROR_SUCCESS)
		RegCloseKey(ssh_registry_root);
	else
		printf("cannot create ssh root reg key, ERROR:%d", r);
}

static void
prereq_setup()
{	
	create_prgdata_ssh_folder();
	generate_host_keys();
	create_openssh_registry_key();
}

int sshd_main(int argc, wchar_t **wargv) {
	char** argv = NULL;
	int i, r;
	_set_invalid_parameter_handler(invalid_parameter_handler);

	if (argc) {
		if ((argv = malloc(argc * sizeof(char*))) == NULL) {
			printf("out of memory");
			exit(255);
		}

		for (i = 0; i < argc; i++)
			argv[i] = utf16_to_utf8(wargv[i]);
	}

	w32posix_initialize();

	r =  main(argc, argv);
	w32posix_done();
	return r;
}

int argc_original = 0;
wchar_t **wargv_original = NULL;

int wmain(int argc, wchar_t **wargv) {
	wchar_t* path_utf16;
	argc_original = argc;
	wargv_original = wargv;
	
	/* change current directory to sshd.exe root */
	if ( (path_utf16 = utf8_to_utf16(w32_programdir())) == NULL) 
		return -1;
	_wchdir(path_utf16);
	free(path_utf16);
	
	if (!StartServiceCtrlDispatcherW(dispatch_table)) {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			return sshd_main(argc, wargv); /* sshd running NOT as service*/
		else
			return -1;
	}

	return 0;
}

int scm_start_service(DWORD num, LPWSTR* args) {
	service_status_handle = RegisterServiceCtrlHandlerW(L"sshd", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	prereq_setup();
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
	return sshd_main(argc_original, wargv_original);
}


