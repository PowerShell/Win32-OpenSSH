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
#include "inc\utf.h"
#include "misc_internal.h"

int main(int, char **);
extern HANDLE main_thread;
extern int is_child;

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

int sshd_main(int argc, wchar_t **wargv) {
	char** argv = NULL;
	int i, r;
	_set_invalid_parameter_handler(invalid_parameter_handler);

	if (argc) {
		if ((argv = malloc(argc * sizeof(char*))) == NULL)
			fatal("out of memory");
		for (i = 0; i < argc; i++)
			argv[i] = utf16_to_utf8(wargv[i]);
	}

	w32posix_initialize();
	if (getenv("SSHD_REMSOC"))
		is_child = 1;
	
	/* change current directory to sshd.exe root */
	wchar_t* path_utf16 = utf8_to_utf16(w32_programdir());
	_wchdir(path_utf16);
	free(path_utf16);

	r =  main(argc, argv);
	w32posix_done();
	return r;
}

int wmain(int argc, wchar_t **wargv) {

	if (!StartServiceCtrlDispatcherW(dispatch_table)) {
		if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			return -1;
	}

	return sshd_main(argc, wargv);
}

int scm_start_service(DWORD num, LPWSTR* args) {
	service_status_handle = RegisterServiceCtrlHandlerW(L"sshd", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
	return sshd_main(num, args);
}


