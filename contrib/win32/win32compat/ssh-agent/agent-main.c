/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
 * NT Service routines
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

#include "agent.h"
#include "..\misc_internal.h"
#include "..\Debug.h"
#include <wchar.h>

#pragma warning(push, 3)

int scm_start_service(DWORD, LPWSTR*);

SERVICE_TABLE_ENTRYW dispatch_table[] =
{
	{ L"ssh-agent", (LPSERVICE_MAIN_FUNCTIONW)scm_start_service },
	{ NULL, NULL }
};
static SERVICE_STATUS_HANDLE service_status_handle;
static SERVICE_STATUS service_status;


static VOID 
ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
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

static VOID WINAPI 
service_handler(DWORD dwControl)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP: {
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 500);
		agent_shutdown();
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	ReportSvcStatus(service_status.dwCurrentState, NO_ERROR, 0);
}

BOOL WINAPI 
ctrl_c_handler(_In_ DWORD dwCtrlType) 
{
	/* for any Ctrl type, shutdown agent*/
	debug4("Ctrl+C received");
	agent_shutdown();
	return TRUE;
}

/*set current working directory to module path*/
static void
fix_cwd()
{
	wchar_t path[PATH_MAX] = { 0 };
	int i, lastSlashPos = 0;
	GetModuleFileNameW(NULL, path, PATH_MAX);
	for (i = 0; path[i]; i++) {
		if (path[i] == L'/' || path[i] == L'\\')
			lastSlashPos = i;
	}

	path[lastSlashPos] = 0;
	_wchdir(path);
}

/* TODO - get rid of this dependency */
void log_init(char*, int, int, int);

int 
wmain(int argc, wchar_t **argv) 
{
	_set_invalid_parameter_handler(invalid_parameter_handler);
	w32posix_initialize();
	fix_cwd();
	if (!StartServiceCtrlDispatcherW(dispatch_table)) {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			/* 
			 * agent is not spawned by SCM 
			 * Its either started in debug mode or a worker child 
			 */
			if (argc == 2) {
				if (wcsncmp(argv[1], L"-ddd", 4) == 0)
					log_init("ssh-agent", 7, 1, 1);
				else if (wcsncmp(argv[1], L"-dd", 3) == 0)
					log_init("ssh-agent", 6, 1, 1);
				else if (wcsncmp(argv[1], L"-d", 2) == 0)
					log_init("ssh-agent", 5, 1, 1);

				/* Set Ctrl+C handler if starting in debug mode */
				if (wcsncmp(argv[1], L"-d", 2) == 0) {
					SetConsoleCtrlHandler(ctrl_c_handler, TRUE);
					agent_start(TRUE);
					return 0;
				}

				/*agent process is likely a spawned child*/
				char* h = 0;
				h += _wtoi(*(argv + 1));
				if (h != 0) {
					log_init("ssh-agent", 3, 1, 0);
					agent_process_connection(h);
					return 0;
				}
			}
			/* to support linux compat scenarios where ssh-agent.exe is typically launched per session*/
			/* - just start ssh-agent service if needed */
			{
				SC_HANDLE sc_handle, svc_handle;

				if ((sc_handle = OpenSCManagerW(NULL, NULL, SERVICE_START)) == NULL ||
					(svc_handle = OpenServiceW(sc_handle, L"ssh-agent", SERVICE_START)) == NULL) {
					fatal("unable to open service handle");
					return -1;
				}

				if (StartService(svc_handle, 0, NULL) == FALSE && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
					fatal("unable to start ssh-agent service, error :%d", GetLastError());
					return -1;
				}

				return 0;
			}
		}
		else
			return -1;
	}
	return 0;
}

int 
scm_start_service(DWORD num, LPWSTR* args) 
{
	service_status_handle = RegisterServiceCtrlHandlerW(L"ssh-agent", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
	log_init("ssh-agent", 3, 1, 0);
	agent_start(FALSE);
	return 0;
}

#pragma warning(pop)
