/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
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
#include "config.h"

int scm_start_servie(DWORD, LPWSTR*);

SERVICE_TABLE_ENTRY diapatch_table[] =
{
	{ L"ssh-agent", (LPSERVICE_MAIN_FUNCTION)scm_start_servie },
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

static VOID WINAPI service_handler(DWORD dwControl)
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

BOOL WINAPI ctrl_c_handler(
	_In_ DWORD dwCtrlType
	) {
	/* for any Ctrl type, shutdown agent*/
	debug("Ctrl+C received");
	agent_shutdown();
	return TRUE;
}

int main(int argc, char **argv) {
	
	w32posix_initialize();
	load_config();
	if (!StartServiceCtrlDispatcher(diapatch_table))  {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			if (argc == 1) {
				/* console app - start in debug mode*/
				SetConsoleCtrlHandler(ctrl_c_handler, TRUE);
				log_init("ssh-agent", 7, 1, 1);
				return agent_start(TRUE, FALSE, 0, 0);
			}
			else {
				log_init("ssh-agent", config_log_level(), 1, 0);
				return agent_start(FALSE, TRUE, (HANDLE)atoi(*(argv+1)), atoi(*(argv+2)));
			}
		}
		else
			return -1;
	}
	return 0;
}

int scm_start_servie(DWORD num, LPWSTR* args) {
	service_status_handle = RegisterServiceCtrlHandler(L"ssh-agent", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
	log_init("ssh-agent", config_log_level(), 1, 0);
	return agent_start(FALSE, FALSE, 0, 0);
}

