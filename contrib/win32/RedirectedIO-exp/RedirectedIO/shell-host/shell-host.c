/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * Primitive shell-host to support parsing of cmd.exe input and async IO redirection
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
#include <Windows.h>
#include <stdio.h>
#include <io.h>

#define MAX_CMD_LEN 512

HANDLE pipe_in;
HANDLE pipe_out;
HANDLE pipe_err;
HANDLE child_pipe_read = INVALID_HANDLE_VALUE;
HANDLE child_pipe_write = INVALID_HANDLE_VALUE;
BOOL istty = TRUE; //TODO - set this to FALSE
HANDLE child = INVALID_HANDLE_VALUE, monitor_thread = INVALID_HANDLE_VALUE;
DWORD in_cmd_len = 0;
char in_cmd[MAX_CMD_LEN];

DWORD WINAPI MonitorChild(
	_In_ LPVOID lpParameter
	) {
	WaitForSingleObject(child, INFINITE);
	CloseHandle(pipe_in);
	//printf("XXXX CHILD PROCESS DEAD XXXXX");
	return 0;
}

#define GOTO_CLEANUP_ON_ERR(exp) do {			\
	ret = (exp);					\
	if (ret == FALSE)				\
		goto cleanup;				\
} while(0)						\

int main() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	wchar_t cmd[MAX_PATH];
	SECURITY_ATTRIBUTES sa;
	BOOL ret;

	pipe_in = GetStdHandle(STD_INPUT_HANDLE);
	pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
	pipe_err = GetStdHandle(STD_ERROR_HANDLE);

	/* copy pipe handles passed through std io*/
	if ((pipe_in == INVALID_HANDLE_VALUE)
	    || (pipe_out == INVALID_HANDLE_VALUE)
	    || (pipe_err == INVALID_HANDLE_VALUE))
		return -1;

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&child_pipe_read, &child_pipe_write, &sa, 128))
		return -1;

	/* A console is attached if a tty is requested */
	if (!AllocConsole())
		istty = TRUE;
	
	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = child_pipe_read;
	si.hStdOutput = pipe_out;
	si.hStdError = pipe_err;

	/* disable inheritance on child_pipe_write and pipe_in*/
	SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(child_pipe_write, HANDLE_FLAG_INHERIT, 0);

	/* create job to hold all child processes */
	{
		/* TODO - this does not work as expected*/
		HANDLE job = CreateJobObject(NULL, NULL);
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
		memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
		job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)))
			return -1;
		CloseHandle(job);
	}

	swprintf(cmd, L"%ls", L"cmd.exe");
	GOTO_CLEANUP_ON_ERR(CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi));

	/* close unwanted handles*/
	CloseHandle(child_pipe_read);
	child_pipe_read = INVALID_HANDLE_VALUE;
	
	child = pi.hProcess;
	/* monitor child exist */
	monitor_thread = CreateThread(NULL, 0, MonitorChild, NULL, 0, NULL);
	if (monitor_thread == INVALID_HANDLE_VALUE)
		goto cleanup;

	/* disable Ctrl+C hander in this process*/
	SetConsoleCtrlHandler(NULL, TRUE);

	/* process data from pipe_in and route appropriately */
	while (1) {
		char buf[128];
		DWORD rd = 0, wr = 0, i = 0;
		GOTO_CLEANUP_ON_ERR(ReadFile(pipe_in, buf, 128, &rd, NULL));

		if (!istty) { /* no tty, juet send it accross */
			GOTO_CLEANUP_ON_ERR(WriteFile(child_pipe_write, buf, rd, &wr, NULL));
			continue;
		}

		while (i < rd) {
			/* skip them for now*/
			if ((rd - i >= 3) && (buf[i] == '\033') && (buf[i + 1] == '[')
				&& (buf[i + 2] >= 'A') && (buf[i + 2] <= 'D')) {
				i += 3;
				continue;
			}

			// Ctrl +C
			if (buf[i] == '\003') {
				GOTO_CLEANUP_ON_ERR(GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0));
				in_cmd_len = 0;
				i++;
				continue;
			}

			// for backspace, we need to send space and another backspace for visual erase
			if (buf[i] == '\b') {
				if (in_cmd_len > 0) {
					GOTO_CLEANUP_ON_ERR(WriteFile(pipe_out, "\b \b", 3, &wr, NULL));
					in_cmd_len--;
				}
				i++;
				continue;
			}

			//for CR and LF
			if ((buf[i] == '\r') || (buf[i] == '\n')) {

				/* TODO - do a much accurate mapping */
				buf[i] = '\n';
				GOTO_CLEANUP_ON_ERR(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
				in_cmd[in_cmd_len] = buf[i];
				in_cmd_len++;
				GOTO_CLEANUP_ON_ERR(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
				in_cmd_len = 0;
				i++;
				continue;
			}


			GOTO_CLEANUP_ON_ERR(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
			in_cmd[in_cmd_len] = buf[i];
			in_cmd_len++;
			if (in_cmd_len == MAX_CMD_LEN - 1) {
				GOTO_CLEANUP_ON_ERR(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
				in_cmd_len = 0;
			}

			i++;
		}
	}

cleanup:
	
	if (child != INVALID_HANDLE_VALUE)
		TerminateProcess(child, 0);
	if (monitor_thread != INVALID_HANDLE_VALUE)
		WaitForSingleObject(monitor_thread, INFINITE);
	return 0;
}

