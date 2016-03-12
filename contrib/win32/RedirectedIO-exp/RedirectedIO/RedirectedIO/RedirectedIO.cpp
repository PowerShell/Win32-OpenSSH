// RedirectedIO.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>

int pipe_counter = 0;
HANDLE in[2];
HANDLE out[2];
HANDLE err[2];

DWORD WINAPI OutThreadProc(
	_In_ LPVOID lpParameter
	)
{
	char buf[1024];
	DWORD tmp;
	BOOL ret = TRUE;
	while (ret) {
		ret = ReadFile(out[0], buf, 1024, &tmp, NULL);
		if (ret)
			ret = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, tmp, &tmp, NULL);
	}

	return ret;
}

DWORD WINAPI InThreadProc(
	_In_ LPVOID lpParameter
	)
{
	DWORD mode;
	
	char buf[1024];
	char *cmd = "dir/r/n";
	DWORD tmp;
	BOOL ret = TRUE;
	while (ret) {
		//ret = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, 1024, &tmp, NULL);
		if (ret)
			//WriteFile(in[1], buf, tmp, &tmp, NULL);
			ret = WriteFile(in[1], cmd, 5, &tmp, NULL);
			Sleep(3000);
	}

	return ret;
}

BOOL WINAPI HandlerRoutine(
	_In_ DWORD dwCtrlType
	) {
	if (dwCtrlType == CTRL_C_EVENT) {
		return TRUE;
	}
	return FALSE;
}

int
fileio_pipe(HANDLE pio[2]) {
	HANDLE read_handle = INVALID_HANDLE_VALUE, write_handle = INVALID_HANDLE_VALUE;
	char pipe_name[MAX_PATH];
	SECURITY_ATTRIBUTES sec_attributes;

	pio[0] = INVALID_HANDLE_VALUE;
	pio[1] = INVALID_HANDLE_VALUE;

	/* create name for named pipe */
	if (-1 == sprintf_s(pipe_name, MAX_PATH, "\\\\.\\Pipe\\W32PosixPipe.%08x.%08x",
		GetCurrentProcessId(), pipe_counter++)) {
		goto error;
	}

	sec_attributes.bInheritHandle = TRUE;
	sec_attributes.lpSecurityDescriptor = NULL;
	sec_attributes.nLength = 0;

	/* create named pipe */
	read_handle = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1,
		4096,
		4096,
		0,
		&sec_attributes);
	if (read_handle == INVALID_HANDLE_VALUE) {
		goto error;
	}

	/* connect to named pipe */
	write_handle = CreateFileA(pipe_name,
		GENERIC_WRITE,
		0,
		&sec_attributes,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	if (write_handle == INVALID_HANDLE_VALUE) {
		goto error;
	}

	pio[0] = read_handle;
	pio[1] = write_handle;
	return 0;

error:
	if (read_handle != INVALID_HANDLE_VALUE)
		CloseHandle(read_handle);
	if (write_handle != INVALID_HANDLE_VALUE)
		CloseHandle(write_handle);
	return -1;
}


int main()
{

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD tmp;
	BOOL ret;
	char buf[1024];
	wchar_t cmd[MAX_PATH];

	fileio_pipe(in);
	fileio_pipe(out);
	fileio_pipe(err);

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpReserved = 0;
	si.lpTitle = NULL; /* NULL means use exe name as title */
	si.dwFillAttribute = 0;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW ;
	si.wShowWindow = 1; // FALSE ;
	si.cbReserved2 = 0;
	si.lpReserved2 = 0;
	//si.hStdInput = in[0];
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = out[1];
	si.hStdError = err[1];

	swprintf(cmd, L"%ls", L"cmd.exe");

	ret = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!ret)
		exit(-1);

	DWORD mode;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & ~( ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT));
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);

	HANDLE t[2];
	t[0] = CreateThread(NULL, 0, OutThreadProc, NULL, 0, NULL);
	//t[1] = CreateThread(NULL, 0, InThreadProc, NULL, 0, NULL);

	//WriteFile(in[1], "dir\n", 4, &tmp, NULL);
	//WriteFile(in[1], "d", 1, &tmp, NULL);
	//WriteFile(in[1], "i", 1, &tmp, NULL);
	//WriteFile(in[1], "r", 1, &tmp, NULL);
	//WriteFile(in[1], "\r", 1, &tmp, NULL);
	//WriteFile(in[1], "\n", 1, &tmp, NULL);
	


	ret = true;
	while (ret) {
		ret = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, 1024, &tmp, NULL);
		if (ret) {
			ret = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, tmp, &tmp, NULL);
			
			if ((tmp == 1) && (buf[0] == 13))
				buf[0] = 10;

			if (ret)
				//ret = WriteFile(in[1], buf, tmp, &tmp, NULL);
				WriteFile(GetStdHandle(STD_INPUT_HANDLE), buf, tmp, &tmp, NULL);
			//ret = WriteFile(in[1], "dir\r\n", 5, &tmp, NULL);
		}
	}

	//SetConsoleCtrlHandler(HandlerRoutine, TRUE);
	
	//	WaitForMultipleObjects(2, t, TRUE, INFINITE);


}

