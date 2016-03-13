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
		if (ret) {
			ret = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, tmp, &tmp, NULL);
		}
	}

	printf("----- OUT STREAM CLOSED -------\n");
	return ret;
}

DWORD WINAPI ErrThreadProc(
	_In_ LPVOID lpParameter
	)
{
	char buf[1024];
	DWORD tmp;
	BOOL ret = TRUE;
	while (ret) {
		ret = ReadFile(err[0], buf, 1024, &tmp, NULL);
		if (ret) {
			ret = WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, tmp, &tmp, NULL);
		}
	}

	printf("-------------ERROR STREAM CLOSED -------------\n");
	return ret;
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
	si.hStdInput = in[0];
	si.hStdOutput = out[1];
	si.hStdError = err[1];

	swprintf(cmd, L"%ls", L"shell-host.exe");


	ret = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, NULL, &si, &pi);
	//ret = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!ret)
		exit(-1);

	/* close unwanted handles*/
	CloseHandle(in[0]);
	CloseHandle(out[1]);
	CloseHandle(err[1]);

	DWORD mode;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & ~( ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT));
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);

	HANDLE t[2];
	t[0] = CreateThread(NULL, 0, OutThreadProc, NULL, 0, NULL);
	t[1] = CreateThread(NULL, 0, ErrThreadProc, NULL, 0, NULL);

	ret = true;
	while (ret) {
		ret = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, 1024, &tmp, NULL);
		if (ret) {
			ret = WriteFile(in[1], buf, tmp, &tmp, NULL);
		}
	}
}

	