
#include "w32fd.h"
#include "inc/defs.h"

#define TERM_IO_BUF_SIZE 2048
int errno_from_Win32Error(int win32_error);

struct io_status {
	char* buf[TERM_IO_BUF_SIZE];
	DWORD transferred;
	DWORD error;
};

static struct io_status read_status, write_status;

static VOID CALLBACK ReadAPCProc(
	_In_ ULONG_PTR dwParam
	) {
	struct w32_io* pio = (struct w32_io*)dwParam;
	pio->read_details.error = read_status.error;
	pio->read_details.remaining = read_status.transferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
}

static DWORD WINAPI ReadThread(
	_In_ LPVOID lpParameter
	) {
	struct w32_io* pio = (struct w32_io*)lpParameter;
	memset(&read_status, 0, sizeof(read_status));
	if (!ReadFile(WINHANDLE(pio), read_status.buf, TERM_IO_BUF_SIZE, &read_status.transferred, NULL)) {
		read_status.error = GetLastError();
	}
	
	if (0 == QueueUserAPC(ReadAPCProc, main_thread, pio))
		DebugBreak();
}

static int
termio_initiate_read(struct w32_io* pio) {
	HANDLE read_thread = CreateThread(NULL, 0, ReadThread, pio, 0, NULL);
	if (read_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		return -1;
	}

	return 0;
}

int 
termio_on_select(struct w32_io* pio, BOOL rd) {
	if (!rd)
		return 0;

	if ((!fileio_is_io_available(pio, rd)) && (!pio->read_details.pending))
		return termio_initiate_read(pio);
}

int 
termio_read(struct w32_io* pio, void *dst, unsigned int max) {
	return fileio_read(pio, dst, max);
}

int 
termio_write(struct w32_io* pio, const void *buf, unsigned int max) {
	//{
	//	/* assert that io is in blocking mode */
	//	if (w32_io_is_blocking(pio) == FALSE) {
	//		debug("write - ERROR, nonblocking write to term is not supported");
	//		errno = ENOTSUP;
	//		return -1;
	//	}
	//	pio->write_details.remaining = bytes_copied;
	//	if (!WriteFile(h, buf, bytes_copied, &pio->write_details.completed, NULL))
	//		pio->write_details.error = GetLastError();
	//	else if (bytes_copied != pio->write_details.completed)
	//		pio->write_details.error = ERROR_INTERNAL_ERROR;

	//	if (pio->write_details.error != 0) {
	//		debug("write - ERROR writing to term %d", pio->write_details.error);
	//		errno = errno_from_Win32Error(pio->write_details.error);
	//		return -1;
	//	}
	//	else {
	//		pio->write_details.completed = 0;
	//		return bytes_copied;
	//	}

	//}
	return fileio_write(pio, buf, max);
}

int termio_close(struct w32_io* pio) {
	return fileio_close(pio);
}