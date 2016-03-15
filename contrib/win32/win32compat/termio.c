
#include "w32fd.h"
#include "inc/defs.h"

/* Win7 - Read Term Support - START*/

int
fileio_initiateReadTerm_Win7(struct w32_io* pio) {

	if (pio->read_details.pending || w32_io_is_io_available(pio, TRUE)) {
		debug("Win7 term read - ERROR - called in wrong state");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/* Win7 - Read Term Support - END*/

int 
termio_on_select(struct w32_io* pio, BOOL rd) {
	return fileio_on_select(pio, rd);
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