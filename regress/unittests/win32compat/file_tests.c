/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/

#include "includes.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

#define SMALL_RECV_BUF_SIZE 128

#pragma warning(disable:4267)

fd_set read_set, write_set, except_set;
struct timeval time_val;
char *send_buf, *recv_buf;
int retValue, r_pipe, w_pipe;
char *tmp_filename = "tmp.txt";

int unset_nonblock(int fd);
int set_nonblock(int fd);
void prep_input_buffer(char* buf, int size, int seed);

void 
file_blocking_io_tests()
{
	char* small_send_buf = "sample payload";
	char small_recv_buf[SMALL_RECV_BUF_SIZE];
	int pipeio[2];

	{
		TEST_START("Basic pipe()");		
		
		retValue = pipe(pipeio);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	{
		TEST_START("pipe read and write");
		
		r_pipe = pipeio[0];
		w_pipe = pipeio[1];
		retValue = write(r_pipe, small_send_buf, strlen(small_send_buf));
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EACCES);
		retValue = read(w_pipe, small_recv_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EACCES);
		retValue = write(w_pipe, small_send_buf, strlen(small_send_buf));
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		retValue = read(r_pipe, small_recv_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		small_recv_buf[retValue] = '\0';
		ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
		memset(small_recv_buf, 0, sizeof(small_recv_buf));
		
		TEST_DONE();
	}

	{
		TEST_START("close pipe fds");
		
		retValue = close(w_pipe);
		ASSERT_INT_EQ(retValue, 0);
		retValue = read(r_pipe, small_recv_buf, SMALL_RECV_BUF_SIZE); /* send on other side is closed*/
		ASSERT_INT_EQ(retValue, 0);
		retValue = close(r_pipe);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}
}

void file_simple_fileio()
{
	TEST_START("file io and fstat");

	char* small_write_buf = "sample payload";
	char small_read_buf[SMALL_RECV_BUF_SIZE];
	int f;
	struct stat st;
	{
		//f = open(tmp_filename, O_WRONLY | O_CREAT | O_TRUNC);
		//ASSERT_INT_EQ(f, -1);
	}
	{
		f = open(tmp_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		ASSERT_INT_NE(f, -1);
		close(f);
	}

	{
		f = open(tmp_filename, O_RDONLY);
		ASSERT_INT_NE(f, -1);		
		retValue = fstat(f, &st);
		ASSERT_INT_EQ(retValue, 0);
		ASSERT_INT_EQ(st.st_size, 0);
		ASSERT_INT_EQ(st.st_mode & 0777, 0666);
		retValue = read(f, small_read_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, 0);		
		close(f);
	}
	
	{
		f = open(tmp_filename, O_WRONLY | O_TRUNC);
		ASSERT_INT_NE(f, -1);
		retValue = write(f, small_write_buf, strlen(small_write_buf));
		ASSERT_INT_EQ(retValue, strlen(small_write_buf));		
		close(f);
	}
	
	{
		f = open(tmp_filename, O_RDONLY);
		ASSERT_INT_NE(f, -1);		
		retValue = stat(tmp_filename, &st);
		ASSERT_INT_EQ(retValue, 0);
		ASSERT_INT_EQ(st.st_size, strlen(small_write_buf));
		ASSERT_INT_EQ(st.st_mode & 0777, 0600);
		char mode[12];
		strmode(st.st_mode, mode);
		ASSERT_CHAR_EQ(mode[0], '-');
		
		struct timeval tv[2];
		tv[0].tv_sec = st.st_atime + 1000;
		tv[1].tv_sec = st.st_mtime + 1000;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		retValue = utimes(tmp_filename, tv);
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, ERROR_SHARING_VIOLATION);

		retValue = read(f, small_read_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, strlen(small_write_buf));
		small_read_buf[retValue] = '\0';
		ASSERT_STRING_EQ(small_write_buf, small_read_buf);
		
		retValue = read(f, small_read_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, 0);

		close(f);
		
		retValue = utimes(tmp_filename, tv);
		ASSERT_INT_EQ(retValue, 0);
	}

	{
		/* test fopen, fgets, fclose*/
		FILE *fp = fopen(tmp_filename, "r");
		ASSERT_PTR_NE(fp, NULL);

		char line[1024];
		char *retp = fgets(line, sizeof(line), fp);
		ASSERT_PTR_NE(retp, NULL);

		retValue = strncmp(line, small_read_buf, strlen(line));
		ASSERT_INT_EQ(retValue, 0);
		fclose(fp);
	}

	{
		/* test writev, ftruncate, isatty, lseek, fdopen */
		f = open(tmp_filename, O_RDWR | O_TRUNC);
		ASSERT_INT_NE(f, -1);
		struct iovec iov;
		iov.iov_base = small_write_buf;
		iov.iov_len = strlen(small_write_buf);
		retValue = writev(f, &iov, 1);
		ASSERT_INT_EQ(retValue, strlen(small_write_buf));

		int truncate_len = 10;
		int ret1 = ftruncate(f, truncate_len);
		ASSERT_INT_EQ(ret1, 0);

		explicit_bzero(small_read_buf, SMALL_RECV_BUF_SIZE);
		retValue = read(f, small_read_buf, SMALL_RECV_BUF_SIZE);
		ASSERT_INT_EQ(retValue, truncate_len);

		retValue = isatty(f);
		ASSERT_INT_EQ(retValue, 0);
		ASSERT_INT_EQ(errno, EINVAL);

		int offset = 3;
		retValue = lseek(f, offset, SEEK_SET);
		ASSERT_INT_EQ(retValue, 0);
		char *tmp = dup_str(small_read_buf);

		retValue = read(f, small_read_buf, SMALL_RECV_BUF_SIZE);
		small_read_buf[retValue] = '\0';
		retValue = strcmp(tmp+offset, small_read_buf);
		ASSERT_INT_EQ(retValue, 0);
		
		FILE *f2 = fdopen(f, "r");
		ASSERT_PTR_NE(f2, NULL);
		fclose(f2);		

		retValue = unlink(tmp_filename);
		ASSERT_INT_EQ(retValue, 0);
	}
	
	{
		// test null device 
		FILE *fp = fopen("/dev/null", "r");
		ASSERT_PTR_NE(fp, NULL);

		f = open("/dev/null", O_RDONLY);
		ASSERT_INT_NE(f, -1);
	}

	TEST_DONE();
}

void file_simple_fileio_mode()
{
	TEST_START("file io and mode");

	char * small_write_buf = "sample payload", *c, small_read_buf[SMALL_RECV_BUF_SIZE];
	int ret;
	FILE* f;
	struct stat st;

	f = fopen(NULL, "w");
	ASSERT_PTR_EQ(f, NULL);

	c = fgets(NULL, 0, f);
	ASSERT_PTR_EQ(c, NULL);

	f = fopen("tmp.txt", "w");
	ASSERT_PTR_NE(f, NULL);
	fclose(f);
	f = fopen("tmp.txt", "r");
	ASSERT_PTR_NE(f, NULL);
	c = fgets(small_read_buf, sizeof(small_read_buf), f);
	ASSERT_PTR_EQ(c, NULL);
	fclose(f);

	ret = stat("tmp.txt", &st);
	ASSERT_INT_EQ(ret, 0);
	ASSERT_INT_EQ(st.st_size, 0);

	f = fopen("tmp.txt", "w");
	ASSERT_PTR_NE(f, NULL);
	ret = fputs(small_write_buf, f);
	ASSERT_INT_EQ(ret, 0);
	fclose(f);

	ret = stat("tmp.txt", &st);
	ASSERT_INT_EQ(ret, 0);
	ASSERT_INT_EQ(st.st_size, strlen(small_write_buf));

	f = fopen("tmp.txt", "r");
	ASSERT_PTR_NE(f, NULL);
	c = fgets(small_read_buf, sizeof(small_read_buf), f);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_STRING_EQ(small_write_buf, small_read_buf);

	c = fgets(small_read_buf, sizeof(small_read_buf), f);
	ASSERT_PTR_EQ(c, NULL);
	fclose(f);
	TEST_DONE();
}

void 
file_nonblocking_io_tests()
{
	TEST_START("non blocking file io");

	char* small_send_buf = "sample payload";
	char small_recv_buf[SMALL_RECV_BUF_SIZE];	
	int pipeio[2];

	retValue = pipe(pipeio);
	ASSERT_INT_EQ(retValue, 0);

	r_pipe = pipeio[0];
	w_pipe = pipeio[1];
	retValue = set_nonblock(r_pipe);
	ASSERT_INT_EQ(retValue, 0);

	retValue = read(r_pipe, small_recv_buf, SMALL_RECV_BUF_SIZE);
	ASSERT_INT_EQ(retValue, -1);
	ASSERT_INT_EQ(errno, EAGAIN);
	
	retValue = unset_nonblock(w_pipe);
	ASSERT_INT_EQ(retValue, 0);
	
	retValue = write(w_pipe, small_send_buf, strlen(small_send_buf));
	ASSERT_INT_EQ(retValue, strlen(small_send_buf));
	
	retValue = unset_nonblock(r_pipe);
	ASSERT_INT_EQ(retValue, 0);
	
	retValue = read(r_pipe, small_recv_buf, SMALL_RECV_BUF_SIZE);
	ASSERT_INT_EQ(retValue, strlen(small_send_buf));
	small_recv_buf[retValue] = '\0';
	ASSERT_STRING_EQ(small_send_buf, small_recv_buf);

	memset(small_recv_buf, 0, sizeof(small_recv_buf));
	send_buf = malloc(10 * 1024);
	ASSERT_PTR_NE(send_buf, NULL);
	
	retValue = set_nonblock(w_pipe);
	ASSERT_INT_EQ(retValue, 0);
	
	retValue = 1;
	while (retValue > 0) {
		retValue = write(w_pipe, send_buf, 10 * 1024);
	}
	ASSERT_INT_EQ(retValue, -1);
	ASSERT_INT_EQ(errno, EAGAIN);
	
	retValue = close(r_pipe);
	ASSERT_INT_EQ(retValue, 0);
	
	retValue = close(w_pipe);
	ASSERT_INT_EQ(retValue, 0);
	free(send_buf);

	TEST_DONE();
}

void
file_select_tests() {
	TEST_START("select on file fds");

	int num_bytes = 1024 * 700; //700KB
	int bytes_sent = 0;
	int bytes_received = 0;
	int seed = 326;
	int eagain_results = 0;
	
	int pipeio[2];
	retValue = pipe(pipeio);
	ASSERT_INT_EQ(retValue, 0);

	r_pipe = pipeio[0];
	w_pipe = pipeio[1];
	retValue = set_nonblock(w_pipe);
	ASSERT_INT_EQ(retValue, 0);

	retValue = set_nonblock(r_pipe);
	ASSERT_INT_EQ(retValue, 0);
	
	send_buf = malloc(num_bytes);
	recv_buf = malloc(num_bytes + 1);
	ASSERT_PTR_NE(send_buf, NULL);
	ASSERT_PTR_NE(recv_buf, NULL);
	
	prep_input_buffer(send_buf, num_bytes, 17);
	FD_ZERO(&read_set);
	FD_ZERO(&write_set);
	FD_SET(w_pipe, &write_set);
	FD_SET(r_pipe, &read_set);
	while (-1 != select(max(r_pipe, w_pipe) + 1, &read_set, &write_set, NULL, &time_val)) {
		if (FD_ISSET(w_pipe, &write_set)) {
			while ((bytes_sent < num_bytes) && ((retValue = write(w_pipe, send_buf + bytes_sent, num_bytes - bytes_sent)) > 0))
				bytes_sent += retValue;
			if (bytes_sent < num_bytes) {
				ASSERT_INT_EQ(retValue, -1);
				ASSERT_INT_EQ(errno, EAGAIN);
				eagain_results++;
			}
		}

		if (FD_ISSET(r_pipe, &read_set)) {
			while ((retValue = read(r_pipe, recv_buf + bytes_received, num_bytes - bytes_received + 1)) > 0)
				bytes_received += retValue;
			if (retValue == 0)
				break;
			ASSERT_INT_EQ(retValue, -1);
			ASSERT_INT_EQ(errno, EAGAIN);
			eagain_results++;
		}

		if (bytes_sent < num_bytes)
			FD_SET(w_pipe, &write_set);
		else {
			FD_CLR(w_pipe, &write_set);
			retValue = close(w_pipe);
			ASSERT_INT_EQ(retValue, 0);
		}
		FD_SET(r_pipe, &read_set);
	}

	/*ensure that we hit send and recv paths that returned EAGAIN. Else it would not have touched the async paths*/
	/*if this assert is being hit, then num_bytes is too small. up it*/
	ASSERT_INT_GT(eagain_results, 0);
	ASSERT_INT_EQ(bytes_sent, bytes_received);
	ASSERT_INT_EQ(memcmp(send_buf, recv_buf, num_bytes), 0);
	retValue = close(r_pipe);
	ASSERT_INT_EQ(retValue, 0);

	free(send_buf);
	free(recv_buf);

	TEST_DONE();
}

void
file_miscellaneous_tests()
{
	TEST_START("file miscellaneous");
	
	char cwd[MAX_PATH];
	char *pcwd = getcwd(cwd, MAX_PATH);
	ASSERT_PTR_NE(pcwd, NULL);

	char thishost[NI_MAXHOST];	
	retValue = gethostname(thishost, sizeof(thishost));
	ASSERT_INT_NE(retValue, -1);

	char *tmp = dup_str(thishost);
	int len = strlen(tmp);

	int f = dup(STDOUT_FILENO);
	ASSERT_INT_NE(f, -1);
	retValue = write(f, tmp, len);
	ASSERT_INT_EQ(errno, 0);
	ASSERT_INT_EQ(retValue, len);
	close(f);

	f = dup(STDIN_FILENO);
	ASSERT_INT_NE(f, -1);
	close(f);

	f = dup(STDERR_FILENO);
	ASSERT_INT_NE(f, -1);
	close(f);

	f = open(tmp_filename, O_RDWR | O_CREAT | O_TRUNC, 0600);
	ASSERT_INT_NE(f, -1);
	int f1 = dup(f);
	ASSERT_INT_EQ(f1, -1);
	HANDLE h = w32_fd_to_handle(f);
	ASSERT_HANDLE(h);
	close(f);

	char *tmp_filename_1 = "tmp_1.txt";
	retValue = rename(tmp_filename, tmp_filename_1);
	ASSERT_INT_EQ(retValue, 0);

	retValue = unlink(tmp_filename_1);
	ASSERT_INT_EQ(retValue, 0);

	if(tmp)
		free(tmp);

	h = w32_fd_to_handle(STDIN_FILENO);
	ASSERT_HANDLE(h);

	h = w32_fd_to_handle(STDOUT_FILENO);
	ASSERT_HANDLE(h);

	h = w32_fd_to_handle(STDERR_FILENO);
	ASSERT_HANDLE(h);

	retValue = w32_allocate_fd_for_handle(h, FALSE);
	ASSERT_HANDLE(h);

	f = open(tmp_filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
	ASSERT_INT_NE(f, -1);
	wchar_t *t = utf8_to_utf16(tmp_filename);
	ASSERT_PTR_NE(t, NULL);
	int perm = get_others_file_permissions(t, 0);
	ASSERT_INT_EQ(perm, 7);
	free(t);
	close(f);
	retValue = unlink(tmp_filename);
	ASSERT_INT_EQ(retValue, 0);
	

	f = open(tmp_filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
	ASSERT_INT_NE(f, -1);
	t = utf8_to_utf16(tmp_filename);
	ASSERT_PTR_NE(t, NULL);
	perm = get_others_file_permissions(t, 1);
	ASSERT_INT_EQ(perm, 5);
	free(t);
	close(f);
	retValue = unlink(tmp_filename);
	ASSERT_INT_EQ(retValue, 0);	

	TEST_DONE();
}

void
file_tests()
{
	file_simple_fileio();
	file_simple_fileio_mode();
	file_blocking_io_tests();
	file_nonblocking_io_tests();
	file_select_tests();
	file_miscellaneous_tests();
}
