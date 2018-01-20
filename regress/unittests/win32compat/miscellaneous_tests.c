#include "includes.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <misc_internal.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

int retValue;

// The ioctl() testcase is failing when ran from Run-OpenSSHUnitTest.
void 
test_ioctl()
{
	if(!isatty(fileno(stdin))) return;

	TEST_START("ioctl");

	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	retValue = ioctl(fileno(stdin), TIOCGWINSZ, &ws);
	ASSERT_INT_EQ(retValue, 0);
	ASSERT_INT_NE(ws.ws_col, 0);
	ASSERT_INT_NE(ws.ws_row, 0);
	ASSERT_INT_NE(ws.ws_xpixel, 0);
	ASSERT_INT_NE(ws.ws_ypixel, 0);	

	TEST_DONE();
}

void
test_path_conversion_utilities()
{
	TEST_START("path conversion utilities");

	char *s = "c:\\testdir\\test";
	char *windows_style_path = dup_str(s);
	int len = strlen(windows_style_path);
	char *backup = malloc(len + 1);
	strncpy(backup, windows_style_path, len);
	backup[len] = '\0';

	convertToForwardslash(windows_style_path);

	char *tmpStr = strstr(windows_style_path, "\\");
	ASSERT_PTR_EQ(tmpStr, NULL);

	convertToBackslash(windows_style_path);
	tmpStr = strstr(windows_style_path, "/");
	ASSERT_PTR_EQ(tmpStr, NULL);

	retValue = strcmp(windows_style_path, backup);
	ASSERT_INT_EQ(retValue, 0);

	free(windows_style_path);

	TEST_DONE();
}

void
test_sanitizedpath()
{
	TEST_START("win32 program dir");
	
	char *win32prgdir = w32_programdir();
	ASSERT_PTR_NE(win32prgdir, NULL);

	ASSERT_PTR_EQ(resolved_path(NULL), NULL);

	char *ret = resolved_path(win32prgdir);
	retValue = strcmp(win32prgdir, ret);
	ASSERT_INT_EQ(retValue, 0);

	char win32prgdir_len = strlen(win32prgdir);
	char *tmp_path = malloc(win32prgdir_len + 2); /* 1-NULL and 1-adding "/" */
	tmp_path[0] = '/';
	strncpy(tmp_path+1, win32prgdir, win32prgdir_len);
	tmp_path[win32prgdir_len+1] = '\0';

	ret = resolved_path(tmp_path);
	retValue = strcmp(win32prgdir, ret);
	ASSERT_INT_EQ(retValue, 0);

	char *s1 = malloc(4), *s2 = malloc(4);
	s1[0] = '/', s1[1] = win32prgdir[0],  s1[2] = ':', s1[3] = '\0';
	s2[0] = win32prgdir[0], s2[1] = ':', s2[2] = '\\', s2[3] = '\0';
	ret = resolved_path(s1);
	retValue = strcmp(ret, s2);
	ASSERT_INT_EQ(retValue, 0);

	TEST_DONE();
}

void
test_pw()
{
	TEST_START("pw tests");

	struct passwd *pw = NULL;
	pw = getpwuid(0);
	ASSERT_PTR_NE(pw, NULL);

	struct passwd *pw1 = NULL;
	char *user = dup_str(pw->pw_name);
	pw1 = getpwnam(user);
	ASSERT_PTR_NE(pw1, NULL);

	TEST_DONE();
}

void
test_statvfs()
{
	TEST_START("test statvfs");

	struct statvfs st;
	char cwd[MAX_PATH];

	char *tmp = getcwd(cwd, MAX_PATH);
	ASSERT_PTR_NE(tmp, NULL);

	retValue = statvfs(NULL, &st);
	ASSERT_INT_EQ(retValue, -1);

	explicit_bzero(&st, sizeof(st));
	retValue = statvfs(cwd, &st);
	ASSERT_INT_EQ(retValue, 0);
	ASSERT_INT_NE(st.f_bavail, 0);

	TEST_DONE();
}

void test_realpath()
{
	TEST_START("test realpath");

	char resolved_path[MAX_PATH];
	char *ret = NULL;
	char *expectedOutput1 = "/c:/windows/system32";
	char *expectedOutput2 = "/c:/";

	ret = realpath(NULL, NULL);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath("c:\\windows\\system32", NULL);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath(NULL, resolved_path);
	ASSERT_PTR_EQ(ret, NULL);

	ret = realpath("c:\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\.\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows\\.\\..\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:\\windows/.\\..\\windows\\system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("c:/windows/system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("/c:/windows/system32", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput1);

	ret = realpath("c:", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	ret = realpath("c:\\", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	ret = realpath("/c:", resolved_path);
	ASSERT_STRING_EQ(ret, expectedOutput2);

	TEST_DONE();
}

void
miscellaneous_tests()
{
	//test_ioctl();
	test_path_conversion_utilities();
	test_sanitizedpath();
	test_pw();
	test_realpath();
	test_statvfs();
}
