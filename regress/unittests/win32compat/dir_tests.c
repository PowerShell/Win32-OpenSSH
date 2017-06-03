#include "includes.h"
#include <sys/stat.h>
#include <unistd.h>
#include <inc/dirent.h>
#include <sys/statvfs.h>
#include <sys/time.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

int retValue;

void
dir_tests_1()
{
	TEST_START("directory testcases");

	char *test_dirname_1 = "test_dir_1";
	char *tes_dirname_2 = "test_dir_2";
	char cwd[MAX_PATH];
	char *p_ret;
	struct stat st;
	char *tmpfile = "tmp.txt";
	char mode[12];
	struct timeval tv[2];
	DIR *dirp = NULL;
	struct dirent *dp = NULL;
	char dir_fullpath[MAX_PATH];
	int f = -1;

	p_ret = getcwd(NULL, MAX_PATH);
	ASSERT_PTR_EQ(p_ret, NULL);

	p_ret = getcwd(cwd, MAX_PATH);
	ASSERT_PTR_NE(p_ret, NULL);

	// delete test_dirname_1, if exits.	
	strcpy(dir_fullpath, cwd);
	strcat(dir_fullpath, "\\");
	strcat(dir_fullpath, test_dirname_1);
	delete_dir_recursive(dir_fullpath);

	// delete test_dirname_2, if exists
	strcpy(dir_fullpath, cwd);
	strcat(dir_fullpath, "\\");
	strcat(dir_fullpath, tes_dirname_2);
	delete_dir_recursive(dir_fullpath);

	retValue = mkdir(NULL, 0);
	ASSERT_INT_EQ(retValue, -1);

	retValue = mkdir(test_dirname_1, S_IRUSR | S_IWUSR | S_IXUSR);
	ASSERT_INT_EQ(retValue, 0);

	retValue = stat(NULL, &st);
	ASSERT_INT_EQ(retValue, -1);

	retValue = stat(test_dirname_1, &st);
	ASSERT_INT_EQ(retValue, 0);
	ASSERT_INT_EQ(st.st_size, 0);
	strmode(st.st_mode, mode);
	ASSERT_CHAR_EQ(mode[0], 'd');

	retValue = chdir(NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = chdir(test_dirname_1);
	ASSERT_INT_EQ(retValue, 0);
	
	p_ret = getcwd(cwd, MAX_PATH);
	ASSERT_PTR_NE(p_ret, NULL);
	p_ret = NULL;
	p_ret = strstr(cwd, test_dirname_1);
	ASSERT_PTR_NE(p_ret, NULL);

	retValue = chdir("..");
	ASSERT_INT_EQ(retValue, 0);

	retValue = rename(NULL, tes_dirname_2);
	ASSERT_INT_EQ(retValue, -1);

	retValue = rename(test_dirname_1, NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = rename(NULL, NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = rename(test_dirname_1, tes_dirname_2);
	ASSERT_INT_EQ(retValue, 0);

	retValue = stat(tes_dirname_2, &st);
	ASSERT_INT_EQ(retValue, 0);

	dirp = opendir(NULL);
	ASSERT_PTR_EQ(dirp, NULL);

	dirp = opendir(tes_dirname_2);
	ASSERT_PTR_NE(dirp, NULL);

	dp = readdir(NULL);
	ASSERT_PTR_EQ(dp, NULL);

	dp = readdir(dirp);
	ASSERT_PTR_EQ(dp, NULL);
	
	tv[0].tv_sec = st.st_atime + 1000;
	tv[1].tv_sec = st.st_mtime + 1000;
	tv[0].tv_usec = tv[1].tv_usec = 0;
	retValue = utimes(tes_dirname_2, tv);
	ASSERT_INT_EQ(retValue, -1);
	ASSERT_INT_EQ(errno, ERROR_SHARING_VIOLATION);

	retValue = closedir(NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = closedir(dirp);
	ASSERT_INT_EQ(retValue, 0);

	retValue = utimes(tes_dirname_2, tv);
	ASSERT_INT_EQ(retValue, 0);

	retValue = chdir(tes_dirname_2);
	ASSERT_INT_EQ(retValue, 0);

	f = open(tmpfile, O_RDWR | O_CREAT | O_TRUNC, 0600);
	ASSERT_INT_NE(f, -1);
	close(f);

	retValue = chdir("..");
	ASSERT_INT_EQ(retValue, 0);

	dirp = opendir(tes_dirname_2);
	ASSERT_PTR_NE(dirp, NULL);

	dp = readdir(dirp);
	ASSERT_PTR_NE(dp, NULL);
	
	retValue = closedir(dirp);
	ASSERT_INT_EQ(retValue, 0);

	retValue = rmdir(NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = rmdir(tes_dirname_2);
	ASSERT_INT_NE(retValue, 0);
	
	retValue = chdir(tes_dirname_2);
	ASSERT_INT_EQ(retValue, 0);

	retValue = unlink(NULL);
	ASSERT_INT_EQ(retValue, -1);

	retValue = unlink(tmpfile);
	ASSERT_INT_EQ(retValue, 0);

	retValue = chdir("..");
	ASSERT_INT_EQ(retValue, 0);

	retValue = rmdir(tes_dirname_2);
	ASSERT_INT_EQ(retValue, 0);

	dirp = opendir(tes_dirname_2);
	ASSERT_PTR_EQ(dirp, NULL);

	TEST_DONE();
}

void
dir_tests()
{
	dir_tests_1();
}
