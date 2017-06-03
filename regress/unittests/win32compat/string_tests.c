#include "includes.h"
#include <string.h>
#include "../test_helper/test_helper.h"
#include "tests.h"

int retValue;

void
str_simple_tests()
{
	TEST_START("string testcases");

	char *s1 = "test_dir";
	char *s2 = NULL;

	s2 = strdup(NULL);
	ASSERT_PTR_EQ(s2, NULL);

	s2 = strdup(s1);
	ASSERT_PTR_NE(s2, NULL);

	retValue = strcasecmp(s1, s2);
	ASSERT_INT_EQ(retValue, 0);

	retValue = strncasecmp(s1, s2, strlen(s1));
	ASSERT_INT_EQ(retValue, 0);

	s2[0] = 'T';
	retValue = strcasecmp(s1, s2);
	ASSERT_INT_EQ(retValue, 0);

	retValue = strncasecmp(s1, s2, strlen(s1));
	ASSERT_INT_EQ(retValue, 0);
	free(s2);

	TEST_DONE();
}

void
str_tests()
{
	str_simple_tests();
}
