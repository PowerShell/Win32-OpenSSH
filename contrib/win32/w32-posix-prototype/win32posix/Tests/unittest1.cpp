#include "CppUnitTest.h"
#include "..\win32posix\w32posix.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{
    TEST_CLASS(UnitTest1)
    {
    public:

        TEST_METHOD(TestMethod1)
        {
            // TODO: Your test code here
            fd_set* set = (fd_set*)malloc(sizeof(fd_set));

            FD_ZERO(set);
            FD_SET(0, set);
            FD_SET(1, set);

            Assert::AreEqual(1, FD_ISSET(0, set), L"", LINE_INFO());
            Assert::AreEqual(1, FD_ISSET(1, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(2, set), L"", LINE_INFO());

            FD_CLR(0, set);
            FD_CLR(1, set);

            Assert::AreEqual(0, FD_ISSET(0, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(1, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(2, set), L"", LINE_INFO());


        }


    };
}