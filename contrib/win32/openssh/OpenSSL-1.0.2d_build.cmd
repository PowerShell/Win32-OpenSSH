set OPENSSL_VERSION=1.0.2d
set PerlPath=c:\perl\bin
set NASMPath=c:\nasm

set VS2013="C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\vcvars32.bat"
set VS2013_AMD64="C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\amd64\vcvars64.bat"
set VS2015="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
set VS2015_AMD64="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\amd64\vcvars64.bat"

set path=%NASMPath%;%PerlPath%;%path%


CALL %VS2015%

cd \Dev\OpenSSL\openssl-%OPENSSL_VERSION%-src-x86
perl Configure VC-WIN32 --prefix=C:\dev\OpenSSL\%OPENSSL_VERSION%\VS2015\Win32\Release
call ms\do_ms.bat
call ms\do_nasm.bat
nmake -f ms\nt.mak clean
nmake -f ms\nt.mak
nmake -f ms\nt.mak install

cd \Dev\OpenSSL\openssl-%OPENSSL_VERSION%-src-x86
perl Configure debug-VC-WIN32 --prefix=C:\dev\OpenSSL\%OPENSSL_VERSION%\VS2015\Win32\Debug
call ms\do_ms.bat
call ms\do_nasm.bat
nmake -f ms\nt.mak clean
nmake -f ms\nt.mak
nmake -f ms\nt.mak install

CALL %VS2015_AMD64%

cd \Dev\OpenSSL\openssl-%OPENSSL_VERSION%-src-x64
perl Configure VC-WIN64A --prefix=C:\dev\OpenSSL\%OPENSSL_VERSION%\VS2015\x64\Release
call ms\do_win64a.bat
nmake -f ms\nt.mak clean
nmake -f ms\nt.mak
nmake -f ms\nt.mak install

cd \Dev\OpenSSL\openssl-%OPENSSL_VERSION%-src-x64
perl Configure debug-VC-WIN64A --prefix=C:\dev\OpenSSL\%OPENSSL_VERSION%\VS2015\x64\Debug
call ms\do_win64a.bat
nmake -f ms\nt.mak clean
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
