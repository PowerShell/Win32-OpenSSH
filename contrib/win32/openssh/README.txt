Custom paths for the visual studio projects are defined in paths.targets.  

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path            =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path            =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Lib-Path            =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
OpenSSL-Win32-Release-Path  =  The directory path of OpenSSL statically linked compiled for Win32-Release. This path is used for
                               include and library paths and for Win32-Release. 
OpenSSL-Win32-Debug-Path    =  The directory path of OpenSSL statically linked compiled for Win32-Debug. This path is used for
                               include and library paths and for Win32-Debug.  
OpenSSL-x64-Release-Path    =  The directory path of OpenSSL statically linked compiled for x64-Release. This path is used for
                               include and library paths and for x64-Release. 
OpenSSL-x64-Debug-Path      =  The directory path of OpenSSL statically linked compiled for x64-Debug. This path is used for
                               include and library paths and for x64-Debug. 

 

The Release/Debug OpenSSL directories output is the standard 'install' output of OpenSSL compiled under Visual Studio 2015 using static c-runtimes.

