In order to build the Visual Studio 2015 solution, the config.h in the Win32-OpenSSH should be overwritten with the contents of the config.h.vs file.


Custom paths for the visual studio projects are defined in paths.targets.  

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path            =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path            =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Lib-Path            =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
OpenSSL-Win32-Release-Path  =  The directory path of OpenSSL statically linked compiled for Win32-Release.  This path is used by all projects
                               for the include path  (since includes are the same for all configurations), and for the Win32-Release library 
							   paths 
OpenSSL-Win32-Debug-Path    =  The directory path of OpenSSL statically linked compiled for Win32-Debug.  This path is used in the Win32-Debug
                               library path 
OpenSSL-x64-Release-Path    =  The directory path of OpenSSL statically linked compiled for x64-Release.  This path is used in the Win32-Release
                               library path
OpenSSL-x64-Debug-Path      =  The directory path of OpenSSL statically linked compiled for x64-Release.  This path is used in the Win32-Release
                               library path

 

The Release/Debug OpenSSL directories output is the standard 'install' output of OpenSSL compiled under Visual Studio 2015 using static c-runtimes.

