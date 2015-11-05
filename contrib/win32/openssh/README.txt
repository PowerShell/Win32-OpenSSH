In order to build the Visual Studio 2015 solution, the config.h in the Win32-OpenSSH should be overwritten with the contents of the config.h.vs file.


Custom paths for the visual studio projects are defined in paths.targets.  

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Bin-Path =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
OpenSSL-Path     =  The directory that contains OpenSSL headers and libaraies.

Notes on OpenSSL path structure
================================

The projects anticipate that the OpenSSL directory will contain sub directorires for Platform and Configuration for example:

OpenSSL -+- Win32 -+- Release -+- include
         |         |           |
         |         |           +- lib
         |         |
         |         +- Debug   -+- include
         |                     |
         |                     +- lib 
         |
         +- x64   -+- Release -+- include
                   |           |
                   |           +- lib
                   |
                   +- Debug   -+- include
                               |
                               +- lib 

The Release/Debug OpenSSL directories output is the standard 'install' output of OpenSSL compiled under Visual Studio 2015 using static c-runtimes.

