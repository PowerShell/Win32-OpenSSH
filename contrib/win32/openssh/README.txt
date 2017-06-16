Custom paths for the visual studio projects are defined in paths.targets.  

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path            =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path            =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Lib-Path            =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
LibreSSL-x86-Path           =  The directory path of LibreSSL statically compiled for x86 platform.
LibreSSL-x64-Path           =  The directory path of LibreSSL statically compiled for x64 platform.

