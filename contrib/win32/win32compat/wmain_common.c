/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Converts UTF-16 arguments to UTF-8
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Windows.h>
#include "inc\utf.h"
#include "misc_internal.h"

int
main(int, char **);

int
wmain(int argc, wchar_t **wargv) {
	char** argv = NULL;
	int i, r;
	_set_invalid_parameter_handler(invalid_parameter_handler);
	if (argc) {
		if ((argv = malloc(argc * sizeof(char*))) == NULL)
			fatal("out of memory");
		for (i = 0; i < argc; i++)
			if ((argv[i] = utf16_to_utf8(wargv[i])) == NULL)
				fatal("out of memory");
        }

	if (getenv("SSH_AUTH_SOCK") == NULL)
		_putenv("SSH_AUTH_SOCK=\\\\.\\pipe\\openssh-ssh-agent");

	if (getenv("TERM") == NULL)
		_putenv("TERM=xterm-256color");

	w32posix_initialize();
	
	r = main(argc, argv);
	w32posix_done();	
	return r;
}
