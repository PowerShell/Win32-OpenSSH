/*
 * SSH2 tty modes for Windows
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include "includes.h"

#include "inc/sys/types.h"

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <stdarg.h>

#include "packet.h"
#include "log.h"
#include "compat.h"
#include "buffer.h"

#define TTY_OP_END		0
/*
 * uint32 (u_int) follows speed in SSH1 and SSH2
 */
#define TTY_OP_ISPEED_PROTO1	192
#define TTY_OP_OSPEED_PROTO1	193
#define TTY_OP_ISPEED_PROTO2	128
#define TTY_OP_OSPEED_PROTO2	129

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
void
tty_make_modes(int fd, struct termios *tiop)
{
	int baud;
	Buffer buf;
	int tty_op_ospeed, tty_op_ispeed;
	void (*put_arg)(Buffer *, u_int);

	buffer_init(&buf);
	if (compat20) {
		tty_op_ospeed = TTY_OP_OSPEED_PROTO2;
		tty_op_ispeed = TTY_OP_ISPEED_PROTO2;
		put_arg = buffer_put_int;
	} else {
		tty_op_ospeed = TTY_OP_OSPEED_PROTO1;
		tty_op_ispeed = TTY_OP_ISPEED_PROTO1;
		put_arg = (void (*)(Buffer *, u_int)) buffer_put_char;
	}

	/* Store input and output baud rates. */
	baud = 9600;

	buffer_put_char(&buf, tty_op_ospeed);
	buffer_put_int(&buf, baud);
	baud = 9600;
	buffer_put_char(&buf, tty_op_ispeed);
	buffer_put_int(&buf, baud);

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	buffer_put_char(&buf, OP); \
	put_arg(&buf, special_char_encode(tio.c_cc[NAME]));

#define TTYMODE(NAME, FIELD, OP) \
	buffer_put_char(&buf, OP); \
	put_arg(&buf, ((tio.FIELD & NAME) != 0));

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	buffer_put_char(&buf, TTY_OP_END);
	if (compat20)
		packet_put_string(buffer_ptr(&buf), buffer_len(&buf));
	else
		packet_put_raw(buffer_ptr(&buf), buffer_len(&buf));
	buffer_free(&buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
void
tty_parse_modes(int fd, int *n_bytes_ptr)
{

	u_int tio[255]; // win32 dummy
	u_int tioFIELD ;
	int opcode, baud;
	int n_bytes = 0;
	int failure = 0;
	u_int (*get_arg)(void);
	int arg_size;

	if (compat20) {
		*n_bytes_ptr = packet_get_int();
		if (*n_bytes_ptr == 0)
			return;
		get_arg = packet_get_int;
		arg_size = 4;
	} else {
		get_arg = packet_get_char;
		arg_size = 1;
	}

	for (;;) {
		n_bytes += 1;
		opcode = packet_get_char();
		switch (opcode) {
		case TTY_OP_END:
			goto set;

		/* XXX: future conflict possible */
		case TTY_OP_ISPEED_PROTO1:
		case TTY_OP_ISPEED_PROTO2:
			n_bytes += 4;
			baud = packet_get_int();
			break;

		/* XXX: future conflict possible */
		case TTY_OP_OSPEED_PROTO1:
		case TTY_OP_OSPEED_PROTO2:
			n_bytes += 4;
			baud = packet_get_int();
			break;

#define TTYCHAR(NAME, OP) \
	case OP: \
	  n_bytes += arg_size; \
	  tio[NAME] = special_char_decode(get_arg()); \
	  break;
#define TTYMODE(NAME, FIELD, OP) \
	case OP: \
	  n_bytes += arg_size; \
	  if (get_arg()) \
	    tioFIELD |= NAME; \
	  else \
	    tioFIELD &= ~NAME;	\
	  break;

#undef TTYCHAR
#undef TTYMODE

		default:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			if (!compat20) {
				/*
				 * SSH1:
				 * Opcodes 1 to 127 are defined to have
				 * a one-byte argument.
				 * Opcodes 128 to 159 are defined to have
				 * an integer argument.
				 */
				if (opcode > 0 && opcode < 128) {
					n_bytes += 1;
					(void) packet_get_char();
					break;
				} else if (opcode >= 128 && opcode < 160) {
					n_bytes += 4;
					(void) packet_get_int();
					break;
				} else {
					/*
					 * It is a truly undefined opcode (160 to 255).
					 * We have no idea about its arguments.  So we
					 * must stop parsing.  Note that some data
					 * may be left in the packet; hopefully there
					 * is nothing more coming after the mode data.
					 */
					logit("parse_tty_modes: unknown opcode %d",
					    opcode);
					goto set;
				}
			} else {
				/*
				 * SSH2:
				 * Opcodes 1 to 159 are defined to have
				 * a uint32 argument.
				 * Opcodes 160 to 255 are undefined and
				 * cause parsing to stop.
				 */
				if (opcode > 0 && opcode < 160) {
					n_bytes += 4;
					(void) packet_get_int();
					break;
				} else {
					logit("parse_tty_modes: unknown opcode %d",
					    opcode);
					goto set;
				}
			}
		}
	}

set:
	if (*n_bytes_ptr != n_bytes) {
		*n_bytes_ptr = n_bytes;
		logit("parse_tty_modes: n_bytes_ptr != n_bytes: %d %d",
		    *n_bytes_ptr, n_bytes);
		return;		/* Don't process bytes passed */
	}
	if (failure == -1)
		return;		/* Packet parsed ok but tcgetattr() failed */

}
