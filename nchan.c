/* $OpenBSD: nchan.c,v 1.63 2010/01/26 01:28:35 djm Exp $ */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "openbsd-compat/sys-queue.h"
#include "ssh1.h"
#include "ssh2.h"
#include "buffer.h"
#include "packet.h"
#include "channels.h"
#include "compat.h"
#include "log.h"

/*
 * SSH Protocol 1.5 aka New Channel Protocol
 * Thanks to Martina, Axel and everyone who left Erlangen, leaving me bored.
 * Written by Markus Friedl in October 1999
 *
 * Protocol versions 1.3 and 1.5 differ in the handshake protocol used for the
 * tear down of channels:
 *
 * 1.3:	strict request-ack-protocol:
 *	CLOSE	->
 *		<-  CLOSE_CONFIRM
 *
 * 1.5:	uses variations of:
 *	IEOF	->
 *		<-  OCLOSE
 *		<-  IEOF
 *	OCLOSE	->
 *	i.e. both sides have to close the channel
 *
 * 2.0: the EOF messages are optional
 *
 * See the debugging output from 'ssh -v' and 'sshd -d' of
 * ssh-1.2.27 as an example.
 *
 */

/* functions manipulating channel states */
/*
 * EVENTS update channel input/output states execute ACTIONS
 */
/*
 * ACTIONS: should never update the channel states
 */

#ifdef WIN32_FIXME      

  void StopSocketThreads();

#endif

static void	chan_send_ieof1(Channel *);
static void	chan_send_oclose1(Channel *);
static void	chan_send_close2(Channel *);
static void	chan_send_eof2(Channel *);
static void	chan_send_eow2(Channel *);

/* helper */
static void	chan_shutdown_write(Channel *);
static void	chan_shutdown_read(Channel *);

static char *ostates[] = { "open", "drain", "wait_ieof", "closed" };
static char *istates[] = { "open", "drain", "wait_oclose", "closed" };

static void
chan_set_istate(Channel *c, u_int next)
{
	if (c->istate > CHAN_INPUT_CLOSED || next > CHAN_INPUT_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, next);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[next]);
	c->istate = next;
}
static void
chan_set_ostate(Channel *c, u_int next)
{
	if (c->ostate > CHAN_OUTPUT_CLOSED || next > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, next);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[next]);
	c->ostate = next;
}

/*
 * SSH1 specific implementation of event functions
 */

static void
chan_rcvd_oclose1(Channel *c)
{
	debug2("channel %d: rcvd oclose", c->self);

  /*
   * FIXME. This function forces stopping all socket threads 
   * at next select. This workaround nivelate problem with
   * infinite hangs up in below scenario:
   * 
   * a) read select start.
   * b) write select start.
   * c) read select ends: SSH2_MSG_CHANNEL_CLOSE received.
   * d) close input channel.
   * e) now write select may never ends.
   */

  #ifdef WIN32_FIXME

    StopSocketThreads();

  #endif

	switch (c->istate) {
	case CHAN_INPUT_WAIT_OCLOSE:
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	case CHAN_INPUT_OPEN:
		chan_shutdown_read(c);
		chan_send_ieof1(c);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	case CHAN_INPUT_WAIT_DRAIN:
		/* both local read_failed and remote write_failed  */
		chan_send_ieof1(c);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	default:
		error("channel %d: protocol error: rcvd_oclose for istate %d",
		    c->self, c->istate);
		return;
	}
}
void
chan_read_failed(Channel *c)
{
	debug2("channel %d: read failed", c->self);
	switch (c->istate) {
	case CHAN_INPUT_OPEN:
		chan_shutdown_read(c);
		chan_set_istate(c, CHAN_INPUT_WAIT_DRAIN);
		break;
	default:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		break;
	}
}
void
chan_ibuf_empty(Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	if (buffer_len(&c->input)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		return;
	}
	switch (c->istate) {
	case CHAN_INPUT_WAIT_DRAIN:
		if (compat20) {
			if (!(c->flags & (CHAN_CLOSE_SENT | CHAN_LOCAL))) {
				#ifdef WIN32_FIXME
				// reset the other side if tty to be how it was before
				if (c->isatty) {
					char *inittermseq =
						"\033[?7h" // end-of-line autowrap ON mode
						"\033[20l"; // force NewLineMode off

					buffer_append(&c->input, inittermseq, strlen(inittermseq));
					int state = c->istate;
					c->istate = CHAN_INPUT_WAIT_DRAIN;
					channel_output_poll();
					packet_write_poll(); // packet_write_wait();
					c->istate = state;
				}
				#endif
				chan_send_eof2(c);
			}
			chan_set_istate(c, CHAN_INPUT_CLOSED);
		} else {
			chan_send_ieof1(c);
			chan_set_istate(c, CHAN_INPUT_WAIT_OCLOSE);
		}
		break;
	default:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		break;
	}
}
static void
chan_rcvd_ieof1(Channel *c)
{
	debug2("channel %d: rcvd ieof", c->self);
	switch (c->ostate) {
	case CHAN_OUTPUT_OPEN:
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		break;
	case CHAN_OUTPUT_WAIT_IEOF:
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		break;
	default:
		error("channel %d: protocol error: rcvd_ieof for ostate %d",
		    c->self, c->ostate);
		break;
	}
}
static void
chan_write_failed1(Channel *c)
{
	debug2("channel %d: write failed", c->self);
	switch (c->ostate) {
	case CHAN_OUTPUT_OPEN:
		chan_shutdown_write(c);
		chan_send_oclose1(c);
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_IEOF);
		break;
	case CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(c);
		chan_send_oclose1(c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		break;
	default:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		break;
	}
}
void
chan_obuf_empty(Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	if (buffer_len(&c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		return;
	}
	switch (c->ostate) {
	case CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(c);
		if (!compat20)
			chan_send_oclose1(c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		break;
	default:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		break;
	}
}
static void
chan_send_ieof1(Channel *c)
{
	debug2("channel %d: send ieof", c->self);
	switch (c->istate) {
	case CHAN_INPUT_OPEN:
	case CHAN_INPUT_WAIT_DRAIN:
		packet_start(SSH_MSG_CHANNEL_INPUT_EOF);
		packet_put_int(c->remote_id);
		packet_send();
		break;
	default:
		error("channel %d: cannot send ieof for istate %d",
		    c->self, c->istate);
		break;
	}
}
static void
chan_send_oclose1(Channel *c)
{
	debug2("channel %d: send oclose", c->self);
	switch (c->ostate) {
	case CHAN_OUTPUT_OPEN:
	case CHAN_OUTPUT_WAIT_DRAIN:
		buffer_clear(&c->output);
		packet_start(SSH_MSG_CHANNEL_OUTPUT_CLOSE);
		packet_put_int(c->remote_id);
		packet_send();
		break;
	default:
		error("channel %d: cannot send oclose for ostate %d",
		    c->self, c->ostate);
		break;
	}
}

/*
 * the same for SSH2
 */
static void
chan_rcvd_close2(Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	if (!(c->flags & CHAN_LOCAL)) {
		if (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	if (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		return;
	}
	switch (c->ostate) {
	case CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		break;
	}
	switch (c->istate) {
	case CHAN_INPUT_OPEN:
		chan_shutdown_read(c);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	case CHAN_INPUT_WAIT_DRAIN:
		if (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(c);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	}
}

void
chan_rcvd_eow(Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	switch (c->istate) {
	case CHAN_INPUT_OPEN:
		chan_shutdown_read(c);
		chan_set_istate(c, CHAN_INPUT_CLOSED);
		break;
	}
}
static void
chan_rcvd_eof2(Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	if (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
}
static void
chan_write_failed2(Channel *c)
{
	debug2("channel %d: write failed", c->self);
	switch (c->ostate) {
	case CHAN_OUTPUT_OPEN:
	case CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(c);
		if (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		break;
	default:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		break;
	}
}
static void
chan_send_eof2(Channel *c)
{
	debug2("channel %d: send eof", c->self);
	switch (c->istate) {
	case CHAN_INPUT_WAIT_DRAIN:
		packet_start(SSH2_MSG_CHANNEL_EOF);
		packet_put_int(c->remote_id);
		packet_send();
		c->flags |= CHAN_EOF_SENT;
		break;
	default:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		break;
	}
}
static void
chan_send_close2(Channel *c)
{
	debug2("channel %d: send close", c->self);
	if (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_INPUT_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} else if (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} else {
		packet_start(SSH2_MSG_CHANNEL_CLOSE);
		packet_put_int(c->remote_id);
		packet_send();
		c->flags |= CHAN_CLOSE_SENT;
	}
}
static void
chan_send_eow2(Channel *c)
{
	debug2("channel %d: send eow", c->self);
	if (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		return;
	}
	if (!(datafellows & SSH_NEW_OPENSSH))
		return;
	packet_start(SSH2_MSG_CHANNEL_REQUEST);
	packet_put_int(c->remote_id);
	packet_put_cstring("eow@openssh.com");
	packet_put_char(0);
	packet_send();
}

/* shared */

void
chan_rcvd_ieof(Channel *c)
{
	if (compat20)
		chan_rcvd_eof2(c);
	else
		chan_rcvd_ieof1(c);
	if (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    buffer_len(&c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(c);
}
void
chan_rcvd_oclose(Channel *c)
{
	if (compat20)
		chan_rcvd_close2(c);
	else
		chan_rcvd_oclose1(c);
}
void
chan_write_failed(Channel *c)
{
	if (compat20)
		chan_write_failed2(c);
	else
		chan_write_failed1(c);
}

void
chan_mark_dead(Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

int
chan_is_dead(Channel *c, int do_send)
{
	if (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		return 1;
	}
	if (c->istate != CHAN_INPUT_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		return 0;
	if (!compat20) {
		debug2("channel %d: is dead", c->self);
		return 1;
	}
	if ((datafellows & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    buffer_len(&c->extended) > 0) {
		debug2("channel %d: active efd: %d len %d",
		    c->self, c->efd, buffer_len(&c->extended));
		return 0;
	}
	if (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		return 1;
	}		
	if (!(c->flags & CHAN_CLOSE_SENT)) {
		if (do_send) {
			chan_send_close2(c);
		} else {
			/* channel would be dead if we sent a close */
			if (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				return 1;
			}
		}
	}
	if ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		return 1;
	}
	return 0;
}

/* helper */
static void
chan_shutdown_write(Channel *c)
{
	buffer_clear(&c->output);
	if (compat20 && c->type == SSH_CHANNEL_LARVAL)
		return;
	/* shutdown failure is allowed if write failed already */
	debug2("channel %d: close_write", c->self);
	if (c->sock != -1) {
		if (shutdown(c->sock, SHUT_WR) < 0)
			debug2("channel %d: chan_shutdown_write: "
			    "shutdown() failed for fd %d: %.100s",
			    c->self, c->sock, strerror(errno));
	} else {
		if (channel_close_fd(&c->wfd) < 0)
			logit("channel %d: chan_shutdown_write: "
			    "close() failed for fd %d: %.100s",
			    c->self, c->wfd, strerror(errno));
	}
}
static void
chan_shutdown_read(Channel *c)
{
	if (compat20 && c->type == SSH_CHANNEL_LARVAL)
		return;
	debug2("channel %d: close_read", c->self);
	if (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		if (shutdown(c->sock, SHUT_RD) < 0
		    && errno != ENOTCONN)
			error("channel %d: chan_shutdown_read: "
			    "shutdown() failed for fd %d [i%d o%d]: %.100s",
			    c->self, c->sock, c->istate, c->ostate,
			    strerror(errno));
	} else {
		if (channel_close_fd(&c->rfd) < 0)
			logit("channel %d: chan_shutdown_read: "
			    "close() failed for fd %d: %.100s",
			    c->self, c->rfd, strerror(errno));
	}
}
