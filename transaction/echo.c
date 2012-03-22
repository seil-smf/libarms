/*	$Id: echo.c 20800 2012-01-19 05:13:45Z m-oki $	*/

/*
 * Copyright (c) 2012, Internet Initiative Japan, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <openssl/ssl.h>

#include <inttypes.h>
#include <sys/select.h>

#include <libarms_log.h>
#include <libarms/queue.h>
#include <libarms/time.h>
#include <libarms/ssl.h>
#include <scheduler/scheduler.h>
#include <transaction/ssltunnel.h>

/*
 * periodic echo w/ SSL tunnel connection
 */

static const char echo_chunk[] = "4;echo-request;trail\r\necho\r\n";

static int
wait_for_write_socket(int s, int sec)
{
	struct timeval tv;
	fd_set fds;
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	return select(s + 1, NULL, &fds, NULL, &tv);
}

/*
 * generally, this function is called by timeout only.
 */
int
arms_chunk_send_echo(struct arms_schedule *obj, int event)
{
	struct arms_schedule *tunnelobj = obj->userdata;
	arms_context_t *res = arms_get_context();
	struct ssltunnel *tunnel;
	int error;

	if (tunnelobj == NULL)
		return SCHED_FINISHED_THIS;
	tunnel = tunnelobj->userdata;

	switch (event) {
	case EVENT_TYPE_FINISH:
		if (tunnelobj != NULL) {
			tunnel = tunnelobj->userdata;
			tunnel->echo = NULL;
		}
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_TIMEOUT:
		if (obj->type == SCHED_TYPE_IOW) {
			libarms_log(ARMS_LOG_ESSL,
				    "tunnel#%d: failed to write echo (timeout)",
				    tunnel->num);
			/* notify to tunnelobj and finish this. */
			tunnel->echo = NULL;
			obj->userdata = NULL;
			/* notify timeout to tunnelobj. */
			arms_get_time_remaining(&tunnelobj->timeout, 0);
			return SCHED_FINISHED_THIS;
		}
		/*FALLTHROUGH*/
	default:
		break;
	}

	if (tunnel->echo_state != ARMS_ECHO_NONE) {
		libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d: no echo response received.",
			    tunnel->num);
		/* notify to tunnelobj and finish this. */
		tunnel->echo = NULL;
		obj->userdata = NULL;
		/* notify timeout to tunnelobj. */
		arms_get_time_remaining(&tunnelobj->timeout, 0);

		return SCHED_FINISHED_THIS;
	}
	/*
	 * if writing data by another transaction,
	 * nothing to do in this time.
	 */
	if (tunnel->write_tr != NULL) {
		/* busy: next try after 1sec. */
		arms_get_time_remaining(&obj->timeout, 1);
		return SCHED_CONTINUE_THIS;
	}
	/* send echo message to ssl server */
	error = arms_ssl_write(tunnel->ssl,
			       echo_chunk, sizeof(echo_chunk) - 1);
	if (error < 0) {
		libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d: failed to write echo chunk.",
			    tunnel->num);
		/* notify to tunnelobj and finish this. */
		tunnel->echo = NULL;
		obj->userdata = NULL;
		/* notify timeout to tunnelobj. */
		arms_get_time_remaining(&tunnelobj->timeout, 0);

		return SCHED_FINISHED_THIS;
	}
	while (error == 0) {
		/*
		 * wait for writing socket.
		 * don't return to scheduler because must retry to send echo.
		 */
		error = wait_for_write_socket(tunnelobj->fd, 10);
		if (error <= 0) {
			libarms_log(ARMS_LOG_ESSL,
				    "tunnel#%d: failed to write echo chunk.",
				    tunnel->num);
			/* notify to tunnelobj and finish this. */
			tunnel->echo = NULL;
			obj->userdata = NULL;
			/* notify timeout to tunnelobj. */
			arms_get_time_remaining(&tunnelobj->timeout, 0);

			return SCHED_FINISHED_THIS;
		}
		/* retry to write */
		error = arms_ssl_write(tunnel->ssl,
				       echo_chunk, sizeof(echo_chunk) - 1);
	}
	tunnel->echo_state = ARMS_ECHO_SENT;
	/* next */
	obj->type = SCHED_TYPE_TIMER;
	obj->fd = -1;
	arms_get_time_remaining(&obj->timeout, res->tunnel_echo_interval);
	return SCHED_CONTINUE_THIS;
}
