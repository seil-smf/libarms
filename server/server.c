/*	$Id: server.c 22684 2012-08-13 00:35:54Z m-oki $	*/

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

#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netdb.h>

#include <axp_extern.h>
#include <libarms_log.h>

#include <libarms/malloc.h>
#include <libarms/sock.h>
#include <libarms/time.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>
#include <server/server.h>

#include "compat.h"

/*
 * Server class
 * - socket
 * - bind
 * - listen
 * - accept (called from scheduler)
 * - close (called from scheduler)
 */

struct arms_server_arg {
	const char *user;
	const char *passwd;
};

/*
 * obj: associated with server socket.
 */
static int
accept_fd(struct arms_schedule *obj, int event)
{
	arms_context_t *res = arms_get_context();
	struct sockaddr_storage ss;
	socklen_t len;
	struct arms_server_arg *arg;
	int s;

	arg = obj->userdata;
	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		if (res->confirm_id != 0) {
			libarms_log(ARMS_LOG_ENETTIMEOUT,
				    "confirmation timeout");
			res->result = ARMS_ETIMEOUT;
			/* finish myself by EVENT_FINISH_THIS */
			return SCHED_FINISHED_SCHEDULER;
		}
		arms_get_time_remaining(&obj->timeout,
					30 * 24 * 60 * 60); /* 30days */
		break;
	case EVENT_TYPE_READ:
	case EVENT_TYPE_WRITE:
		len = sizeof(ss);
		s = arms_accept(obj->fd, (struct sockaddr *)&ss, &len);
		if (s == -1)
			return SCHED_CONTINUE_THIS;
		/* new session */
		new_push_transaction(s, &ss, len, arg->user);
		break;
	case EVENT_TYPE_FINISH:
		FREE(obj->userdata);
		CLOSE_FD(obj->fd);
		arms_set_global_state(ARMS_ST_PUSH_REBOOT);
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	return SCHED_CONTINUE_THIS;
}

int
new_arms_server(int af, int port, const char *user, const char *passwd)
{
	struct addrinfo hints, *res;
	struct timeval timo;
	struct arms_server_arg *arg;
	int result = -1;
	int fd, on, r;
	int retry;
	char sbuf[NI_MAXSERV];

	fd = -1;
	res = NULL;

	arg = CALLOC(1, sizeof(struct arms_server_arg));
	if (arg == NULL) {
		result = ARMS_ESYSTEM;
		goto eret;
	}
	arg->user = user;
	arg->passwd = passwd;

	snprintf(sbuf, sizeof(sbuf), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(NULL, sbuf, &hints, &res);
	if (r != 0 || res == NULL) {
		result = ARMS_ESYSTEM;
		goto eret;
	}

	fd = arms_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd == -1) {
		libarms_log(ARMS_LOG_ESOCKET, "socket(2) failed.");
		result = ARMS_ESYSTEM;
		goto eret;
	}
#ifdef HAVE_FCNTL
	arms_fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	on = 1;
	arms_ioctl(fd, FIONBIO, &on);
#ifdef HAVE_SETSOCKOPT
	arms_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
	if (res->ai_family == AF_INET6 &&
	    arms_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		libarms_log(ARMS_LOG_ESOCKET,
		            "setsockopt(IPV6_V6ONLY) failed");
		goto eret;
	}
#endif
#endif

	retry = 0;
	while (arms_bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
		if (retry++ > 6) {
			/* failed 1+6 times.  fallback to Pull. */
			libarms_log(ARMS_LOG_ESOCKET,
			    "too many times bind(2) failed.  fallback.\n");
			result = ARMS_EPULL;
			goto eret;
		}
		libarms_log(ARMS_LOG_ESOCKET,
			    "bind(2) failed. wait 60sec and retrying(%d)\n",
			    retry);
		arms_sleep(60);
	}
	if (arms_listen(fd, 5) == -1) {
		libarms_log(ARMS_LOG_ESOCKET,
			    "listen(2) failed.");
		result = ARMS_ESYSTEM;
		goto eret;
	}

	freeaddrinfo(res);
	arms_get_time_remaining(&timo, 60); /* 60sec wait for confirm-done */
	new_arms_schedule(SCHED_TYPE_IOR, fd, &timo, accept_fd, arg);
	return 0;
eret:
	if (arg != NULL) {
		FREE(arg);
	}
	if (res != NULL)
		freeaddrinfo(res);
	if (fd != -1)
		CLOSE_FD(fd);
	return result;
}
