/*	$Id: arms_push_method_query.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <inttypes.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <libarms/queue.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>

/*
 * API: arms_push_method_query
 */

int
arms_push_method_query(arms_context_t *res,
		       arms_callback_tbl_t *cb_tbl, void *udata)
{
#ifdef HAVE_SIGNAL
	struct sigaction oldact, newact;
#endif

	/* check parameter */
	if (res == NULL)
		return ARMS_EINVAL;
	if (cb_tbl == NULL)
		return ARMS_EINVAL;

	/* setup */
	arms_scheduler_init();
	res->udata = udata;
	arms_free_rs_tunnel_url(res);
	res->tunnel_echo_interval = 60; /* default: 60sec */
	if (res->rs_pull_1st == -1)
		res->rs_pull_1st = 0;

#ifdef HAVE_SIGNAL
	/* block SIGPIPE */
	memset(&newact, 0, sizeof(newact));
	memset(&oldact, 0, sizeof(oldact));
	newact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &newact, &oldact);
#endif

	if (new_method_query_transaction(res,
			      strdistid(&res->dist_id)) == 0) {
		/* start */
		arms_scheduler();
	}
#ifdef HAVE_SIGNAL
	sigaction(SIGPIPE, &oldact, NULL);
#endif
	return res->result;
}
