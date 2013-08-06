/*	$Id: arms_pull.c 24391 2013-06-25 00:21:10Z yamazaki $	*/

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

/*
 * API: arms_pull()
 */

#include "config.h"

#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/queue.h>

#include <openssl/ssl.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <armsd_conf.h> /* for ACMI */
#include <libarms_log.h>

#include <libarms/time.h>
#include <libarms/ssl.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>


#define DEBUG

#ifdef DEBUG
#define DPRINTF(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

static int
pull_timeout(struct arms_schedule *obj, int event)
{
	arms_context_t *res = arms_get_context();

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* total timeout.  fatal.  stop to pull. */
		res->result = ARMS_ETIMEOUT;
		return SCHED_FINISHED_SCHEDULER;
	case EVENT_TYPE_FINISH:
		return SCHED_FINISHED_THIS;
	default:
		/*bug?*/
		return SCHED_CONTINUE_THIS;
	}
}

int
arms_ls_pull(arms_context_t *res, const char *distid, struct timeval *timo)
{
	int retry, ls_retry_max;
	int line, line_max;
	int sec, err;

	ls_retry_max = acmi_retry_max(res->acmi, ACMI_CONFIG_RSSOL) * 500;
	line_max = acmi_get_max_line(res->acmi, ACMI_CONFIG_RSSOL);
	sec = acmi_retry_interval(res->acmi, ACMI_CONFIG_RSSOL) * 20;
	err = 0;

	if (line_max == 0) {
		DPRINTF("line configuration not found.  see initial-config");
		res->trigger = "LS not found";
		arms_sleep(60);
		err = ARMS_EPULL;
	}
	DPRINTF("calculated. ls max retry %d times.", ls_retry_max);
	DPRINTF("calculated. ls retry interval %d sec.", sec);
	for (retry = 0; retry <= ls_retry_max; retry++) {
		if (retry > 0) {
			struct timeval now;

			arms_monotime(&now);
			if (timercmp(&now, timo, >)) {
				/* global timeout. */
				res->result = ARMS_ETIMEOUT;
				DPRINTF("global timeout. ARMS_ETIMEOUT");
				break;
			}
			libarms_log(ARMS_LOG_ILS_ACCESS_RETRY,
			    "LS retry(%d/%d), wait %d sec.",
				    retry, ls_retry_max, sec);
			arms_sleep(sec);
		}
		for (line = 0; line < line_max; line++) {
			int derr;

			err = arms_line_connect(
				res, ACMI_CONFIG_RSSOL, line, timo);
			if (err == ARMS_ECALLBACK) {
				/*fatal*/
				return ARMS_ECALLBACK;
			}
			if (err == 0) {
				/* setting pull schedule, and */
				if (new_ls_pull_transaction(res, distid) == 0) {
					/* go! */
					new_arms_schedule(SCHED_TYPE_TIMER, -1,
							  timo, pull_timeout,
							  NULL);
					res->result = ARMS_EMAXRETRY;
					arms_scheduler();
					err = res->result;
				} else {
					err = ARMS_ESYSTEM;
				}
			}
			if ((derr = arms_line_disconnect(
				     res, ACMI_CONFIG_RSSOL,
				     line, timo)) != 0) {
				/* ECALLBACK, or ETIMEOUT */
				if (derr == ARMS_ECALLBACK) {
					/*fatal*/
					return ARMS_ECALLBACK;
				}
				if (err == 0)
					err = res->result;
				break;
			}
			/* arms_scheduler result check */
			if (err == 0 ||
			    err == ARMS_EDONTRETRY ||
			    err == ARMS_EPULL ||
			    err == ARMS_EREBOOT)
				break;
		}
		if (err == 0 ||
		    err == ARMS_EDONTRETRY ||
		    err == ARMS_EPULL ||
		    err == ARMS_ECALLBACK ||
		    err == ARMS_EREBOOT)
			break;
	}
	return err;
}

int
arms_rs_pull(arms_context_t *res, const char *distid, struct timeval *timo)
{
	int retry, rs_retry_max;
	int line, line_max;
	int sec, err;

	rs_retry_max = acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
	line_max = acmi_get_max_line(res->acmi, ACMI_CONFIG_CONFSOL);
	sec = acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
	err = 0;

	if (line_max == 0) {
		DPRINTF("line configuration not found.  see location-config");
		res->trigger = "RS not found";
		arms_sleep(60);
		err = ARMS_EPULL;
	}
	DPRINTF("calculated. rs max retry %d times.", rs_retry_max);
	DPRINTF("calculated. rs retry interval %d sec.", sec);
	for (retry = 0; retry <= rs_retry_max; retry++) {
		if (retry > 0) {
			struct timeval now;

			arms_monotime(&now);
			if (timercmp(&now, timo, >)) {
				/* global timeout. */
				res->result = ARMS_ETIMEOUT;
				DPRINTF("global timeout. ARMS_ETIMEOUT");
				break;
			}
			libarms_log(ARMS_LOG_IRS_ACCESS_RETRY,
			    "RS retry(%d/%d), wait %d sec.",
				    retry, rs_retry_max, sec);
			arms_sleep(sec);
		}
		for (line = 0; line < line_max; line++) {
			int realline;
			int derr;

			realline = (res->last_line + line) % line_max;
			err = arms_line_connect(
				res, ACMI_CONFIG_CONFSOL, realline, timo);
			if (err == ARMS_ECALLBACK) {
				/*fatal*/
				return ARMS_ECALLBACK;
			}
			if (err == 0) {
				/* setting pull schedule, and */
				if (new_rs_pull_transaction(res, distid) == 0) {
					/* go! */
					new_arms_schedule(SCHED_TYPE_TIMER, -1,
							  timo, pull_timeout,
							  NULL);
					res->result = ARMS_EMAXRETRY;
					arms_scheduler();
					err = res->result;
					if (err == 0) {
						res->last_line = realline;
					}
				} else {
					err = ARMS_ESYSTEM;
				}
			}
			if ((derr = arms_line_disconnect(
				     res, ACMI_CONFIG_CONFSOL,
				     realline, timo)) != 0) {
				/* ECALLBACK, or ETIMEOUT */
				if (derr == ARMS_ECALLBACK) {
					/*fatal*/
					return ARMS_ECALLBACK;
				}
				if (err == 0)
					err = res->result;
				break;
			}
			/* arms_scheduler result check */
			if (err == 0 ||
			    err == ARMS_EDONTRETRY ||
			    err == ARMS_EPULL ||
			    err == ARMS_EREBOOT)
				break;
		}
		if (err == 0 ||
		    err == ARMS_EDONTRETRY ||
		    err == ARMS_EPULL ||
		    err == ARMS_ECALLBACK ||
		    err == ARMS_EREBOOT)
			break;
	}
	return err;
}

int
arms_pull(arms_context_t *res,
	  time_t timeout, size_t fragment, arms_callback_tbl_t *cb_tbl,
	  arms_line_desc_t *lines, void *udata)
{
#ifdef HAVE_SIGNAL
	struct sigaction oldact, newact;
#endif
	struct timeval timo;
	char *distid;

	/* check parameter */
	if (timeout < ARMS_MIN_TIMEOUT && timeout != 0)
		return ARMS_EINVAL;

	if (timeout > ARMS_MAX_TIMEOUT)
		return ARMS_EINVAL;

	if (timeout != 0)
		res->timeout = timeout;
	else
		res->timeout = ARMS_DEFAULT_TIMEOUT;

	if (cb_tbl == NULL || lines == NULL) {
		return ARMS_EINVAL;
	}
	/* setup */
	acmi_set_lines(res->acmi, ACMI_CONFIG_RSSOL, lines);
	acmi_reset_line(res->acmi, ACMI_CONFIG_RSSOL);

	arms_free_hbtinfo(res);
	arms_free_rsinfo(res);
	arms_free_rs_tunnel_url(res);
	memset(res->hbt_info, 0, sizeof(res->hbt_info));
	memset(res->rs_push_address, 0, sizeof(res->rs_push_address));
	memset(res->rs_pull_url, 0, sizeof(res->rs_pull_url));
	res->fragment = fragment;
	res->line_af = AF_UNSPEC;
	memcpy(&res->callbacks, cb_tbl, sizeof(res->callbacks));
	res->udata = udata;
	if (res->trigger == NULL)
		res->trigger = "power on boot";
	res->retry_inf = 0;
	arms_scheduler_init();

#ifdef HAVE_SIGNAL
	/* block SIGPIPE */
	memset(&newact, 0, sizeof(newact));
	memset(&oldact, 0, sizeof(oldact));
	newact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &newact, &oldact);
#endif
	/* setting timer of total timeout */
	arms_get_time_remaining(&timo, res->timeout);
	new_arms_schedule(SCHED_TYPE_TIMER, -1, &timo, pull_timeout, NULL);

	/* HTTP/1.0 */
	res->http_preferred_version = 0;

	distid = strdistid(&res->dist_id);

	for (;;) {
		if (res->rs_endpoint[0] == '\0') {
			/* reset last RS line */
			res->last_line = 0;

			libarms_log(ARMS_LOG_ILS_ACCESS_START,
			    "Pull from LS.");
			arms_set_global_state(ARMS_ST_LSPULL);
			acmi_clear(res->acmi, ACMI_CONFIG_CONFSOL);
			res->result = arms_ls_pull(res, distid, &timo);
			if (res->result != 0) {
				/* fatal. */
				break;
			}
		} else {
			libarms_log(ARMS_LOG_IRS_ACCESS_START,
			    "Skip LS access.  Pull from RS.");
		}
#if 0
		acmi_dump(res->acmi);
#endif

		arms_set_global_state(ARMS_ST_RSPULL);
		res->result = arms_rs_pull(res, distid, &timo);
		if (res->result == 0 ||
		    res->result == ARMS_ETIMEOUT ||
		    res->result == ARMS_EDONTRETRY ||
		    res->result == ARMS_ECALLBACK ||
		    res->result == ARMS_EREBOOT) {
			/* RS pull suucess, fatal error, or total timeout */
			break;
		}
		/* other result (includes ARMS_EPULL): RS -> LS fallback. */
		res->rs_endpoint[0] = '\0';
	}

#ifdef HAVE_SIGNAL
	/* restore SIGPIPE */
	sigaction(SIGPIPE, &oldact, NULL);
#endif

	if (res->result == 0) {
		/* update heartbeat information */
		arms_hb_update_server(&res->hb_ctx,
				      res->hbt_info, res->num_of_hbt);

		arms_set_global_state(ARMS_ST_PULLDONE);
	} else {
		arms_set_global_state(ARMS_ST_BOOT_FAIL);
	}
	return res->result;
}
