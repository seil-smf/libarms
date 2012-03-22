/*	$Id: arms_event_loop.c 20955 2012-01-31 04:03:18Z m-oki $	*/

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

#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/socket.h> /* for AF_INET */
#include <netdb.h>

#include <libarms.h>
#include <libarms_log.h>
#include <lsconfig.h>
#include <libarms_param.h>
#include <libarms_resource.h>

#include <libarms/time.h>
#include <libarms/ssl.h>
#include <libarms/malloc.h>
#include <scheduler/scheduler.h>
#include <armsd_conf.h> /* for ACMI */
#include <transaction/transaction.h>
#include <transaction/ssltunnel.h>
#include <protocol/arms_methods.h>
#include <server/server.h>
#include <http/http.h>

#include "compat.h"

static struct arms_schedule *app_event_obj = NULL;
static struct arms_schedule *heartbeat_obj = NULL;

const struct timeval *
arms_get_app_event_interval(arms_context_t *res)
{
	if (res == NULL) {
		return NULL;
	}
	return &res->app_timeout;
}

void
arms_hb_stop(arms_context_t *res)
{
	if (res == NULL)
		return;
	res->hb_running = 0;
}

void
arms_hb_start(arms_context_t *res)
{
	if (res == NULL)
		return;
	res->hb_running = 1;
}

int
arms_hb_is_running(arms_context_t *res)
{
	return (res != NULL && res->hb_running && heartbeat_obj != NULL);
}

int
arms_set_app_event_interval(arms_context_t *res, const struct timeval *timo)
{
	/* check value */
	if (res == NULL) {
		return -1;
	}
	if (timo == NULL) {
		return -1;
	}
	if (timo->tv_sec < 0 || timo->tv_sec > 600) {
		return -1;
	}
	if (timo->tv_usec < 0 || timo->tv_usec >= 1000 * 1000) {
		return -1;
	}
	/* at least 0.1 sec. */
	if (timo->tv_sec == 0 && timo->tv_usec < 100 * 1000) {
		return -1;
	}
	if (timo->tv_sec == 600 && timo->tv_usec > 0) {
		return -1;
	}

	/* store new timeout value. */
	res->app_timeout = *timo;
	if (app_event_obj != NULL) {
		arms_get_timeval_remaining(&app_event_obj->timeout, timo);
	}

	return 0;
}

static int
arms_app_event(struct arms_schedule *obj, int event)
{
	arms_context_t *res = arms_get_context();
	int rv;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* call only if not running configure */
		rv = res->callbacks.app_event_cb(res->udata);
		if (rv == ARMS_EPULL) {
			res->result = ARMS_EPULL;
			return SCHED_FINISHED_SCHEDULER;
		}
		if (!arms_is_running_configure(res)) {
			if (rv != 0) {
				res->result = ARMS_EPUSH;
				return SCHED_FINISHED_SCHEDULER;
			}
		}
		break;
	case EVENT_TYPE_FINISH:
		/* nothing to free resource yet */
		app_event_obj = NULL;
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	arms_get_timeval_remaining(&obj->timeout, &res->app_timeout);
	return SCHED_CONTINUE_THIS;
}

static int
arms_heartbeat_event(struct arms_schedule *obj, int event)
{
	arms_context_t *res = arms_get_context();
	struct timeval now, base, delta, interval, remain;
	hb_send_result_t result;
	int i, rv;

	arms_monotime(&base);

	switch (event) {
	case EVENT_TYPE_EXEC:
	case EVENT_TYPE_TIMEOUT:
		if (!arms_is_running_configure(res)) {
			/* call only if not running configure */
			arms_hb_clear(&res->hb_ctx);
			rv = res->callbacks.hb_store_statistics_cb(
			    res, res->udata);
			if (rv != 0) {
				res->result = ARMS_EPUSH;
				return SCHED_FINISHED_SCHEDULER;
			}
			if (!res->hb_running)
				break;
			/* send heartbeat packet */
			arms_hb_send(&res->hb_ctx, res->sa_af, &result);
			for (i = 0; i < res->hb_ctx.numsvr; i++) {
				if (result.server[i].stage == 0) {
					/* log */
					libarms_log(ARMS_LOG_DEBUG,
					    "Sent heartbeat to %s",
					    res->hb_ctx.server[i].host);
				}
			}
		}
		break;
	case EVENT_TYPE_FINISH:
		/* nothing to free resource yet */
		heartbeat_obj = NULL;
		if (res->hb_running)
			libarms_log(ARMS_LOG_IHEARTBEAT_STOP,
			    "Stop heartbeat.");
		arms_hb_stop(res);
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	arms_monotime(&now);
	if (timercmp(&now, &base, >)) {
		timersub(&now, &base, &delta);
	} else {
		/* backtime clock_gettime? */
		delta.tv_sec = 0;
		delta.tv_usec = 0;
	}
	/* server timeout from hbt_info */
	interval.tv_sec = res->hbt_info[0].interval;
	interval.tv_usec = 0;
	timersub(&interval, &delta, &remain);
	arms_get_timeval_remaining(&obj->timeout, &remain);
	return SCHED_CONTINUE_THIS;
}

static void
arms_https_simple_loop(arms_context_t *res, int port)
{
	int i, rs, nrs, solrs;

	if (res->rs_pull_url[0] == NULL) {
		libarms_log(ARMS_LOG_EHOST,
			    "RS not found.");
		res->trigger = "RS not found";
		res->result = ARMS_ETIMEOUT;
		return;
	}

	/* calc number of RS. */
	for (nrs = 0; nrs < MAX_RS_INFO; nrs++) {
		if (res->rs_pull_url[nrs] == NULL) {
			/* no more RS. */
			break;
		}
	}
	/*
	 * register schedule.
	 * use rs index by conf-sol if possible.
	 *
	 * in current scheduler register routine,
	 * use "insert to head" algorithm.
	 */
	solrs = acmi_get_current_server(res->acmi, ACMI_CONFIG_CONFSOL);
	if (nrs == acmi_get_num_server(res->acmi, ACMI_CONFIG_CONFSOL))
		res->rs_pull_1st = solrs;
	if (res->rs_pull_1st == -1)
		res->rs_pull_1st = 0;
	for (i = nrs - 1; i >= 0; i--) {
		/* calc rs index. */
		rs = (i + res->rs_pull_1st) % nrs;
		if (new_confirm_start_transaction(res,
		    strdistid(&res->dist_id),
		    res->rs_pull_url[rs], rs) != 0) {
			return;
		}
	}
	/* register server if https-simple */
	if (res->sa_af == AF_INET6)
		snprintf(res->push_endpoint, sizeof(res->push_endpoint),
		         "https://[%s]:%d/", res->sa_address, port);
	else
		snprintf(res->push_endpoint, sizeof(res->push_endpoint),
		         "https://%s:%d/", res->sa_address, port);
	res->result = new_arms_server(res->sa_af, port,
				      strdistid(&res->dist_id),
				      res->rs_preshared_key);
	if (res->result != 0)
		return;
	res->confirm_id = -1;
	res->rs_pull_1st = -1;

	/* start push-confirmation */
	arms_scheduler();
	/*
	 * res->result
	 * 0: success
	 * ARMS_ESYSTEM: fatal error
	 * ARMS_ETIMEOUT: confirmation timeout
	 * ARMS_EPULL:
	 * ARMS_EREBOOT:
	 * ARMS_EDONTRETRY: don't retry.
	 */
	if (res->result == ARMS_ETIMEOUT)
		libarms_log(ARMS_LOG_IPROTO_CONFIRM_FAILED,
			    "Failed push confirmation by simple.");
}

void
arms_hb_start_loop(arms_context_t *res)
{
	if (heartbeat_obj != NULL) {
		/* already running.  simply ignore. */
		return;
	}

	/* register heartbeat timer if available */
	if (res->callbacks.version >= 7 &&
	    res->callbacks.hb_store_statistics_cb != NULL) {
		struct timeval timo;
		struct addrinfo hints, *re;
		int i;

		/* log */
		libarms_log(ARMS_LOG_IHEARTBEAT_START,
			    "Start heartbeat (interval: %d sec)",
			    res->hbt_info[0].interval);
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = res->sa_af;
		for (i = 0; i < res->num_of_hbt; i++) {
			if (getaddrinfo(res->hbt_info[i].host,
					NULL, &hints, &re) == 0) {
				libarms_log(ARMS_LOG_IHEARTBEAT_SERVER,
				    " heartbeat server: %s",
				    res->hbt_info[i].host);
				if (re != NULL)
					freeaddrinfo(re);
			}
		}
		/* call event function immediately */
		arms_get_time_remaining(&timo, 0);
		heartbeat_obj = new_arms_schedule(SCHED_TYPE_EXEC, -1,
		    &timo, arms_heartbeat_event, NULL);
		arms_hb_start(res);
	}
}

int
arms_event_loop(arms_context_t *res, int port, size_t fragment,
		arms_callback_tbl_t *cb_tbl, void *udata)
{
#ifdef HAVE_SIGNAL
	struct sigaction oldact, newact;
#endif
	struct timeval timo;
	int m, n;

	/* check parameter */
	if (res == NULL)
		return ARMS_EINVAL;
	if (cb_tbl == NULL)
		return ARMS_EINVAL;
	if (port < 0  || port > 65535)
		return ARMS_EINVAL;

	/* setup */
	if (port == 0)
		port = 10443;
	res->fragment = fragment;
	res->udata = udata;
	res->server_port = port;
	arms_scheduler_init();

	/* reset tunnel skip status. */
	res->rs_tunnel_1st = -1;

#ifdef HAVE_SIGNAL
	/* block SIGPIPE */
	memset(&newact, 0, sizeof(newact));
	memset(&oldact, 0, sizeof(oldact));
	newact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &newact, &oldact);
#endif
	if (res->callbacks.version < 5) {
		/* temporary backward compatibility: method query. */
		res->http_preferred_version = 0;
		res->result = 0;
		arms_push_method_query(res, cb_tbl, udata);
	}
	if (res->nmethods == 0) {
		libarms_log(ARMS_LOG_EHTTP,
			    "no push method.");
		libarms_log(ARMS_LOG_EHTTP,
			    "(forgot to call arms_push_method_query()?)");
		res->trigger = "no push method";
		return ARMS_EPULL;
	}

	do {
		res->result = 0;

		/* HTTP/1.1 */
		res->http_preferred_version = 1;

		/* try accepted method */
		for (m = 0; m < res->nmethods; m++) {
			/* register app_event timer if available */
			if (res->callbacks.app_event_cb != NULL) {
				arms_get_timeval_remaining(&timo,
							&res->app_timeout);
				app_event_obj = new_arms_schedule(
					SCHED_TYPE_TIMER, -1,
					&timo, arms_app_event, NULL);
			}
			res->cur_method = res->method_info[m];
			switch (res->cur_method) {
			case ARMS_PUSH_METHOD_SIMPLE:
				if (res->proxy_is_available) {
					libarms_log(ARMS_LOG_DEBUG,
					    "Web proxy server available, skip simple method");
					break;
				}
				libarms_log(ARMS_LOG_IPUSH_METHOD_SIMPLE,
					    "Push method: simple");
				arms_https_simple_loop(res, port);
				break;
			case ARMS_PUSH_METHOD_TUNNEL:
				libarms_log(ARMS_LOG_IPUSH_METHOD_TUNNEL,
					    "Push method: tunnel");
				for (n = 0; n < MAX_RS_INFO; n++) {
					if (res->rs_tunnel_url[n] == NULL)
						break;
					libarms_log(ARMS_LOG_DEBUG,
					    "tunnel#%d: %s",
					    n, res->rs_tunnel_url[n]);
				}
				if (n == 0) {
					libarms_log(ARMS_LOG_EHTTP,
						    "tunnel destination URL is not found.");
					res->trigger = "tunnel URL not found";
					res->result = ARMS_ETIMEOUT;
					continue;/* try next method */
				}
				arms_ssltunnel_loop(res, n, res->rs_tunnel_url);
				break;
			default:
				break;
			}
			if (res->result != ARMS_ETIMEOUT) {
				break;
			}
			/* timeout: try next method */
		}
		/*
		 * failed to push-wait loop by simple and tunnel method.
		 */
		if (res->result == ARMS_ETIMEOUT)
			res->result = ARMS_EPULL;
		/*
		 * stop scheduler by app_event_cb, pull-config,
		 * reboot or rollback failed in configure.
		 */
		if (res->result == 0)
			res->result = ARMS_EPULL;
	} while (res->result == ARMS_EPUSH);

#ifdef HAVE_SIGNAL
	sigaction(SIGPIPE, &oldact, NULL);
#endif
	libarms_log(ARMS_LOG_DEBUG,
		    "end of arms_event_loop (result=%d)", res->result);
	res->cur_method = ARMS_PUSH_METHOD_UNKNOWN;

	return res->result;
}
