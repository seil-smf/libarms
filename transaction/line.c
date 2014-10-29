/*	$Id: line.c 25283 2014-06-02 08:56:04Z yamazaki $	*/

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
#include <unistd.h>
#include <time.h>
#include <sys/queue.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <libarms_log.h>
#include <armsd_conf.h> /* for ACMI */

#include <libarms/time.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>

#define DEBUG

#ifdef DEBUG
#define DPRINTF(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

static int line_ctrl(arms_context_t *, int, int, void *, time_t);

static const char *
arms_line_type_str(int type)
{
	static char buf[32];

	switch (type) {
	case ARMS_LINE_PPPOE:
		return "PPPoE";

	case ARMS_LINE_PPPOE_IPV6:
		return "PPPoE-IPv6";

	case ARMS_LINE_DHCP:
		return "DHCP";

	case ARMS_LINE_MOBILE:
		return "MOBILE";

	case ARMS_LINE_STATIC:
		return "STATIC";

	case ARMS_LINE_RA:
		return "RA";

	default:
		snprintf(buf, sizeof(buf), "%d", type);
		return buf;
	}
}

int
arms_line_connect(arms_context_t *res, int conf, int idx, struct timeval *timo)
{
	int line_type;
	union line_conf_u *line_conf;
	time_t lltimeout;
	struct timeval now;
	int err;

	acmi_set_current_line(res->acmi, conf, idx);

	lltimeout = acmi_get_lltimeout(res->acmi, conf);
	err = acmi_get_lconf(res->acmi, conf, (void *)&line_conf);
	line_type = acmi_get_ltype(res->acmi, conf);

	arms_monotime(&now);
#if 0
 	printf("line: connect: now:%ld, timo:%ld\n",
	       now.tv_sec, timo->tv_sec);
#endif
	if (timercmp(&now, timo, >)) {
		/* global timeout. */
		res->result = ARMS_ETIMEOUT;
		return ARMS_ETIMEOUT;
	}
	switch (line_type) {
	case ARMS_LINE_PPPOE:
#if 0
		DPRINTF("line: connecting(%d): PPPoE %s, %s", idx,
		       line_conf->pppoe.id, line_conf->pppoe.pass);
#else
		DPRINTF("line: connecting(%d): PPPoE", idx);
#endif
		res->line_af = AF_INET;
		break;
	case ARMS_LINE_PPPOE_IPV6:
#if 0
		DPRINTF("line: connecting(%d): PPPoE %s, %s", idx,
		       line_conf->pppoe.id, line_conf->pppoe.pass);
#else
		DPRINTF("line: connecting(%d): PPPoE(IPv6)", idx);
#endif
		res->line_af = AF_INET6;
		break;
	case ARMS_LINE_DHCP:
		DPRINTF("line: connecting(%d): DHCP", idx);
		res->line_af = AF_INET;
		break;
	case ARMS_LINE_MOBILE:
		DPRINTF("line: connecting(%d): MOBILE", idx);
		res->line_af = AF_INET;
		break;
	case ARMS_LINE_STATIC:
		DPRINTF("line: connecting(%d): STATIC", idx);
		res->line_af = AF_UNSPEC;
		break;
	case ARMS_LINE_RA:
		DPRINTF("line: connecting(%d): RA", idx);
		res->line_af = AF_INET6;
		break;
	default:
		DPRINTF("line: connecting(%d): unknown type %d",
			idx, line_type);
		res->line_af = AF_UNSPEC;
		break;
	}

	err = line_ctrl(res, ARMS_LINE_ACT_CONNECT,
			line_type, line_conf, lltimeout);

	switch (err) {
	case ARMS_LINE_CONNECTED:
		/* success */
		libarms_log(ARMS_LOG_ILINE_CONNECTED,
		    "Line %s(%d) Connected.",
		    arms_line_type_str(line_type), idx);
		break;
	case ARMS_LINE_AUTHFAIL:
		libarms_log(ARMS_LOG_ELINE_AUTH_FAIL, NULL);
		return ARMS_EMAXRETRY;
	case ARMS_LINE_NEEDPOLL:
		DPRINTF("line: NEEDPOLL.");
		return ARMS_EMAXRETRY;
	case ARMS_LINE_TIMEOUT:
		libarms_log(ARMS_LOG_ELINE_TIMEOUT, NULL);
		return ARMS_EMAXRETRY;
	case ARMS_LINE_NOTAVAILABLE:
		libarms_log(ARMS_LOG_ELINE_NOTAVAIL,
		    "Line %s(%d) not available.",
		    arms_line_type_str(line_type), idx);
		return ARMS_EMAXRETRY;
	default:
		DPRINTF("line: error from callback. ARMS_ECALLBACK");
		res->result = ARMS_ECALLBACK;
		arms_set_global_state(ARMS_ST_BOOT_FAIL);
		return ARMS_ECALLBACK;
	}
	
	return 0;
}

/*
 * 0: success (disconencted)
 * ARMS_ECALLBACK: error
 * ARMS_ETIMEOUT: timeout. (total)
 */
int
arms_line_disconnect(arms_context_t *res, int conf, int idx,
		     struct timeval *timo)
{
	int line_type;
	void *line_conf;
	time_t lltimeout;
	int err;

	for (;;) {
		struct timeval now;

		arms_monotime(&now);
#if 0
		printf("line: disconnect: now:%ld, timo:%ld\n",
		       now.tv_sec, timo->tv_sec);
#endif
		if (timercmp(&now, timo, >)) {
			/* global timeout. */
			res->result = ARMS_ETIMEOUT;
			return ARMS_ETIMEOUT;
		}
		acmi_set_current_line(res->acmi, conf, idx);

		line_type = acmi_get_ltype(res->acmi, conf);
		err = acmi_get_lconf(res->acmi, conf, &line_conf);
		lltimeout = acmi_get_lltimeout(res->acmi, conf);

		switch (line_type) {
		case ARMS_LINE_PPPOE:
			DPRINTF("line: disconnecting(%d): PPPoE", idx);
			break;
		case ARMS_LINE_PPPOE_IPV6:
			DPRINTF("line: disconnecting(%d): PPPoE(IPv6)", idx);
			break;
		case ARMS_LINE_DHCP:
			DPRINTF("line: disconnecting(%d): DHCP", idx);
			break;
		case ARMS_LINE_MOBILE:
			DPRINTF("line: disconnecting(%d): MOBILE", idx);
			break;
		case ARMS_LINE_STATIC:
			DPRINTF("line: disconnecting(%d): STATIC", idx);
			break;
		case ARMS_LINE_RA:
			DPRINTF("line: disconnecting(%d): RA", idx);
			break;
		default:
			DPRINTF("line: disconnecting(%d): unknown type %d",
				idx, line_type);
			break;
		}
		err = line_ctrl(res, ARMS_LINE_ACT_DISCONNECT,
				line_type, line_conf, lltimeout);

		switch (err) {
		case ARMS_LINE_DISCONNECTED:
			/* success */
			libarms_log(ARMS_LOG_ILINE_DISCONNECTED,
			    "Line %s(%d) Disconnected.",
			    arms_line_type_str(line_type), idx);
			return 0;
		case ARMS_LINE_NEEDPOLL:
			DPRINTF("line: NEEDPOLL.");
			/* for loop */
			break;
		case ARMS_LINE_TIMEOUT:
			DPRINTF("line: timeout.");
			/* for loop */
			break;
		case ARMS_LINE_AUTHFAIL:
			DPRINTF("line: authentication failed.");
			/* for loop */
			break;
		default:
			DPRINTF("line: error from callback. ARMS_ECALLBACK");
			res->result = ARMS_ECALLBACK;
			arms_set_global_state(ARMS_ST_BOOT_FAIL);
			return ARMS_ECALLBACK;
		}
	}
	return 0;
}

/*
 * Internal API:
 *   wrapper for callback functions.
 * valid return value of this function:
 *	CONNECTED, DISCONNECTED, AUTHFAIL, TIMEOUT
 *
 * valid return value of callback:
 *  ACT_CONNECT    --> CONNECTED, DISCONNECTED, NEEDPOLL, AUTHFAIL, TIMEOUT
 *  ACT_DISCONNECT --> CONNECTED, DISCONNECTED, NEEDPOLL, TIMEOUT
 *  ACT_STATUS     --> CONNECTED, DISCONNECTED, NEEDPOLL, AUTHFAIL, TIMEOUT
 */
#define POLL_INT 1
static int
line_ctrl(arms_context_t *res,
	  int line_action, int line_type, void *line_conf, time_t tout)
{
	int err = 0;
	int i;
	struct timeval timo, now;

	if (res->callbacks.line_ctrl_cb == NULL) {
		return err;
	}

	/* 1st try */
	err = res->callbacks.line_ctrl_cb(line_action, line_type,
					line_conf, res->udata);
	switch (err) {
	case ARMS_LINE_CONNECTED:
		switch (line_action) {
		case ARMS_LINE_ACT_CONNECT:
			/*FALLTHROUGH*/
		case ARMS_LINE_ACT_STATUS:
			goto success;

		case ARMS_LINE_ACT_DISCONNECT:
		default:
			/* still connected, polling */
			break;
		}
		break;
	case ARMS_LINE_DISCONNECTED:
		switch (line_action) {
		case ARMS_LINE_ACT_DISCONNECT:
			/*FALLTHROUGH*/
		case ARMS_LINE_ACT_STATUS:
			goto success;

		case ARMS_LINE_ACT_CONNECT:
		default:
			/* still disconnected, polling */
			break;
		}
		break;

	case ARMS_LINE_AUTHFAIL:
	case ARMS_LINE_TIMEOUT:
	case ARMS_LINE_NOTAVAILABLE:
		return err;

	case ARMS_LINE_NEEDPOLL:
		/* need polling */
		DPRINTF("line: start polling.");
		break;
	default:
		(void)libarms_log(ARMS_LOG_ECALLBACK, NULL);
		res->result = ARMS_ECALLBACK;
		return -1;
	}

	arms_get_time_remaining(&timo, tout);

	/* Polling */
	for (i = 0; i < tout; i++) {
		arms_monotime(&now);
		if (timercmp(&now , &timo, >))
			break;

		arms_sleep(POLL_INT);
		err = res->callbacks.line_ctrl_cb(ARMS_LINE_ACT_STATUS,
				line_type, line_conf, res->udata);
		switch (err) {
		case ARMS_LINE_CONNECTED:
			if (line_action == ARMS_LINE_ACT_CONNECT) {
				goto success;
			}
			if (line_action == ARMS_LINE_ACT_STATUS) {
				/* got status successful */
				goto success;
			}
			break;
		case ARMS_LINE_DISCONNECTED:
			if (line_action == ARMS_LINE_ACT_DISCONNECT) {
				goto success;
			}
			if (line_action == ARMS_LINE_ACT_STATUS) {
				/* got status successful */
				goto success;
			}
			break;
		case ARMS_LINE_AUTHFAIL:
			libarms_log(ARMS_LOG_ELINE_AUTH_FAIL, NULL);
			return err;
		case ARMS_LINE_TIMEOUT:
			libarms_log(ARMS_LOG_ELINE_TIMEOUT, NULL);
			return err;
		case ARMS_LINE_NEEDPOLL:
			break;
		default:
			(void)libarms_log(ARMS_LOG_ECALLBACK, NULL);
			res->result = ARMS_ECALLBACK;
			return -1;
		}
	}
	/* polling timeout */
	return ARMS_LINE_TIMEOUT;

 success:
	return err;
}
