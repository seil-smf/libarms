/*	$Id: proto_push_traceroute.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <libarms_log.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

/*
 * Callback Functions
 */
/* context alloc */
static void *
traceroute_context(tr_ctx_t *);

/* copy argument */
static int
traceroute_cparg(AXP *, uint32_t, int, const char *, size_t, tr_ctx_t *);
static int traceroute_exec(transaction *);
static int
traceroute_done(transaction *, char *, int, int *);

/* context free */
static void
traceroute_release(tr_ctx_t *);

/*
 * XML Schema: traceroute-start-request
 */
static struct axp_schema traceroute_start_req[] = {
	{ARMS_TAG_ADDR, "address", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_CNT, "count", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_MAX_HOP, "max-hop", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema traceroute_start_req_msg[] = {
	{ARMS_TAG_TRACEROUTE_SREQ, "traceroute-start-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, traceroute_start_req},
	{0, NULL, 0, NULL, NULL, NULL}
};

/*
 * Method definition
 */
arms_method_t traceroute_methods = {
	ARMS_TR_TRACEROUTE,		/* pm_type */
	"traceroute",			/* type string */
	traceroute_start_req_msg,	/* schema for request parameters */
	0,				/* pm_flags */
	build_generic_res,		/* pm_response */
	traceroute_done,		/* pm_done */
	traceroute_exec,		/* pm_exec */
	traceroute_cparg,		/* pm_copyarg */
	NULL,				/* pm_rollback */
	traceroute_context,		/* pm_context */
	traceroute_release,		/* pm_release */
};

#define BEGIN  1
#define RESULT 2

/*
 * Method implementations
 */
/*
 * argument define
 */
struct traceroute_args {
	char *dst;
	int cnt;
	int hop;
	int state;
	int idx;
	struct arms_traceroute_info ti[MAX_HOP];
};

/*
 * traceroute-done-request
 */
static int
traceroute_exec(transaction *tr)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct arms_traceroute_arg ta;
	struct arms_traceroute_info *ti;
	struct traceroute_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int err;

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;/*Not Support*/
		return 0;
	}

	ta.addr = arg->dst;
	ta.count = arg->cnt;
	ta.maxhop = arg->hop;
	ti = arg->ti;

	err = res->callbacks.command_cb(
		0,
		ARMS_PUSH_TRACEROUTE,
		(void *)&ta, sizeof(ta),
		(void *)ti, MAX_HOP * sizeof(struct arms_traceroute_info),
		NULL,
		res->udata);
	if (err != 0) {
		tr_ctx->result = 502;/*Push Failed*/
		return 0;
	}
	return 0;
}

/*
 * traceroute-done-request
 */
static int
traceroute_done(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct arms_traceroute_info *ti;
	struct traceroute_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int i;

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;/*Not Support*/
		*wrote = arms_write_empty_message(tr, buf, len);
		return TR_WRITE_DONE;
	}

	switch (arg->state) {
	case BEGIN:
		libarms_log(ARMS_LOG_DEBUG, "Generate response to RS");
		*wrote = arms_write_begin_message(tr, buf, len);
		arg->state = RESULT;
		arg->idx = 0;
		return TR_WANT_WRITE;
	case RESULT:
		if (tr_ctx->result == 100) {
			ti = arg->ti;
			i = arg->idx;
			if (i < arg->hop && ti[i].addr[0] != '\0') {
				*wrote = snprintf(buf, len,
					  "<nodeinfo hop=\"%d\">%s</nodeinfo>",
					  ti[i].hop, arms_escape(ti[i].addr));
				arg->idx++;
				return TR_WANT_WRITE;
			}
		}
		*wrote = arms_write_end_message(tr, buf, len);
		return TR_WRITE_DONE;
	default:
		break;
	}
	return TR_WRITE_DONE;
}

/*
 * CParg
 */
static int
traceroute_cparg(AXP *axp, uint32_t pm_type, int tag,
		 const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct traceroute_args *arg = tr_ctx->arg;

	switch (tag) {
	case ARMS_TAG_ADDR:
		arg->dst = STRDUP(buf);
		if (arg->dst == NULL)
			return -1;
		break;
	case ARMS_TAG_CNT:
		if (buf) {
			sscanf(buf, "%d", &arg->cnt);
		}
		break;
	case ARMS_TAG_MAX_HOP:
		if (buf) {
			sscanf(buf, "%d", &arg->hop);
			if (arg->hop > MAX_HOP) {
				libarms_log(ARMS_LOG_DEBUG,
				    "requested hop limit %d is larger then %d",
				    arg->hop, MAX_HOP);
				tr_ctx->result = 203;
			}
		}
		break;
	case ARMS_TAG_END_CPARG:
		/* required parameter check */
		if (arg->dst == NULL ||
		    arg->cnt == 0) {
			tr_ctx->result = 203;/*Invalid parameter*/
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Context
 */
static void *
traceroute_context(tr_ctx_t *tr_ctx)
{
	struct traceroute_args *arg;
	arms_context_t *res = arms_get_context();

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;
		return 0;
	}

	arg = CALLOC(1, sizeof(*arg));
	if (arg == NULL)
		tr_ctx->result = 413;/*Resource Exhausted*/
	else
		arg->state = BEGIN;

	return arg;
};

/*
 * Context
 */
static void
traceroute_release(tr_ctx_t *tr_ctx)
{
	struct traceroute_args *arg;

	arg = tr_ctx->arg;
	if (arg) {
		if (arg->dst)
			FREE(arg->dst);
		FREE(arg);
	}
};
