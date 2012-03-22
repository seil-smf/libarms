/*	$Id: proto_push_ping.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

/*
 * Callback Functions
 */
/* context alloc */
static void *
ping_context(tr_ctx_t *);

/* copy argument */
static int ping_cparg(AXP *, uint32_t, int, const char *, size_t, tr_ctx_t *);
/* done */
static int ping_exec(transaction *);
static int ping_done(transaction *, char *, int, int *);
/* context free */
static void ping_release(tr_ctx_t *);

/*
 * XML Schema: ping-start-request
 */
static struct axp_schema ping_start_req[] = {
	{ARMS_TAG_ADDR, "address", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_CNT, "count", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_SIZ, "size", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema ping_start_req_msg[] = {
	{ARMS_TAG_PING_SREQ, "ping-start-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, ping_start_req},
	{0, NULL, 0, NULL, NULL, NULL}
};

/*
 * Method definition
 */
arms_method_t ping_methods = {
	ARMS_TR_PING,		/* pm_type */
	"ping",			/* type string */
	ping_start_req_msg,	/* schema for request parameters */
	0,			/* pm_flags */
	build_generic_res,	/* pm_response */
	ping_done,		/* pm_done */
	ping_exec,		/* pm_exec */
	ping_cparg,		/* pm_copyarg */
	NULL,			/* pm_rollback */
	ping_context,		/* pm_context */
	ping_release,		/* pm_release */
};

/*
 * Method implementations
 */
/*
 * argument define
 */
struct ping_args {
	char *dst;
	int cnt;
	int siz;
	struct arms_ping_report rep;
};

static int
ping_exec(transaction *tr)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct arms_ping_arg parg;
	struct ping_args *arg = tr_ctx->arg;
	int err;

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;/*Not Support*/
		return 0;
	}

	parg.dst = arg->dst;
	parg.count = arg->cnt;
	parg.size = arg->siz;

	err = res->callbacks.command_cb(
		0,
		ARMS_PUSH_PING,
		(void *)&parg, sizeof(parg),
		(void *)&arg->rep, sizeof(arg->rep),
		NULL,
		res->udata);
	if (err != 0) {
		tr_ctx->result = 502;/*Push Failed*/
		return 0;
	}
	return 0;
}

static int
ping_done(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct ping_args *arg = tr_ctx->arg;
	int size, total;

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;/*Not Support*/
		*wrote = arms_write_empty_message(tr, buf, len);
		return TR_WRITE_DONE;
	}

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	if (tr_ctx->result == 100) {
		size = snprintf(buf, len,
				"<success>%d</success>"
				"<failure>%d</failure>",
				arg->rep.success, arg->rep.failure);
		buf += size;
		len -= size;
		total += size;
	}
	total += arms_write_end_message(tr, buf, len);
	*wrote = total;
	return TR_WRITE_DONE;
}

/*
 * CParg
 */
static int
ping_cparg(AXP *axp, uint32_t pm_type, int tag,
	   const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct ping_args *arg = tr_ctx->arg;

	switch (tag) {
	case ARMS_TAG_ADDR:
		if (buf) {
			arg->dst = STRDUP(buf);
		}
		break;
	case ARMS_TAG_CNT:
		if (buf) {
			sscanf(buf, "%d", &arg->cnt);
		}
		break;
	case ARMS_TAG_SIZ:
		if (buf) {
			sscanf(buf, "%d", &arg->siz);
		}
		break;
	case ARMS_TAG_END_CPARG:
		/* required parameter check */
		if (arg->dst == NULL) {
			tr_ctx->result = 203;/*Invalid parameter*/
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Context Alloc
 */
static void *
ping_context(tr_ctx_t *tr_ctx)
{
	struct ping_args *arg;
	arms_context_t *res = arms_get_context();

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;
		return 0;
	}

	arg = (struct ping_args *)CALLOC(1, sizeof(*arg));
	if (arg == NULL) {
		tr_ctx->result = 413;/*Resource Exhausted*/
	}

	return arg;
};

/*
 * release resources
 */
static void
ping_release(tr_ctx_t *tr_ctx)
{
	struct ping_args *arg = tr_ctx->arg;

	if (arg) {
		if (arg->dst != NULL)
			FREE(arg->dst);
		FREE(tr_ctx->arg);
	}
};
