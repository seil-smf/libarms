/*	$Id: proto_push_method_query.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <string.h>

#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <libarms_log.h>

#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * push method query - new ARMS protocol method w/ SMF-NAT
 */
static int
store_method_query(AXP *, int, int, int, const char *, size_t, void *);

static void *method_query_context(tr_ctx_t *);
static void method_query_release(tr_ctx_t *);
static int method_query_request(transaction *, char *, int, int *);
static int method_query_parse(transaction *, const char *, int);
static int method_query_judgement(transaction *, AXP *);

arms_method_t method_query_methods = {
	ARMS_TR_METHOD_QUERY,	/* pm_type */
	"push-method-query",	/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	NULL,			/* pm_response */
	method_query_request,	/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	method_query_context,	/* pm_context */
	method_query_release,	/* pm_release */
	method_query_parse,	/* pm_parse */
};

static struct axp_schema method_query_method[] = {
	{ARMS_TAG_PUSH_METHOD, "push-method",
	 AXP_TYPE_TEXT, NULL, store_method_query, NULL},
	{ARMS_TAG_TUNNEL_URL, "https-tunnel-url",
	 AXP_TYPE_TEXT, NULL, store_method_query, NULL},
	{ARMS_TAG_ECHO_INTERVAL, "https-tunnel-echo-interval",
	 AXP_TYPE_INT, NULL, store_method_query, NULL},

	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema method_query_res[] = {
	{ARMS_TAG_RCODE, "result-code",
		AXP_TYPE_INT, NULL, NULL, NULL},
	{ARMS_TAG_RDESC, "description",
		AXP_TYPE_TEXT, NULL, NULL, NULL},
	{ARMS_TAG_METHOD_QUERY_RES, "push-method-query-response",
	 AXP_TYPE_CHILD, NULL, NULL, method_query_method},

	{0, NULL, 0, NULL, NULL, NULL}
};

static char *method_query_res_attr[] = {
	"type", NULL,
	NULL, NULL
};

static struct axp_schema method_query_res_body[] = {
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
		method_query_res_attr, NULL,
		method_query_res},

	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema method_query_res_msg[] = {
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, store_method_query, method_query_res_body},

	{0, NULL, 0, NULL, NULL, NULL}
};

struct method_query_arg {
	AXP *axp;
	/* method priority list */
	int nmethods;
	int method_info[MAX_METHOD_INFO];
	int nurls;
};

/*
 * store into context data
 */
static int
store_method_query(AXP *axp, int when, int type, int tag, const char *buf,
		size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;
	struct method_query_arg *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();

	if (when != AXP_PARSE_END)
		return 0;

	switch (tag) {
	case ARMS_TAG_PUSH_METHOD:
		if (arg->nmethods >= MAX_METHOD_INFO) {
			/* error: max 5 methods */
			tr_ctx->res_result = 203;/*Parameter Problem*/
			tr_ctx->read_done = 1;
			return -1;
		}
		if (!strcmp(buf, "https-simple")) {
			arg->method_info[arg->nmethods++] = ARMS_PUSH_METHOD_SIMPLE;
		} else if (!strcmp(buf, "https-tunnel")) {
			arg->method_info[arg->nmethods++] = ARMS_PUSH_METHOD_TUNNEL;
		} else {
			/* unknown method type, ignore. */
			libarms_log(ARMS_LOG_DEBUG,
				    "unknown method %s, ignored", buf);
		}
		break;
	case ARMS_TAG_TUNNEL_URL:
		if (arg->nurls >= MAX_RS_INFO) {
			/* error: max 5 RSs */
			tr_ctx->res_result = 203;/*Parameter Problem*/
			tr_ctx->read_done = 1;
			return -1;
		}
		res->rs_tunnel_url[arg->nurls++] = STRDUP(buf);
		break;
	case ARMS_TAG_ECHO_INTERVAL:
#ifdef HAVE_STDINT_H
		res->tunnel_echo_interval = (intptr_t)buf;
#else
		res->tunnel_echo_interval = (int)buf;
#endif
		break;
	case ARMS_TAG_MSG:
		tr_ctx->read_done = 1;
		break;
	default:
		break;
	}
	return 0;
}

static void *
method_query_context(tr_ctx_t *tr_ctx)
{
	struct method_query_arg *ctx;
	
	ctx = CALLOC(1, sizeof(struct method_query_arg));
	if (ctx == NULL) {
		/* not enough memory. */
	} else {
		/* create response parser */
		ctx->axp = axp_create(method_query_res_msg,
				      "US-ASCII", tr_ctx, 0);
		if (ctx->axp == NULL) {
			/* error */
			FREE(ctx);
			return NULL;
		}
		MSETPOS(ctx->axp);
	}
	return ctx;
}

static void
method_query_release(tr_ctx_t *tr_ctx)
{
	if (tr_ctx->arg) {
		struct method_query_arg *arg = tr_ctx->arg;

		if (arg->axp != NULL) {
			axp_destroy(arg->axp);
			arg->axp = NULL;
		}
		FREE(tr_ctx->arg);
	}
}

/*
 * Method implementations
 */

/*
 * send capability.
 */
static int
method_query_request(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();
	int total, size;

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;

	if (!res->proxy_is_available) {
		size = snprintf(buf, len,
		    "<push-method>https-simple</push-method>");
		buf += size;
		len -= size;
		total += size;
	}
	size = snprintf(buf, len, "<push-method>https-tunnel</push-method>");
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);

	*wrote = total;
	return TR_WRITE_DONE;
}

/*
 */
static int
method_query_parse(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct method_query_arg *ctx;
	int err;

	if (buf == NULL) {
		tr_ctx->read_done = 1;
		return TR_READ_DONE;
	}		

	ctx = tr_ctx->arg;
	/* check result code */
	if (!tr_ctx->read_done) {
		err = axp_parse(ctx->axp, buf, len);
		if (err < 0) {
			return TR_PARSE_ERROR;
		}
	}
	if (tr_ctx->read_done) {
		err = axp_endparse(ctx->axp);
		if (err != 0) {
			tr_ctx->res_result = 200;
			return TR_PARSE_ERROR;
		}
		/* read done. judgement! */
		return method_query_judgement(tr, ctx->axp);
	}
	return TR_WANT_READ;
}

/*
 * check result code and set method information into res.
 */
static int
method_query_judgement(transaction *tr, AXP *axp)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct method_query_arg *arg;
	int err, rcode;

	arg = tr_ctx->arg;
	/* check result */
	err = axp_refer(axp, ARMS_TAG_RCODE, &rcode);
	if (err != 0) {
		tr_ctx->result = 402;/*SA failure*/
		return TR_WANT_RETRY;
	}
	tr_ctx->res_result = rcode;

	if (rcode >= 300 && rcode < 500) {
		return TR_WANT_RETRY;
	}
	if (rcode >= 500) {
		res->result = ARMS_EREBOOT;
		switch (rcode) {
		case 501:
			res->result = ARMS_EDONTRETRY;
			break;
		case 502:
			res->result = ARMS_EPULL;
			break;
		case 503:
			res->result = ARMS_EREBOOT;
			break;
		case 507:
			/*
			 * invalid type: older RS response.
			 * compatible method: simple and push-ready.
			 */
			res->result = 0;
			break;
		case 508:
			/* State Mismatch. */
			res->result = ARMS_EPULL;
			break;
		}
		return TR_WANT_STOP;
	}
	if (rcode >= 200) {
		res->result = ARMS_EPULL;
		return TR_WANT_STOP;
	}
	res->nmethods = arg->nmethods;
	memcpy(res->method_info, arg->method_info, sizeof(res->method_info));

	return TR_READ_DONE;
}
