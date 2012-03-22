/*	$Id: proto_push_confirmation.c 20894 2012-01-25 12:47:57Z m-oki $	*/

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
 * push-confirmation message.
 *
 * 2way message, but special.
 * - confirm-start is sent from SA.
 * - confirm-done is sent from RS.
 *
 * workaround:
 *  confirm-start as pull message.  mostly like as push-ready.
 *  confirm-done as 1way push message.
 */

static int store_tag(AXP *axp, int when, int type, int tag,
		const char *buf, size_t len, void *u);


static void *confirm_start_context(tr_ctx_t *);
static void confirm_start_release(tr_ctx_t *);
static int confirm_start_request(transaction *, char *, int, int *);
static int confirm_start_parse(transaction *, const char *, int);
static int confirm_done_cparg(AXP *, uint32_t, int, const char *,
			      size_t, tr_ctx_t *);
static void confirm_done_release(tr_ctx_t *);

arms_method_t confirm_start_methods = {
	ARMS_TR_CONFIRM_START,	/* pm_type */
	"push-confirmation-start",/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	NULL,			/* pm_response */
	confirm_start_request,	/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	confirm_start_context,	/* pm_context */
	confirm_start_release,	/* pm_release */
	confirm_start_parse,	/* pm_parse */
};

arms_method_t confirm_done_methods = {
	ARMS_TR_CONFIRM_DONE,	/* pm_type */
	"push-confirmation-done",/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	build_generic_res,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	confirm_done_cparg,	/* pm_copyarg */
	NULL,			/* rollback */
	NULL,			/* pm_context */
	confirm_done_release	/* pm_release */
};

typedef struct confirm_context {
	AXP *parse;
} confirm_context_t;

static char *confirm_res_attr[] = {
	"type", NULL,
	NULL
};

static struct axp_schema confirm_res_body[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RCODE, "result-code", AXP_TYPE_INT,  NULL, NULL, NULL},
	{ARMS_TAG_RDESC, "description", AXP_TYPE_TEXT, NULL, NULL, NULL},
	{ARMS_TAG_TRANSACTION_ID, "transaction-id", AXP_TYPE_INT, NULL, NULL, NULL},

	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema arms_confirm_res[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
	 confirm_res_attr, NULL, confirm_res_body},

	{0, NULL, 0, NULL, NULL, NULL}
};

/* exported.  used by parse_configure_done.  */
struct axp_schema arms_confirm_res_msg[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, store_tag, arms_confirm_res},

	{0, NULL, 0, NULL, NULL, NULL}
};

/* tag parser <arms-message> for push-confirmation-start response. */
static int
store_tag(AXP *axp, int when, int type, int tag,
		const char *buf, size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;

	/* Emergency stop requested */
	if (tr_ctx->read_done) {
		return 0;
	}

	if (when == AXP_PARSE_END)
		tr_ctx->read_done = 1;
	return 0;
}

static void *
confirm_start_context(tr_ctx_t *tr_ctx)
{
	confirm_context_t *arg;

	libarms_log(ARMS_LOG_DEBUG, "Start confirmation");
	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->parse = axp_create(arms_confirm_res_msg,
					"US-ASCII", tr_ctx, 0);
	}
	return arg;
}

static void
confirm_start_release(tr_ctx_t *tr_ctx)
{
	confirm_context_t *ctx;

	if (tr_ctx->arg) {
		ctx = tr_ctx->arg;
		if (ctx->parse != NULL) {
			axp_destroy(ctx->parse);
			ctx->parse = NULL;
		}
		FREE(tr_ctx->arg);
		tr_ctx->arg = NULL;
	}
	libarms_log(ARMS_LOG_DEBUG,
	    "Sent confirmation request.  wait for response.");
}

static int
confirm_start_request(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();
	int size, total;

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;

	if (res->cur_method == ARMS_PUSH_METHOD_SIMPLE) {
		size = snprintf(buf, len,
				"<push-method>https-simple</push-method>"
				"<push-endpoint>%s</push-endpoint>",
				res->push_endpoint);
	} else if (res->cur_method == ARMS_PUSH_METHOD_TUNNEL) {
		size = snprintf(buf, len,
				"<push-method>https-tunnel</push-method>");
	}
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);

	tr->tr_ctx.read_done = 0;

	*wrote = total;
	return TR_WRITE_DONE;
}

static int
confirm_start_parse(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	confirm_context_t *ctx = tr_ctx->arg;
	int err;

	if (!tr_ctx->read_done) {
		tr_ctx->res_result = 100;
		err = axp_parse(ctx->parse, buf, len);
		if (err < 0) {
			return TR_PARSE_ERROR;
		}
	}
	if (tr_ctx->read_done) {
		int rcode;

		err = axp_endparse(ctx->parse);
		if (err != 0) {
			tr_ctx->res_result = 200;
			return TR_PARSE_ERROR;
		}
		/* refer transaction id */
		err = axp_refer(ctx->parse, ARMS_TAG_TRANSACTION_ID,
				&tr_ctx->id);
		if (err != 0) {
			return TR_PARSE_ERROR;
		}
		err = axp_refer(ctx->parse, ARMS_TAG_RCODE, &rcode);
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
		return TR_READ_DONE;
	}
	return TR_WANT_READ;
}

static int
confirm_done_cparg(AXP *axp, uint32_t pm_type, int tag,
		 const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	arms_context_t *res = arms_get_context();
	char *p;
	int id;

	switch (tag) {
	case ARMS_TAG_START_CPARG:
		break;
	case ARMS_TAG_END_CPARG:
		break;
	case ARMS_TAG_TRANSACTION_ID:
		/* compare transaction id */
		id = strtoul(buf, &p, 10);
		if (*p != '\0')
			return -1;
		if (res->cur_method == ARMS_PUSH_METHOD_SIMPLE) {
			/* do nothing. */
		} else if (res->cur_method == ARMS_PUSH_METHOD_TUNNEL) {
			/* tunnel: parallel confirmation.  lookup from tr. */
			tr_ctx->id = id;
		}
		break;
	default:
		break;
	}
	return 0;
}

static void
confirm_done_release(tr_ctx_t *tr_ctx)
{
	arms_context_t *res = arms_get_context();

	/* disable watchdog */
	res->confirm_id = 0;
	/* set global state */
	arms_set_global_state(ARMS_ST_PUSH_WAIT);
	/* start heartbeat */
	arms_hb_start_loop(res);
}
