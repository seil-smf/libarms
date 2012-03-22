/*	$Id: proto_pull_ls.c 20894 2012-01-25 12:47:57Z m-oki $	*/

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

#include <libarms_log.h>
#include <libarms_resource.h>
#include <axp_extern.h>
#include <arms_xml_tag.h>

#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

/*
 * LS pull - rs-solicitation.
 */

static void *lspull_context(tr_ctx_t *);
static void lspull_release(tr_ctx_t *);
static int lspull_request(transaction *, char *, int, int *);
static int lspull_parse(transaction *, const char *, int);
static int lspull_judgement(tr_ctx_t *);
/*
 * Method defineition
 */
arms_method_t rs_sol_methods = {
	ARMS_TR_LSPULL,		/* pm_type */
	"rs-solicitation",	/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	NULL,			/* pm_response */
	lspull_request,		/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	lspull_context,		/* pm_context */
	lspull_release,		/* pm_release */
	lspull_parse,		/* pm_parse */
};

static int
store_tag(AXP *axp, int when, int type, int tag,
	  const char *buf, size_t len, void *u);

/*
 * Schema for response(rs_sol_res)
 */
static struct axp_schema rs_sol_res_rsinfo[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_URL, "url", AXP_TYPE_TEXT,
		NULL, store_tag, NULL},
	{ARMS_TAG_MDCONF, "md-config", AXP_TYPE_TEXT,
		NULL, store_tag, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema rs_sol_res_data[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RS_KEY, "rs-preshared-key", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_LLTIMEOUT, "ll-timeout", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_RS_RETRY_MAX, "rs-retry-max", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_RS_RETRY_INT, "rs-retry-interval", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_LIFETIME, "lifetime", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_RS_INFO, "rs-info", AXP_TYPE_CHILD,
		NULL, NULL, rs_sol_res_rsinfo},

	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema rs_sol_res_body[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RCODE, "result-code", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_RDESC, "result-description", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_RDESC, "description", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_EREASON, "error-reason", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_RSSOL_RES, "rs-solicitation-response", AXP_TYPE_CHILD,
		NULL, NULL, rs_sol_res_data},
	{0, NULL, 0, NULL, NULL, NULL}
};

static char *rs_sol_res_attr[] = {
	"type", NULL,
	NULL,
};

static struct axp_schema rs_sol_res_msg[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
		rs_sol_res_attr, NULL, rs_sol_res_body},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema rs_sol_res_schema[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, store_tag, rs_sol_res_msg},
	{0, NULL, 0, NULL, NULL, NULL}

};

struct axp_schema *rs_sol_res = rs_sol_res_schema;

typedef struct lspull_data {
	int num_url;
	url_t url[MAX_RS_LIST];
	int num_mdconfig;
	char mdconfig[MAX_RS_LIST][MAX_LS_MDCONFIG];
} lspull_data_t;

typedef struct lspull_context {
	AXP *parse;
	int report;

	lspull_data_t data;
} lspull_context_t;

void *
lspull_context(tr_ctx_t *tr_ctx)
{
	lspull_context_t *arg;

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->parse = axp_create(rs_sol_res, "US-ASCII", tr_ctx, 0);
	}
	return arg;
}

static void
lspull_release(tr_ctx_t *tr_ctx)
{
	lspull_context_t *arg;

	if (tr_ctx->arg) {
		arg = tr_ctx->arg;
		if (arg->parse != NULL) {
			axp_destroy(arg->parse);
			arg->parse = NULL;
		}
		FREE(tr_ctx->arg);
		tr_ctx->arg = NULL;
	}
}

/*
 * Method implementations
 */

/*
 * request builder.
 * call if
 *  - line is connected,
 *  - socket is connected.
 *  - SSL is connected.
 *  - HTTP header is sent.
 */
static int
lspull_request(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();
	int size, total;

	libarms_log(ARMS_LOG_ILS_ACCESS_START, NULL);

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	
	size = snprintf(buf, len, "<trigger>%s</trigger>", res->trigger);
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);

	*wrote = total;
	return TR_WRITE_DONE;
}

/*
 * Parser
 */
static int
store_tag(AXP *axp, int when, int type, int tag,
		const char *buf, size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;
	lspull_context_t *ctx = tr_ctx->arg;
	char *mdconfig;
	url_t *url;

	if (when != AXP_PARSE_END)
		return 0;

	switch (tag) {
	case ARMS_TAG_MDCONF:
		if (ctx->data.num_mdconfig < MAX_RS_LIST) {
			mdconfig =
				ctx->data.mdconfig[ctx->data.num_mdconfig];
			memcpy(mdconfig, buf, len);
			mdconfig[len] = '\0';
			ctx->data.num_mdconfig++;
		} else {
			/* too many RS information. */
			tr_ctx->res_result = 203;
			tr_ctx->read_done = 1;
		}
		break;
	case ARMS_TAG_URL:
		if (ctx->data.num_url < MAX_RS_LIST) {
			char *urlp;

			url = &(ctx->data.url[ctx->data.num_url]);
			urlp = url->string;
			/* trancate url */
			if (sizeof(url->string) < len)
				len = sizeof(url->string) - 1;
			/* skip newline and space */
			while (*buf == '\n' ||
			       *buf == '\r' ||
			       *buf == ' ')
				buf++;
			/* copy but ignore newline */
			while (*buf != '\0' && len > 0) {
				if (*buf != '\n' && *buf != '\r')
					*urlp = *buf;
				urlp++; buf++; len--;
			}
			*urlp = '\0';
			ctx->data.num_url++;
		} else {
			/* too many RS information. */
			tr_ctx->res_result = 203;
			tr_ctx->read_done = 1;
		}
		break;
	case ARMS_TAG_MSG:
		/* end of message. */
		tr_ctx->read_done = 1;
		break;
	default:
		break;
	}

	return 0;
}

/*
 * rs-solicitation-response parser.
 */
static int
lspull_parse(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	lspull_context_t *ctx = tr_ctx->arg;
	int err;

	if (buf == NULL) {
		tr_ctx->read_done = 1;
		return TR_READ_DONE;
	}		

	if (!tr_ctx->read_done) {
		err = axp_parse(ctx->parse, buf, len);
		if (err < 0) {
			libarms_log(ARMS_LOG_ELS_ACCESS_FAIL, NULL);
			return TR_PARSE_ERROR;
		}
	}
	if (tr_ctx->read_done) {
		err = axp_endparse(ctx->parse);
		if (err != 0) {
			tr_ctx->res_result = 200;
			libarms_log(ARMS_LOG_ELS_ACCESS_FAIL, NULL);
			return TR_PARSE_ERROR;
		}
		/* read done. judgement! */
		return lspull_judgement(tr_ctx);
	}
	return TR_WANT_READ;
}

static int
lspull_judgement(tr_ctx_t *tr_ctx)
{
	lspull_context_t *ctx = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int err, rcode;

	/* Get result code */
	err = axp_refer(ctx->parse, ARMS_TAG_RCODE, &rcode);
	if (err < 0) {
		libarms_log(ARMS_LOG_ELS_ACCESS_FAIL, NULL);
		tr_ctx->res_result = 200;
		return TR_WANT_RETRY;
	}
	/*
	 * Check Result code from LS.
	 */
	tr_ctx->res_result = rcode;

	if (rcode >= 100 && rcode < 200) {
		/* 100 - 199 */
		int x, i;
		char *rs_key;

		/* Retry Max */
		x = 0;
		axp_refer(ctx->parse, ARMS_TAG_RS_RETRY_MAX, &x);
		acmi_set_rmax(res->acmi, ACMI_CONFIG_CONFSOL, x);

		/* Retry Interval */
		x = 0;
		axp_refer(ctx->parse, ARMS_TAG_RS_RETRY_INT, &x);
		acmi_set_rint(res->acmi, ACMI_CONFIG_CONFSOL, x);

		/* RS preshared key */
		rs_key = NULL;
		axp_refer(ctx->parse, ARMS_TAG_RS_KEY, &rs_key);
		if (rs_key != NULL) {
			strlcpy(res->rs_preshared_key,
				rs_key,
				sizeof(res->rs_preshared_key));
		}

		/* LL Timeout */
		x = 0;
		axp_refer(ctx->parse, ARMS_TAG_LLTIMEOUT, &x);
		acmi_set_lltimeout(res->acmi, ACMI_CONFIG_CONFSOL, x);

		/* Server URL */
		for (i = 0; i < ctx->data.num_url; i++) {
			acmi_set_url(res->acmi, ACMI_CONFIG_CONFSOL,
				ctx->data.url[i].string, URL_MAX_LEN, i);
		}

		/* Config */
		for (i = 0; i < ctx->data.num_mdconfig; i++) {
			char *data;
			int len;

			data = ctx->data.mdconfig[i];
			len = strlen(data); /* XXX */
			err = acmi_set_textconf(res->acmi,
					ACMI_CONFIG_CONFSOL,
					i, data, len);
			if (err < 0) {
				libarms_log(ARMS_LOG_ELS_ACCESS_FAIL, NULL);
				tr_ctx->res_result = 200;
				return TR_WANT_RETRY;
			}
		}

#ifdef ARMS_DEBUG
		acmi_dump(res->acmi);
#endif
		libarms_log(ARMS_LOG_ILS_ACCESS_END, NULL);
		return TR_READ_DONE;
	}

	libarms_log(ARMS_LOG_ELS_ACCESS_FAIL, NULL);
	return TR_WANT_RETRY;
}
