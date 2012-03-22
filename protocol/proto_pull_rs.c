/*	$Id: proto_pull_rs.c 20894 2012-01-25 12:47:57Z m-oki $	*/

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
 * RS pull - config-solicitation.
 */

#include "config.h"

#include <inttypes.h>
#include <string.h>

#include <libarms_log.h>
#include <libarms_resource.h>
#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <module_db_mi.h>

#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <libarms/ssl.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

static void *rspull_context(tr_ctx_t *);
static void rspull_release(tr_ctx_t *);

static int rspull_request(transaction *, char *, int, int *);
static int rspull_parse(transaction *, const char *, int);

/*
 * Method defineition
 */
arms_method_t conf_sol_methods = {
	ARMS_TR_RSPULL,		/* pm_type */
	"config-solicitation",	/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	NULL,			/* pm_response */
	rspull_request,		/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	rspull_context,		/* pm_context */
	rspull_release,		/* pm_release */
	rspull_parse,		/* pm_parse */
};

static int rspull_judgement(tr_ctx_t *);

/* AXP Extention handler */
static int store_hbt_info(AXP *axp, int when, int type, int tag,
			  const char *buf, size_t len, void *u);

static int inc_hbt_info(AXP *axp, int when, int type, int tag,
			const char *buf, size_t len, void *u);

static int store_tag(AXP *axp, int when, int type, int tag,
		const char *buf, size_t len, void *u);

/*
 * Schema for response(conf_sol_res)
 */
char *mdconfig_attr[] = {
	"id", NULL,
	"content-type", NULL,
	"commit-order", NULL,
	"encoding", NULL,
	NULL,
};
char *module_attr[] = {
	"id", NULL,
	"version", NULL,
	"install-order", NULL,
	NULL,
};

struct axp_schema proposal_for_sa[] = {
  /* id, tag, type, attr, callback, child */
	{ARMS_TAG_PUSH_PORT,    "push-port",    AXP_TYPE_INT, NULL,NULL,NULL},
	{ARMS_TAG_PUSH_TIMEOUT, "push-timeout", AXP_TYPE_INT, NULL,NULL,NULL},
	{ARMS_TAG_NONE}
};

struct axp_schema heartbeat_body[] = {
	{ARMS_TAG_HOST,       "host", AXP_TYPE_TEXT,  NULL, store_hbt_info, NULL},
	{ARMS_TAG_PORT,       "port", AXP_TYPE_INT,  NULL, store_hbt_info, NULL},
	{ARMS_TAG_PASSPHRASE, "passphrase", AXP_TYPE_TEXT,  NULL, store_hbt_info, NULL},
	{ARMS_TAG_INTERVAL,   "interval", AXP_TYPE_INT,  NULL, store_hbt_info, NULL},
	{ARMS_TAG_ALGORITHM,  "algorithm", AXP_TYPE_TEXT,  NULL, store_hbt_info, NULL},
	{ARMS_TAG_NONE}
};

struct axp_schema conf_sol_res_data[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_SA_CERTIFICATE, "sa-certificate", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_SA_PRIVATE_KEY, "sa-private-key", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_PROPOSAL, "proposal-for-sa", AXP_TYPE_CHILD,
		NULL, NULL, proposal_for_sa},

	{ARMS_TAG_HBEAT_INFO, "heartbeat-info", AXP_TYPE_CHILD,
		NULL, inc_hbt_info, heartbeat_body},

	{ARMS_TAG_HEALTH_URL, "health-url", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_HEALTH_INT, "health-interval", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_POLL_URL, "poll-url", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_POLL_INT, "poll-interval", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_PUSH_ADDRESS, "rs-push-server-address", AXP_TYPE_TEXT,
		NULL, store_tag, NULL},

	{ARMS_TAG_PULL_SERVER_URL, "rs-pull-server-url", AXP_TYPE_TEXT,
		NULL, store_tag, NULL},

	{ARMS_TAG_MDCONF, "md-config", AXP_TYPE_TEXT,
		mdconfig_attr, store_tag, NULL},

	{ARMS_TAG_MODULE, "module", AXP_TYPE_TEXT,
		module_attr, store_tag, NULL},

	{ARMS_TAG_NONE}
};

struct axp_schema conf_sol_res_body[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RCODE, "result-code", AXP_TYPE_INT,
		NULL, NULL, NULL},

	{ARMS_TAG_RDESC, "description", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_EREASON, "error-reason", AXP_TYPE_TEXT,
		NULL, NULL, NULL},

	{ARMS_TAG_CONFSOL_RES, "config-solicitation-response", AXP_TYPE_CHILD,
		NULL, NULL, conf_sol_res_data},

	{ARMS_TAG_NONE}
};

char *conf_sol_res_attr[] = {
	"type", NULL,
	NULL,
};

struct axp_schema conf_sol_res_msg[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
		conf_sol_res_attr, NULL, conf_sol_res_body},

	{ARMS_TAG_NONE}
};

struct axp_schema conf_sol_res_schema[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, store_tag, conf_sol_res_msg},

	{ARMS_TAG_NONE}
};
struct axp_schema *conf_sol_res = conf_sol_res_schema;

static int purge_module(uint32_t id, const char *pkg_name, void *udata);

static module_cb_tbl_t configure_module_cb = {
	NULL,
	purge_module,
	NULL
};

static int
purge_module(uint32_t id, const char *pkg_name, void *udata)
{
	libarms_res_t *res;
	arms_config_cb_t config_cb;
	int err = 0;

	res = udata;
	config_cb = res->callbacks.config_cb;
	if (config_cb) {
		err = (*config_cb) (id, 0,
				    "",
				    ARMS_REMOVE_MODULE,
				    NULL, 0, 0,
				    res->udata);
	}
	return err;
}

typedef struct rspull_data {
	unsigned char first_fragment;
} rspull_data_t;

typedef struct rspull_context {
	AXP *parse;
	uint32_t last_modid;
	int report;
	int pa_index;
	int pu_index;
	int num_of_hbt;
	arms_hbt_info_t hbt_info[MAX_HBT_INFO];
	rspull_data_t data;
	arms_base64_stream_t base64;
} rspull_context_t;

/*
 * Module data handling
 */

#define min(a,b) ((a) < (b) ? (a) : (b))

/* AXP Extention handler */
static int
store_hbt_info(AXP *axp, int when, int type, int tag,
	       const char *buf, size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;
	rspull_context_t *ctx = tr_ctx->arg;
	arms_hbt_info_t *hbp;
	int idx;
	int err = 0;

	if (when != AXP_PARSE_END)
		return 0;

	idx = ctx->num_of_hbt - 1;
	hbp = &ctx->hbt_info[idx];
	switch (tag) {
	case ARMS_TAG_HOST:
		hbp->host = STRDUP(buf);
		break;
	case ARMS_TAG_PORT:
		hbp->port = (int)(long)buf;	/* XXX: should be passed as strings, and atoi() here? */
		break;
	case ARMS_TAG_PASSPHRASE:
		hbp->passphrase = STRDUP(buf);
		break;
	case ARMS_TAG_INTERVAL:
		hbp->interval = (int)(long)buf;	/* XXX: should be passed as strings, and atoi() here? */
		break;
	case ARMS_TAG_ALGORITHM:
		/* max 3 algorithms */
		if (hbp->numalg >= MAX_HBT_ALGORITHMS)
			break;
		hbp->algorithm[hbp->numalg++] = STRDUP(buf);
		break;
	default:
		err = -1;
		break;
	}

	return err;
}

/* AXP Extention handler */
static int
inc_hbt_info(AXP *axp, int when, int type, int tag,
	       const char *buf, size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;
	rspull_context_t *ctx = tr_ctx->arg;

	if (when != AXP_PARSE_START)
		return 0;

	if (++ctx->num_of_hbt > MAX_HBT_INFO) {
		/* heartbeat-info tag is found too many. */
		ctx->num_of_hbt = MAX_HBT_INFO;
		tr_ctx->res_result = 203;/*Parameter Problem*/
		tr_ctx->read_done = 1;

		return -1;
	}
	return 0;
}

/* AXP Extention handler */
static int
store_tag(AXP *axp, int when, int type, int tag,
		const char *buf, size_t len, void *u)
{
	/*
	 * note: max size of encoded text via expat is 64kirobyte.
	 * decoded binary size is 3/4 of encoded text.
	 * + 2: module bytes
	 */
	static char decbuf[AXP_BUFSIZE * 3 / 4 + 2 + 1];

	tr_ctx_t *tr_ctx = u;
	rspull_context_t *ctx = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	uint32_t mod_id = 0;
	const char *mod_ver = NULL;
	const char *mod_loc = NULL;
	static int module_added = 0;
	arms_config_cb_t func;
	int flag, err = 0;

	/* Emergency stop requested */
	if (tr_ctx->read_done) {
		return 0;
	}

	if ((func = res->callbacks.config_cb) == NULL) {
		return -1;
	}

	switch (tag) {
	case ARMS_TAG_MODULE:
		if (when != AXP_PARSE_END)
			return 0;
		/* chained to new module storage */
		mod_id = get_module_id(axp, ARMS_TAG_MODULE);
		mod_ver = get_module_ver(axp, ARMS_TAG_MODULE);
		err = add_module(mod_id, mod_ver, (const char *)buf);
		if (err < 0) {
			tr_ctx->res_result = 415;/*System Error*/
			tr_ctx->read_done = 1;
			err = 0; /* not parser err */
			break;
		}
		module_added = 1;
		break;
	case ARMS_TAG_MDCONF:
		if (module_added) {
			/* module db: new -> current */
			configure_module_cb.udata = res;
			init_module_cb(&configure_module_cb);
			err = sync_module();
			if (err < 0) {
				tr_ctx->res_result = 415;/*System Error*/
				tr_ctx->read_done = 1;
				break;
			}
			module_added = 0;
		}
		if (when == AXP_PARSE_START) {
			ctx->data.first_fragment = 1;
			return 0;
		}
		/* CONTENT or END */
		flag = 0;
		if (ctx->data.first_fragment == 1) {
			flag |= ARMS_FRAG_FIRST;
			ctx->data.first_fragment = 0;
		}
		/* chained to md-config storage */
		mod_id = get_module_id(axp, ARMS_TAG_MDCONF);
		if (!arms_module_is_exist(mod_id)) {
			/*
			 * <md-config> found, but <module> not found.
			 */
			tr_ctx->res_result = 415;/*System Error*/
			tr_ctx->read_done = 1;
			break;
		}
		mod_ver = lookup_module_ver(mod_id);
		mod_loc = lookup_module_location(mod_id);

		if (arms_get_encoding(axp, tag) == ARMS_DATA_BINARY) {
			int newlen;
			newlen = arms_base64_decode_stream(&ctx->base64,
			    decbuf, sizeof(decbuf) - 1, buf, len);
			if (newlen < 0) {
				libarms_log(ARMS_LOG_EBASE64_DECODE,
					    "base64 decode error "
					    "srclen %d, dstlen %d",
					    len, sizeof(decbuf) - 1);
				tr_ctx->res_result = 402;/*SA Failure*/
				tr_ctx->read_done = 1;
				break;
			}
			len = newlen;
			decbuf[len] = '\0';
			buf = decbuf;
		}
		/* callback it */
		do {
			int slen;
			/* call config callback */
			if (res->fragment != 0 && len > res->fragment) {
				slen = res->fragment;
			} else {
				slen = len;
				/* if last fragment */
				if (when == AXP_PARSE_END)
					flag |= ARMS_FRAG_FINISHED;
			}
			err = (*func)(mod_id,
				      mod_ver,		/* version */
				      mod_loc,		/* infostring */
				      ARMS_PULL_STORE_CONFIG,
				      buf, slen, flag, res->udata);
			if (err < 0) {
				res->trigger = "invalid config";
				tr_ctx->res_result = 415;/*System Error*/
				tr_ctx->read_done = 1;
				err = 0; /* not parser err */
				break;
			}
			buf += slen;
			len -= slen;
			flag &= ~ARMS_FRAG_FIRST;
			flag |= ARMS_FRAG_CONTINUE;
		} while(len > 0);

		break;
	case ARMS_TAG_PUSH_ADDRESS:
		if (when != AXP_PARSE_END)
			return 0;
		if (ctx->pa_index < MAX_RS_INFO) {
			res->rs_push_address[ctx->pa_index++] = STRDUP(buf);
		}
		break;
	case ARMS_TAG_PULL_SERVER_URL:
		if (when != AXP_PARSE_END)
			return 0;
		if (ctx->pu_index < MAX_RS_INFO) {
			res->rs_pull_url[ctx->pu_index++] = STRDUP(buf);
		}
		break;
	case ARMS_TAG_MSG:
		if (when != AXP_PARSE_END)
			return 0;

		if (module_added) {
			/* care no <md-config> case. */
			configure_module_cb.udata = res;
			init_module_cb(&configure_module_cb);
			err = sync_module();
			if (err < 0) {
				tr_ctx->res_result = 415;/*System Error*/
				tr_ctx->read_done = 1;
				break;
			}
			module_added = 0;
		}
		if (acmi_get_num_server(res->acmi, ACMI_CONFIG_CONFSOL) == ctx->pu_index) {
			res->rs_pull_1st = acmi_get_current_server(res->acmi,
								   ACMI_CONFIG_CONFSOL);
		} else {
			res->rs_pull_1st = -1;
		}
		tr_ctx->read_done = 1;
		break;
	default:
		break;
	}

	return err;
}


static void *
rspull_context(tr_ctx_t *tr_ctx)
{
	rspull_context_t *arg;

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->parse = axp_create(conf_sol_res, "US-ASCII", tr_ctx, 0);
	}
	return arg;
}

static void
rspull_release(tr_ctx_t *tr_ctx)
{
	rspull_context_t *ctx;
	int i, a;

	if (tr_ctx->arg) {
		ctx = tr_ctx->arg;
		if (ctx->parse != NULL) {
			axp_destroy(ctx->parse);
			ctx->parse = NULL;
		}
		/* free hbt_info temporary. */
		for (i = 0; i < ctx->num_of_hbt; i++) {
			arms_hbt_info_t *hbp = &ctx->hbt_info[i];

			FREE((void *)hbp->host);
			FREE((void *)hbp->passphrase);
			for (a = 0; a < hbp->numalg; a++) {
				FREE((void *)hbp->algorithm[a]);
			}
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
rspull_request(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();
	rspull_context_t *ctx = tr->tr_ctx.arg;
	int total, size;

	libarms_log(ARMS_LOG_IRS_ACCESS_START, NULL);

	/* reset arg if retried */
	ctx->pa_index = 0;

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	
	size = snprintf(buf, len,
			"<protocol-version>%d.%d</protocol-version>",
			ARMS_PROTOCOL_VERSION_MAJOR,
			ARMS_PROTOCOL_VERSION_MINOR);
	buf += size;
	len -= size;
	total += size;

	size = snprintf(buf, len, "<trigger>%s</trigger>", res->trigger);
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);

	tr->tr_ctx.read_done = 0;

	*wrote = total;
	return TR_WRITE_DONE;
}

/*
 * config-solicitation-response parser.
 */
static int
rspull_parse(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	rspull_context_t *ctx = tr_ctx->arg;
	int err;

	if (!tr_ctx->read_done) {
		tr_ctx->res_result = 100;
		err = axp_parse(ctx->parse, buf, len);
		if (err < 0) {
			libarms_log(ARMS_LOG_ERS_ACCESS_FAIL, NULL);
			return TR_PARSE_ERROR;
		}
	}
	if (tr_ctx->read_done) {
		if (tr_ctx->res_result != 100) {
			/* parse error should be retry. */
			libarms_log(ARMS_LOG_ERS_ACCESS_FAIL, NULL);
			tr_ctx->res_result = 100;
			return TR_PARSE_ERROR;
		}
		err = axp_endparse(ctx->parse);
		if (err != 0) {
			libarms_log(ARMS_LOG_ERS_ACCESS_FAIL, NULL);
			return TR_PARSE_ERROR;
		}
		axp_refer(ctx->parse,
			  ARMS_TAG_PUSH_PORT, &res->proposed_push_port);
		axp_refer(ctx->parse,
			  ARMS_TAG_PUSH_TIMEOUT, &res->proposed_push_timeout);
		/* read done. judgement! */
		return rspull_judgement(tr_ctx);
	}
	return TR_WANT_READ;
}

static int
rspull_judgement(tr_ctx_t *tr_ctx)
{
	rspull_context_t *ctx = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	char *desc;
	int rcode, err;

	/* Get result code */
	err = axp_refer(ctx->parse, ARMS_TAG_RCODE, &rcode);
	if (err < 0) {
		libarms_log(ARMS_LOG_ERS_ACCESS_FAIL, NULL);
		return TR_WANT_RETRY;
	}
	err = axp_refer(ctx->parse, ARMS_TAG_RDESC, &desc);
	if (err < 0) {
		/* description is optional */
	} else {
		if (desc) {
		}
	}

	/*
	 * Check Result code from RS.
	 */

	tr_ctx->res_result = rcode;
	if (rcode >= 100 && rcode < 200) {
		/* 100 - 199 */
		int i, a;
		const char *sa_cert = NULL;
		const char *sa_key = NULL;
		const char *ca_cert = NULL;

		axp_refer(ctx->parse, ARMS_TAG_SA_CERTIFICATE, &sa_cert);
		axp_refer(ctx->parse, ARMS_TAG_SA_PRIVATE_KEY, &sa_key);
		ca_cert = acmi_get_cert_idx(res->acmi, ACMI_CONFIG_CONFSOL, 0);
		if (sa_cert == NULL) {
			libarms_log(ARMS_LOG_ECERTIFICATE,
			    "SA certificate is not received from RS");
			memset(res->sa_cert, 0, ARMS_MAX_PEM_LEN);
		} else {
			strlcpy(res->sa_cert, sa_cert, ARMS_MAX_PEM_LEN);
		}
		if (sa_key == NULL) {
			libarms_log(ARMS_LOG_ECERTIFICATE,
			    "SA private key is not received from RS");
			memset(res->sa_key, 0, ARMS_MAX_PEM_LEN);
		} else {
			strlcpy(res->sa_key, sa_key, ARMS_MAX_PEM_LEN);
		}
		if (ca_cert == NULL) {
			/*
			 * connected to RS, then call this function.
			 * --> ca_cert != NULL.
			 * this check is PARANOIA.
			 */
			libarms_log(ARMS_LOG_ECERTIFICATE,
			    "RS CA certificate is not received from RS");
		}
		if (arms_ssl_register_cert(sa_cert, sa_key) != 0) {
			libarms_log(ARMS_LOG_ECERTIFICATE,
			    "Failed to register SA certificate and private key.");
			return TR_WANT_RETRY;
		}
		if (arms_ssl_register_cacert(ca_cert) != 0) {
			libarms_log(ARMS_LOG_ECERTIFICATE,
			    "Failed to register RS CA certificate.");
			return TR_WANT_RETRY;
		}

		/* copy hbt_info to res */
		res->num_of_hbt = ctx->num_of_hbt;
		for (i = 0; i < ctx->num_of_hbt; i++) {
			arms_hbt_info_t *dst = &res->hbt_info[i];
			arms_hbt_info_t *hbp = &ctx->hbt_info[i];

			/* at first, verity data. */
			if (hbp->host == NULL || hbp->passphrase == NULL) {
				/* invalid. */
				return TR_WANT_RETRY;
			}
			for (a = 0; a < hbp->numalg; a++) {
				if (hbp->algorithm[a] == NULL) {
					libarms_log(ARMS_LOG_EHB_NO_ALGORITHM,
					    "Heartbeat info: no algorithm.");
					/* invalid. */
					return TR_WANT_RETRY;
				}
			}
			/* and copy. */
			dst->host = STRDUP(hbp->host);
			dst->port = hbp->port;
			dst->passphrase = STRDUP(hbp->passphrase);
			dst->interval = hbp->interval;
			dst->numalg = hbp->numalg;
			for (a = 0; a < hbp->numalg; a++) {
				dst->algorithm[a] = STRDUP(hbp->algorithm[a]);
			}
		}

		libarms_log(ARMS_LOG_IRS_ACCESS_END, NULL);
		return TR_READ_DONE;
	}

	libarms_log(ARMS_LOG_ERS_ACCESS_FAIL, NULL);
	return TR_WANT_RETRY;
}
