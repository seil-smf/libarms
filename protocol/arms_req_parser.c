/*	$Id: arms_req_parser.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <time.h>

#include <libarms_resource.h>
#include <libarms_log.h>
#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>
#include <http/http.h>

#include "compat.h" /* for strlcpy */

/*
 * Generic Praser for start request messages
 */
static struct axp_schema arms_push_req_param[PUSH_MAX_MSG + 1] = {
	{ARMS_TAG_DISTID, "distribution-id", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_DESC, "description", AXP_TYPE_TEXT,
		NULL, NULL, NULL},
	{ARMS_TAG_RESULT_URL, "result-url", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{ARMS_TAG_TRANSACTION_ID, "transaction-id", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	/* extended by push_add_schema() */

	{0, NULL, 0, NULL, NULL, NULL}
};
static char *push_req_attr[] = {
	"type", NULL,
	NULL
};
static struct axp_schema arms_push_req_body[] = {
	{ARMS_TAG_REQ, "arms-request", AXP_TYPE_CHILD,
		push_req_attr, push_default_hook, arms_push_req_param},
	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema arms_push_req_msg[] = {
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, push_default_hook, arms_push_req_body},
	{0, NULL, 0, NULL, NULL, NULL}

};

/*
 * TYPE Defs
 */
push_tr_type_t push_type_tbl[PUSH_MAX_MSG + 1] = {
	{ARMS_TR_GENERIC_ERROR, "generic-error"},
	/* extended by push_add_schema */

	{ARMS_TR_NONE, NULL}
};

int
push_add_schema(int type, const char *type_str, struct axp_schema *schema)
{
	int i;
	struct axp_schema *space = NULL;

	if (type == 0 || type_str == NULL)
		return -1;

	/* setup type id <-> string table */
	for (i = 0; i < PUSH_MAX_MSG; i++) {
		if (push_type_tbl[i].type != 0)
			continue;

		push_type_tbl[i].type = type;
		push_type_tbl[i].str = type_str;
		break;
	}

	if (schema == NULL)
		return 0;

	/* setup schema */
	for (i = 0; i < PUSH_MAX_MSG; i++) {
		if (arms_push_req_param[i].as_tagtype != 0)
			continue;
		space = &arms_push_req_param[i];
		break;
	}
	if (!space)
		return -1;

	memcpy(space, schema, sizeof(*space));
	memset(space + 1, 0, sizeof(*space));

	return 0;
}

/*
 * PUSH Transactions
 */
int
pushstr2type(const char *str)
{
	push_tr_type_t *tr_type;
	int baselen;
	const char *extra;
	int found = 0;

	for (tr_type = push_type_tbl; tr_type->type; tr_type++){
		baselen = strlen(tr_type->str);
		if (strncmp(str, tr_type->str, baselen) != 0)
			continue;
		extra = str + baselen;
		/* sync */
		if (strcmp(extra, "") == 0) {
			found = 1;
			break;
		}
		/* async start */
		if (strcmp(extra, "-start") == 0) {
			found = 1;
			break;
		}
		/* async done */
		if (strcmp(extra, "-done") == 0) {
			found = 1;
			break;
		}
	}

	if (!found)
		return 0;

	return tr_type->type;
}

const char *
pushtype2str(int type)
{
	push_tr_type_t *tr_type;
	int found = 0;

	for (tr_type = push_type_tbl; tr_type->type; tr_type++){
		if (tr_type->type != type)
			continue;
		found = 1;
		break;
	}
	if (!found)
		return NULL;
	return tr_type->str;
}

/*
 * called from AXP.
 */
int
push_default_hook(AXP *axp, int when, int type, int tag, const char *buf,
		size_t len, void *u)
{
	tr_ctx_t *tr_ctx = u;
	const char *attr;
	arms_method_t *method;

#if 0 /* DEBUG */
	if (tr_ctx)
		dump_tr_ctx(tr_ctx);
#endif

#if 0
	if (tr_ctx->read_done) {
		/* no parse. */
		return 0;
	}
#endif
	tr_ctx->parse_state = when;

	if (when == AXP_PARSE_START) {
		switch (tag) {
		case ARMS_TAG_REQ:
			attr = axp_find_attr(axp, tag, "type");
			if (attr == NULL) {
				libarms_log(ARMS_LOG_DEBUG,
				    "RS bug: <arms-request> has no type.");
				break;
			}
			/*
			 * attr: <arms-request type="?????">"
			 *  ??????: md-command, read-storage-start, etc.
			 */
			/*
			 * pm_type: ARMS_TR_XXXXXX
			 */
			tr_ctx->pm_type = pushstr2type(attr);
			if (tr_ctx->pm_type == 0) {
				libarms_log(ARMS_LOG_DEBUG,
				    "RS bug: <arms-request> has invalid type %s.\n", attr);
				break;
			}
			method = type2method(tr_ctx->pm_type);
			if (method == NULL) {
				tr_ctx->result = 202; /*Invalid Message Type*/
				tr_ctx->read_done = 1;
				return 0;
			}
			tr_ctx->pm = method;
			tr_ctx->id = 0;
			if (method->pm_done) {
				/* asnyc method */
				if (tr_ctx->result == 406) {
					tr_ctx->read_done = 1;
					return 0;
					}
				tr_ctx->id = (int)random();
			}
			tr_ctx->result = 100;
			if (tr_ctx->id != 0) {
				libarms_log(ARMS_LOG_DEBUG,
					    "[%d] Start %s",
					    tr_ctx->id, method->pm_string);
			} else {
				libarms_log(ARMS_LOG_DEBUG,
					    "[-] Start %s",
					    method->pm_string);
			}
			if (method->pm_context) {
				tr_ctx->arg = (*method->pm_context)(tr_ctx);
			}
			/* don't add transaction if error detected */
			if (tr_ctx->result != 100)
				break;

			if (method->pm_copyarg && tr_ctx->axp) {
				(*method->pm_copyarg)(tr_ctx->axp,
						      tr_ctx->pm_type,
						      ARMS_TAG_START_CPARG,
						      buf, len, tr_ctx);
			}
			tr_ctx->read_done = 0;
			break;
		default:
			break;
		}
	}
	if (when == AXP_PARSE_CONTENT) {
		method = tr_ctx->pm;
		if (method == NULL) {
			return 0;
		}
		if (tr_ctx->pm_type) {
			if (method->pm_copyarg && tr_ctx->axp) {
				(*method->pm_copyarg) (tr_ctx->axp, 
				   tr_ctx->pm_type, tag, buf, len, tr_ctx);
			}
		}
	}
	if (when == AXP_PARSE_END) {
		arms_context_t *res = arms_get_context();
		int err;

		if (tr_ctx->result != 100) {
			tr_ctx->read_done = 1;
			return 0;
		}
		method = tr_ctx->pm;
		if (method == NULL) {
			return 0;
		}

		switch (tag) {
		case ARMS_TAG_MSG:
			/* terminate argument copy */
			if (method->pm_copyarg && tr_ctx->axp) {
				(*method->pm_copyarg) (tr_ctx->axp, 
				   tr_ctx->pm_type, ARMS_TAG_END_CPARG,
				   buf, len, tr_ctx);
			}
			tr_ctx->read_done = 1;
			break;
		case ARMS_TAG_DISTID:
			/* compare */
			if (strcmp(strdistid(&res->dist_id), buf) != 0) {
				/*
				 * distribution id is not mine.
				 * set error and stop parser.
				 */
				tr_ctx->result = 423;
				tr_ctx->read_done = 1;
				return 0;
			}
			break;
		case ARMS_TAG_RESULT_URL:
			err = arms_parse_url(buf, NULL, 0, NULL, 0, NULL,0);
			if (err == URL_ERROR) {
				tr_ctx->result = 203;
				tr_ctx->read_done = 1;
				return 0;
			}
			strlcpy(res->rs_endpoint, buf,
				sizeof(res->rs_endpoint));
			break;
		default:
			break;
		}
		if (tr_ctx->pm_type) {
			if (method->pm_copyarg && tr_ctx->axp) {
				(*method->pm_copyarg) (tr_ctx->axp, 
				   tr_ctx->pm_type, tag, buf, len, tr_ctx);
			}
		}
	}

	return 0;
}

int
arms_req_parser(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	int err;

	if (tr_ctx->axp == NULL) {
		/* first call, create axp */
		tr_ctx->axp = axp_create(arms_push_req_msg,
					 "US-ASCII", tr_ctx, 0);
		if (tr_ctx->axp == NULL) {
			return TR_FATAL_ERROR;
		}
	}
	if (buf == NULL) {
		/*
		 * client request is finished, but parser wants text.
		 * errrrrror.
		 */
		axp_destroy(tr_ctx->axp);
		tr_ctx->axp = NULL;
		tr_ctx->pm_type = ARMS_TR_GENERIC_ERROR;
		if (tr_ctx->pm == NULL)
			tr_ctx->pm = &generic_error_methods;
		tr_ctx->result = 201;	/* Invalid XML */
		SET_TR_BUILDER(tr, http_response_builder);
		return TR_PARSE_ERROR;
	}
	err = axp_parse(tr_ctx->axp, buf, len);
	if (err < 0) {
		axp_destroy(tr_ctx->axp);
		tr_ctx->axp = NULL;
		tr_ctx->result = 201;	/* Invalid XML */
		tr_ctx->pm_type = ARMS_TR_GENERIC_ERROR;
		if (tr_ctx->pm == NULL)
			tr_ctx->pm = &generic_error_methods;
		SET_TR_BUILDER(tr, http_response_builder);
		return TR_PARSE_ERROR;
	}
	if (tr_ctx->read_done) {
		axp_destroy(tr_ctx->axp);
		tr_ctx->axp = NULL;
		SET_TR_BUILDER(tr, http_response_builder);
		return TR_READ_DONE;
	}
	return TR_WANT_READ;
}
