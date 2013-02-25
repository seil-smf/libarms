/*	$Id: proto_push_md_command.c 23398 2013-01-31 03:19:52Z m-oki $	*/

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

#include <libarms_log.h>
#include <arms_xml_tag.h>
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>
#include <module_db_mi.h>

#include "compat.h"

/*
 * Callback Functions
 */
static void *md_command_context(tr_ctx_t *);
static int
md_command_cparg(AXP *, uint32_t, int, const char *, size_t, tr_ctx_t *);
static int md_command_response(transaction *, char *, int, int *);
static void md_command_release(tr_ctx_t *);


static char *arms_md_command_attr[] = {
	"id", NULL,
	"encoding", NULL,
	NULL
};

/*
 * XML Schema: md-command-request
 */
static struct axp_schema arms_md_command_req_body[] = {
	{ARMS_TAG_MDCOMMAND, "md-command", AXP_TYPE_TEXT,
		arms_md_command_attr, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema md_command_request = {
	ARMS_TAG_MDCOMMAND_REQ, "md-command-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, arms_md_command_req_body
};

/*
 * Method definition
 */
arms_method_t md_command_methods = {
	ARMS_TR_MD_COMMAND,	/* pm_type */
	"md-command",		/* type string */
	&md_command_request,	/* schema */
	0,			/* pm_flags */
	md_command_response,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	md_command_cparg,	/* pm_copyarg */
	NULL,			/* pm_rollback */
	md_command_context,	/* pm_context */
	md_command_release,	/* pm_release */
};

/*
 * Method implementations
 */

#define BEGIN        1
#define FIRST_RESULT 2
#define NEXT_RESULT  3
#define DONE         4
#define END          5
#define ERROR_RESULT 6
struct md_command_args {
	int mod_id;
	int mod_count;
	int already_running;
	int state;
	int req_len;
	int encoding;
	char request[8192];
	char result[1024 + 1];
	int resultlen;
	int next;
	arms_base64_stream_t base64;
};

static int already_running = 0;


/*
 * Context Alloc
 */
static void *
md_command_context(tr_ctx_t *ctx)
{
	struct md_command_args *arg;

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		if (already_running) {
			arg->already_running = already_running;
		} else {
			/* only one md-command */
			already_running = 1;
		}
		arg->state = BEGIN;
	}
	return arg;
}

/*
 * Context Free
 */
static void
md_command_release(tr_ctx_t *tr_ctx)
{
	struct md_command_args *arg;

	if (tr_ctx->arg) {
		arg = tr_ctx->arg;
		if (arg->already_running == 0)
			already_running = 0;
		FREE(arg);
	}
}

/*
 * Copy argument
 */
static int
md_command_cparg(AXP *axp, uint32_t pm_type, int tag,
		 const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct md_command_args *arg = tr_ctx->arg;
	uint32_t mod_id;

	if (arg->already_running) {
		tr_ctx->result = 302;
		return 0;
	}

	switch (tag) {
		case ARMS_TAG_START_CPARG:
			break;
		case ARMS_TAG_END_CPARG:
			if (arg->mod_count < 1) {
				tr_ctx->result = 203;/*Parameter Problem*/
			}
			break;
		case ARMS_TAG_MDCOMMAND:
			if (tr_ctx->read_done)
				break;
			arg->mod_count++;
			if (arg->mod_count > 1) {
				tr_ctx->result = 422;/*Multiple Request*/
				return -1;
			}
			mod_id = get_module_id(axp, tag);
			arg->mod_id = mod_id;
			if (sizeof(arg->request) < len) {
				tr_ctx->result = 402;/*SA Failure*/
				return -1;
			}
			if (arms_get_encoding(axp, tag) == ARMS_DATA_BINARY) {
				/* decode base64 */
				len = arms_base64_decode_stream(&arg->base64,
							 arg->request,
							 sizeof(arg->request),
							 buf, len);
			} else {
				memcpy(arg->request, buf, len);
			}
			arg->req_len = len;
			break;
		default:
			break;
	}

	return 0;
}

/*
 * Generate md-command-response mesage.
 */
static int
md_command_response(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct md_command_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int size, total, rv;

	switch (arg->state) {
	case BEGIN:
		libarms_log(ARMS_LOG_DEBUG, "Generate response to RS");
		arg->result[0] = '\0';
		arg->next = ARMS_FRAG_FIRST;
		rv = res->callbacks.command_cb(
			arg->mod_id,
			ARMS_PUSH_MD_COMMAND,
			arg->request, arg->req_len,
			arg->result, sizeof(arg->result) - 1,
			&arg->next,
			res->udata);
		arg->encoding = ARMS_DATA_TEXT;
		if (ARMS_RESULT_IS_ERROR(rv)) {
			if (rv != ARMS_EAPPEXEC) {
				tr_ctx->result = 402;/*system error*/
				arg->state = END;
				return TR_WANT_WRITE;
			}
			tr_ctx->result = 102;/*exec error*/
			arg->state = ERROR_RESULT;
		} else {
			arg->state = FIRST_RESULT;
		}
		if (ARMS_RESULT_IS_BYTES(rv)) {
			if (ARMS_RV_DATA_MASK(rv) < sizeof(arg->result)) {
				arg->encoding = ARMS_DATA_BINARY;
				arg->resultlen = ARMS_RV_DATA_MASK(rv);
			} else {
				/* too big bytes.  no md-result */
				tr_ctx->result = 102;/*exec error*/
				arg->state = ERROR_RESULT;
				snprintf(arg->result, sizeof(arg->result),
					 "data length too big (%d bytes)",
					 ARMS_RV_DATA_MASK(rv));
			}
		}
		size = arms_write_begin_message(tr, buf, len);
		buf += size;
		len -= size;
		if (arg->encoding == ARMS_DATA_BINARY) {
			size += snprintf(buf, len,
				 "<md-result id=\"%d\" encoding=\"base64\">",
					 arg->mod_id);
		} else {
			size += snprintf(buf, len,
				 "<md-result id=\"%d\">", arg->mod_id);
		}
		*wrote = size;
		return TR_WANT_WRITE;
	case ERROR_RESULT:
		*wrote = strlcpy(buf, arms_escape(arg->result), len);
		arg->state = DONE;
		return TR_WANT_WRITE;
	case FIRST_RESULT:
		if (arg->encoding == ARMS_DATA_BINARY) {
			int blen;

			blen = ROUND_BASE64_BINARY(arg->resultlen);
			arg->resultlen -= blen;
			*wrote = arms_base64_encode(buf, len,
						    arg->result,
						    blen);
			memcpy(arg->result,
			       arg->result + blen, arg->resultlen);
		} else {
			*wrote = strlcpy(buf, arms_escape(arg->result), len);
			arg->resultlen = 0;
		}
		if ((arg->next & ARMS_FRAG_FINISHED) != 0)
			arg->state = DONE;
		else
			arg->state = NEXT_RESULT;
		return TR_WANT_WRITE;
	case NEXT_RESULT:
		arg->result[arg->resultlen] = '\0';
		arg->next = ARMS_FRAG_CONTINUE;
		rv = res->callbacks.command_cb(
			arg->mod_id,
			ARMS_PUSH_MD_COMMAND,
			NULL, 0,
			arg->result + arg->resultlen,
			sizeof(arg->result) - 1 - arg->resultlen,
			&arg->next,
			res->udata);
		if (ARMS_RESULT_IS_BYTES(rv) &&
		    ARMS_RV_DATA_MASK(rv) < sizeof(arg->result)) {
			int blen;

			/* binary */
			arg->resultlen += ARMS_RV_DATA_MASK(rv);
			blen = ROUND_BASE64_BINARY(arg->resultlen);
			arg->resultlen -= blen;
			*wrote = arms_base64_encode(buf, len,
						    arg->result,
						    blen);
			memcpy(arg->result,
			       arg->result + blen, arg->resultlen);
		} else {
			/* text */
			*wrote = strlcpy(buf, arms_escape(arg->result), len);
			arg->resultlen = 0;
		}
		if ((arg->next & ARMS_FRAG_FINISHED) != 0)
			arg->state = DONE;
		else
			arg->state = NEXT_RESULT;
		return TR_WANT_WRITE;
	case DONE:
		if (arg->resultlen > 0) {
			total = size = arms_base64_encode(buf, len,
					  arg->result, arg->resultlen);
			buf += size;
			len -= size;
		} else {
			total = 0;
		}

		size = snprintf(buf, len, "</md-result>");
		buf += size;
		len -= size;
		total += size;

		total += arms_write_end_message(tr, buf, len);
		*wrote = total;
		arg->state = END;
		return TR_WRITE_DONE;
	case END:
		return TR_WRITE_DONE;
	default:
		break;
	}
	return TR_FATAL_ERROR;
}
