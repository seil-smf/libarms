/*	$Id: proto_push_dump_debug.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <module_db_mi.h>

#include <libarms_log.h>
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

/*
 * Callback Functions
 */
/* context alloc */
static void *dump_debug_context(tr_ctx_t *);
static int dump_debug_response(transaction *, char *, int, int *);
static void dump_debug_release(tr_ctx_t *);


/*
 * XML Schema: dump-debug-request
 */
static struct axp_schema dump_debug_request = {
	ARMS_TAG_DUMP_DEBUG_REQ, "dump-debug-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, NULL
};

/*
 * Method defineition
 */
arms_method_t dump_debug_methods = {
	ARMS_TR_DUMP_DEBUG,	/* pm_type */
	"dump-debug",		/* type string */
	&dump_debug_request,	/* schema */
	0,			/* pm_flags */
	dump_debug_response,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* pm_rollback */
	dump_debug_context,	/* pm_context */
	dump_debug_release,	/* pm_release */
};

/*
 * Method implementations
 */

#define BEGIN  1
#define RESULT 2
#define DONE   3
struct dump_debug_args {
	int state;
	int encoding;
	char result[1024];
	int resultlen;
};

/*
 * Context Alloc
 */
static void *
dump_debug_context(tr_ctx_t *tr_ctx)
{
	struct dump_debug_args *arg;

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->state = BEGIN;
	}
	return arg;
}

/*
 * Context Free
 */
static void
dump_debug_release(tr_ctx_t *tr_ctx)
{
	struct dump_debug_args *arg;

	if (tr_ctx->arg) {
		arg = tr_ctx->arg;
		FREE(arg);
	}
}

/*
 * Generate md-command-response mesage.
 */
static int
dump_debug_response(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct dump_debug_args *arg = tr_ctx->arg;
	int size, rv;

	libarms_log(ARMS_LOG_DEBUG, "Generate response to RS");

	switch (arg->state) {
	case BEGIN:
		if (res->callbacks.command_cb == NULL) {
			tr_ctx->result = 505;/*Not Support*/
			*wrote = arms_write_empty_message(tr, buf, len);
			return TR_WRITE_DONE;
		}
		rv = res->callbacks.command_cb(
			0,
			ARMS_PUSH_DUMP_DEBUG,
			NULL, 0,
			arg->result, sizeof(arg->result),
			NULL,
			res->udata);
		if (ARMS_RESULT_IS_ERROR(rv)) {
			tr_ctx->result = 402;/*SA Failure*/
			*wrote = arms_write_empty_message(tr, buf, len);
			return TR_WRITE_DONE;
		}
		size = arms_write_begin_message(tr, buf, len);
		buf += size;
		len -= size;
		if (ARMS_RESULT_IS_BYTES(rv)) {
			if (ARMS_RV_DATA_MASK(rv) > sizeof(arg->result)) {
				/* too big bytes.  no md-result */
				tr_ctx->result = 402;/*SA Failure*/
				size += arms_write_end_message(tr, buf, len);
				*wrote = size;
				return TR_WRITE_DONE;
			}
			arg->resultlen = ARMS_RV_DATA_MASK(rv);
			arg->encoding = ARMS_DATA_BINARY;
			size += snprintf(buf, len,
				 "<md-result id=\"0\" encoding=\"base64\">");
		} else {
			arg->encoding = ARMS_DATA_TEXT;
			size += snprintf(buf, len,
				 "<md-result id=\"0\">");
		}
		arg->state = RESULT;
		*wrote = size;
		return TR_WANT_WRITE;
	case RESULT:
		if (arg->encoding == ARMS_DATA_BINARY) {
			/* binary */
			*wrote = arms_base64_encode(buf, len,
						    arg->result,
						    arg->resultlen);
		} else {
			/* text */
			*wrote = strlcpy(buf, arms_escape(arg->result), len);
		}
		arg->state = DONE;
		return TR_WANT_WRITE;
	case DONE:
		size = snprintf(buf, len, "</md-result>");
		buf += size;
		len -= size;
		size += arms_write_end_message(tr, buf, len);
		*wrote = size;
		return TR_WRITE_DONE;
	default:
		break;
	}
	return TR_FATAL_ERROR;
}
