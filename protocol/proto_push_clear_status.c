/*	$Id: proto_push_clear_status.c 24213 2013-05-30 08:46:26Z yamazaki $	*/

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
#include <module_db_mi.h>

#include <libarms/malloc.h>
#include <libarms/base64.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * Callback Functions
 */
static void *clear_status_context(tr_ctx_t *ctx);
static int
clear_status_cparg(AXP *axp, uint32_t pm_type, int tag, const char *buf,
		size_t len, tr_ctx_t *ctx);
static int
clear_status_done(transaction *tr, char *buf, int len, int *wrote);
static void clear_status_release(tr_ctx_t *ctx);

/*
 * XML Schema: clear-status-start-request
 */
static char *status_req_attr[] = {
	"id", NULL,
	"encoding", NULL,
	NULL
};
static struct axp_schema arms_clear_status_sreq_body[] = {
	{ARMS_TAG_STATUS_REQ, "status-request", AXP_TYPE_TEXT,
		status_req_attr, push_default_hook, NULL},

	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema clear_status_start_request = {
	ARMS_TAG_CLEARSTATUS_SREQ, "clear-status-start-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, arms_clear_status_sreq_body
};

/*
 * Method definition
 */
arms_method_t clear_status_methods = {
	ARMS_TR_CLEAR_STATUS,	/* pm_type */
	"clear-status",		/* pm_string */
	&clear_status_start_request, /* schema */
	0,			/* pm_flags */
	build_generic_res,	/* pm_response */
	clear_status_done,	/* pm_done */
	NULL,			/* pm_exec */
	clear_status_cparg,	/* pm_copyarg */
	NULL,			/* pm_rollback */
	clear_status_context,	/* pm_context */
	clear_status_release,	/* pm_release */
};

/*
 * Method implementations
 */

#define BEGIN  1
#define RESULT 2
#define DONE   3

struct status_req {
	int id;
	char *buf;
	size_t len;
};

struct clear_status_args {
	int mod_id;
	int nstatus;
	int i;

	int state;
	int maxindex;
	struct status_req *status_list;
	char result[1024];
	arms_base64_stream_t base64;
};

/*
 * Context Alloc
 */
static void *
clear_status_context(tr_ctx_t *tr_ctx)
{
	struct clear_status_args *arg;
	arms_context_t *res = arms_get_context();

	if (res->callbacks.command_cb == NULL) {
		tr_ctx->result = 505;/*Not Support*/
		return NULL;
	}
	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->state = BEGIN;
		arg->maxindex = 16;
		arg->status_list = CALLOC(arg->maxindex + 1,
		    sizeof(*arg->status_list));
		if (arg->status_list == NULL) {
			FREE(arg);
			arg = NULL;
			tr_ctx->result = 413;/*413 Resource Exhausted*/
		}
	} else {
		tr_ctx->result = 413;/*413 Resource Exhausted*/
	}

	return arg;
}

/*
 * Context Free
 */
static void
clear_status_release(tr_ctx_t *tr_ctx)
{
	struct clear_status_args *arg;

	arg = tr_ctx->arg;
	if (arg) {
		if (arg->status_list != NULL) {
			int i;

			for (i = 0; i < arg->nstatus; i++) {
				if (arg->status_list[i].len > 0)
					FREE(arg->status_list[i].buf);
			}
			FREE(arg->status_list);
		}
		FREE(arg);
	}
}

/*
 * Copy argument
 */
static int
add_status_id(struct clear_status_args *arg,
	      int mod_id, const char *buf, size_t len, int encoding)
{
	int newmax;
	struct status_req *newlist;
	char *newbuf;

	if (arg->nstatus >= arg->maxindex) {
		newmax = arg->maxindex * 2;
		newlist = REALLOC(arg->status_list,
				  sizeof(struct status_req) * (newmax + 1));
		if (newlist == NULL)
			return -1;
		arg->maxindex = newmax;
		arg->status_list = newlist;
	}

	arg->status_list[arg->nstatus].id = mod_id;
	arg->status_list[arg->nstatus].buf = newbuf = MALLOC(len + 1);
	if (newbuf == NULL)
		return -1;
	if (encoding == ARMS_DATA_BINARY) {
		/* decode base64 */
		len = arms_base64_decode_stream(
			&arg->base64, newbuf, len, buf, len);
	} else {
		memcpy(newbuf, buf, len);
	}
	newbuf[len] = '\0';
	arg->status_list[arg->nstatus].len = len;
	arg->nstatus++;

	return 0;
}

static int
clear_status_cparg(AXP *axp, uint32_t pm_type, int tag,
		const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct clear_status_args *arg = tr_ctx->arg;

	if (tag == ARMS_TAG_STATUS_REQ) {
		const char *attr;
		
		attr = axp_find_attr(axp, tag, "id");
		if (attr == NULL) {
			return -1;
		}
		if (add_status_id(arg, atoi(attr),
				  buf, len, arms_get_encoding(axp, tag)) < 0) {
			tr_ctx->result = 413;/*Resouce Exhausted*/
		}
	} else if (tag == ARMS_TAG_END_CPARG) {
		if (arg->nstatus == 0) {
			/* <status-request id="xx"> tag not found. */
			tr_ctx->result = 203;/*Invalid Parameter*/
		}
	} else {
		/* other tag (ignored) */
	}

	return 0;
}

/*
 * Done
 */
static int
clear_status_done(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct clear_status_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int size, total, rv;

	switch (arg->state) {
	case BEGIN:
		libarms_log(ARMS_LOG_DEBUG,
			    "Generate clear-status-done");
		size = arms_write_begin_message(tr, buf, len);
		buf += size;
		len -= size;
		arg->state = RESULT;
		*wrote = size;
		return TR_WANT_WRITE;
	case RESULT:
		rv = res->callbacks.command_cb(
			arg->status_list[arg->i].id,
			ARMS_PUSH_CLEAR_STATUS,
			arg->status_list[arg->i].buf,
			arg->status_list[arg->i].len,
			arg->result, sizeof(arg->result),
			NULL,
			res->udata);
		if (ARMS_RESULT_IS_ERROR(rv) ||
		    (ARMS_RESULT_IS_BYTES(rv) &&
		     ARMS_RV_DATA_MASK(rv) > sizeof(arg->result))) {
			/* callback error */
			total = 0;
			size = snprintf(buf, len,
			    "<status-report id=\"%d\" result=\"402\">%s",
			    arg->status_list[arg->i].id,
			    arms_escape(arg->result));
			buf += size;
			len -= size;
			total += size;
		} else if (ARMS_RESULT_IS_BYTES(rv)) {
			total = 0;
			size = snprintf(buf, len,
				  "<status-report id=\"%d\""
				  " encoding=\"base64\" result=\"100\">",
				  arg->status_list[arg->i].id);
			buf += size;
			len -= size;
			total += size;

			size = arms_base64_encode(buf, len,
						  arg->result,
						  ARMS_RV_DATA_MASK(rv));
			buf += size;
			len -= size;
			total += size;
		} else {
			/* text */
			total = 0;
			size = snprintf(buf, len,
				  "<status-report id=\"%d\" result=\"100\">"
				  "%s",
				  arg->status_list[arg->i].id,
				  arms_escape(arg->result));
			buf += size;
			len -= size;
			total += size;
		}
		total += snprintf(buf, len, "</status-report>");
		*wrote = total;
		arg->i++;
		if (arg->i >= arg->nstatus)
			arg->state = DONE;
		return TR_WANT_WRITE;
	case DONE:
		*wrote = arms_write_end_message(tr, buf, len);
		return TR_WRITE_DONE;
	default:
		break;
	}
	return TR_FATAL_ERROR;
}
