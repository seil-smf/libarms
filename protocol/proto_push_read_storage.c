/*	$Id: proto_push_read_storage.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

/*
 * Callback Functions
 */
/* context alloc */
static void *read_storage_context(tr_ctx_t *tr_ctx);
/* copy argument */
static int
read_storage_cparg(AXP *axp, uint32_t pm_type, int tag, const char *buf, size_t len, tr_ctx_t *tr_ctx);
/* done */
static int
read_storage_done(transaction *, char *buf, int, int *);
/* context free */
static void read_storage_release(tr_ctx_t *tr_ctx);

/*
 * XML Schema: read-storage-start-request
 */
static struct axp_schema arms_push_readstorage_req[] = {
	{ARMS_TAG_STORAGE, "storage", AXP_TYPE_TEXT,
	 NULL, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};
struct axp_schema read_storage_start_req = {
	ARMS_TAG_READSTORAGE_SREQ, "read-storage-start-request", AXP_TYPE_CHILD,
	 	NULL, push_default_hook, arms_push_readstorage_req
};

/*
 * Method definition
 */
arms_method_t read_storage_methods = {
	ARMS_TR_READ_STORAGE,	/* pm_type */
	"read-storage",		/* pm_string */
	&read_storage_start_req,/* schema */
	0,			/* pm_flags */
	build_generic_res,	/* pm_response */
	read_storage_done,	/* pm_done */
	NULL,			/* pm_exec */
	read_storage_cparg,	/* pm_copyarg */
	NULL,			/* pm_rollback */
	read_storage_context,	/* pm_context */
	read_storage_release,	/* pm_release */
};

/*
 * Method implementations
 */

#define BEGIN        1
#define FIRST_RESULT 2
#define NEXT_RESULT  3
#define DONE_RESULT  4
#define DONE         5

struct read_storage_args {
	int props_id; /* storage type: running, candidata, or backup */
	int mod_index;
	int mod_max;
	uint32_t mod_id;
	int next;
	int state;
	int resultlen;
	char result[1024];
	char term;	/* trailing NUL */
};

/*
 * Context Alloc
 */
static void *
read_storage_context(tr_ctx_t *tr_ctx)
{
	struct read_storage_args *arg;
	arms_context_t *res = arms_get_context();

	if (res->callbacks.read_config_cb == NULL) {
		tr_ctx->result = 505;
		return 0;
	}

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		arg->state = BEGIN;
	} else {
		tr_ctx->result = 413; /*Resource Exhausted*/
	}

	return arg;
}

/*
 * Context Free
 */
static void
read_storage_release(tr_ctx_t *tr_ctx)
{
	struct read_storage_args *arg;

	arg = tr_ctx->arg;
	if (arg) {
		FREE(tr_ctx->arg);
	}
}

/*
 * Copy argument
 */
static int
parse_propsid(const char *buf, size_t len)
{
	if (buf == NULL)
		return -1;
	if (len <= 0)
		return -1;

#if 0 /* libarms doesn't support startup */
	if (strncmp("startup", buf, len) == 0) {
		return ARMS_CONFIG_STARTUP;
	}
#endif
	else if (strncmp("candidate", buf, len) == 0) {
		return ARMS_CONFIG_CANDIDATE;
	}
	else if (strncmp("running", buf, len) == 0) {
		return ARMS_CONFIG_RUNNING;
	}
	else if (strncmp("backup", buf, len) == 0) {
		return ARMS_CONFIG_BACKUP;
	}

	return -1;
}

static int
read_storage_cparg(AXP *axp, uint32_t pm_type, int tag,
		   const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct read_storage_args *arg = tr_ctx->arg;

	if (tag == ARMS_TAG_STORAGE) {
		arg->props_id = parse_propsid(buf, len);
		if (arg->props_id < 0) {
			/* storage type is invalid. */
			tr_ctx->result = 203;
		}
	} else {
		/* other tag (error?) */
	}
	return 0;
}

/*
 * read-storage-done
 *
 * like read-storage-done, but <md-config> tag has no result attribute.
 *  so fat, empty config means error.  umm...
 *
 * SMF SDK 1.00 (and 1.10) cannot receive error result via any tag.
 * - md-config has no result attribute.
 * - transaction-result doesn't work between proxy and RS.
 * workaround: done-req doesn't include md-config tag means error.
 */
static int
read_storage_done(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct read_storage_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	int size, err, rv;

	switch (arg->state) {
	case BEGIN:
		libarms_log(ARMS_LOG_DEBUG,
			    "Generate read-storage-done");

		arg->mod_max = arms_count_module();
		size = arms_write_begin_message(tr, buf, len);
		buf += size;
		len -= size;
		if (tr_ctx->result == 100)
			arg->state = FIRST_RESULT;
		else
			arg->state = DONE;
		*wrote = size;
		return TR_WANT_WRITE;
	case FIRST_RESULT:
		/*
		 * mod_index++ if err or FINISHED.
		 */
		rv = 0;
		err = arms_get_module_id(&arg->mod_id, arg->mod_index);
		if (err == 0) {
			arg->next = ARMS_FRAG_FIRST;
			arg->result[0] = '\0';
			rv = res->callbacks.read_config_cb(
				arg->mod_id,
				arg->props_id,
				arg->result, sizeof(arg->result),
				&arg->next,
				res->udata);
			if (ARMS_RESULT_IS_BYTES(rv)) {
				int blen;

				/* binary */
				size = snprintf(buf, len,
						"<md-config id=\"%d\" "
						"encoding=\"base64\">",
						arg->mod_id);
				buf += size;
				len -= size;

				arg->resultlen = ARMS_RV_DATA_MASK(rv);
				blen = ROUND_BASE64_BINARY(arg->resultlen);
				arg->resultlen -= blen;
				size += arms_base64_encode(buf, len,
					   arg->result,
					   blen);
				memcpy(arg->result,
				       arg->result + blen, arg->resultlen);
			} else {
				/* text or error */
				size = snprintf(buf, len,
						"<md-config id=\"%d\">%s",
						arg->mod_id,
						arms_escape(arg->result));
				arg->resultlen = 0;
			}
			*wrote = size;
		}
		if ((arg->next & ARMS_FRAG_FINISHED) != 0 ||
		    ARMS_RESULT_IS_ERROR(rv))
			arg->state = DONE_RESULT;
		else
			arg->state = NEXT_RESULT;
		return TR_WANT_WRITE;
	case NEXT_RESULT:
		arg->next = ARMS_FRAG_CONTINUE;
		rv = res->callbacks.read_config_cb(
			arg->mod_id,
			arg->props_id,
			arg->result + arg->resultlen,
			sizeof(arg->result) - arg->resultlen,
			&arg->next,
			res->udata);
		if (ARMS_RESULT_IS_ERROR(rv)) {
			*wrote = 0;
			arg->state = DONE_RESULT;
			return TR_WANT_WRITE;
		}
		if (ARMS_RESULT_IS_BYTES(rv)) {
			int blen;

			arg->resultlen += ARMS_RV_DATA_MASK(rv);
			blen = ROUND_BASE64_BINARY(arg->resultlen);
			arg->resultlen -= blen;
			*wrote = arms_base64_encode(buf, len,
						    arg->result,
						    blen);
			memcpy(arg->result,
			       arg->result + blen, arg->resultlen);
		} else {
			*wrote = strlcpy(buf, arms_escape(arg->result), len);
		}
		if ((arg->next & ARMS_FRAG_FINISHED) != 0)
			arg->state = DONE_RESULT;
		return TR_WANT_WRITE;
	case DONE_RESULT:
		if (arg->resultlen > 0) {
			size = arms_base64_encode(buf, len,
					  arg->result, arg->resultlen);
			buf += size;
			len -= size;
		} else {
			size = 0;
		}
		size += snprintf(buf, len, "</md-config>");
		*wrote = size;
		arg->mod_index++;
		if (arg->mod_index >= arg->mod_max)
			arg->state = DONE;
		else
			arg->state = FIRST_RESULT;
		return TR_WANT_WRITE;
	case DONE:
		*wrote = arms_write_end_message(tr, buf, len);
		libarms_log(ARMS_LOG_DEBUG,
			    "Read Storage Execute done.");
		return TR_WRITE_DONE;
	default:
		break;
	}
	return TR_FATAL_ERROR;
}
