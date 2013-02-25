/*	$Id: util.c 23398 2013-01-31 03:19:52Z m-oki $	*/

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
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * result code utilities.
 */
static const struct result_data {
	int code;
	const char *string;
} result_list[] = {
	{ 100, "Success" },
	{ 102, "Command Execute Error" },

	{ 201, "Invalid XML" },
	{ 202, "Invalid Message type" },
	{ 203, "Invalid Parameter" },

	{ 301, "Server Busy" },
	{ 302, "SA Busy" },
	{ 303, "Module syncing" },

	{ 400, "Bad Request" },
	{ 401, "Server Failure" },
	{ 402, "SA Failure" },
	{ 403, "Authentication Falure" },
	{ 404, "SA Marked as stand-by" },
	{ 405, "Not found" },
	{ 406, "Too many Transaction" },
	{ 407, "Too many Status" },
	{ 408, "Invalid Storage" },
	{ 409, "Invalid Module ID" },
	{ 410, "Validation Failure" },
	{ 411, "Commit Failure" },
	{ 412, "Transction Failure" },
	{ 413, "Resource Exhausted" },
	{ 414, "SA Rollbacked" },
	{ 415, "System Error" },
	{ 416, "System Mismatch" },
	{ 417, "Invalid Hardware" },
	{ 418, "Invalid Firmware" },
	{ 419, "Module Sync needed" },
	{ 420, "Distribution ID not found" },
	{ 421, "Configuration not found" },
	{ 422, "Multiple Request" },
	{ 423, "Distribution ID Mismatch" },

	{ 501, "Out of Service" },
	{ 502, "Push Failed" },
	{ 503, "Need Reboot" },
	{ 504, "Addresss Mismatch" },
	{ 505, "Not Support" },
	{ 506, "Server Moved" },
	{ 507, "Invalid type" },
	{ 508, "Rollback Failure" }, /*undocumented*/

	/* terminator */
	{   0, NULL }
};


static inline const char *
arms_get_result_str(int result)
{
	const struct result_data *p;

	for (p = result_list; p->code != 0; p++) {
		if (result == p->code)
			return p->string;
	}
	return "Unknown result";
}

/*
 * utility string function
 */

/*
 * escape character for XML.
 *
 * WARNINIG: arms_escape() returns a pointer to statically allocated
 * buffer.  another call will change the content!
 */
const char *
arms_escape(const char *text)
{
	static char *out = NULL;	/* not allocated at startup */
	static int outlen;
	char *p, ch;
	int remaining, size;

	if (out == NULL) {
		/* initial setup */
		outlen = 1024;
		out = CALLOC(1, outlen);
		if (out == NULL) {
			return "";
		}
	}
	if (text == NULL) {
		/* fini: free allocated space. */
		FREE(out);
		return "";
	}
	p = out;
	remaining = outlen;

	while ((ch = *text++) != '\0') {
	retry:
		switch (ch) {
		case '<':
			size = snprintf(p, remaining, "&lt;");
			break;
		case '>':
			size = snprintf(p, remaining, "&gt;");
			break;
		case '&':
			size = snprintf(p, remaining, "&amp;");
			break;
		case '"':
			size = snprintf(p, remaining, "&quot;");
			break;
		case '\'':
			size = snprintf(p, remaining, "&apos;");
			break;
		default:
			size = 1;
			*p = isascii(ch) ? ch : '?';
			break;
		}
		/*
		 * size excludes NUL.
		 * size < remaining by snprintf.
		 * max value of size == remaining - 1.
		 */
		if (size >= remaining - 1) {
			/* not enough size, expand out. */
			int off = p - out;
			outlen += 1024;
			out = REALLOC(out, outlen);
			/* XXX: if (out == NULL) fatal()... */
			remaining += 1024;
			p = out + off;
			memset(p, 0, remaining);
			goto retry;
		}
		p += size;
		remaining -= size;
	}
	/* ok becouse remaining > 0 */
	*p = '\0';
	return out;
}

#define REQ 1
#define RES 2
static inline int
arms_req_or_res(transaction *tr)
{
	if (TR_DIR(tr->state) == TR_REQUEST)
		return REQ;
	if (TR_DIR(tr->state) == TR_RESPONSE)
		return RES;

	return 0;
}

static inline const char *
arms_distid_str(transaction *tr)
{
	arms_context_t *res = arms_get_context();

	return strdistid(&res->dist_id);
}

static inline const char *
arms_get_transaction_result(transaction *tr)
{
	static char trbuf[80];

	if (TR_TYPE(tr->state) != TR_DONE)
		return "";

	snprintf(trbuf, sizeof(trbuf),
		 "<transaction-result>%d</transaction-result>",
		 tr->tr_ctx.result);
	return trbuf;
}

static inline const char *
arms_get_transaction_id(tr_ctx_t *tr_ctx)
{
	static char idbuf[80];
	if (tr_ctx->id == 0)
		return "";
	snprintf(idbuf, sizeof(idbuf),
		 "<transaction-id>%d</transaction-id>",
		 tr_ctx->id);
	return idbuf;
}

static inline const char *
arms_msg_way_str(transaction *tr)
{
	if (TR_TYPE(tr->state) == TR_START)
		return "-start";
	if (TR_TYPE(tr->state) == TR_DONE)
		return "-done";

	return "";
}

static inline const char *
arms_msg_type_str(transaction *tr)
{
	if (tr->state == TR_START_REQUEST)
		return "-start-request";
	if (tr->state == TR_DONE_REQUEST)
		return "-done-request";

	if (tr->state == TR_START_RESPONSE)
		return "-start-response";
	if (tr->state == TR_DONE_RESPONSE)
		return "-done-response";

	if (TR_DIR(tr->state) == TR_REQUEST)
		return "-request";
	if (TR_DIR(tr->state) == TR_RESPONSE)
		return "-response";

	return "";
}

/*
 * rv: wrote bytes excludes NUL.
 *
 * pm_string: "hoge"(sync),
 *		"hoge-start"(async from RS),
 *
 * <arms-message>
 * <arms-request type="hoge"or"hoge-start"or"hoge-done">
 * <hoge-request>or<hoge-start-request>or<hoge-done-request>
 */
int
arms_write_begin_message(transaction *tr, char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();

	switch (arms_req_or_res(tr)) {
	case REQ:
		return snprintf(buf, len,
				"<arms-message>"
				"<arms-request type=\"%s%s\">"
				"%s"
				"<distribution-id>%s</distribution-id>"
				"%s"
				"<description>%s</description>"
				"<%s%s>",
				tr_ctx->pm->pm_string,
				arms_msg_way_str(tr),
				arms_get_transaction_result(tr),
				arms_distid_str(tr),
				arms_get_transaction_id(tr_ctx),
				arms_escape(res->description),
				tr_ctx->pm->pm_string, arms_msg_type_str(tr));
	case RES:
		return snprintf(buf, len,
				"<arms-message>"
				"<arms-response type=\"%s%s\">"
				"%s"
				"<result-code>%d</result-code>"
				"<description>%s</description>"
				"<%s%s>",
				tr_ctx->pm->pm_string,
				arms_msg_way_str(tr),
				arms_get_transaction_id(tr_ctx),
				tr_ctx->result,
				arms_get_result_str(tr_ctx->result),
				tr_ctx->pm->pm_string, arms_msg_type_str(tr));
	default:
		/*bug?*/
		return 0;
	}
}

/*
 * rv: wrote bytes excludes NUL.
 */
int
arms_write_end_message(transaction *tr, char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;

	return snprintf(buf, len,
			"</%s%s>"
			"</arms-%s>"
			"</arms-message>",
			tr_ctx->pm->pm_string, arms_msg_type_str(tr),
			arms_req_or_res(tr) == REQ ? "request" : "response");
}

/*
 * rv: wrote bytes excludes NUL.
 */
int
arms_write_empty_message(transaction *tr, char *buf, int len)
{
	int size;

	size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	size += arms_write_end_message(tr, buf, len);

	return size;
}

int
arms_get_encoding(AXP *axp, int tag)
{
	const char *enc;

	enc = axp_find_attr(axp, tag, "encoding");
	if (enc != NULL && !strcmp(enc, "base64"))
		return ARMS_DATA_BINARY;

	return ARMS_DATA_TEXT;
}
