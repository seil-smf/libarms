/*	$Id: arms_res_parser.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <sys/time.h>

#include <libarms_resource.h>
#include <libarms_log.h>
#include <axp_extern.h>

#include <arms_xml_tag.h>

#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * generic response parser.
 *
 * for push *-done-response,
 *  resolved and done or retry.
 *
 * for pull *-response,
 *  call each response function.
 */

/*
 * generic *-done-response
 */
static char *generic_done_res_attr[] = {
	"type", NULL,
	NULL
};

static struct axp_schema generic_done_res_body[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RCODE, "result-code", AXP_TYPE_INT,  NULL, NULL, NULL},
	{ARMS_TAG_RDESC, "description", AXP_TYPE_TEXT, NULL, NULL, NULL},

	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema arms_generic_done_res[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
	 generic_done_res_attr, NULL, generic_done_res_body},

	{0, NULL, 0, NULL, NULL, NULL}
};

/* exported.  used by parse_configure_done.  */
struct axp_schema arms_generic_done_res_msg[] = {
	/* id, tag, type, attr, callback, child */
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, NULL, arms_generic_done_res},

	{0, NULL, 0, NULL, NULL, NULL}
};

/*
 * *-start-response or *-done-response parser.
 */
int
arms_res_parser(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	arms_method_t *method;
	AXP *axp;
	int err, rcode = 0;

	method = tr_ctx->pm;

	if (method == NULL) {
		libarms_log(ARMS_LOG_DEBUG, "res:method is not found.");
		return TR_FATAL_ERROR;
	}
	if (method != NULL && method->pm_parse) {
		return method->pm_parse(tr, buf, len);
	}

	/* check result code */
	axp = axp_create(arms_generic_done_res_msg, "US-ASCII", tr_ctx, 0);
	MSETPOS(axp);
	if (axp == NULL)
		err = 1;
	else 
		err = axp_parse(axp, buf, len);
	if (err == 0) {
		const char *typestr;
		typestr = axp_find_attr(axp, ARMS_TAG_RES, "type");

		if (tr->state == TR_DONE_RESPONSE) {
			/* async */
			int typelen;
			/*
			 * type check.
			 * pm_string: hoge
			 * typestr: hoge-done
			 */
			typelen = strlen(method->pm_string);
			if (typestr != NULL &&
			    !strncmp(typestr, method->pm_string, typelen) &&
			    !strcmp(&typestr[typelen], "-done")) {
				err = axp_refer(axp, ARMS_TAG_RCODE, &rcode);
			} else {
				err = 1;
			}
		} else {
			/* sync */
			if (typestr != NULL &&
			    !strcmp(method->pm_string, typestr)) {
				err = axp_refer(axp, ARMS_TAG_RCODE, &rcode);
			} else {
				err = 1;
			}
		}
	}
	axp_destroy(axp);

	if (err != 0) {
		tr_ctx->result = 402;/*SA failure*/
		return TR_WANT_RETRY;
	}
	tr_ctx->res_result = rcode;

	libarms_log(ARMS_LOG_DEBUG,
		    "libarms got result %d from server.",
		    tr_ctx->res_result);
	if (rcode >= 300 && rcode < 500) {
		/* don't (can't) retry because tunnel or HTTP/1/1. */
		return TR_READ_DONE;
	}
	if (rcode >= 500) {
		res->result = ARMS_EREBOOT;
		res->trigger = "got result of failure from server";
		switch (rcode) {
		case 501:
			res->result = ARMS_EDONTRETRY;
			res->trigger = "received 501 Out of service";
			break;
		case 502:
			res->result = ARMS_EPULL;
			res->trigger = "received 502 Push failed";
			break;
		case 503:
			res->result = ARMS_EREBOOT;
			res->trigger = "received 503 Need reboot";
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
		res->trigger = "got result of failure from server";
		return TR_WANT_STOP;
	}

	return TR_READ_DONE;
}
