/*	$Id: proto_error.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

static int build_generic_err(transaction *, char *, int, int *);

/*
 * Generic error
 */
arms_method_t generic_error_methods = {
	ARMS_TR_GENERIC_ERROR,	/* pm_type */
	"generic-error",
	NULL,			/* schema */
	0,			/* pm_flags */
	build_generic_err,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	NULL,			/* pm_context */
	NULL,			/* pm_release */
};

static int
build_generic_err(transaction *tr, char *buf, int len, int *wrote)
{
	int size, total;

	size = snprintf(buf, len,
			"<arms-message>"
			"<arms-response type=\"generic-error\">"
			"<result-code>%d</result-code>"
			"<description></description>",
			tr->tr_ctx.result);
	total = size;
	buf += size;
	len -= size;
	if (tr->tr_ctx.id != 0) {
	  size = snprintf(buf, len,
			  "<transaction-id>%d</transaction-id>",
			  tr->tr_ctx.id);
	total += size;
	buf += size;
	len -= size;
	}
	/* no body */
	size = snprintf(buf, len,
			"</arms-response>"
			"</arms-message>");
	total += size;

	*wrote = total;
	return TR_WRITE_DONE;
}
