/*	$Id: arms_res_builder.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <axp_extern.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * transaction_reflect --> build_generic_res
 * &abuf_tmp --> buf, len, wrote
 * void *u (== tr_ctx) --> tr
 */
int
build_generic_res(transaction *tr, char *buf, int len, int *wrote)
{
	int size;

	size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	/* no body */
	size += arms_write_end_message(tr, buf, len);
	*wrote = size;
	return TR_WRITE_DONE;
}

/*
 * response builder: method is selected by pm_type.
 */
int
arms_res_builder(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_method_t *method;
	int rv;

	if (tr_ctx->write_done != TR_WANT_WRITE)
		return tr_ctx->write_done;

	method = tr_ctx->pm;

	if (method == NULL) {
		/*
		 * request type is not found, return generic-error.
		 */
		tr_ctx->pm_type = ARMS_TR_GENERIC_ERROR;
		if (tr_ctx->pm == NULL)
			tr_ctx->pm = &generic_error_methods;
		tr_ctx->id = 0;
		tr_ctx->result = 202;
		rv = build_generic_res(tr, buf, len, wrote);
		tr_ctx->write_done = rv;
		return TR_WANT_WRITE;
	}
	if (method->pm_response == NULL) {
		/*
		 * request type is found, return "NOT SUPPORTED".
		 */
		tr_ctx->pm_type = ARMS_TR_GENERIC_ERROR;
		if (tr_ctx->pm == NULL)
			tr_ctx->pm = &generic_error_methods;
		tr_ctx->id = 0;
		tr_ctx->result = 505;
		rv = build_generic_res(tr, buf, len, wrote);
		tr_ctx->write_done = rv;
		return TR_WANT_WRITE;
	}
	/*
	 * chack too many transaction
	 */
	if (method->pm_done == NULL) {
		/* sync'd method running immediately. */
		if (tr_ctx->result == 406)
			tr_ctx->result = 100;
	}
	if (tr_ctx->result >= 200) {
		/*
		 * error detected in -request parser.
		 * e.g. too many transaction,
		 *      distribution-id mismatch,
		 */
		if (tr_ctx->pm == NULL)
			tr->tr_ctx.pm = &generic_error_methods;
		rv = build_generic_res(tr, buf, len, wrote);
		tr_ctx->write_done = rv;
		return TR_WANT_WRITE;
	}
	rv = method->pm_response(tr, buf, len, wrote);
	tr_ctx->write_done = rv;
	return TR_WANT_WRITE;
}
