/*	$Id: proto_push_check_transaction.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <sys/types.h>
#include <unistd.h>

#include <libarms/queue.h>

#include <libarms.h>
#include <libarms_log.h>
#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <transaction/transaction.h>
#include <transaction/ssltunnel.h>
#include <protocol/arms_methods.h>

/*
 * check-transaction
 * - 1way
 * - no parameter
 */

/*
 * Callback Functions
 */
/* response */
static int
check_transaction_response(transaction *, char *, int , int *);

/*
 * Method defineition
 */
arms_method_t check_transaction_methods = {
	ARMS_TR_CHECK_TRANSACTION,	/* pm_type */
	"check-transaction",		/* type string */
	NULL,				/* schema for request parameters */
	0,				/* pm_flags */
	check_transaction_response,	/* pm_response */
	NULL,				/* pm_done */
	NULL,				/* pm_exec */
	NULL,				/* pm_copyarg */
	NULL,				/* pm_rollback */
	NULL,				/* pm_context */
	NULL,				/* pm_release */
};

/*
 * Method implementations
 */
/*
 * Response
 */
static int
check_transaction_response(transaction *tr, char *buf, int len, int *wrote)
{
	transaction *t;
	struct ssltunnel *tunnel;
	int size, total;

	libarms_log(ARMS_LOG_DEBUG,
			"Generate check-transaction response");
	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	/* https-simple transaction */
	LIST_FOREACH(t, get_tr_list(), next) {
		size = snprintf(buf, len,
				"<transaction-id>%d</transaction-id>",
				t->tr_ctx.id);
		buf += size;
		len -= size;
		total += size;
	}
	/* https-tunnel transaction */
	LIST_FOREACH(tunnel, get_tunnel_list(), next) {
		LIST_FOREACH(t, &tunnel->tr_list, next) {
			size = snprintf(buf, len,
				"<transaction-id>%d</transaction-id>",
				t->tr_ctx.id);
			buf += size;
			len -= size;
			total += size;
		}
	}
	total += arms_write_end_message(tr, buf, len);
	*wrote = total;
	return TR_WRITE_DONE;
}
