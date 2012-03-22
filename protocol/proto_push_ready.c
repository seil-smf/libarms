/*	$Id: proto_push_ready.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>

#include <axp_extern.h>
#include <arms_xml_tag.h>

#include <transaction/transaction.h>
#include <protocol/arms_methods.h>
#include <http/http.h>

static int push_ready_request(transaction *, char *, int, int *);

/*
 * Method defineition
 */
arms_method_t push_ready_methods = {
	ARMS_TR_PUSH_READY,	/* pm_type */
	"push-ready",		/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	NULL,			/* pm_response */
	push_ready_request,	/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	NULL,			/* pm_context */
	NULL,			/* pm_release */
	NULL,			/* pm_parse */
};

static int
push_ready_request(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();
	int size, total;

	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	size = snprintf(buf, len,
			"<push-endpoint>%s</push-endpoint>",
			res->push_endpoint);
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);
	*wrote = total;

	SET_TR_PARSER(tr, http_response_parser);

	return TR_WRITE_DONE;
}
