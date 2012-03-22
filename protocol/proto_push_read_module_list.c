/*	$Id: proto_push_read_module_list.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libarms.h>
#include <axp_extern.h>

#include <libarms_log.h>
#include <arms_xml_tag.h>
#include <module_db_mi.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * Callback Functions
 */
/* context alloc */
/* copy argument */
/* execute */
/* done */
/* response */
static int
read_module_list_response(transaction *, char *, int, int *);

/*
 * XML Schema: check-transaction-start-response
 */
static struct axp_schema read_mod_list_res[] = {
	{ARMS_TAG_RCODE, "result-code",
		AXP_TYPE_INT, NULL, NULL, NULL},
	{ARMS_TAG_RDESC, "description",
		AXP_TYPE_TEXT, NULL, push_default_hook, NULL},
	{ARMS_TAG_READMODLIST_RES, "read-module-list-response",
		AXP_TYPE_TEXT, NULL, push_default_hook, NULL},

	{0, NULL, 0, NULL, NULL, NULL}
};
static char *read_mod_list_res_attr[] = {
	"type", NULL,
	NULL, NULL
};
static struct axp_schema read_mod_list_res_body[] = {
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
		read_mod_list_res_attr, push_default_hook,
		read_mod_list_res},

	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema read_mod_list_res_msg[] = {
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, push_default_hook, read_mod_list_res_body},

	{0, NULL, 0, NULL, NULL, NULL}
};

/*
 * Method definition
 */
arms_method_t read_module_list_methods = {
	ARMS_TR_READ_MODULE_LIST,	/* pm_type */
	"read-module-list",		/* type string */
	read_mod_list_res_msg,		/* schema for request parameters */
	0,				/* pm_flags */
	read_module_list_response,	/* pm_response */
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
read_module_list_response(transaction *tr, char *buf, int len, int *wrote)
{
	int size, total;

	libarms_log(ARMS_LOG_DEBUG,
			"Generate read-module-list response");
	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;
	size = arms_dump_module(buf, len);
	buf += size;
	len -= size;
	total += size;
	total += arms_write_end_message(tr, buf, len);
	*wrote = total;
	return TR_WRITE_DONE;
}
