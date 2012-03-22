/*	$Id: proto_push_pull_config.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * Callback Functions
 */
/* copy argument */
static int
pullconfig_cparg(AXP *, uint32_t, int, const char *, size_t, tr_ctx_t *);
/* response */
static int
pullconfig_response(transaction *, char *, int, int *);

static struct axp_schema pullconfig_type[] = {
	{ARMS_TAG_TYPE, "type", AXP_TYPE_TEXT,
		NULL, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema pullconfig_req = {
	ARMS_TAG_PULLCONFIG_REQ, "pull-config-request", AXP_TYPE_CHILD,
	NULL, push_default_hook, pullconfig_type
};
/*
 * Method defineition
 */
arms_method_t pull_config_methods = {
	ARMS_TR_PULL_CONFIG,	/* pm_type */
	"pull-config",		/* pm_string */
	&pullconfig_req,	/* pm_schema */
	0,			/* pm_flags */
	pullconfig_response,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	pullconfig_cparg,	/* pm_copyarg */
	NULL,			/* rollback */
	NULL,			/* pm_context */
	NULL,			/* pm_release */
};


/*
 * Method implementations
 */

static int
pullconfig_response(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();

	/* set arms_event_loop return value */
	res->result = ARMS_EPULL;

	build_generic_res(tr, buf, len, wrote);

	/* stop scheduler */
	res->trigger = "Pull requested by RS";
	return TR_WANT_STOP;
}


/*
 * Copy argument
 */
static int
pullconfig_cparg(AXP *axp, uint32_t pm_type, int tag,
		 const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	arms_context_t *res = arms_get_context();

	switch (tag) {
	case ARMS_TAG_TYPE:
		/* copy type into libarms context */
		if (!strncmp(buf, "LS", len)) {
			/* clear old rs endpoint information (for access LS) */
			res->rs_endpoint[0] = '\0';
		} else if (!strncmp(buf, "RS", len)) {
		} else {
			/* invalid type */
		}
		break;
	default:
		break;
	}

	return 0;
}
