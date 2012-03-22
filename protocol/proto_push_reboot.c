/*	$Id: proto_push_reboot.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <libarms_resource.h>
#include <axp_extern.h>

#include <arms_xml_tag.h>

#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

static int reboot_response(transaction *, char *, int, int *);

/*
 * Method definition
 */
arms_method_t reboot_methods = {
	ARMS_TR_REBOOT,		/* pm_type */
	"reboot",		/* pm_string */
	NULL,			/* pm_schema */
	0,			/* pm_flags */
	reboot_response,	/* pm_response */
	NULL,			/* pm_done */
	NULL,			/* pm_exec */
	NULL,			/* pm_copyarg */
	NULL,			/* rollback */
	NULL,			/* pm_context */
	NULL,			/* pm_release */
};

/*
 * Method implementations
 */
static int
reboot_response(transaction *tr, char *buf, int len, int *wrote)
{
	arms_context_t *res = arms_get_context();

	/* set arms_event_loop return value */
	res->trigger = "Reboot requested by RS";
	res->result = ARMS_EREBOOT;

	build_generic_res(tr, buf, len, wrote);

	/* stop scheduler */
	return TR_WANT_STOP;
}
