/*	$Id: arms_methods.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <stdlib.h>
#include <inttypes.h>

#include <axp_extern.h>

#include <arms_xml_tag.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

static arms_method_t *method_tbl = NULL;

/*
 * Generic Praser for start request messages
 */

static int
register_arms_method(arms_method_t *method)
{
	int count;
	int i;
	arms_method_t *new_tbl;

	if (method == NULL) {
		/* error in caller */
		return -1;
	}

	if (method_tbl == NULL) {
		/* first entry */
		new_tbl = CALLOC(2, sizeof(*new_tbl));
		if (new_tbl == NULL) {
			return -1;
		}
		new_tbl[0] = *method;
	} else {
		count = 0;
		while (method_tbl[count].pm_type != 0) {
			count++;
		}
		/* create new buffer */
		new_tbl = CALLOC(count + 2, sizeof(*new_tbl));
		if (new_tbl == NULL) {
			return -1;
		}
		/* copy buffer */
		for (i = 0;  i < count; i++) {
			new_tbl[i] = method_tbl[i];
		}
		new_tbl[count] = *method;
		/* replace table */
		FREE(method_tbl);
	}
	method_tbl = new_tbl;

	/* update XML parser */
	push_add_schema(method->pm_type, method->pm_string,
			method->pm_schema);
	return 0;
}

void
free_arms_method_table(void)
{
	FREE(method_tbl);
}

arms_method_t *
type2method(uint32_t type)
{
	arms_method_t *method = method_tbl;
	int found = 0;

	if (method == NULL) {
		return NULL;
	}

	while (method->pm_type != 0) {
		if (method->pm_type == type) {
			found = 1;
			break;
		}
		method++;
	}

	if (!found) {
		return NULL;
	}

	return method;
}

void
arms_method_init(void)
{
	/* generic error methods */
	register_arms_method(&generic_error_methods);

#if 0 /* pull method is no need to registration.  (e.g. LS pull and RS pull) */
	/* pull methods */
	register_arms_method(&push_ready_methods);
	register_arms_method(&method_query_methods);
#endif

	/* push methods */
	register_arms_method(&confirm_done_methods);
	register_arms_method(&check_transaction_methods);
	register_arms_method(&clear_status_methods);
	register_arms_method(&configure_methods);
	register_arms_method(&dump_debug_methods);
	register_arms_method(&md_command_methods);
	register_arms_method(&read_module_list_methods);
	register_arms_method(&read_status_methods);
	register_arms_method(&read_storage_methods);
	register_arms_method(&reboot_methods);
	register_arms_method(&ping_methods);
	register_arms_method(&pull_config_methods);
	register_arms_method(&traceroute_methods);
}
