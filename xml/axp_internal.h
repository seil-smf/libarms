/*	$Id: axp_internal.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <sys/queue.h>
#include "expat.h"

#ifndef LIST_FIRST
#define LIST_FIRST(head) \
	((head)->lh_first)
#endif

#ifndef LIST_NEXT
#define LIST_NEXT(elm, field) ((elm)->field.le_next)
#endif

#ifndef LIST_FOREACH
#define LIST_FOREACH(elm, head, field) \
	for (elm = LIST_FIRST(head); elm; elm = LIST_NEXT(elm, field))
#endif

#define AXP_MAX_HASH_ARRAY 50

struct axp_schema_entry {
	LIST_ENTRY(axp_schema_entry) next;
	struct axp_schema *schema;
};

struct axp_attr_entry {
	LIST_ENTRY (axp_attr_entry) next;
	char *prop;
	char *value;
};

struct axp_val_storage {
	LIST_ENTRY(axp_val_storage) next;
	int tag;
	int type;
	void *value;
	LIST_HEAD(axp_attr, axp_attr_entry) attr;
};
struct arms_xml_parse {
	struct axp_schema *schema;
	int state;
	int tagstate;
	char *buf;
	size_t len;
	XML_Parser parser;
	AXP_BUILDCALLBACK buildfunc;
	LIST_HEAD(axp_stores, axp_val_storage) valhash[AXP_MAX_HASH_ARRAY];
	LIST_HEAD(axp_stack, axp_schema_entry) sc_stack;
	void *userdata;
};

int axp_register_handler(AXP *obj);
int axp_set_value(AXP *obj, int tagtype, void *valp, int type);
