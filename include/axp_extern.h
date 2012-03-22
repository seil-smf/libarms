/*	$Id: axp_extern.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

/*
 * TODO:
 * - encoding
 * - escape
 */
#ifndef __AXP_PATTERN_H__
#define __AXP_PATTERN_H__

#include <sys/types.h>

struct arms_xml_parse;

typedef struct arms_xml_parse AXP;
typedef int (*AXP_CALLBACK)(AXP *,
			    int,
			    int,
			    int,
			    const char *, size_t,
			    void *);

typedef int (*AXP_BUILDCALLBACK)(AXP *,
				 char *, size_t,
				 void *);

/*
 * schema sample (maybe automatically generated)
 *
 * struct axp_schema rs_sol_msg[] = {
 *	{ ARMS_MESSAGE, "arms-message", NULL, AXP_TYPE_CHILD, NULL, rs_sol_msg1,},
 *	NULL,
 * };
 *
 * struct axp_schema rs_sol_msg1[] = {
 *	{ ARMS_RESPONSE, "arms-response", {"type", "rs-solicitation", NULL},
 *	  AXP_TYPE_CHILD, NULL, rs_sol_msg2, },
 *	NULL,
 * };
 *
 * struct axp_schema rs_sol_msg2[] = {
 *	{ RESULT_CODE, "result-code", NULL, AXP_TYPE_INT, result_cb, NULL },
 *	{ "result-description", NULL, AXP_TYPE_STRING, result_str_cb, NULL },
 *	{ "rs-solicitation-response", NULL, AXP_TYPE_CHILD, NULL, rs_sol_msg3 },
 *	NULL,
 * };
 *
 * struct axp_schema rs_sol_msg3[] = {
 *	{ LL_TIMEOUT, "ll-timeout" },
 *	{ RS_RETRY_MAX, "rs-retry-max" },
 *	{ RS_RETRY_INTERVAL, "rs-retry-interval", },
 *	{ LIFETIME, "lifetime", },
 *	{ RS_INFO, "rs-info", ..., rs_sol_msg4 },
 *	NULL,
 * };
 *
 * struct axp_schema rs_sol_msg4[] = {
 *	{ URL, "url", NULL, AXP_TYPE_TEXT, },
 *	{ MD_CONFIG, "md-config", NULL, AXP_TYPE_TEXT, config_cb, NULL },
 };
 */
struct axp_schema {
	int as_tagtype;
	char *as_tag;
	int as_type;
	char **as_attr;
	AXP_CALLBACK as_cb;
	struct axp_schema *as_child;
};

enum {
	AXP_TYPE_INT,
	AXP_TYPE_TEXT,
	AXP_TYPE_CHILD
};


enum {
	AXP_PARSE_START,
	AXP_PARSE_CONTENT,
	AXP_PARSE_END,
	AXP_PARSE_TAG,
	AXP_PARSE_VALUE,
	AXP_PARSE_ERROR
};

/* content buffer size */
#define AXP_BUFSIZE 65536

AXP *axp_create(struct axp_schema *, const char *, void *, AXP_BUILDCALLBACK);
int axp_parse(AXP *, const char *, size_t);
int axp_endparse(AXP *);
int axp_destroy(AXP *);

/*
 * e.g.  axp_refer(obj, RESULT_CODE, &result);
 */
int axp_refer(AXP *, int, void *);

const char * axp_find_attr(AXP *, int, char *);

/*
 * XML text build functions.
 * 1. obj = axp_create();
 * 2. axp_setbufsiz(obj, size);
 * 3. while(<>) {
 *	axp_set(obj, tag, &val); // callback if buffer is filled.
 *    };
 * 4. axp_build(obj); // callback
 */
int axp_setbufsiz(AXP *, size_t);
int axp_set(AXP *, int, void *);
void axp_reset(AXP *, int);
int axp_set_attr(AXP *, int, const char *, const char *);
int axp_build(AXP *);

int axp_get_tagstate(AXP *);
int axp_set_userdata(AXP *, void *);
void *axp_get_userdata(AXP *);

#endif  /* __AXP_PATTERN_H__ */
