/*	$Id: axp.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
 * Arms Xml Processor API routines.
 * requires: expat
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>

#include <axp_extern.h>
#include <libarms/malloc.h>
#include <xml/axp_internal.h>

AXP *
axp_create(struct axp_schema *as, const char *encoding,
	   void *userdata, AXP_BUILDCALLBACK func)
{
	AXP *obj;
	struct axp_schema_entry *ent;
	int i;
	char *buf;

	/* allocate all data structures first for easy error handling */
	obj = MALLOC(sizeof(AXP));
	buf = MALLOC(AXP_BUFSIZE);
	ent = MALLOC(sizeof(*ent));
	if (obj == NULL || buf == NULL || ent == NULL)
		goto free_and_return;

	obj->parser = XML_ParserCreate(encoding);
	if (obj->parser == NULL) {
		goto free_and_return;
	}
	XML_SetUserData(obj->parser, obj);

	/* XXX? copy? */
	obj->schema = as;

	obj->userdata = userdata;
	obj->state = AXP_PARSE_START;
	obj->tagstate = AXP_PARSE_TAG;
	obj->buf = buf;
	obj->len = 0;
	axp_register_handler(obj);

	ent->schema = obj->schema;
	for (i = 0; i < AXP_MAX_HASH_ARRAY; i++) {
		LIST_INIT(&obj->valhash[i]);
	}
	LIST_INIT(&obj->sc_stack);
	LIST_INSERT_HEAD(&obj->sc_stack, ent, next);

	return obj;

free_and_return:
	if (obj != NULL)
		 FREE(obj);
	if (buf != NULL)
		 FREE(buf);
	if (ent != NULL)
		 FREE(ent);
	return NULL;
}

int
axp_parse(AXP *obj, const char *buf, size_t len)
{
	int error;

	if (obj->state == AXP_PARSE_END)
		return -1;

	obj->state = AXP_PARSE_CONTENT;
	error = XML_Parse(obj->parser, buf, (int)len, 0);
	if (error == XML_STATUS_ERROR) {
#ifdef XML_DEBUG
		char errbuf[40 + 1];
		int offset, errlen;

		fprintf(stderr, "Parse error at line %ld:\n%s\n",
			XML_GetCurrentLineNumber(obj->parser),
			XML_ErrorString(XML_GetErrorCode(obj->parser)));
		offset = XML_GetCurrentByteCount(obj->parser);
		if (offset == 0) {
			fprintf(stderr, "No column info.\n");
		}
		else {
			errlen = len - offset;
			if (errlen > 40)
				errlen = 40;
			memcpy(errbuf, buf + offset, errlen);
			errbuf[errlen] = '\0';
			fprintf(stderr, "Error Position: %s\n", errbuf);
		}
#endif
		obj->state = AXP_PARSE_ERROR;
		return -1;
	}
	return 0;
}

int
axp_endparse(AXP *obj)
{
	int error;

	error = XML_Parse(obj->parser, 0, 0, 1); /* Done */
	if (error == XML_STATUS_ERROR) {
#if XML_DEBUG
		fprintf(stderr, "Parse error at line %ld:\n%s\n",
			XML_GetCurrentLineNumber(obj->parser),
			XML_ErrorString(XML_GetErrorCode(obj->parser)));
#endif
		obj->state = AXP_PARSE_ERROR;
		return -1;
	}
	obj->state = AXP_PARSE_END;
	return 0;
}

int
axp_destroy(AXP *obj)
{
	int i;

	if (obj != 0) {
		struct axp_schema_entry *ent;

		/* free expat parser */
		XML_ParserFree(obj->parser);
		/* free var and attr */
		for (i = 0; i < AXP_MAX_HASH_ARRAY; i++) {
			struct axp_val_storage *p;

			while ((p = LIST_FIRST(&obj->valhash[i])) != 0) {
				struct axp_attr_entry *attr;

				while ((attr = LIST_FIRST(&p->attr)) != 0) {
					LIST_REMOVE(attr, next);
					FREE(attr->prop);
					FREE(attr->value);
					FREE(attr);
				}
				LIST_REMOVE(p, next);
				if (p->type == AXP_TYPE_TEXT &&
				    p->value != NULL)
					FREE(p->value);
				FREE(p);
			}
		}
		/* free stack */
		while ((ent = LIST_FIRST(&obj->sc_stack)) != 0) {
			LIST_REMOVE(ent, next);
			FREE(ent);
		}
		/* free buffer */
		FREE(obj->buf);
		/* free obj */
		FREE(obj);
	}
	return 0;
}

int
axp_get_tagstate(AXP *obj)
{
	return obj->tagstate;
}

int
axp_set_userdata(AXP *obj, void *userdata)
{
	obj->userdata = userdata;
	return 0;
}

void *
axp_get_userdata(AXP *obj)
{
	return obj->userdata;
}

static void *
axp_find_var(AXP *obj, int tag)
{
	struct axp_val_storage *p;
	int hash;

	hash = tag % AXP_MAX_HASH_ARRAY;
	LIST_FOREACH(p, &obj->valhash[hash], next) {
		if (p->tag == tag)
			return p;
	}
	return 0;
}

/* XXX int or string */
int
axp_refer(AXP *obj, int tagtype, void *valp)
{
	struct axp_val_storage *p;
	p = axp_find_var(obj, tagtype);
	if (p) {
		*(void **)valp = p->value;
		return 0;
	} else {
		return -1;
	}
}

/*
 * note: tagtype validation is disabled now.
 */
int
axp_set(AXP *obj, int tagtype, void *valp)
{
	return axp_set_value(obj, tagtype, valp, AXP_TYPE_TEXT);
}

void
axp_reset(AXP *obj, int tagtype)
{
	struct axp_val_storage *p;

	p = axp_find_var(obj, tagtype);
	if (p) {
		struct axp_attr_entry *attr;

		/* reuse p, clear all attribute */
		while ((attr = LIST_FIRST(&p->attr)) != 0) {
			LIST_REMOVE(attr, next);
			FREE(attr->prop);
			FREE(attr->value);
			FREE(attr);
		}
	}
}

int
axp_set_value(AXP *obj, int tagtype, void *valp, int type)
{
	struct axp_val_storage *p;

	p = axp_find_var(obj, tagtype);
	if (p) {
		if (p->type == AXP_TYPE_TEXT) {
			if (p->value)
				FREE(p->value);
			if (valp)
				p->value = STRDUP(valp);
			else
				p->value = valp;
		} else {
			p->value = valp;
		}
	} else {
		int hash;

		hash = tagtype % AXP_MAX_HASH_ARRAY;
		p = MALLOC(sizeof(struct axp_val_storage));
		p->tag = tagtype;
		p->type = type;
		if (p->type == AXP_TYPE_TEXT && valp != NULL) {
			p->value = STRDUP(valp);
		} else {
			p->value = valp;
		}
		LIST_INIT(&p->attr);
		LIST_INSERT_HEAD(&obj->valhash[hash], p, next);
	}
	return 0;
}

int
axp_set_attr(AXP *obj, int tagtype, const char *prop, const char *value)
{
	struct axp_val_storage *p;
	struct axp_attr_entry *attr;

	p = axp_find_var(obj, tagtype);
	if (!p) {
		/* subset case, or empty */
		axp_set(obj, tagtype, 0);
		/* again */
		p = axp_find_var(obj, tagtype);
	}
	LIST_FOREACH(attr, &p->attr, next) {
		if (!strcmp(attr->prop, prop)) {
			/* found, overwrite value */
			FREE(attr->value);
			attr->value = STRDUP(value);
			return 0;
		}
	}
	/* not found, add new entry */
	attr = MALLOC(sizeof(*attr));
	attr->prop = STRDUP(prop);
	attr->value = STRDUP(value);
	LIST_INSERT_HEAD(&p->attr, attr, next);
	return 0;
}

const char *
axp_find_attr(AXP *obj, int tagtype, char *prop)
{
	struct axp_val_storage *p;
	struct axp_attr_entry *attr;

	p = axp_find_var(obj, tagtype);
	if (!p) {
		/* tag don't have any attribute */
		return 0;
	}
	LIST_FOREACH(attr, &p->attr, next) {
		if (!strcmp(attr->prop, prop)) {
			return attr->value;
		}
	}
	/* attribute not found */
	return 0;
}
