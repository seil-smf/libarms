/*	$Id: handler.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
 * ARMS XML processor (parser/builder).
 * it requires expat library.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <axp_extern.h>
#include <libarms/malloc.h>
#include <xml/axp_internal.h>

#undef XML_DEBUG
#ifdef XML_DEBUG
#define DPRINTF(n) printf n
#else
#define DPRINTF(n) 
#endif

static void callit(AXP *obj, struct axp_schema *sc, int when);
/*
 * libexpat handler
 *
 * <start>data</start>
 * |      |   |
 * |      |   axp_end_element
 * |      axp_char_data
 * axp_start_element
 */

static void
axp_print_stack(const AXP *obj)
{
#ifdef XML_DEBUG
	struct axp_schema_entry *ent;

	printf("current stack:\n");
	LIST_FOREACH(ent, &obj->sc_stack, next) {
		printf(" %s\n", ent->schema->as_tag);
	}
	printf("\n");
#endif
}

static struct axp_schema no_such_tag_sc[] = {
  {0, "", AXP_TYPE_CHILD, NULL, NULL, no_such_tag_sc},
  {0, NULL, 0, NULL, NULL, NULL}
};

static void XMLCALL
axp_start_element(void *userData, const char *name, const char **attr)
{
	struct axp_schema_entry *ent;
	struct axp_schema *sc = NULL;
	AXP *obj;

	DPRINTF(("axp_start_element (%s)\n", name));
	obj = userData;
	if (obj->tagstate != AXP_PARSE_TAG) {
		/* error: must not include the tag in this context. */
#ifdef XML_DEBUG
		fprintf(stderr, "axp_start_element: tagstate != TAG\n");
#endif
		return;
	}

	ent = LIST_FIRST(&obj->sc_stack);
	if (ent) {
		sc = ent->schema;
	}
	if (sc == NULL) {
		printf("XXX\n");
		return;
	}
	while (sc->as_tagtype != 0) {
		if (!strcmp(sc->as_tag, name)) {
			/* matched */
			break;
		}
		sc++;
	}
	if (sc->as_tagtype == 0) {
		/* error: tag not found in current context. */
#ifdef XML_DEBUG
		fprintf(stderr, "tag \"%s\" is invalid.\n", name);
		fprintf(stderr, "valid tag is one of:\n");
		for (sc = ent->schema; sc->as_tagtype != 0; sc++) {
			fprintf(stderr, "\t%s\n", sc->as_tag);
		}
#endif
#ifdef AXP_STRICT_TAG_CHECK
		XML_StopParser(obj->parser, XML_FALSE);
		return;
#else
		sc = no_such_tag_sc;
#endif
	}
	DPRINTF(("  (%s)\n", sc->as_tag));

	/* make (or reset) tag object */
	axp_reset(obj, sc->as_tagtype);

	/* XXX attribute matching */
	while (*attr != 0) {
		char **attr_list;
		for (attr_list = sc->as_attr; attr_list && *attr_list != 0;
			       	attr_list+=2) {
#ifdef XML_DEBUG
			fprintf(stderr, "matching attr %s vs %s\n",
					*attr, *attr_list);
#endif
			if (!strcmp(*attr, *attr_list))
				break;
		}
		if (attr_list == NULL)
			break;
		if (*attr_list == 0) {
			/* don't matched */
#ifdef XML_DEBUG
			fprintf(stderr, "attribute %s is invalid for %s\n",
				*attr, sc->as_tag);
#endif
			/*XML_StopParser(obj->parser, XML_FALSE);*/
			return;
		}
		axp_set_attr(obj, sc->as_tagtype, attr[0], attr[1]);
		/* next attribute */
		attr += 2;
	}

	if (sc->as_child != 0) {
		obj->tagstate = AXP_PARSE_TAG;
		/* 1st, pointed tag */
		ent = MALLOC(sizeof(*ent));
		ent->schema = sc;
		LIST_INSERT_HEAD(&obj->sc_stack, ent, next);
		/* 2nd, top of schema list at child */
		ent = MALLOC(sizeof(*ent));
		ent->schema = sc->as_child;
		LIST_INSERT_HEAD(&obj->sc_stack, ent, next);
	} else {
		/* reset buffer */
		obj->tagstate = AXP_PARSE_VALUE;
		ent = MALLOC(sizeof(*ent));
		ent->schema = sc;
		LIST_INSERT_HEAD(&obj->sc_stack, ent, next);
	}		
	obj->len = 0;
	axp_print_stack(obj);

	callit(obj, sc, AXP_PARSE_START);
}

static void
callit(AXP *obj, struct axp_schema *sc, int when)
{
	void *buf;
	char *endptr;
	int len;
	int intval;

	/* return if no such tag (ignore it) */
	if (sc->as_tagtype == 0)
		return;

	if (sc->as_type == AXP_TYPE_INT) {
		obj->buf[obj->len] = '\0';
		intval = (int)strtol(obj->buf, &endptr, 10);
		
		if (endptr != &obj->buf[obj->len]) {
			/* XXX error */
#ifdef XML_DEBUG
			fprintf(stderr, "%s: int but error.\n", sc->as_tag);
			fprintf(stderr, "  len:%d,  strtol next off %d\n",
				(int)obj->len, (int)(endptr - obj->buf));
			fprintf(stderr, "  buf:%s\n", obj->buf);
			fprintf(stderr, "  int:%d\n", intval);
#endif
			return;
		}
		buf = (void *)(long)intval;
		len = sizeof(int);
	} else {
		buf = obj->buf;
		len = obj->len;
		obj->buf[len] = '\0';
	}

	if (sc->as_cb != 0) {
		/* callback it */
		DPRINTF(("callback it\n"));
		if (sc->as_cb(obj,
			      when,
			      sc->as_type,
			      sc->as_tagtype,
			      buf, len,
			      obj->userdata) < 0) {
			/* error detected. stop parser. */
			XML_StopParser(obj->parser, XML_FALSE);
		}
	} else {
		if (when == AXP_PARSE_END) {
			char *buf2 = NULL;

			DPRINTF(("store it.\n"));
			/* store into object. */
			if (sc->as_type != AXP_TYPE_TEXT) {
				axp_set_value(obj, sc->as_tagtype, buf,
					      AXP_TYPE_INT);
			} else {
				/* duplicate buffer */
				if (buf != NULL) {
					buf2 = MALLOC(obj->len + 1);
					memcpy(buf2, buf, obj->len);
					/* XXX: free buf2 at last */
					buf = buf2;
					((char *)buf)[obj->len] = '\0';
				}
				axp_set_value(obj, sc->as_tagtype, buf,
					      AXP_TYPE_TEXT);
				if (buf2)
					FREE(buf2);
			}
			return;
		}
	}
	/* reset buffer */
	obj->len = 0;
}

static void XMLCALL
axp_end_element(void *userData, const char *name)
{
	AXP *obj;
	struct axp_schema_entry *ent;
	struct axp_schema *sc = NULL;

	obj = userData;
	DPRINTF(("axp_end_element (%s) len=%d\n", name, (int)obj->len));

	ent = LIST_FIRST(&obj->sc_stack);
	if (ent != 0 && obj->tagstate == AXP_PARSE_TAG) {
		LIST_REMOVE(ent, next);
		FREE(ent);
		ent = LIST_FIRST(&obj->sc_stack);
	}
	if (ent != 0)
		sc = ent->schema;
	if (sc == NULL) {
		/* error */
		printf("XXX\n");
		return;
	}
	obj->tagstate = AXP_PARSE_TAG;
	callit(obj, sc, AXP_PARSE_END);

	LIST_REMOVE(ent, next);
	FREE(ent);
	/* XXX free val_storage */
	axp_print_stack(obj);
}

static void XMLCALL
axp_char_data(void *userData, const XML_Char *str, int len)
{
	struct axp_schema_entry *ent;
	struct axp_schema *sc = NULL;
	AXP *obj;
	int avail, copysize;

	obj = userData;
	DPRINTF(("axp_char_data (len %d, obj->len %d)\n", len, (int)obj->len));
	if (obj->tagstate != AXP_PARSE_VALUE) {
		/* delimiter character */
		return;
	}
	ent = LIST_FIRST(&obj->sc_stack);
	if (ent)
		sc = ent->schema;
	if (sc == NULL) {
		/* error */
		return;
	}

	/*
	 * str: unknown length string.
	 * len: length of str.
	 * obj->buf: AXP_BUFSIZE with \0.
	 * obj->len: filled length.
	 */
	while (len > 0) {
		avail = (AXP_BUFSIZE - 1) - obj->len;
		copysize = avail > len ? len : avail;

		/* fill it */
		memcpy(&obj->buf[obj->len], str, copysize);
		obj->len += copysize;
		str += copysize;
		len -= copysize;
		/* always append trailing '\0' */
		obj->buf[obj->len] = '\0';

		if (obj->len >= AXP_BUFSIZE - 1) {
			/* callback it */
			callit(obj, sc, AXP_PARSE_CONTENT);
			obj->len = 0;
		}
	}
}

int
axp_register_handler(AXP *obj)
{
	XML_SetElementHandler(obj->parser, axp_start_element, axp_end_element);
	XML_SetCharacterDataHandler(obj->parser, axp_char_data);
	return 0;
}
