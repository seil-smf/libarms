/*	$Id: module_db_mi.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <sys/types.h>
#include <sys/queue.h>
#include <unistd.h>

#include <libarms.h>
#include <axp_extern.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include <module_db_mi.h>

#include <libarms/malloc.h>

module_cb_tbl_t mod_cb_tbl = {
	NULL,
	NULL,
	NULL
};

/* missing macro in sys/queue.h (montavista linux case.) */
#ifndef LIST_HEAD_INITIALIZER
#define LIST_HEAD_INITIALIZER(head) { NULL }
#endif
#ifndef LIST_FOREACH
#define	LIST_FOREACH(var, head, field)					\
	for ((var) = ((head)->lh_first);				\
		(var);							\
		(var) = ((var)->field.le_next))
#endif
#ifndef LIST_FIRST
#define	LIST_FIRST(head)		((head)->lh_first)
#endif

LIST_HEAD(module_storage_head, module_storage);

struct module_storage_head new =
	LIST_HEAD_INITIALIZER(module_storage_head);
struct module_storage_head addition =
	LIST_HEAD_INITIALIZER(module_storage_head);
struct module_storage_head current =
	LIST_HEAD_INITIALIZER(module_storage_head);

struct module_storage {
	uint32_t id;
	char *ver;
	char *pkg_name;
	char *url;

	LIST_ENTRY(module_storage) chain;
};

static struct module_storage *
alloc_storage(void)
{
	struct module_storage *p;

	p = MALLOC(sizeof(*p));
	if (p == NULL)
		return NULL;

	memset(p, 0, sizeof(*p));
	return p;
}

static struct module_storage *
copy_storage(struct module_storage *src)
{
	struct module_storage *cpy;

	cpy = alloc_storage();
	if (cpy == NULL)
		return NULL;

	cpy->id = src->id;
	if (src->ver != NULL)
		cpy->ver = STRDUP(src->ver);
	else
		cpy->ver = NULL;
	cpy->pkg_name = STRDUP(src->pkg_name);
	if (src->url != NULL)
		cpy->url = STRDUP(src->url);
	else
		cpy->url = NULL;

	return cpy;
}

static void
free_storage(struct module_storage *p)
{
	if (p == NULL)
		return;

	if (p->ver)
		FREE(p->ver);
	if (p->url)
		FREE(p->url);
	if (p->pkg_name)
		FREE(p->pkg_name);
	FREE(p);

	return;
}

static void
free_storage_list(struct module_storage_head *h)
{
	struct module_storage *p;

	if (h == NULL)
		return;

	while ( (p = LIST_FIRST(h)) != NULL) {
		LIST_REMOVE(p, chain);
		free_storage(p);
	}

	return;
}

static char *
get_pkg_name(const char *url)
{
	return STRDUP(url);
#if 0
	char work[256 + 1];
	char *workp;
	const char *urlp;
	const char *start = NULL;

	if (strlen(url) > sizeof(work))
		return NULL;

	/* find end of scheme */
	for (urlp = url; *urlp != '/'; urlp++)
		;
	while (*urlp == '/')
		urlp++;

	start = urlp;
	/* find directory separater */
	while (*urlp != '\0') {
		if (*urlp == '/') {
			while (*urlp == '/') urlp++;
			start = urlp;
		}
		urlp++;
	}

	/* is file name specified? */
	if (start == NULL)
		return NULL;

	/* copy until '.' found */
	memset(work, 0, sizeof(work));
	workp = work;
	urlp = start;
	while (*urlp != '\0') {
		if (*urlp == '.')
			break;
		*workp = *urlp;
		workp++;
		urlp++;
	}
	/* copy 1st '.' */
	*workp = *urlp;
	workp++;
       	urlp++;

	/* copy until '.' found */
	while (*urlp != '\0') {
		if (*urlp == '.')
			break;
		*workp = *urlp;
		workp++;
		urlp++;
	}
		
	/* terminate */
	*workp = '\0';

	return STRDUP(work);
#endif
}

static struct module_storage *
find_current(uint32_t id, const char*ver, const char *pkg_name)
{
	struct module_storage *p;

	LIST_FOREACH(p, &current, chain) {
		if (p->id != id)
			continue;
		if (p->ver == NULL && ver != NULL)
			continue;
		if (p->ver != NULL && ver == NULL)
			continue;
		if (p->ver != NULL && strcmp(p->ver, ver) != 0)
			continue;

		return p;
	};

	return NULL;
}

int
add_module(int id, const char *ver, const char *url)
{
	struct module_storage *p;

	p = alloc_storage();
	if (p == NULL)
		return -1;

	p->id = id;
	if (ver != NULL)
		p->ver = STRDUP(ver);
	if (url != NULL)
		p->url = STRDUP(url);
	p->pkg_name = get_pkg_name(url);

	LIST_INSERT_HEAD(&new, p, chain);

	return 0;
}

static int
get_module(char *url)
{
	if (mod_cb_tbl.get_module_cb != NULL) {
		return (*mod_cb_tbl.get_module_cb)(url, mod_cb_tbl.udata);
	}

	return 0;
}

static int
purge_module(uint32_t id, char *pkg_name)
{
	if (mod_cb_tbl.purge_module_cb != NULL) {
		return (*mod_cb_tbl.purge_module_cb)(id, pkg_name,
						     mod_cb_tbl.udata);
	}

	return 0;
}

/*
 * update current module list.  sync with 'new'.
 */
int
sync_module(void)
{
	struct module_storage *p, *c, *n;
	int err;
	int failed = 0;
#if 0
	int nmod_sys, retry = 0;
#endif

	/*
	 * first, lookup additional module and removal module.
	 */
	LIST_FOREACH(p, &new, chain) {
		c = find_current(p->id, p->ver, p->pkg_name);
		if (c) {
			/*
			 * skip use preloaded module
			 * (remove from current list)
			 */
			LIST_REMOVE(c, chain);
			free_storage(c);
			continue;
		}
		/*
		 * not find in current
		 * (add to addition list)
		 */
		n = copy_storage(p);
		if (n) {
			LIST_INSERT_HEAD(&addition, n, chain);
		}
	}

	/*
	 * now, modules in current list is NOT includes in new list.
	 * purge unused module (call user function)
	 */
	LIST_FOREACH(p, &current, chain) {
		err = purge_module(p->id, p->pkg_name);
		if (err) {
			failed = 1;
			continue;
		}
	}

	/*
	 * install new module (call user function)
	 * note: list is not modified
	 */
	LIST_FOREACH(p, &addition, chain) {
		err = get_module(p->url);
		if (err) {
			failed = 1;
			continue;
		}
	}

	/* XXX: if (failed) ... */

	/*
	 * rebuild db
	 * copy new list to current list
	 */
	free_storage_list(&current);
	free_storage_list(&addition);
	LIST_FOREACH(p, &new, chain) {
		n = copy_storage(p);
		LIST_INSERT_HEAD(&current, n, chain);
	}
	free_storage_list(&new);

	if (failed)
		return -1;
	return 0;
}

int
purge_all_modules(void)
{
	struct module_storage *p;
	int err, failed;

	failed = 0;
	LIST_FOREACH(p, &current, chain) {
		err = purge_module(p->id, p->pkg_name);
		if (err) {
			failed = 1;
			continue;
		}
	}

	free_storage_list(&new);
	free_storage_list(&addition);
	free_storage_list(&current);

	if (failed)
		return -1;
	return 0;
}

uint32_t
get_module_id(AXP *axp, int tag)
{
	const char *mod_idstr;
	uint32_t mod_id = 0;

	if (axp == NULL) {
		return 0;
	}

	/* module-id attribute */
	mod_idstr = axp_find_attr(axp, tag, "module-id");
	if (mod_idstr) {
		if (sscanf(mod_idstr, "%u", &mod_id) != 1) {
			sscanf(mod_idstr, "0x%x", &mod_id);
		}

		return mod_id;
	}

	mod_idstr = axp_find_attr(axp, tag, "id");
	if (mod_idstr) {
		if (sscanf(mod_idstr, "%u", &mod_id) != 1) {
			sscanf(mod_idstr, "0x%x", &mod_id);
		}
		return mod_id;
	}
	return 0;
}

uint32_t
get_module_order(AXP *axp, int tag)
{
	const char *mod_idstr;
	uint32_t mod_id = 0;

	if (axp == NULL) {
		return 0;
	}

	/* module-id attribute */
	mod_idstr = axp_find_attr(axp, tag, "commit-order");
	if (mod_idstr) {
		if (sscanf(mod_idstr, "%u", &mod_id) != 1) {
			sscanf(mod_idstr, "0x%x", &mod_id);
		}

		return mod_id;
	}
	return 0;
}

const char *
get_module_ver(AXP *axp, int tag)
{
	const char *ver_str;

	if (axp == NULL) {
		return 0;
	}

	/* module-id attribute */
	ver_str = axp_find_attr(axp, tag, "version");

	return ver_str;
}

char *
lookup_module_ver(uint32_t id)
{
	struct module_storage *p;

	LIST_FOREACH(p, &current, chain) {
		if (p->id == id)
			return p->ver;
	}
	return NULL;
}

char *
lookup_module_location(uint32_t id)
{
	struct module_storage *p;

	LIST_FOREACH(p, &current, chain) {
		if (p->id == id)
			return p->url;
	}
	return NULL;
}

int
init_module_cb(module_cb_tbl_t *tbl)
{
	if (tbl == NULL)
		return -1;

	memset(&mod_cb_tbl, 0, sizeof(mod_cb_tbl));
	mod_cb_tbl.get_module_cb = tbl->get_module_cb;
	mod_cb_tbl.purge_module_cb = tbl->purge_module_cb;
	mod_cb_tbl.udata = tbl->udata;

	return 0;
}

int
arms_count_module(void)
{
	struct module_storage *p;
	int i = 0;

	LIST_FOREACH(p, &current, chain) {
		i++;
	}
	return i;
}

/* ugly implementation */
int
arms_get_module_id(uint32_t *mod_id, int n)
{
	struct module_storage *p;

	LIST_FOREACH(p, &current, chain) {
		if (n-- > 0)
			continue;
		*mod_id = p->id;
		return 0;
	}

	/* not found */
	return -1;
}

/*
 * rv: wrote bytes (exclude trailer NUL)
 */
int
arms_dump_module(char *buf, int len)
{
	struct module_storage *p;
	int size, total;

	total = 0;
	LIST_FOREACH(p, &current, chain) {
		size = snprintf(buf, len,
				"<module id=\"%d\" version=\"%s\">",
				p->id,
				p->ver != NULL ? arms_escape(p->ver) : "");
		buf += size;
		len -= size;
		total += size;
		size = snprintf(buf, len,
				"%s</module>",
				p->url != NULL ? arms_escape(p->url) : "");
		buf += size;
		len -= size;
		total += size;
	}
	return total;
}

int
arms_module_is_added(int32_t id)
{
	struct module_storage *p;

	LIST_FOREACH(p, &new, chain) {
		if (p->id == id)
			return 1;
	}
	return 0;
}

int
arms_module_is_exist(int32_t id)
{
	struct module_storage *p;

	LIST_FOREACH(p, &current, chain) {
		if (p->id == id)
			return 1;
	}
	return 0;
}
