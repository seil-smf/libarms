/*	$Id: malloc.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>

#include <libarms/queue.h>

#include <libarms/malloc.h>

#ifdef ARMS_DEBUG
#include <libarms.h>
#include <libarms_log.h>

#include <openssl/crypto.h>

struct malloc_info {
	LIST_ENTRY(malloc_info) next;

	int magic;
	const char *fn;
	int ln;
	const char *func;
	size_t size;
	int flag;

	const char *free_fn;
	int free_ln;
	const char *free_func;
};

#define INFO_LOG(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)
#define DEBUG_LOG(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)
#define ERROR_LOG(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)

#define ARMS_ALIGNED_N(size,aligned_size) ((((size) + (aligned_size) - 1)/(aligned_size))*(aligned_size))
#define ARMS_ALIGNED_INT(size) ARMS_ALIGNED_N((size), sizeof(int))

LIST_HEAD(malloc_list, malloc_info) mlist = LIST_HEAD_INITIALIZER(mlist);

static void *
ssl_malloc_ex(size_t s, const char *f, int l)
{
	return arms_malloc(s, f, l, __func__);
}

static void *
ssl_realloc_ex(void *p, size_t s, const char *f, int l)
{
	return arms_realloc(p, s, f, l, __func__);
}

static void
ssl_free_ex(void *p)
{
	FREE(p);
}

void
arms_malloc_init(void)
{
	/* for openssl debug malloc */
	CRYPTO_set_mem_ex_functions(ssl_malloc_ex,
				    ssl_realloc_ex,
				    ssl_free_ex);
}

void *
arms_malloc(size_t size, const char *fn, int ln, const char *func)
{
	struct malloc_info *p;

	/* adjust alignment */
	size = ARMS_ALIGNED_INT(size);

	/* sizeof(int): tail marker */
	p = malloc(sizeof(struct malloc_info) + size + sizeof(int));
	if (p == NULL) {
		ERROR_LOG("malloc(%d) failed. from %s (%s:%d).",
			size, func, fn, ln);
		return NULL;
	}
	p->magic = 0x12345678;
	p->fn = fn;
	p->ln = ln;
	p->func = func;
	p->size = size;
	p->flag = 0;
	p->free_fn = "(none)";
	p->free_ln = 0;
	p->free_func = "(none)";
	LIST_INSERT_HEAD(&mlist, p, next);
#ifdef ARMS_DEBUG_MALLOC
	DEBUG_LOG("alloced %p by %s (%s:%d)", p + 1,
		  p->func, p->fn, p->ln);
#endif
	p++;
	*(int *)(((char *)p) + size) = 0xdeadbeef;
	return p;
}

void *
arms_calloc(size_t num, size_t size, const char *fn, int ln, const char *func)
{
	void *p;

	p = arms_malloc(num * size, fn, ln, func);
	memset(p, 0, num * size);
	return p;
}

void *
arms_realloc(void *ptr, size_t size, const char *fn, int ln, const char *func)
{
	struct malloc_info *p;

	/* adjust alignment */
	size = ARMS_ALIGNED_INT(size);

	p = ptr;
	p--;
	if (p->magic != 0x12345678)
		ERROR_LOG("XXX broken pointer requested by %s (%s:%d).",
			  func, fn, ln);
	if (*(int *)(((char *)ptr) + p->size) != 0xdeadbeef)
		ERROR_LOG("XXX memory broken. alloced by %s (%s:%d).",
			  p->func, p->fn, p->ln);
	if (p->flag) {
		ERROR_LOG("XXX XXX realloc free'ed pointer by %s (%s:%d) XXX XXX",
			  func, fn, ln);
		ERROR_LOG("XXX XXX alloced by %s (%s:%d) XXX XXX",
			  p->func, p->fn, p->ln);
	}
	LIST_REMOVE(p, next);
	p = realloc(p, sizeof(struct malloc_info) + size + sizeof(int));
	p->size = size;
	LIST_INSERT_HEAD(&mlist, p, next);
	p++;
	*(int *)(((char *)p) + size) = 0xdeadbeef;

	return p;
}

void
arms_free(void *ptr, const char *fn, int ln, const char *func)
{
	struct malloc_info *p;

	if (ptr == NULL) {
		ERROR_LOG("free NULL pointer from %s (%s:%d).  do nothing.",
			  func, fn, ln);
		return;
	}
	p = ptr;
	p--;
	if (p->magic != 0x12345678)
		ERROR_LOG("XXX broken pointer requested by %s (%s:%d).",
			  func, fn, ln);
	if (*(int *)(((char *)ptr) + p->size) != 0xdeadbeef)
		ERROR_LOG("XXX memory broken. alloced by %s (%s:%d).",
			  p->func, p->fn, p->ln);
	if (p->flag) {
		ERROR_LOG("XXX XXX double free pointer by %s (%s:%d) XXX XXX",
			  func, fn, ln);
		ERROR_LOG("XXX XXX alloced by %s (%s:%d) XXX XXX",
			  p->func, p->fn, p->ln);
		ERROR_LOG("XXX XXX freed by %s (%s:%d) XXX XXX",
			  p->free_func, p->free_fn, p->free_ln);
	} else {
		LIST_REMOVE(p, next);
		p->free_fn = fn;
		p->free_ln = ln;
		p->free_func = func;
#ifdef ARMS_DEBUG_MALLOC
		DEBUG_LOG("freeing %p by %s (%s:%d)", p + 1,
			  p->free_func, p->free_fn, p->free_ln);
		/* fill 0xff, for debug */
		memset(p + 1, 0xff, p->size);
#else
		/* real free, but don't check free twice. */
		free(p);
		return;
#endif
	}
	p->flag++;
}

char *
arms_strdup(const char *str, const char *fn, int ln, const char *func)
{
	char *p;

	p = arms_malloc(strlen(str) + 1, fn, ln, func);
	if (p) {
		strcpy(p, str);
	}
	return p;
}

void
arms_mcheck(void *ptr, const char *fn, int ln, const char *func)
{
	struct malloc_info *p;

	p = ptr;
	if (p == NULL) {
		ERROR_LOG("XXX pointer == NULL %s (%s:%d).", func, fn, ln);
		return;
	}
	p--;
	if (p->magic != 0x12345678)
		ERROR_LOG("XXX broken pointer requested by %s (%s:%d).",
			  func, fn, ln);
	if (*(int *)(((char *)ptr) + p->size) != 0xdeadbeef)
		ERROR_LOG("XXX memory broken. alloced by %s (%s:%d).",
			  p->func, p->fn, p->ln);
	if (p->flag) {
		ERROR_LOG("XXX XXX pointer is already free. XXX XXX");
		ERROR_LOG("XXX XXX alloced by %s (%s:%d) XXX XXX",
			  p->func, p->fn, p->ln);
		ERROR_LOG("XXX XXX freed by %s (%s:%d) XXX XXX",
			  p->free_func, p->free_fn, p->free_ln);
		return;
	}
}

void
arms_msetpos(void *ptr, const char *fn, int ln, const char *func)
{
	struct malloc_info *p;

	p = ptr;
	p--;
	p->fn = fn;
	p->ln = ln;
	p->func = func;
}

void
arms_freeall()
{
	struct malloc_info *p;
	int i;

	i = 0;
	LIST_FOREACH(p, &mlist, next) {
		char *ptr;

		if (p->magic != 0x12345678)
			ERROR_LOG("XXX broken pointer detected");
		ptr = (char *)(p + 1);
		if (*(int *)(ptr + p->size) != 0xdeadbeef)
			ERROR_LOG("XXX memory broken. alloced by %s (%s:%d).",
				  p->func, p->fn, p->ln);
		if (p->flag == 0)
			i++;
	}
	if (i > 0)
		ERROR_LOG("leak %d blocks orz", i);
	else
		ERROR_LOG("leak is not found.");
	LIST_FOREACH(p, &mlist, next) {
		if (p->flag == 0)
			ERROR_LOG("leaked %d bytes, %p by %s (%s:%d)",
				  p->size, p + 1, p->func, p->fn, p->ln);
	}
}

#endif /* ARMS_DEBUG */
