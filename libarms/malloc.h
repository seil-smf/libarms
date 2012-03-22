/*	$Id: malloc.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef ARMS_DEBUG

#include <stdlib.h>

#define MALLOC(size)     malloc(size)
#define CALLOC(num,size) calloc((num),(size))
#define REALLOC(p,size)  realloc((p),(size))
#define FREE(p)          free(p)
#define STRDUP(s)        strdup(s)
#define MCHECK(p)        /* do nothing */
#define FREEALL()	 /* do nothing */
#define MSETPOS(p)	 /* do nothing */

#else /* ARMS_DEBUG */

void arms_malloc_init(void);

void *arms_malloc(size_t, const char *, int, const char *);
void *arms_calloc(size_t, size_t, const char *, int, const char *);
void *arms_realloc(void *, size_t, const char *, int, const char *);
void arms_free(void *, const char *, int, const char *);
char *arms_strdup(const char *, const char *, int, const char *);
void arms_mcheck(void *, const char *, int, const char *);
void arms_freeall(void);
void arms_msetpos(void *, const char *, int, const char *);

#define MALLOC(size)     arms_malloc(size, __FILE__, __LINE__, __func__)
#define CALLOC(num,size) arms_calloc((num),(size), __FILE__, __LINE__, __func__)
#define REALLOC(p,size)  arms_realloc((p),(size), __FILE__, __LINE__, __func__)
#define FREE(p)          arms_free((void *)(p), __FILE__, __LINE__, __func__)
#define STRDUP(s)        arms_strdup(s, __FILE__, __LINE__, __func__)
#define MCHECK(p)        arms_mcheck(p, __FILE__, __LINE__, __func__)
#define FREEALL()	 arms_freeall()
#define MSETPOS(p)       arms_msetpos(p, __FILE__, __LINE__, __func__)
#endif
