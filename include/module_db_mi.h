/*	$Id: module_db_mi.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef _MODULE_DB_MI_H__
#define _MODULE_DB_MI_H__

struct module_cb_tbl {
	int (*get_module_cb)(const char *, void *);
	int (*purge_module_cb)(uint32_t, const char *, void *);
	void *udata;
};
typedef struct module_cb_tbl module_cb_tbl_t;

int init_module_cb(module_cb_tbl_t *);

/*
 * DB operation
 */
int add_module(int, const char *, const char *);
int sync_module(void);
int purge_all_modules(void);

char *lookup_module_ver(uint32_t);
char *lookup_module_location(uint32_t);

int arms_count_module(void);
int arms_get_module_id(uint32_t *, int);

/* XML utility functions */
uint32_t get_module_id(AXP *, int);
uint32_t get_module_order(AXP *, int);
const char *get_module_ver(AXP *, int);

int arms_dump_module(char *, int);
int arms_module_is_added(int32_t id);
int arms_module_is_exist(int32_t id);

#endif /* _MODULE_DB_MI_H__ */
