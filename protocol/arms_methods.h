/*	$Id: arms_methods.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __ARMS_METHODS_H__
#define __ARMS_METHODS_H__

/*
 * If new method is added,
 *  (1) imprement it
 *  (2) add method HERE.
 *  (3) add method to arms_method_init() in arms_methods.c
 */
enum arms_transaction_args {
	ARMS_TR_ARG_NONE = 0,
	ARMS_TR_ARG_MODID,
	ARMS_TR_ARG_MODSUBID,

	ARMS_TR_ARG_LAST
};

enum arms_transaction_types {
	ARMS_TR_NONE = 0,
	ARMS_TR_GENERIC_ERROR,

	ARMS_TR_LSPULL,
	ARMS_TR_RSPULL,
	ARMS_TR_PUSH_READY,
	ARMS_TR_METHOD_QUERY,
	ARMS_TR_CONFIRM_START,
	ARMS_TR_CONFIRM_DONE,

	ARMS_TR_READ_STATUS,
	ARMS_TR_REBOOT,
	ARMS_TR_CONFIGURE,
	ARMS_TR_READ_STORAGE,
	ARMS_TR_CHECK_TRANSACTION,
	ARMS_TR_DUMP_DEBUG,
	ARMS_TR_PING,
	ARMS_TR_TRACEROUTE,
	ARMS_TR_READ_MODULE_LIST,
	ARMS_TR_CLEAR_STATUS,
	ARMS_TR_PULL_CONFIG,
	ARMS_TR_MD_COMMAND,

	ARMS_TR_LAST
};

/* Transaction Types */
typedef struct push_tr_type {
	int type;
	const char *str;
} push_tr_type_t;

/* Encodings */
enum {
	ARMS_DATA_TEXT = 0,
	ARMS_DATA_BINARY
};

/*
 * ARMS Method Table
 *
 * basic sequence for push:
 * 1. pm_context (allocate context structure)
 * 2. pm_copyarg (parse (*-start-)request message)
 * 3. pm_response (build (*-start-)response message)
 * 4. (send response message and wait for sent)
 * 5. pm_exec (executing request)
 * 6. pm_done (build *-done-request message)
 * 7. (send request message and wait for response)
 * 8. pm_rollback if configure and no response.
 * 9. pm_release (release context structure and related resources)
 */

typedef struct arms_method {
	uint32_t pm_type;
	char *pm_string;
	/* schema for message */
	struct axp_schema *pm_schema;

	uint32_t pm_flags;

	/* generate push start-response XML */
	int (*pm_response)(transaction *, char *, int, int *);
	/* generate done-request XML */
	int (*pm_done)(transaction *, char *, int, int *);
	/* execute push */
	int (*pm_exec) (transaction *);
	/* copy and check argument */
	int (*pm_copyarg) (AXP *, uint32_t, int tag, const char *, size_t, tr_ctx_t *);
	/* rollback */
	int (*pm_rollback) (transaction *);
	/* create context */
	void *(*pm_context) (tr_ctx_t *);
	/* release context */
	void (*pm_release) (tr_ctx_t *);
	/* response parser for pull */
	int (*pm_parse)(transaction *, const char *, int);
} arms_method_t;


/*
 * implemantations are found at protocol/
 */
extern arms_method_t generic_error_methods;

extern arms_method_t rs_sol_methods;
extern arms_method_t conf_sol_methods;
extern arms_method_t push_ready_methods;
extern arms_method_t method_query_methods;

extern arms_method_t configure_methods;
extern arms_method_t read_status_methods;
extern arms_method_t reboot_methods;
extern arms_method_t read_storage_methods;
extern arms_method_t check_transaction_methods;
extern arms_method_t dump_debug_methods;
extern arms_method_t ping_methods;
extern arms_method_t traceroute_methods;
extern arms_method_t read_module_list_methods;
extern arms_method_t clear_status_methods;
extern arms_method_t pull_config_methods;
extern arms_method_t md_command_methods;
extern arms_method_t confirm_start_methods;
extern arms_method_t confirm_done_methods;

void arms_method_init(void);
void free_arms_method_table(void);

arms_method_t *type2method(uint32_t);
int pushstr2type(const char *);
const char *pushtype2str(int);
int push_add_schema(int, const char *, struct axp_schema *);
int push_default_hook(AXP *, int, int, int, const char *, size_t, void *);

int arms_req_parser(transaction *, const char *, int);
int arms_res_parser(transaction *, const char *, int);

int arms_req_builder(transaction *, char *, int, int *);
int arms_res_builder(transaction *, char *, int, int *);

int build_generic_res(transaction *, char *, int, int *);

int arms_write_begin_message(transaction *, char *, int);
int arms_write_end_message(transaction *, char *, int);
int arms_write_empty_message(transaction *, char *, int);

const char * arms_escape(const char *);
int arms_get_encoding(AXP *, int);

#endif /* __ARMS_METHODS_H__ */
