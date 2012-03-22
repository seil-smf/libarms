/*	$Id: transaction.h 20856 2012-01-23 12:06:27Z m-oki $	*/

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

#ifndef __TRANSACTION_TRANSACTION_H__
#define __TRANSACTION_TRANSACTION_H__
/*
 * pm_type as each arms-message type.
 * compatible with classic libarms protocol part.
 *
 *  type:         "hoge-start" or "hoge-done"
 *  pm.pm_string: "hoge"
 *  ARMS message: <hoge-start-request>, -start-req, -done-req, -done-res
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#include <axp_extern.h>
#include <libarms_resource.h>

struct arms_method;
struct arms_schedule;

typedef struct tr_ctx {
	AXP *axp;	  /* must be axp_destroy before release transaction */
	void *arg;	  /* must be pm_release before release transaction */
	int parse_state;
	int read_done;
	int write_done;
	int pm_type;
	struct arms_method *pm;
	/* ARMS result (SA -> RS) */
	int result;
	/* ARMS result (RS -> SA) */
	int res_result;
	/* transaction id */
	int id;
} transaction_context_t;
typedef transaction_context_t tr_ctx_t;

/*
 * buffer memory chain for retransmit
 */
struct mem_block {
	TAILQ_ENTRY(mem_block) next;
	int len;
	int wrote;
	char buf[8192];
	char nul;
};

/*
 * Transaction class.
 */
typedef struct transaction {
	LIST_ENTRY(transaction) next;
	int num;

	/* SSL data */
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int zero;

	/* HTTP BASIC Authorizatoin data */
	const char *user;
	const char *passwd;

	/*
	 * state:
	 *  - TR_REQUEST
	 *  - TR_RESPONSE
	 *  - TR_START_REQUSET
	 *  - TR_START_RESPONSE
	 *  - TR_DONE_REQUEST
	 *  - TR_DONE_RESPONSE
	 */
	int state;
	/*
	 * compatible struct.
	 */
	tr_ctx_t tr_ctx;
	/*
	 * parser and builder function.
	 */
	int (*parser)(struct transaction *, const char *, int);
	int (*builder)(struct transaction *, char *, int, int *);

	/*
	 * message releated data (MALLOCED)
	 * freely used by parser and builder.
	 */
	void *data;
	int (*release_data)(struct transaction *);

	/*
	 * retry related information (for http client)
	 *
	 *    for (retry = 0; retry <= retry_max; retry++)
	 *      for (cur_uri = 0; cur_uri < nuri; cur_uri++)
	 *	  acess uriinfo[cur_uri];
	 *	wait retry_interval**retry [sec]
	 */
#if CONF_MAX_LS_LIST > CONF_MAX_RS_LIST
#define MAX_URIINFO	CONF_MAX_LS_LIST
#else
#define MAX_URIINFO	CONF_MAX_RS_LIST
#endif
	char *uriinfo[MAX_URIINFO];/* XXX MAX_LS,MAX_RS */
	int cur_uri; /* counter */
	int nuri;

	int retry; /* counter */
	int retry_max;
	int retry_interval;  /* base value */
	int retry_remaining; /* calculated interval */

	TAILQ_HEAD(mem_list, mem_block) head;
	struct mem_block *block;
	int total; /* content length */

	/* for configure.  rollback state. */
	int rollbacked;

	/* for ssltunnel, chunk id */
	int chunk_id;

	/* message read/write buffer */
	int len;
	char *wp;
	char buf[8192];
	char term;	/* always NUL */

	/* for push-endpoint */
	char sa_address[128]; /* XXX */
	int sa_af;
} transaction;

#if 0/*DEBUG*/
#define SET_TR_BUILDER(t, b) \
 printf("SET_TR_BUILDER(%s:%d:%s) = " #b "\n",__FILE__,__LINE__,__func__);\
 t->builder = b
#define SET_TR_PARSER(t, p) \
 printf("SET_TR_PARSER(%s:%d:%s) = " #p "\n",__FILE__,__LINE__,__func__);\
 t->parser = p
#else
#define SET_TR_BUILDER(t, b) \
 t->builder = b
#define SET_TR_PARSER(t, p) \
 t->parser = p
#endif

#define TR_REQUEST	   1
#define TR_RESPONSE        2
#define TR_DIR_MASK        0xff
#define TR_DIR(state)      ((state) & TR_DIR_MASK)

#define TR_LSPULL          (1<<8)
#define TR_RSPULL          (2<<8)
#define TR_PUSH_READY      (3<<8)
#define TR_START           (4<<8)
#define TR_DONE            (5<<8)

#define TR_PULL_DONE       (6<<8)
#define TR_PUSH_WAIT       (7<<8)
#define TR_BOOT_FAIL       (8<<8)
#define TR_TERM            (9<<8)
#define TR_REBOOT          (10<<8)

#define TR_METHOD_QUERY	   (11<<8)
#define TR_CONFIRM_START   (12<<8)
#define TR_CONFIRM_DONE    (13<<8)

#define TR_TYPE_MASK       (0xff<<8)
#define TR_TYPE(state)     ((state) & TR_TYPE_MASK)

#define TR_OUT(state) (state == TR_LSPULL_REQUEST || \
		       state == TR_RSPULL_REQUEST || \
		       state == TR_METHOD_QUERY_REQUEST || \
		       state == TR_CONFIRM_START_REQUEST || \
		       state == TR_CONFIRM_DONE_RESPONSE || \
		       state == TR_START_RESPONSE || \
		       state == TR_RESPONSE || \
		       state == TR_DONE_REQUEST)

#define TR_LSPULL_REQUEST        (TR_LSPULL|TR_REQUEST)
#define TR_LSPULL_RESPONSE       (TR_LSPULL|TR_RESPONSE)
#define TR_RSPULL_REQUEST        (TR_RSPULL|TR_REQUEST)
#define TR_RSPULL_RESPONSE       (TR_RSPULL|TR_RESPONSE)
#define TR_PUSH_READY_REQUEST    (TR_PUSH_READY|TR_REQUEST)
#define TR_PUSH_READY_RESPONSE   (TR_PUSH_READY|TR_RESPONSE)
#define TR_METHOD_QUERY_REQUEST  (TR_METHOD_QUERY|TR_REQUEST)
#define TR_METHOD_QUERY_RESPONSE (TR_METHOD_QUERY|TR_RESPONSE)
#define TR_CONFIRM_START_REQUEST  (TR_CONFIRM_START|TR_REQUEST)
#define TR_CONFIRM_START_RESPONSE (TR_CONFIRM_START|TR_RESPONSE)
#define TR_CONFIRM_DONE_REQUEST  (TR_CONFIRM_DONE|TR_REQUEST)
#define TR_CONFIRM_DONE_RESPONSE (TR_CONFIRM_DONE|TR_RESPONSE)
#define TR_START_REQUEST         (TR_START|TR_REQUEST)
#define TR_START_RESPONSE        (TR_START|TR_RESPONSE)
#define TR_DONE_REQUEST          (TR_DONE|TR_REQUEST)
#define TR_DONE_RESPONSE         (TR_DONE|TR_RESPONSE)


enum { TR_RESERVE,
       TR_HTTP_AUTH_ERROR,
       TR_WANT_READ,
       TR_READ_DONE,
       TR_WANT_WRITE,
       TR_WRITE_DONE,
       TR_WANT_RETRY,
       TR_WANT_ROLLBACK,
       TR_WANT_STOP,
       TR_PARSE_ERROR,
       TR_FATAL_ERROR,
};

LIST_HEAD(tr_list, transaction);
struct tr_list *get_tr_list(void);

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
#define sockaddr_storage sockaddr_in
#define ss_family sin_family
#endif

int arms_line_connect(arms_context_t *, int, int, struct timeval *);
int arms_line_disconnect(arms_context_t *, int, int, struct timeval *);
void arms_line_next(arms_context_t *, int);

int new_ls_pull_transaction(arms_context_t *, const char *);
int new_rs_pull_transaction(arms_context_t *, const char *);
int new_push_ready_transaction(arms_context_t *, const char *);
int new_method_query_transaction(arms_context_t *, const char *);
int new_push_transaction(int, struct sockaddr_storage *, socklen_t,
			 const char *);
int new_confirm_start_transaction(arms_context_t *, const char *,
				  const char *, int);

int arms_retry_wait(transaction *);
void arms_set_global_state(int);
int arms_get_global_state(void);

int ssl_client_retry(struct arms_schedule *, transaction *);
void arms_transaction_setup(transaction *);
void arms_transaction_free(transaction *);
void arms_tr_reset_callback_state(transaction *);
void arms_tr_ctx_free(tr_ctx_t *);

#endif /* __TRANSACTION_TRANSACTION_H__ */
