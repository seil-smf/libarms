/*	$Id: ssltunnel.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef _SSLTUNNEL_H_
#define _SSLTUNNEL_H_

#include <transaction/transaction.h>

struct ssltunnel {
	LIST_ENTRY(ssltunnel) next;
	int num;

	char host[80], port[8], path[80];
	int sa_af;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int state;

	int id; /* chunk id for read */
	int chunklen;

	int wid; /* chunk id for write */
	int wflag; /* chunk header write flag */

	/* write buffer */
	char buf[8192 + sizeof('\0')];
	char *p;
	int wlen;
	/* read buffer */
	char rbuf[8192 + sizeof('\0')];
	char *rp;
	int rlen;

	int retry;
	int retry_interval;
	int retry_max;

	struct transaction *write_tr;	/* current transaction (w) */
	struct tr_list tr_list;		/* ALL transactions on this tunnel */

	struct arms_schedule *obj;
	struct arms_schedule *echo;
	int echo_state;
};

/*
 * ssltunnel state
 */
enum {
	BUILD_CONFIRM_REQ,
	SEND_CONFIRM_START_REQ,
	RECV_CONFIRM_START_RES,
	RECV_CONFIRM_DONE_REQ,
	BUILD_CONFIRM_DONE_RES,
	SEND_CONFIRM_DONE_RES
};

/*
 * ssltunnel chunk type
 */
enum {
	ARMS_CHUNK_MESSAGE,
	ARMS_CHUNK_ECHO,
	ARMS_CHUNK_ECHO_REPLY,
	ARMS_CHUNK_EOM
};

/*
 * ssltunnel chunk header write flag
 */
enum {
	FLAG_WRITE_CHUNK_HEADER,
	FLAG_WRITE_CHUNK_HEADER_TRAIL,
	FLAG_WRITE_CHUNK_BODY,
	FLAG_WRITE_CHUNK_CRLF
};

/*
 * echo state
 */
enum {
	ARMS_ECHO_NONE,
	ARMS_ECHO_SENT,
};

LIST_HEAD(tunnel_list, ssltunnel);
struct tunnel_list *get_tunnel_list(void);

/* echo.c */
int arms_chunk_send_echo(struct arms_schedule *, int);

/* tunnel_chunk.c */
int arms_ssl_chunk_write_header(SSL *, int, int, int);
int arms_ssl_chunk_write_body(SSL *, char *, int);
int arms_ssl_chunk_write_trail(SSL *);
int arms_ssl_chunk_write_zero(SSL *);
int arms_ssl_chunk_parse_header(struct ssltunnel *,
				char *, int,
				int *, int *, char **, int *,
				int *);

int arms_ssltunnel_loop(arms_context_t *, int, char *[]);

#endif /*_SSLTUNNEL_H_*/
