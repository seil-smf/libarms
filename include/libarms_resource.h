/*	$Id: libarms_resource.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __LIBARMS_RESOURCE_H__
#define __LIBARMS_RESOURCE_H__

#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include <time.h>

#include <libarms.h>
#include <libarms_param.h>
#include <lsconfig.h>
#include <armsd_conf.h> /* for ACMI */
#include <libhb.h>

#define MAX_METHOD_INFO 5
/*
 * Global Resource repository for libarms
 */
typedef struct arms_context {
	/* Library configurations */
	time_t timeout;			/* Global timeout value */
	size_t fragment;		/* Data fragment size */
	arms_callback_tbl_t callbacks;	/* Callback functions */
	void *udata;			/* User data for callbacks */

	/* Certifications */
	char root_ca_cert[ARMS_MAX_PEM_LEN];
	char sa_cert[ARMS_MAX_PEM_LEN];
	char sa_key[ARMS_MAX_PEM_LEN];

	/* Client ID */
	distribution_id_t dist_id;
	char version[ARMS_MAX_VER_LEN + 1];
	char description[ARMS_MAX_DESC_LEN + 1];
	char error_reason[ARMS_MAX_DESC_LEN];

	/* LS Access Info */
	ls_config_t *lsconf;

	/* RS Access Info */
	char rs_endpoint[128];
	char *rs_pull_url[MAX_RS_INFO];		/* for method-query dst */
	int rs_pull_1st;
	int last_line;

	/* LS and RS preshared key */
	char ls_preshared_key[64+1];
	char rs_preshared_key[64+1];

	/* SA Access Info */
	int line_af;
	int sa_af;
	char sa_address[128];
	char push_endpoint[128];  /* XXX: */
	/* endpoint information */
	int server_port;

	/* proposals */
	int proposed_push_port;
	int proposed_push_timeout;

	int confirm_id;

	/* push method information */
	int nmethods;
	int method_info[MAX_METHOD_INFO];
	int cur_method;

	/* push information */
	char *rs_push_address[MAX_RS_INFO];	/* for start-req src */
	char *rs_tunnel_url[MAX_RS_INFO];	/* for ssl tunnel */
	int rs_tunnel_1st;
	int tunnel_echo_interval;

	/* heartbeat info */
	int num_of_hbt;
	arms_hbt_info_t hbt_info[MAX_HBT_INFO];
	hb_context_t hb_ctx;
	int hb_running;

	/* Configutaion DB */
	ACMI *acmi;

	/* HTTP version (0=HTTP/1.0, 1=HTTP/1.1) */
	int http_preferred_version;

	/* HTTP proxy server information */
	int proxy_is_available;
	char proxy_url[128];

#ifdef HAVE_SIGNAL
	struct sigaction oldact;	/* signal() management */
#endif
	char *trigger;			/* Trigger inrfomation */
	int result;			/* Result information */
	struct timeval app_timeout;	/* app_event_cb timeout value */

	size_t bufsiz[1];
} libarms_res_t;

/* like distid2str, but buffer is statically allocated. */
char *strdistid(distribution_id_t *src);

/* 1234-5678-9abc-def0:... */
int distid2str(distribution_id_t *src, char *dst, int len);

/* 123456789abcdef... */
int distid2hex(distribution_id_t *src, char *dst, int len);


arms_context_t *arms_alloc_context(void);
arms_context_t *arms_get_context(void);
void arms_free_context(void);

void arms_sleep(unsigned int);

void arms_free_hbtinfo(arms_context_t *);
void arms_free_rsinfo(arms_context_t *);
void arms_free_rs_tunnel_url(arms_context_t *);

struct timeval;
int arms_ls_pull(arms_context_t *, const char *, struct timeval *);
int arms_rs_pull(arms_context_t *, const char *, struct timeval *);

int arms_is_running_configure(arms_context_t *);

void arms_hb_start_loop(arms_context_t *);

#endif /* __LIBARMS_RESOURCE_H__ */
