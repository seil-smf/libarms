/*	$Id: libarms.c 23863 2013-03-28 09:30:16Z m-oki $	*/

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

#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>

#include <sys/socket.h>/*test*/
#include <unistd.h>
#include <netdb.h>

#include <openssl/err.h>

#include <libarms_resource.h>
#include <libarms_log.h>
#include <lsconfig.h>
#include <armsd_conf.h>
#include <axp_extern.h>
#include <module_db_mi.h>

#include <libarms/malloc.h>
#include <libarms/ssl.h>
#include <libarms/queue.h>
#include <transaction/transaction.h>
#include <transaction/ssltunnel.h>
#include <protocol/arms_methods.h>

#include "compat.h"

void
arms_sleep(unsigned int sec)
{
	while ((sec = sleep(sec)) > 0)
	       ;
}


/*
 * API
 */
int
arms_init(distribution_id_t *distid, arms_context_t **ctxp)
{
	static const struct timeval default_app_evt_timo = { 60, 0 };
	static const char *ls_urls[] = {
		"https://202.221.49.106/arms.cgi",
		"https://202.221.51.6/arms.cgi",
#ifdef USE_INET6
		"https://[2001:240:bb88::2]/arms.cgi",
		"https://[2001:240:bb88::6]/arms.cgi",
#endif
		NULL
	};
	arms_context_t *res;
	struct _rand_seed {
		distribution_id_t distid;
		struct timeval tv;
	} rand_seed;
	int i;

	if (distid == NULL) {
		return ARMS_EINVAL;
	}
#ifdef ARMS_DEBUG
	printf("Initialize ARMS library\n");
	arms_malloc_init();
#endif

	*ctxp = res = arms_alloc_context();
	if (res == NULL) {
		return ARMS_ESYSTEM;
	}

	arms_ssl_init();

	rand_seed.distid = *distid;
	gettimeofday(&rand_seed.tv, NULL);
#ifdef HAVE_SRANDOM
	srandom(rand_seed.tv.tv_sec ^ rand_seed.tv.tv_usec);
#endif
	arms_ssl_register_randomness((char *)&rand_seed, sizeof(rand_seed));


	/* Initialize resource data */
	res->trigger = NULL;
	res->lsconf = NULL;
	res->cur_method = ARMS_PUSH_METHOD_UNKNOWN;
	memcpy(&res->dist_id, distid, sizeof(res->dist_id));
	res->line_af = AF_UNSPEC;
	arms_set_keep_push_wait(res, 1);
	arms_hb_init(&res->hb_ctx, 1024, res->dist_id);

	/* Create MI Configuration Store */
	res->acmi = acmi_create();
	if (res->acmi == NULL) {
		return ARMS_EFATAL;
	}

	/* Load Initial Configuration */
	for (i = 0; ls_urls[i] != NULL; i++) {
		acmi_set_url(res->acmi, ACMI_CONFIG_RSSOL,
			     ls_urls[i], URL_MAX_LEN, i);
	}
	acmi_set_rmax(res->acmi, ACMI_CONFIG_RSSOL, LS_RETRY_MAX);
	acmi_set_rint(res->acmi, ACMI_CONFIG_RSSOL, LS_RETRY_INT);
	acmi_set_lltimeout(res->acmi, ACMI_CONFIG_RSSOL, LLTIMEOUT);

	arms_method_init();

	arms_set_app_event_interval(res, &default_app_evt_timo);
#if 0
	print_openssl_ciphers();
#endif

#if 0
 {
	 struct addrinfo hints, *re;
	 int s, i;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo(NULL, "8080", &hints, &re);

	 for (i = 0; i < 1000; i++) {
		 s = socket(re->ai_family, re->ai_socktype, re->ai_protocol);
		 printf("s=%d\n", s);
		 close(s);
	 }
 }
#endif

	return 0;
}

/*
 * API
 */
int
arms_load_config(arms_context_t *res, const char *encrypted_config, size_t len)
{
	int i;
	char *plain;

	if (res == NULL)
		return ARMS_EFATAL;

#ifdef USE_KEY
	plain = decrypt_lsconfig((unsigned char *)encrypted_config, len);
#else
	plain = strdup(encrypted_config);
#endif
	if (plain == NULL) {
		libarms_log(ARMS_LOG_EINITIAL_CONFIG,
			    "initial config decrypt error.");
		return ARMS_EINVAL;
	}

	/* len is encrypted len.   plain length is ...??? */
	res->lsconf = parse_lsconfig(plain, len);
	if (res->lsconf == NULL) {
		libarms_log(ARMS_LOG_EINITIAL_CONFIG,
			    "initial config parse error.");
		free(plain);
		return ARMS_EINVAL;
	}
	free(plain);
#if defined(ARMS_DEBUG) && defined(DEBUG_ENABLE)
	print_lsconfig(res->lsconf);
#endif
	acmi_clear(res->acmi, ACMI_CONFIG_RSSOL);
	for (i = 0; i < res->lsconf->num_url; i++) {
		if (res->lsconf->url[i] == NULL)
			break;
		acmi_set_url(res->acmi, ACMI_CONFIG_RSSOL,
				res->lsconf->url[i], URL_MAX_LEN, i);
	}
	acmi_set_rmax(res->acmi, ACMI_CONFIG_RSSOL, res->lsconf->retry_max);
	acmi_set_rint(res->acmi, ACMI_CONFIG_RSSOL, res->lsconf->retry_int);
	acmi_set_lltimeout(res->acmi, ACMI_CONFIG_RSSOL, LLTIMEOUT);
	acmi_set_anonpppoe(res->acmi, ACMI_CONFIG_RSSOL,
			   res->lsconf->anonid, res->lsconf->anonpass);
	acmi_set_anonpppoe_ipv6(res->acmi, ACMI_CONFIG_RSSOL,
			   res->lsconf->v6anonid, res->lsconf->v6anonpass);
	acmi_set_anonmobile(res->acmi, ACMI_CONFIG_RSSOL,
			    res->lsconf->telno, res->lsconf->cid,
			    res->lsconf->apn, res->lsconf->pdp_type,
			    res->lsconf->pppid, res->lsconf->ppppass);

#if defined(ARMS_DEBUG) && defined (DEBUG_ENABLE)
	acmi_dump(res->acmi);
#endif

	return 0;
}

/*
 * API
 */
int
arms_register_cert(arms_context_t *res, const char *root_ca_cert)
{
	int err;

	if (res == NULL)
		return ARMS_EFATAL;

	if (root_ca_cert == NULL)
		return ARMS_EINVAL;

	strlcpy(res->root_ca_cert, root_ca_cert, ARMS_MAX_PEM_LEN);

#ifdef ARMS_DEBUG 
	printf("ROOT CA CERT\n");
	printf("%s", res->root_ca_cert);
#endif
	err = arms_ssl_register_cacert(res->root_ca_cert);
	if (err != 0) {
		return ARMS_EINVAL;
	}
	
	return 0;
}

/*
 * API
 */
int
arms_register_description(arms_context_t *res,
			  const char *description, const char *version)
{
	if (res == NULL)
		return ARMS_EFATAL;

	if (description != NULL) {
		if (strlen(description) > ARMS_MAX_DESC_LEN) {
			return ARMS_EINVAL;
		}
		strlcpy(res->description, description,
			sizeof(res->description));
	}
	if (version != NULL) {
		if (strlen(version) > ARMS_MAX_VER_LEN) {
			return ARMS_EINVAL;
		}
		strlcpy(res->version, version, sizeof(res->version));
	}

	return 0;
}

int
arms_register_authkey(arms_context_t *res, const char *key)
{
	if (strlen(key) > 64)
		return ARMS_EINVAL;
	strlcpy(res->ls_preshared_key, key, sizeof(res->ls_preshared_key));
	return 0;
}

/*
 * API
 * 2.20
 */
int
arms_get_rsinfo(arms_context_t *res, arms_rs_info_t *rsp, int size)
{
	int n = -1;

	if (res == (arms_context_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (rsp == (arms_rs_info_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (size < sizeof(arms_rs_info_t)) {
	/* error: too small */
		n = -1;
	}
	else {
		for (n = 0; n < MAX_RS_INFO; n++) {
			if (res->rs_push_address[n] == NULL) {
			/* reach to end of date */
				break;
			}
			if (sizeof(arms_rs_info_t) * (n + 1) > size) {
			/* skip: no more buffer */
				continue;
			}
			rsp[n].host = res->rs_push_address[n];
		}
	}

	return n;
}

/*
 * free information allocated by conf-sol
 */
void
arms_free_rsinfo(arms_context_t *res)
{
	int i;

	for (i = 0; i < MAX_RS_INFO; i++) {
		if (res->rs_push_address[i] != NULL)
			FREE(res->rs_push_address[i]);
	}
	for (i = 0; i < MAX_RS_INFO; i++) {
		if (res->rs_pull_url[i] != NULL)
			FREE(res->rs_pull_url[i]);
	}
}

/*
 * API
 * 2.20
 */
int
arms_get_proposed_push_port(arms_context_t *res)
{
	return res->proposed_push_port;
}

/*
 * API
 * 2.20
 */
int
arms_get_proposed_push_timeout(arms_context_t *res)
{
	return res->proposed_push_timeout;
}

/*
 * API
 */
int
arms_get_hbtinfo(arms_context_t *res, arms_hbt_info_t *hbp, int size)
{
	int	n = -1;

	if (res == (arms_context_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (hbp == (arms_hbt_info_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (size < 0 || size < sizeof(res->hbt_info[0])) {
	/* error: too small */
		n = -1;
	}
	else {
		for (n = 0; n < MAX_HBT_INFO; n++) {
			if (res->hbt_info[n].host == NULL) {
			/* reach to end of date */
				break;
			}
			if (sizeof(arms_hbt_info_t) * (n + 1) > size) {
			/* skip: no more buffer */
				continue;
			}
			memcpy(&(hbp[n]), &(res->hbt_info[n]), sizeof(arms_hbt_info_t));
		}
	}

	return n;
}

void
arms_free_hbtinfo(arms_context_t *res)
{
	int i;

	for (i = 0; i < res->num_of_hbt; i++) {
		int j;
		arms_hbt_info_t *hbp;

		hbp = &res->hbt_info[i];
		FREE((void *)hbp->host);
		FREE((void *)hbp->passphrase);
		for (j = 0; j < hbp->numalg; j++) {
			FREE((void *)hbp->algorithm[j]);
		}
	}
	res->num_of_hbt = 0;
}

/*
 * API
 */
int
arms_get_ls_url(arms_context_t *res, arms_url_t *urlp, int size)
{
	int	n = 0;

	if (res == (arms_context_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (urlp == (arms_url_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (size < sizeof(arms_url_t)) {
	/* error: too small */
		n = -1;
	}
	else {
		for (n = 0; n < MAX_LS_INFO; n++) {

			if (sizeof(arms_url_t) * (n + 1) > size) {
			/* skip: no more buffer */
				continue;
			}
			urlp[n].url = acmi_refer_url(res->acmi,
			    ACMI_CONFIG_RSSOL, n);
			if (urlp[n].url[0] == '\0')
				urlp[n].url = NULL;
			if (urlp[n].url == NULL)
				break;
		}
	}

	return n;
}

/*
 * API
 */
int
arms_get_rs_url(arms_context_t *res, arms_url_t *urlp, int size)
{
	int	n = 0;

	if (res == (arms_context_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (urlp == (arms_url_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (size < sizeof(arms_url_t)) {
	/* error: too small */
		n = -1;
	}
	else {
		for (n = 0; n < MAX_RS_INFO; n++) {
			if (res->rs_pull_url[n] == NULL) {
			/* reach to end of date */
				break;
			}
			if (sizeof(arms_url_t) * (n + 1) > size) {
			/* skip: no more buffer */
				continue;
			}
			urlp[n].url = res->rs_pull_url[n];
		}
	}

	return n;
}

/*
 * API
 */
int
arms_get_rs_tunnel_url(arms_context_t *res, arms_url_t *urlp, int size)
{
	int n;

	if (res == (arms_context_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (urlp == (arms_url_t*)0) {
	/* error: invalid value */
		n = -1;
	}
	else if (size < sizeof(arms_url_t)) {
	/* error: too small */
		n = -1;
	}
	else {
		for (n = 0; n < MAX_RS_INFO; n++) {
			if (res->rs_tunnel_url[n] == NULL) {
			/* reach to end of date */
				break;
			}
			if (sizeof(arms_rs_info_t) * (n + 1) > size) {
			/* skip: no more buffer */
				continue;
			}
			urlp[n].url = res->rs_tunnel_url[n];
		}
	}

	return n;
}

/*
 * free tunnel url 
 */
void
arms_free_rs_tunnel_url(arms_context_t *res)
{
	int i;

	for (i = 0; i < MAX_RS_INFO; i++) {
		if (res->rs_tunnel_url[i] != NULL) {
			FREE(res->rs_tunnel_url[i]);
			res->rs_tunnel_url[i] = NULL;
		}
	}
}

/*
 * API
 */
int
arms_set_pull_trigger(arms_context_t *res, int trigger)
{
	static const struct {
		int trigger;
		char *string;
	} trig[] = {
		{ ARMS_TRIGGER_CONFIG_ERROR, "invalid config", },
		{ ARMS_TRIGGER_SYNC_FAILED,  "module sync failed", },
	};
	int i;

	for (i = 0; i < sizeof(trig) / sizeof(trig[0]); i++) {
		if (trig[i].trigger == trigger) {
			res->trigger = trig[i].string;
			return 0;
		}
	}
	/* invalid trigger */
	return -1;
}

/*
 * API
 */
int
arms_get_connection_info(arms_context_t *res,
			 arms_connection_info_t *info,
			 int size)
{
	struct ssltunnel *tunnel;

	if (res == NULL || info == NULL) {
		return -1;
	}

	if (size != sizeof(arms_connection_info_t)) {
		return -1;
	}

	/* connection type: simple or tunnel */
	info->method = res->cur_method;

	/* protocol info */
	info->af = res->sa_af;

	/* endpoint address and port */
	if (info->method == ARMS_PUSH_METHOD_SIMPLE) {
		strlcpy(info->un.simple_info.sa_address,
			res->push_endpoint,
			sizeof(info->un.simple_info.sa_address));
		info->un.simple_info.sa_port = res->server_port;
	}
	if (info->method == ARMS_PUSH_METHOD_TUNNEL) {
		memset(info->un.tunnel_info, 0, sizeof(info->un.tunnel_info));
		LIST_FOREACH(tunnel, get_tunnel_list(), next) {
			if (tunnel->num < 0 || tunnel->num >= MAX_RS_INFO)
				continue;
			info->un.tunnel_info[tunnel->num] = ARMS_TUNNEL_ACTIVE;
		}
	}

	return 0;
}

/*
 * (internal)API
 */
int
arms_keep_push_wait(arms_context_t *res)
{
	return res->keep_wait;
}

/*
 * (internal)API
 */
int
arms_set_keep_push_wait(arms_context_t *res, int onoff)
{
	int old;

	old = res->keep_wait;
	res->keep_wait = onoff;

	return old;
}

/*
 * API
 */
void
arms_end(arms_context_t *res)
{
	/* libarms cleanup */
	purge_all_modules();
	arms_escape(NULL);

	/* OpenSSL cleanup */
	arms_ssl_cleanup();

	if (res != NULL) {
		arms_hb_end(&res->hb_ctx);
		arms_free_hbtinfo(res);
		arms_free_rsinfo(res);
		arms_free_rs_tunnel_url(res);
		if (res->lsconf != NULL) {
			free_lsconfig(res->lsconf);
			res->lsconf = NULL;
		}

		if (res->acmi != NULL) {
			acmi_destroy(res->acmi);
			res->acmi = NULL;
		}
		free_arms_method_table();
#ifndef ARMS_DEBUG
		/*
		 * in ARMS_DEBUG case, FREEALL() call log_cb in res.
		 * don't free it.
		 */
		arms_free_context();
#endif
	}
	/* for debug malloc */
	FREEALL();
}

char *
strdistid(distribution_id_t *src)
{
	static char string[MAX_DISTIDSTR + 1];
	int err;

	if (src == NULL) return NULL;

	memset(string, 0, sizeof(string));
	err = distid2str(src, string, MAX_DISTIDSTR);
	if (err < 0) {
		return NULL;
	}

	return string;
}

int
distid2str(distribution_id_t *src, char *dst, int len)
{
	if (len < 40)           /* strlen(distid) = 39, and 1 for NUL */
		return -1;

	snprintf(dst, len, "%04X-%04X-%04X-%04X-%04X-%04X-%04X-%04X",

		/* version (16bit) */
		src->version & 0xffff,

		/* vendor (32bit) */
		(src->vendor_code >> 16) & 0xffff,
		src->vendor_code & 0xffff,

		/* sa_type (16bit) */
		src->sa_type & 0xffff,

		/* sa_code (64bit) */
		(unsigned int)((src->sa_code >> 48) & 0xffff),
		(unsigned int)((src->sa_code >> 32) & 0xffff),
		(unsigned int)((src->sa_code >> 16) & 0xffff),
		(unsigned int)(src->sa_code & 0xffff));

	return 0;
}
