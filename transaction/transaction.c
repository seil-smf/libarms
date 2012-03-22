/*	$Id: transaction.c 20918 2012-01-27 04:31:58Z m-oki $	*/

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

#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <libarms/queue.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif
#include <sys/ioctl.h>

#include <openssl/ssl.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <armsd_conf.h> /* for ACMI */

#include <axp_extern.h>
#include <libarms/malloc.h>
#include <libarms/time.h>
#include <libarms/ssl.h>
#include <armsd_conf.h>
#include <libarms_log.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>
#include <http/http.h>

#include "compat.h"

static struct tr_list tr_list =
	LIST_HEAD_INITIALIZER(tr_list);

/* for pull (LS-PULL, RS-PULL, PUSH-READY) */
static int ssl_send_req(struct arms_schedule *, int);
static int ssl_recv_res(struct arms_schedule *, int);

/* for push */
static int ssl_req_accept(struct arms_schedule *, int);
static int ssl_req_ssl_connect(struct arms_schedule *, int);
static int ssl_recv_req(struct arms_schedule *, int);
static int ssl_send_res(struct arms_schedule *, int);
static int ssl_req_connect(struct arms_schedule *, int);

/* with proxy */
static int ssl_req_proxy_connect(struct arms_schedule *, int);
static int ssl_req_proxy_response(struct arms_schedule *, int);

/*
 * for check-transaction
 */
struct tr_list *
get_tr_list(void)
{
	return &tr_list;
}

static const char *
tr_msgstr(const transaction *tr)
{
	const tr_ctx_t *tr_ctx = &tr->tr_ctx;

	if (tr_ctx->pm)
		return tr_ctx->pm->pm_string;

	return "transaction";
}

static const char *
tr_rsstr(transaction *tr)
{
	static char buf[16];

	if (TR_TYPE(tr->state) == TR_DONE) {
		snprintf(buf, sizeof(buf), "End Point");
	} else {
		snprintf(buf, sizeof(buf), "RS[%d]", tr->cur_uri);
	}
	return buf;
}

/*
 * socket is connected or accepted
 *
 * tr->ssl
 * tr->ssl_ctx
 */
static int
ssl_setup(transaction *tr, int fd, arms_context_t *res)
{
	EVP_PKEY *mykey;
	X509 *mycert;
	X509_STORE *store;
	struct sockaddr_storage ss;
	socklen_t ss_len;
	char hostname[128];

	if (tr->state == TR_START_REQUEST) {
		tr->ssl_ctx = arms_ssl_ctx_new(ARMS_SSL_SERVER_METHOD);
	} else {
		tr->ssl_ctx = arms_ssl_ctx_new(ARMS_SSL_CLIENT_METHOD);
	}
	if (tr->ssl_ctx == NULL) {
		libarms_log(ARMS_LOG_DEBUG, "SSL_CTX_new failed.");
		return -1;
	}

	store = SSL_CTX_get_cert_store(tr->ssl_ctx);
	if (TR_TYPE(tr->state) == TR_LSPULL) {
		arms_ssl_register_cacert(res->root_ca_cert);
	} else {
		arms_ssl_register_cacert(
			acmi_get_cert_idx(res->acmi, ACMI_CONFIG_CONFSOL, 0));
	}
	X509_STORE_add_cert(store, arms_ssl_cacert());
	SSL_CTX_set_verify_depth(tr->ssl_ctx, SSL_VERIFY_DEPTH);
	tr->ssl = arms_ssl_new(tr->ssl_ctx);
	if (tr->ssl == NULL) {
		libarms_log(ARMS_LOG_DEBUG, "SSL_new failed.");
		return -1;
	}
	SSL_set_fd(tr->ssl, fd); 

	mycert = arms_ssl_mycert();
	mykey =  arms_ssl_mykey();
	if (mycert) {
		if (SSL_use_certificate(tr->ssl, mycert) != 1) {
			libarms_log(ARMS_LOG_DEBUG, "SSL_use_certificate failed.");
			return -1;
		}
	}
	if (mykey) {
		if (SSL_use_PrivateKey(tr->ssl, mykey) != 1) {
			libarms_log(ARMS_LOG_DEBUG, "SSL_use_PrivateKey failed.");
			return -1;
		}
		if (SSL_check_private_key(tr->ssl) != 1) {
			return -1;
		}
	}
	SSL_set_ex_data(tr->ssl, 0, tr);
	SSL_set_verify(tr->ssl, SSL_VERIFY_PEER,
		       arms_ssl_servercert_verify_cb);

	memset(&ss, 0, sizeof(ss));
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN) && !defined(__OpenBSD__)
	ss_len = ss.ss_len = sizeof(ss);
#else
	ss_len = sizeof(ss);
#endif
	if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) == 0) {
		if (getnameinfo((struct sockaddr *)&ss, ss_len,
				hostname, sizeof(hostname), NULL, 0,
				NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
			tr->sa_af = ss.ss_family;
			strlcpy(tr->sa_address, hostname,
			        sizeof(tr->sa_address));
		}
	}

	return 0;
}

static void
ssl_close(transaction *tr)
{
	if (tr->ssl) {
		arms_ssl_shutdown(tr->ssl);
		arms_ssl_free(tr->ssl);
		tr->ssl = NULL;
	}
	if (tr->ssl_ctx) {
		arms_ssl_ctx_free(tr->ssl_ctx);
		tr->ssl_ctx = NULL;
	}
}

/*
 * call pending callback function for output.
 * this function is useful if SSL is disconnected
 * when sending application data.
 */
void
arms_tr_reset_callback_state(transaction *tr)
{
	if (TR_OUT(tr->state) &&
	    tr->tr_ctx.pm != NULL && tr->builder != NULL &&
	    tr->uriinfo[tr->cur_uri] != NULL) {
		/* dummy call to reset state of callback. */
		int rv, len;
		do {
			rv = tr->builder(tr,
					 tr->buf, sizeof(tr->buf),
					 &len);
		} while (rv == TR_WANT_WRITE);
	}
}

void
arms_tr_ctx_free(tr_ctx_t *tr_ctx)
{
	/* release tr_ctx->arg */
	if (tr_ctx->pm != NULL) {
		if (tr_ctx->id != 0) {
			libarms_log(ARMS_LOG_DEBUG,
				    "[%d] End %s",
				    tr_ctx->id,
				    tr_ctx->pm->pm_string);
		} else {
			libarms_log(ARMS_LOG_DEBUG,
				    "[-] End %s",
				    tr_ctx->pm->pm_string);
		}
		if (tr_ctx->pm->pm_release != NULL) {
			tr_ctx->pm->pm_release(tr_ctx);
		}
	}
	/* release tr_ctx->axp */
	if (tr_ctx->axp) {
		axp_destroy(tr_ctx->axp);
		tr_ctx->axp = NULL;
	}
}

static void
tr_clean_sendbuf(transaction *tr)
{
	struct mem_block *blk;

	while ((blk = TAILQ_FIRST(&tr->head)) != NULL) {
		TAILQ_REMOVE(&tr->head, blk, next);
		FREE(blk);
	}
}

static void
tr_clean(transaction *tr)
{
	int i;

	memset(tr->buf, 0, sizeof(tr->buf));
	tr->len = 0;

	for (i = 0; (i < tr->nuri) && (i < MAX_URIINFO); i++) {
		if (tr->uriinfo[i] != NULL) {
			FREE(tr->uriinfo[i]);
			tr->uriinfo[i] = NULL;
		}
	}
	tr->cur_uri = 0;
	tr->nuri = 0;
	/* free http */
	if (tr->release_data) {
		tr->release_data(tr);
		tr->release_data = NULL;
	}
}

/*
 * public version function
 */
void
arms_transaction_free(transaction *tr)
{
	ssl_close(tr);
	tr_clean_sendbuf(tr);
	tr_clean(tr);
	FREE(tr);
}

/*
 * remove transaction from list and free it.
 */
static void
tr_remove(transaction *tr)
{
	LIST_REMOVE(tr, next);
	arms_tr_reset_callback_state(tr);
	arms_tr_ctx_free(&tr->tr_ctx);
	arms_transaction_free(tr);
}

static
void
tr_shift(transaction *tr)
{
	arms_context_t *res = arms_get_context();
	int	num_server = 0;
	int	current_server = 0;

	switch (TR_TYPE(tr->state)) {
	case TR_LSPULL:
		acmi_shift_current_server(res->acmi, ACMI_CONFIG_RSSOL, 1);
		num_server = acmi_get_num_server(res->acmi, ACMI_CONFIG_RSSOL);
		current_server = acmi_get_current_server(res->acmi, ACMI_CONFIG_RSSOL);
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
					"shift server: ACMI_CONFIG_RSSOL: %d of %d\n", current_server + 1, num_server);
#endif	/* defined(ARMS_DEBUG) */
		break;

	case TR_RSPULL:
		acmi_shift_current_server(res->acmi, ACMI_CONFIG_CONFSOL, 1);
		num_server = acmi_get_num_server(res->acmi, ACMI_CONFIG_CONFSOL);
		current_server = acmi_get_current_server(res->acmi, ACMI_CONFIG_CONFSOL);
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
					"shift server: ACMI_CONFIG_CONFSOL: %d of %d\n", current_server + 1, num_server);
#endif	/* defined(ARMS_DEBUG) */
		break;

	default:
	/* ignore */
		break;
	}
}


/*
 * start
 */
void
arms_transaction_setup(transaction *tr)
{
	arms_context_t *res = arms_get_context();
	const char *url;
	int i;
	int	num_server = 0;
	int	current_server = 0;
	tr_ctx_t *tr_ctx;

	tr_ctx = &tr->tr_ctx;
	switch (TR_TYPE(tr->state)) {
	case TR_LSPULL:
		tr->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_RSSOL);
		tr->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_RSSOL);
		num_server = acmi_get_num_server(res->acmi, ACMI_CONFIG_RSSOL);
		current_server = acmi_get_current_server(res->acmi, ACMI_CONFIG_RSSOL);
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
		    "current server: ACMI_CONFIG_RSSOL: %d of %d\n",
		    current_server + 1, num_server);
#endif	/* defined(ARMS_DEBUG) */
		for (i = 0; i < num_server; i++) {
			url = acmi_refer_url(res->acmi,
					     ACMI_CONFIG_RSSOL,
					     ACMI_MODULO_SHIFT(current_server, i, num_server));
			if (url == NULL)
				break;
			if (strlen(url) == 0) {
				tr->uriinfo[i] = NULL;
				break;
			}
			tr->uriinfo[i] = STRDUP(url);
#if	defined(ARMS_DEBUG)
			libarms_log(ARMS_LOG_DEBUG,
			    "uriinfo[%d] = %s\n", i, tr->uriinfo[i]);
#endif	/* defined(ARMS_DEBUG) */
		}
		tr->cur_uri = 0;
		tr->nuri = i;
		tr->tr_ctx.pm = &rs_sol_methods;
		tr->passwd = res->ls_preshared_key;
		break;

	case TR_RSPULL:
		tr->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
		tr->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
		num_server = acmi_get_num_server(res->acmi, ACMI_CONFIG_CONFSOL);
		current_server = acmi_get_current_server(res->acmi, ACMI_CONFIG_CONFSOL);
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
		    "current server: ACMI_CONFIG_CONFSOL: %d of %d\n",
		    current_server + 1, num_server);
#endif	/* defined(ARMS_DEBUG) */
		for (i = 0; i < num_server; i++) {
			url = acmi_refer_url(res->acmi,
					     ACMI_CONFIG_CONFSOL,
					     ACMI_MODULO_SHIFT(current_server, i, num_server));
			if (url == NULL)
				break;
			if (strlen(url) == 0) {
				tr->uriinfo[i] = NULL;
				break;
			}
			tr->uriinfo[i] = STRDUP(url);
#if	defined(ARMS_DEBUG)
			libarms_log(ARMS_LOG_DEBUG,
			    "uriinfo[%d] = %s\n", i, tr->uriinfo[i]);
#endif	/* defined(ARMS_DEBUG) */
		}
		tr->cur_uri = 0;
		tr->nuri = i;
		tr->passwd = res->rs_preshared_key;
		tr->tr_ctx.pm = &conf_sol_methods;
		break;
	case TR_METHOD_QUERY:
		/* like RSPULL, but method is method-query-methods */
		tr->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
		tr->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
		/* calc number of uri */
		for (tr->nuri = 0; tr->nuri < MAX_RS_INFO; tr->nuri++) {
			url = res->rs_pull_url[tr->nuri];
			if (url == NULL) {
				/* no more RS. */
				break;
			}
		}
		/* put (shifted) uri */
		for (i = 0; i < tr->nuri; i++) {
			int n = (res->rs_pull_1st + i) % tr->nuri;
			url = res->rs_pull_url[n];
			if (strlen(url) == 0) {
				tr->uriinfo[i] = NULL;
				break;
			}
			tr->uriinfo[i] = STRDUP(url);
		}
#if	defined(ARMS_DEBUG)
		for (i = 0; i < tr->nuri; i++) {
			libarms_log(ARMS_LOG_DEBUG,
				    "uriinfo[%d] = %s\n", i, tr->uriinfo[i]);
		}
#endif	/* defined(ARMS_DEBUG) */
		tr->cur_uri = 0;
		tr->passwd = res->rs_preshared_key;
		tr->tr_ctx.pm = &method_query_methods;
		break;

	case TR_CONFIRM_START:
		/* like RSPULL, but method is confirm-start-methods */
		tr->retry_interval = 0;
		tr->retry_max = 0;
		tr->cur_uri = 0;
		tr->nuri = 1;
		/* uriinfo[0] is prepared by new_confirm_start_transaction. */
		tr->passwd = res->rs_preshared_key;
		tr->tr_ctx.pm = &confirm_start_methods;
		break;

	case TR_START:
	case TR_CONFIRM_DONE:
		/*
		 * like PUSH_READY, but incoming settings.
		 * - method is unkonwn.
		 * - only one url (make from <result-url> in the request)
		 */
		tr->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
		tr->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
		tr->passwd = res->rs_preshared_key;
		return;

	case TR_DONE:
		/*
		 * like PUSH_READY, but URL is only one
		 * (and already prepared by start-req.)
		 */
		tr->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
		tr->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
		return;
	default:
		break;
	}
	if (TR_TYPE(tr->state) != TR_START &&
	    TR_TYPE(tr->state) != TR_DONE) {
		/*
		 * PULL, PUSH-READY.
		 */
		if (tr_ctx->pm != NULL) {
			if (tr_ctx->id != 0) {
				libarms_log(ARMS_LOG_DEBUG,
				    "[%d] Start %s",
				    tr_ctx->id, tr_ctx->pm->pm_string);
			} else {
				libarms_log(ARMS_LOG_DEBUG,
				    "[-] Start %s",
				    tr_ctx->pm->pm_string);
			}
			if (tr_ctx->pm->pm_context != NULL &&
			    tr_ctx->arg == NULL)
				tr_ctx->arg =
					tr_ctx->pm->pm_context(tr_ctx);
		}
	}
}

/*
 * call from libarms.
 *
 * builder: chunked or directly content builder w/ http header.
 */
int
new_ls_pull_transaction(arms_context_t *res, const char *user)
{
	transaction *tr;
	struct timeval timo;

	tr = CALLOC(1, sizeof(transaction));
	if (tr == NULL) {
		return -1;
	}
	tr->user = user;
	TAILQ_INIT(&tr->head);
	LIST_INSERT_HEAD(&tr_list, tr, next);

	tr->state = TR_LSPULL_REQUEST;

	/* server type depnded setup */
	arms_transaction_setup(tr);
	if (tr->nuri == 0) {
		libarms_log(ARMS_LOG_EHOST,
			    "LS not found.");
		res->trigger = "LS not found";
		res->result = ARMS_ESYSTEM;
		return -1;
	}

	arms_get_time_remaining(&timo, 0);
	new_arms_schedule(SCHED_TYPE_EXEC,
			  -1, &timo, ssl_req_connect, tr);
	return 0;
}

int
new_rs_pull_transaction(arms_context_t *res, const char *user)
{
	transaction *tr;
	struct timeval timo;
	int i;

	tr = CALLOC(1, sizeof(transaction));
	if (tr == NULL) {
		return -1;
	}
	tr->user = user;
	TAILQ_INIT(&tr->head);
	LIST_INSERT_HEAD(&tr_list, tr, next);

	tr->state = TR_RSPULL_REQUEST;

	/* server type depnded setup */
	arms_transaction_setup(tr);
	if (tr->nuri == 0) {
		libarms_log(ARMS_LOG_EHOST,
			    "RS not found.");
		res->trigger = "RS not found";
		res->result = ARMS_ESYSTEM;
		return -1;
	}
	for (i = 0; i < tr->nuri; i++) {
		libarms_log(ARMS_LOG_DEBUG,
		    "RS[%d]: %s", i, tr->uriinfo[i]);
	}

	arms_get_time_remaining(&timo, 0);
	new_arms_schedule(SCHED_TYPE_EXEC,
			  -1, &timo, ssl_req_connect, tr);
	return 0;
}

/*
 * push-method-query transaction.
 * call from libarms.
 *
 * builder: chunked or directly content builder w/ http header.
 */
int
new_method_query_transaction(arms_context_t *res, const char *user)
{
	transaction *tr;
	struct timeval timo;

	if (res->rs_pull_url[0] == NULL) {
		libarms_log(ARMS_LOG_EHOST,
			    "RS not found.");
		res->trigger = "push server not found";
		res->result = ARMS_ESYSTEM;
		return -1;
	}

	tr = CALLOC(1, sizeof(transaction));
	if (tr == NULL) {
		return -1;
	}
	tr->user = user;
	tr->num = res->rs_pull_1st;
	TAILQ_INIT(&tr->head);
	LIST_INSERT_HEAD(&tr_list, tr, next);

	tr->state = TR_METHOD_QUERY_REQUEST;

	/* server type depnded setup */
	arms_transaction_setup(tr);

	arms_get_time_remaining(&timo, 0);
	new_arms_schedule(SCHED_TYPE_EXEC,
			  -1, &timo, ssl_req_connect, tr);
	return 0;
}

/*
 * push-confirmation transaction.
 * call from libarms.
 *
 * builder: chunked or directly content builder w/ http header.
 */
int
new_confirm_start_transaction(arms_context_t *res, const char *user,
			      const char *rs_url, int num)
{
	transaction *tr;
	struct timeval timo;

	tr = CALLOC(1, sizeof(transaction));
	if (tr == NULL) {
		return -1;
	}
	tr->user = user;
	tr->num = num;
	TAILQ_INIT(&tr->head);
	LIST_INSERT_HEAD(&tr_list, tr, next);

	tr->state = TR_CONFIRM_START_REQUEST;

	/* server type depnded setup */
	arms_transaction_setup(tr);
	tr->uriinfo[0] = STRDUP(rs_url);

	arms_get_time_remaining(&timo, 0);
	new_arms_schedule(SCHED_TYPE_EXEC,
			  -1, &timo, ssl_req_connect, tr);

	if (arms_get_global_state() != ARMS_ST_PUSH_SENDREADY)
		libarms_log(ARMS_LOG_IPROTO_CONFIRM_START,
		    "Start push confirmation");
	arms_set_global_state(ARMS_ST_PUSH_SENDREADY);
	return 0;
}

/*
 * call from server.
 */
int
new_push_transaction(int s,
		     struct sockaddr_storage *ss, socklen_t socklen,
		     const char *user)
{
	struct timeval timo;
	transaction *tr;

	tr = CALLOC(1, sizeof(transaction));
	if (tr == NULL) {
		return -1;
	}
	tr->state = TR_START_REQUEST;
	tr->user = user;
	/* send response buffer */
	TAILQ_INIT(&tr->head);
	arms_transaction_setup(tr);
	/* default result (for retry) -- 4xx */
	tr->tr_ctx.result = 400;

	LIST_INSERT_HEAD(&tr_list, tr, next);

	SET_TR_PARSER(tr, http_request_parser);
	SET_TR_BUILDER(tr, http_response_builder);

	arms_get_time_remaining(&timo, 30);
	new_arms_schedule(SCHED_TYPE_IO,
			  s, &timo, ssl_req_accept, tr);
	return 0;
}

/*
 * called from scheduler directly.
 */
static int
ssl_req_accept(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	int rv;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
	case EVENT_TYPE_FINISH:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	/* new ssl */
	if (tr->ssl == NULL) {
		if (ssl_setup(tr, obj->fd, res) < 0) {
			tr_remove(tr);
			CLOSE_FD(obj->fd);
			return SCHED_FINISHED_THIS;
		}
	}
	rv = SSL_accept(tr->ssl);
	if (rv <= 0) {
		switch (SSL_get_error(tr->ssl, rv)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return SCHED_CONTINUE_THIS;
		default:
			libarms_log(ARMS_LOG_ESSL,
			    "SSL Connection reset by peer.");
			tr_remove(tr);
			CLOSE_FD(obj->fd);
			return SCHED_FINISHED_THIS;
		}
	}

	SET_NEW_METHOD(obj, ssl_recv_req);
	arms_get_time_remaining(&obj->timeout, 30);
	return SCHED_CONTINUE_THIS;
}

/*
 * called from scheduler directly.
 */
static int
ssl_recv_req(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	int len, n;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_READ:
		break;
	case EVENT_TYPE_WRITE:
		break;
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_DEBUG,
			    "transaction timeout id=%d",
			    tr->tr_ctx.id);
		/*FALLTHROUGH*/
	case EVENT_TYPE_FINISH:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	if (tr->parser == NULL) {
		/* request parser is nothing.  umm, bug? */
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

rerun:
	len = sizeof(tr->buf);
	if (res->fragment > 0 && len > res->fragment)
		len = res->fragment;
	if ((tr->len = n = arms_ssl_read(tr->ssl, tr->buf, len)) > 0) {
		transaction *ntr;
		int numtr, r;

		tr->zero = 0;
		/* read partly.  call parser (http_req_parser). */
		switch ((r = tr->parser(tr, tr->buf, n))) {
		case TR_PARSE_ERROR:
			goto tr_send_response;
		case TR_HTTP_AUTH_ERROR:
			goto tr_send_response;
		case TR_READ_DONE:
			numtr = 0;
			LIST_FOREACH(ntr, &tr_list, next)
				numtr++;
			if (numtr > TR_LIMIT)
				tr->tr_ctx.result = 406;
tr_send_response:
			/*
			 * start to send response.
			 * tr->builder is prepared by parser.
			 */
			tr->len = 0;
			if (tr->tr_ctx.pm != NULL &&
			    tr->tr_ctx.pm->pm_done != NULL)
				tr->state = TR_START_RESPONSE;
			else
				tr->state = TR_RESPONSE;
			obj->type = SCHED_TYPE_IOW;
			arms_get_time_remaining(&obj->timeout, 30);
			SET_NEW_METHOD(obj, ssl_send_res);
			return SCHED_CONTINUE_THIS;

		case TR_WANT_READ:
			if (SSL_pending(tr->ssl) > 0)
				goto rerun;
			return SCHED_CONTINUE_THIS;

		case TR_FATAL_ERROR:
			tr_remove(tr);
			CLOSE_FD(obj->fd);
			return SCHED_FINISHED_THIS;
		default:
			/*bug?*/
			libarms_log(ARMS_LOG_DEBUG,
				    "unknown result %d\n", r);
			break;
		}
	} else if (n == 0) {
		obj->type = SCHED_TYPE_IOR;
		return SCHED_CONTINUE_THIS;
		/*NOTREACHED*/
	} else {
		/* if configure transaction is failed,  fatal error. */
		libarms_log(ARMS_LOG_ESSL,
		    "SSL Connection reset by peer.");
		if (tr->tr_ctx.pm && tr->tr_ctx.pm->pm_rollback) {
			libarms_log(ARMS_LOG_DEBUG,
			    "configure transaction cannot continue.");
			res->result = ARMS_EPULL;
			return SCHED_FINISHED_SCHEDULER;
		}
		/* transaction is lost. */
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
		/*NOTREACHED*/
	}
	/*bug?*/
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	return SCHED_FINISHED_THIS;
}

/*
 * called from scheduler directly.
 */
static int
ssl_send_res(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	int rv;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_DEBUG,
			    "transaction timeout id=%d",
			    tr->tr_ctx.id);
		/*FALLTHROUGH*/
	case EVENT_TYPE_FINISH:
		do {
			rv = tr->builder(tr, tr->buf,
					 sizeof(tr->buf), &tr->len);
		} while (rv == TR_WANT_WRITE);
		goto err;
	case EVENT_TYPE_READ:
	case EVENT_TYPE_WRITE:
		break;
	default:
		break;
	}

	if (tr->builder == NULL) {
		/* response builder is nothing.  umm, bug? */
		goto err;
	}

rerun:
	/* fill data by builder, and write. */
	if (tr->len > 0) {
		rv = TR_WANT_WRITE;
	} else {
		/* start timer */
		arms_get_time_remaining(&obj->timeout, 30);
		rv = tr->builder(tr, tr->buf, sizeof(tr->buf), &tr->len);
		tr->wp = tr->buf;
	}
	switch (rv) {
	case TR_WANT_STOP:
		libarms_log(ARMS_LOG_DEBUG,
		    "stop scheduler requested by internal routine");
		return SCHED_FINISHED_SCHEDULER;

	case TR_WRITE_DONE:
		/* sent response. */
		if ((tr->tr_ctx.pm != NULL &&
		     tr->tr_ctx.pm->pm_done == NULL) ||
		    tr->tr_ctx.result != 100) {
			/*
			 * sync method.
			 *  or async method with error.
			 */
			/* goto err; */
			break;
		}
		/*
		 * async method.
		 * release SSL and fd, but transaction is
		 * still alive.  don't release data.
		 * tr->builder is replaced with for done-req
		 * by old tr-builder.
		 */
		ssl_close(tr);
		CLOSE_FD(obj->fd);
		tr_clean(tr);
		tr_clean_sendbuf(tr);

		/*
		 * if execution method is available, call it.
		 */
		if (tr->tr_ctx.pm != NULL && tr->tr_ctx.pm->pm_exec) {
			if (tr->tr_ctx.pm->pm_exec(tr) != 0) {
				/*
				 * exec and rollback failure.
				 * fatal.  reboot.
				 */
				res->trigger = "rollback failure";
				res->result = ARMS_EPULL;
				libarms_log(ARMS_LOG_EROLLBACK,
					    "rollback failure.");
				return SCHED_FINISHED_SCHEDULER;
			}
		}
		/*
		 * prepare for done-req.
		 */
		tr->state = TR_DONE_REQUEST;
		tr->tr_ctx.write_done = 0;
		SET_TR_BUILDER(tr, http_request_builder);
		SET_TR_PARSER(tr, http_response_parser);
		obj->type = SCHED_TYPE_TIMER;
		arms_get_time_remaining(&obj->timeout, 0);
		SET_NEW_METHOD(obj, ssl_req_connect);
		return obj->method(obj, EVENT_TYPE_EXEC);

	case TR_WANT_WRITE:
		if (tr->len == 0) {
			/* if tr->builder return 0 bytes data */
			goto rerun;
		}
		do {
			rv = arms_ssl_write(tr->ssl, tr->wp, tr->len);
			if (rv > 0) {
				arms_get_time_remaining(&obj->timeout, 30);
				tr->wp += rv;
				tr->len -= rv;
				/*refill or send */
			}
		} while (tr->len > 0 && rv > 0);
		if (tr->len == 0) {
			/* all data sent. refill */
			goto rerun;
		}
		if (rv >= 0) {
			/* no error. */
			return SCHED_CONTINUE_THIS;
		}
		libarms_log(ARMS_LOG_ESSL,
		    "SSL Connection reset by peer.");
		do {
			rv = tr->builder(tr, tr->buf,
					 sizeof(tr->buf), &tr->len);
		} while (rv == TR_WANT_WRITE);

		/* if configure transaction is failed,  fatal error. */
		if (tr->tr_ctx.pm && tr->tr_ctx.pm->pm_rollback) {
			libarms_log(ARMS_LOG_DEBUG,
				    "configure transaction cannot continue.");
			res->result = ARMS_EPULL;
			return SCHED_FINISHED_SCHEDULER;
		}
		/*FALLTHROUGH*/
	default:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;

	case TR_FATAL_ERROR:
		libarms_log(ARMS_LOG_DEBUG,
			    "fatal error detected");
		return SCHED_FINISHED_SCHEDULER;
	}
err:
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	return SCHED_FINISHED_THIS;
}

/*
 * SCHED_TYPE_EXEC or SCHED_TYPE_TIMER.
 * call from scheduler directly if retry.
 *
 * TR_LSPULL
 * TR_RSPULL
 * TR_PUSH_READY
 * TR_DONE
 */
static int
ssl_req_connect(struct arms_schedule *obj, int event)
{
	struct addrinfo hints, *re, *dst_re, *proxy_re;
	const char *url;
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	char hostname[80], port[8];
	int r, s, on, scheme;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
		    "SSL Connection failed: %s: %d.", __func__, __LINE__);
#endif	/* defined(ARMS_DEBUG) */
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		/* socket is not opened */
		tr_remove(tr);
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	default:
		break;
	}

	tr->tr_ctx.res_result = 100; /* success is default */
	dst_re = NULL;
	proxy_re = NULL;
	memset(&hints, 0, sizeof(hints));
#ifdef USE_INET6
	hints.ai_family = PF_UNSPEC;	/* any protocol such as IPv6 */
#else
	hints.ai_family = AF_INET;
#endif
	hints.ai_socktype = SOCK_STREAM;

	/* get hostname and port from URL */

	if (TR_TYPE(tr->state) == TR_DONE) {
		/* push done-request */
		url = res->rs_endpoint;
	} else {
		/* pull or push-ready. */
		url = tr->uriinfo[tr->cur_uri];
	}
	scheme = arms_parse_url(url,
				hostname, sizeof(hostname),
				port, sizeof(port), NULL, 0);
	/* invalid URL, retry next url */
	if (scheme == URL_ERROR) {
		libarms_log(ARMS_LOG_EURL, "invalid url: %s", url);
		goto soft_err;
	}
	if (scheme != URL_SCHEME_HTTPS) {
		libarms_log(ARMS_LOG_EURL,
		    "%s: scheme is not https, cannot access", url);
		goto soft_err;
	}

	r = getaddrinfo(hostname, port, &hints, &dst_re);
	if (r != 0 || dst_re == NULL) {
		libarms_log(ARMS_LOG_EHOST,
		    "failed to get host information: %s:%s",
		    hostname, port);
		goto soft_err;
	}
	/* adress family mismatched in URL and line, retry next url */
	if (tr->state == TR_LSPULL_REQUEST || tr->state == TR_RSPULL_REQUEST) {
		if (res->line_af != AF_UNSPEC &&
		    res->line_af != dst_re->ai_family) {
			libarms_log(ARMS_LOG_DEBUG,
		            "address family mismatched: %s", hostname);
			goto next_url;
		}
	}
	if (tr->state == TR_CONFIRM_START_REQUEST) {
		if (res->sa_af && res->sa_af != dst_re->ai_family) {
			libarms_log(ARMS_LOG_DEBUG,
		            "address family mismatched: %s", hostname);
			goto af_err;
		}
	}

	tr->sa_af = dst_re->ai_family;
	if (res->proxy_is_available) {
		char h[80], p[8];

		arms_parse_url(res->proxy_url,
			       h, sizeof(h),
			       p, sizeof(p), NULL, 0);
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = dst_re->ai_family;
		hints.ai_socktype = SOCK_STREAM;
		r = getaddrinfo(h, p, &hints, &proxy_re);
		if (r != 0 || proxy_re == NULL) {
			libarms_log(ARMS_LOG_DEBUG, "no web proxy available");
			goto next_url;
		}
		re = proxy_re;
	} else {
		re = dst_re;
	}

	s = socket(re->ai_family, re->ai_socktype, re->ai_protocol);
	if (s == -1) {
		/* fatal. */
		libarms_log(ARMS_LOG_ESOCKET, "socket(2) failed.");
		res->trigger = "internal error(socket)";
		goto err;
	}
#ifdef HAVE_FCNTL
	fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
	on = 1;
	ioctl(s, FIONBIO, &on);
	obj->fd = s;
	libarms_log(ARMS_LOG_DEBUG,
	    "%s: socket prepared. connecting...", tr_rsstr(tr));
	r = connect(obj->fd, re->ai_addr, re->ai_addrlen);
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	freeaddrinfo(dst_re);
	proxy_re = NULL;
	dst_re = NULL;
	if (r == 0 || errno == EINPROGRESS || errno == EINTR) {
		if (res->proxy_is_available) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssl_req_proxy_connect);
			arms_get_time_remaining(&obj->timeout, 30);
			if (r == 0)
				return obj->method(obj, EVENT_TYPE_EXEC);
			return SCHED_CONTINUE_THIS;
		}
		if (ssl_setup(tr, obj->fd, res) == 0) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssl_req_ssl_connect);
			arms_get_time_remaining(&obj->timeout, 30);
			if (tr->state == TR_METHOD_QUERY_REQUEST) {
				res->sa_af = tr->sa_af;
				strlcpy(res->sa_address, tr->sa_address,
				        sizeof(res->sa_address));
			}
			return obj->method(obj, EVENT_TYPE_EXEC);
		} else {
		}
		/* SSL_new is failed... */
	}
	libarms_log(ARMS_LOG_ECONNECT,
	    "%s: Connect error (%d).", tr_rsstr(tr), errno); 
 soft_err:
	/* failed to connect. retry? */
#if	defined(ARMS_DEBUG)
	libarms_log(ARMS_LOG_DEBUG,
	    "SSL Connection failed: %s: %d.", __func__, __LINE__);
#endif	/* defined(ARMS_DEBUG) */
	/*FALLTHROUGH*/
 next_url:
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);
	return ssl_client_retry(obj, tr);

 af_err:
	/*
	 * address family mismatched.
	 * don't retry, but other push-confirmation is working in progress.
	 */
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	return SCHED_FINISHED_THIS;

 err:
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);
	if (TR_TYPE(tr->state) == TR_PUSH_READY)
		res->result = ARMS_EPULL;
	else if (TR_TYPE(tr->state) == TR_CONFIRM_START)
		res->result = ARMS_ETIMEOUT;
	else
		res->result = ARMS_EREBOOT;

	return SCHED_FINISHED_SCHEDULER;
}

/*
 * call from scheduler directly.
 */
static int
ssl_req_proxy_connect(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	int rv;
	socklen_t optlen;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	case EVENT_TYPE_READ:
		/* initialize */
		tr->len = 0;
		break;
	default:
		break;
	}

	optlen = sizeof(rv);
	if (getsockopt(obj->fd, SOL_SOCKET, SO_ERROR, &rv, &optlen) != 0) {
		return ssl_client_retry(obj, tr);
	}
	if (rv != 0) {
		libarms_log(ARMS_LOG_ECONNECT,
		    "web proxy connect error (%d).", rv); 
		return ssl_client_retry(obj, tr);
	}
	libarms_log(ARMS_LOG_IHTTP_PROXY_CONNECTED,
	    "Connected to web proxy %s.", res->proxy_url);
	/* fill data by builder, and write. */
	if (tr->len > 0) {
	} else {
		char hostname[80], port[8];

		/* build HTTP CONNECT request */
		arms_parse_url(tr->uriinfo[tr->cur_uri],
			       hostname, sizeof(hostname),
			       port, sizeof(port), NULL, 0);

#ifdef USE_INET6
		if (tr->sa_af == AF_INET6) {
			tr->len = snprintf(tr->buf, sizeof(tr->buf),
			    "CONNECT [%s]:%s HTTP/1.1\r\n"
			    "Host: [%s]:%s\r\n\r\n",
			    hostname, port,
			    hostname, port);
		} else
#endif
		{
			tr->len = snprintf(tr->buf, sizeof(tr->buf),
			    "CONNECT %s:%s HTTP/1.1\r\n"
			    "Host: %s:%s\r\n\r\n",
			    hostname, port,
			    hostname, port);
		}
		if (tr->len < 0) {
			return ssl_client_retry(obj, tr);
		}

		tr->wp = tr->buf;
	}
	do {
		rv = write(obj->fd, tr->wp, tr->len);
		if (rv > 0) {
			arms_get_time_remaining(&obj->timeout, 30);
			tr->wp += rv;
			tr->len -= rv;
			/*refill or send */
		}
	} while (tr->len > 0 && rv > 0);
	if (tr->len == 0) {
		/* sent request.  prepare for receive response */
		obj->type = SCHED_TYPE_IOR;
		SET_NEW_METHOD(obj, ssl_req_proxy_response);
		arms_get_time_remaining(&obj->timeout, 30);
		return SCHED_CONTINUE_THIS;
	}
	if (rv >= 0) {
		/* no error. */
		return SCHED_CONTINUE_THIS;
	}

	return ssl_client_retry(obj, tr);
}

/*
 * call from scheduler directly.
 */
static int
ssl_req_proxy_response(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	default:
		break;
	}

	if ((tr->len = read(obj->fd, tr->buf, sizeof(tr->buf) - 1)) > 0) {
		int n, major, minor, result;

		tr->buf[tr->len] = '\0';
		n = sscanf(tr->buf, "HTTP/%u.%u %u",
			   &major, &minor, &result);
		if (n != 3 || result < 200 || result > 299) {
			libarms_log(ARMS_LOG_ECONNECT,
				    "web proxy server response %d", result);
			return ssl_client_retry(obj, tr);
		}

		if (ssl_setup(tr, obj->fd, res) == 0) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssl_req_ssl_connect);
			arms_get_time_remaining(&obj->timeout, 30);
			if (tr->state == TR_METHOD_QUERY_REQUEST) {
				res->sa_af = tr->sa_af;
				strlcpy(res->sa_address, tr->sa_address,
					sizeof(res->sa_address));
			}
			return obj->method(obj, EVENT_TYPE_EXEC);
		}
		/* SSL_new is failed... */
#if	defined(ARMS_DEBUG)
		libarms_log(ARMS_LOG_DEBUG,
		    "SSL Connection failed: %s: %d.", __func__, __LINE__);
#endif	/* defined(ARMS_DEBUG) */
		return ssl_client_retry(obj, tr);
	}
	return SCHED_CONTINUE_THIS;
}

/*
 * call from scheduler directly.
 */
static int
ssl_req_ssl_connect(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	int rv;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
		libarms_log(ARMS_LOG_ESSL,
		    "%s: SSL Connection timeout.", tr_rsstr(tr));
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	default:
		break;
	}

	rv = arms_ssl_connect(tr->ssl);
	if (rv == 1) {
		libarms_log(ARMS_LOG_DEBUG,
		    "%s: SSL connection established.", tr_rsstr(tr));
		obj->type = SCHED_TYPE_IO;
		SET_TR_BUILDER(tr, http_request_builder);
		SET_NEW_METHOD(obj, ssl_send_req);
		tr->len = 0;
		return ssl_send_req(obj, EVENT_TYPE_WRITE);
	}
	if (rv == 0) {
		obj->type = SCHED_TYPE_IO;
		return SCHED_CONTINUE_THIS;
	}

	libarms_log(ARMS_LOG_ESSL,
	    "%s: SSL Connection reset by peer.", tr_rsstr(tr));
	/* retry? */
	return ssl_client_retry(obj, tr);
}

int
ssl_client_retry(struct arms_schedule *obj, transaction *tr)
{
	arms_context_t *res = arms_get_context();
	tr_ctx_t *tr_ctx = &tr->tr_ctx;

	arms_tr_reset_callback_state(tr);

	tr_ctx->write_done = 0;
	tr_ctx->read_done = 0;
	tr->len = 0;
	if (tr->release_data) {
		tr->release_data(tr);
		tr->release_data = NULL;
	}
	ssl_close(tr);
	CLOSE_FD(obj->fd);

	if (tr_ctx->res_result >= 500 ||
	    (tr_ctx->res_result >= 200 && tr_ctx->res_result <= 299)) {
		res->result = ARMS_EREBOOT;
		switch(tr_ctx->res_result) {
		case 501: /* Out of service. */
			res->trigger = "received 501 Out of service";
			res->result = ARMS_EDONTRETRY;
			break;
		case 502: /* Push failed */
			res->trigger = "received 502 Push failed";
			res->result = ARMS_EPULL;
			break;
		case 503: /* Need reboot. */
			res->trigger = "received 503 Need reboot";
			break;
		default:
			res->trigger = "got result of failure from server";
			break;
		}
		libarms_log(ARMS_LOG_DEBUG,
			    "libarms got result %d from %s.",
		    tr_ctx->res_result, tr_rsstr(tr));
		return SCHED_FINISHED_SCHEDULER;
	}
#if	defined(ARMS_DEBUG)
	libarms_log(ARMS_LOG_DEBUG,
		    "res_result = %03d.", tr_ctx->res_result);
	libarms_log(ARMS_LOG_DEBUG, "retry operation start.");
#endif	/* defined(ARMS_DEBUG) */

	/* failed to send request, or failed to receive response. retry? */
	if (TR_TYPE(tr->state) != TR_DONE &&
	    TR_TYPE(tr->state) != TR_CONFIRM_START &&
	    tr_ctx->pm != NULL &&
	    tr_ctx->pm->pm_release) {
		/*
		 * pull or push-method-query.
		 * release and (re)alloc data for next URL.
		 */
		tr_ctx->pm->pm_release(tr_ctx);
		if (tr_ctx->pm->pm_context != NULL) {
			tr_ctx->arg = tr_ctx->pm->pm_context(tr_ctx);
		}
	}
	tr->state = TR_TYPE(tr->state) | TR_REQUEST;
	tr->cur_uri++;
	if (tr->nuri > 1) {
		/* shift RS index only if multiple URLs are available. */
		tr->num = tr->num + 1 % tr->nuri;
	}
	tr_shift(tr);
	if (tr->cur_uri < tr->nuri &&
	    tr->uriinfo[tr->cur_uri] != NULL) {
		/* try next server immediately */
		arms_get_time_remaining(&obj->timeout, 0);
		obj->type = SCHED_TYPE_EXEC;
		SET_NEW_METHOD(obj, ssl_req_connect);
		return SCHED_CONTINUE_THIS;
	}

	if (TR_TYPE(tr->state) == TR_LSPULL ||
	    TR_TYPE(tr->state) == TR_RSPULL) {
		/* exit immediately if method has external retry loop. */
		return SCHED_FINISHED_SCHEDULER;
	}

	/*
	 * tr_clean_sendbuf(tr) must not call!
	 * Reuse prepared send buffer by retry.
	 */
	/* re-setup uriinfo. */
	tr_clean(tr);
	arms_transaction_setup(tr);

	switch (TR_TYPE(tr->state)) {
	case TR_CONFIRM_START:
		/*
		 * parallel confirmation,
		 * scheduler shouldn't be stopped.
		 * only the transaction is finished.
		 */
		if (res->rs_pull_1st == tr->num)
			res->rs_pull_1st = -1;
		/*FALLTHROUGH*/
	case TR_DONE:
		if (tr_ctx->pm && tr_ctx->pm->pm_rollback) {
			/* configure-done-req should be retry to send. */
			break;
		}
		/*
		 * done-request/done-response: don't retry.
		 * because we can't reset application state of callback.
		 */
		libarms_log(ARMS_LOG_DEBUG,
			    "transaction is aborted.");
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	default:
		break;
	}

	/* retry? */
	if (++(tr->retry) <= tr->retry_max) {
		libarms_log(ARMS_LOG_ITRANSACTION_RETRY,
		    "retry %s (%d/%d), wait %d sec.",
		    tr_msgstr(tr),
		    tr->retry, tr->retry_max, arms_retry_wait(tr));
		arms_get_time_remaining(&obj->timeout,
					arms_retry_wait(tr));
		obj->type = SCHED_TYPE_EXEC;
		SET_NEW_METHOD(obj, ssl_req_connect);
		return SCHED_CONTINUE_THIS;
	}
	libarms_log(ARMS_LOG_ERETRY, "retry %s is over.", tr_msgstr(tr));
	/* request timeout and retry over. */

	/*
	 * clean send buffer because no more send data.
	 */
	tr_clean_sendbuf(tr);

	tr->retry = 0;
	switch (TR_TYPE(tr->state)) {
	case TR_METHOD_QUERY:
		res->trigger = "retry is over";
		res->result = ARMS_EPULL;
		return SCHED_FINISHED_SCHEDULER;
	case TR_DONE:
		if (!tr->rollbacked &&
		    tr_ctx->pm && tr_ctx->pm->pm_rollback) {
			tr_ctx->pm->pm_rollback(tr);
			SET_TR_BUILDER(tr, http_request_builder);
			arms_get_time_remaining(&obj->timeout,
					arms_retry_wait(tr));
			obj->type = SCHED_TYPE_EXEC;
			SET_NEW_METHOD(obj, ssl_req_connect);
			return SCHED_CONTINUE_THIS;
		}
		if (tr->rollbacked) {
			/*
			 * rollback result is timeout.
			 * fatal.  reboot.
			 */
			res->trigger = "rollback failure";
			res->result = ARMS_EPULL;
			libarms_log(ARMS_LOG_EROLLBACK,
			    "rollback failure.");
			return SCHED_FINISHED_SCHEDULER;
		}
		/* done-request/response is lost. ignore... */
		tr_remove(tr);
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	default:
		/*bug?*/
		break;
	}
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	res->trigger = "retry is over";
	res->result = ARMS_EREBOOT;
	return SCHED_FINISHED_THIS;
}

/*
 * call from scheduler directly.
 */
static int
ssl_send_req(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	int rv;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_ESSL,
		    "%s: SSL Connection timeout.", tr_rsstr(tr));
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		goto err;
	case EVENT_TYPE_WRITE:
	case EVENT_TYPE_READ:
	default:
		break;
	}
	if (tr->builder == NULL) {
		/* response builder is nothing.  umm, bug? */
		goto err;
	}

rerun:
	/* fill data by builder, and write. */
	if (tr->len > 0) {
		rv = TR_WANT_WRITE;
	} else {
		rv = tr->builder(tr, tr->buf, sizeof(tr->buf), &tr->len);
		tr->wp = tr->buf;
	}
	switch (rv) {
	case TR_WANT_STOP:
		if (TR_TYPE(tr->state) == TR_DONE)
			arms_set_global_state(ARMS_ST_PUSH_REBOOT);
		else
			arms_set_global_state(ARMS_ST_BOOT_FAIL);

		return SCHED_FINISHED_SCHEDULER;
	case TR_WRITE_DONE:
		/* sent request.  prepare for receive response */
		obj->type = SCHED_TYPE_IOR;
		SET_TR_PARSER(tr, http_response_parser);
		SET_NEW_METHOD(obj, ssl_recv_res);
		if (tr->state == TR_DONE_REQUEST)
			tr->state = TR_DONE_RESPONSE;
		arms_get_time_remaining(&obj->timeout, 30);
		return SCHED_CONTINUE_THIS;
	case TR_WANT_WRITE:
		if (tr->len == 0) {
			/* if tr->builder return 0 bytes data */
			goto rerun;
		}
		do {
			rv = arms_ssl_write(tr->ssl, tr->wp, tr->len);
			if (rv > 0) {
				arms_get_time_remaining(&obj->timeout, 30);
				tr->wp += rv;
				tr->len -= rv;
				/*refill or send */
			}
		} while (tr->len > 0 && rv > 0);
		if (tr->len == 0) {
			/* all data sent. refill */
			goto rerun;
		}
		if (rv >= 0) {
			/* no error. */
			return SCHED_CONTINUE_THIS;
		}
		switch (SSL_get_error(tr->ssl, rv)) {
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			return SCHED_CONTINUE_THIS;

		case SSL_ERROR_ZERO_RETURN:
			/* peer connection has been closed */
		default:
			return ssl_client_retry(obj, tr);
		}
		break;
	case TR_FATAL_ERROR:
		libarms_log(ARMS_LOG_EFATAL,
			    "fatal error from internal routine");
		return SCHED_FINISHED_SCHEDULER;
		break;
	default:
		break;
	}
err:
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	return SCHED_FINISHED_THIS;
}

/*
 * called from scheduler directly.
 */
static int
ssl_recv_res(struct arms_schedule *obj, int event)
{
	transaction *tr = obj->userdata;
	arms_context_t *res = arms_get_context();
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	int nrs;

	if (tr == NULL) {
		CLOSE_FD(obj->fd);
		return SCHED_FINISHED_THIS;
	}

	switch (event) {
	case EVENT_TYPE_READ:
		break;
	case EVENT_TYPE_WRITE:
		break;
	case EVENT_TYPE_TIMEOUT:
		SET_TR_BUILDER(tr, http_request_builder);
		return ssl_client_retry(obj, tr);
	case EVENT_TYPE_FINISH:
		goto err;
	default:
		break;
	}
	if (tr->parser == NULL) {
		/* request parser is nothing.  umm, bug? */
		goto err;
	}

rerun:
	if ((tr->len = arms_ssl_read(tr->ssl, tr->buf, sizeof(tr->buf))) > 0) {
		tr->zero = 0;
		/* read partly.  call parser. */
		switch (tr->parser(tr, tr->buf, tr->len)) {
		case TR_WANT_READ:
			if (SSL_pending(tr->ssl) > 0)
				goto rerun;
			return SCHED_CONTINUE_THIS;

		case TR_WANT_STOP:
			/*
			 * send push-ready immediately if result == ARMS_EPUSH.
			 * global state is unchanged in this case.
			 */
			if (res->result != ARMS_EPUSH) {
			    if (TR_TYPE(tr->state) == TR_DONE) {
				arms_set_global_state(ARMS_ST_PUSH_REBOOT);
			    } else {
				arms_set_global_state(ARMS_ST_BOOT_FAIL);
				res->trigger = "boot failed";
			    }
			}
			/* after return, killed by EVENT_TYPE_FINISH */
			return SCHED_FINISHED_SCHEDULER;

		case TR_WANT_ROLLBACK:
			ssl_close(tr);
			CLOSE_FD(obj->fd);
			tr_clean(tr);
			tr_clean_sendbuf(tr);
			if (!tr->rollbacked &&
			    tr_ctx->pm &&
			    tr_ctx->pm->pm_rollback != NULL &&
			    tr_ctx->pm->pm_rollback(tr) == 0) {
				SET_TR_BUILDER(tr, http_request_builder);
				arms_get_time_remaining(&obj->timeout,
							arms_retry_wait(tr));
				obj->type = SCHED_TYPE_TIMER;
				SET_NEW_METHOD(obj, ssl_req_connect);
				return SCHED_CONTINUE_THIS;
			}
			if (tr->rollbacked) {
				/*
				 * rollback result is timeout.
				 * fatal.  reboot.
				 */
				res->trigger = "rollback failure";
				res->result = ARMS_EPULL;
				libarms_log(ARMS_LOG_EROLLBACK,
					    "rollback failure.");
				return SCHED_FINISHED_SCHEDULER;
			}
			/* done-request/response is lost. ignore... */
			/*goto err;*/
			break;
			
		case TR_HTTP_AUTH_ERROR:
		case TR_PARSE_ERROR:
		case TR_WANT_RETRY:
			return ssl_client_retry(obj, tr);

		case TR_READ_DONE:
			/*
			 * response is received.
			 */
			switch (TR_TYPE(tr->state)) {
			case TR_LSPULL:
				res->result = 0;
				/* after return, killed by EVENT_TYPE_FINISH */
				return SCHED_FINISHED_SCHEDULER;

			case TR_RSPULL:
				/* make URL for push-ready */
				strlcpy(res->rs_endpoint,
					tr->uriinfo[tr->cur_uri],
					sizeof(res->rs_endpoint));
				libarms_log(ARMS_LOG_DEBUG,
				    "RS End point: %s", res->rs_endpoint);
				res->result = 0;
				/* after return, killed by EVENT_TYPE_FINISH */
				return SCHED_FINISHED_SCHEDULER;

			case TR_PUSH_READY:
				tr->state = TR_PUSH_WAIT;
				libarms_log(ARMS_LOG_IPROTO_CONFIRM_DONE,
				    "Done push confirmation");
				arms_set_global_state(ARMS_ST_PUSH_WAIT);
				res->result = 0;
				/* after return, killed by EVENT_TYPE_FINISH */
				return SCHED_FINISHED_SCHEDULER;
			case TR_METHOD_QUERY:
				res->rs_pull_1st = tr->num;
				/*FALLTHROUGH*/
			case TR_CONFIRM_START:
				if (res->rs_pull_1st == -1)
					res->rs_pull_1st = tr->num;
				/* calc number of RS. */
				for (nrs = 0; nrs < MAX_RS_INFO; nrs++) {
					if (res->rs_pull_url[nrs] == NULL) {
						/* no more RS. */
						break;
					}
				}
				if (res->rs_pull_1st == tr->num &&
				    nrs == acmi_get_num_server(res->acmi, ACMI_CONFIG_CONFSOL)) {
					/* feedback for conf-sol. */
					acmi_set_current_server(res->acmi, ACMI_CONFIG_CONFSOL, tr->num);
				}
				/*FALLTHROUGH*/
			default:
				break;
			}
			/* goto err; */
			break;

		case TR_FATAL_ERROR:
			break;
		}
	} else if (tr->len == 0) {
		return SCHED_CONTINUE_THIS;
		/*NOTREACHED*/
	} else {
		return ssl_client_retry(obj, tr);
		/*NOTREACHED*/
	}
err:
	tr_remove(tr);
	CLOSE_FD(obj->fd);
	return SCHED_FINISHED_THIS;
}
