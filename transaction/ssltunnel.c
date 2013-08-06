/*	$Id: ssltunnel.c 24211 2013-05-29 08:43:46Z yamazaki $	*/

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
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif

#include <openssl/ssl.h>

#include <libarms_log.h>
#include <libarms/base64.h>
#include <libarms/queue.h>
#include <libarms/malloc.h>
#include <libarms/sock.h>
#include <libarms/ssl.h>
#include <libarms/time.h>
#include <http/http.h>
#include <protocol/arms_methods.h>
#include <scheduler/scheduler.h>
#include <transaction/transaction.h>
#include <transaction/ssltunnel.h>

#include <arms_xml_tag.h>

#include "compat.h"

/*
 * ssltunnel.c - SSL (https) tunnel code.
 */

static int ssltunnel_connect(struct arms_schedule *, int);
static int ssltunnel_connect_ssl(struct arms_schedule *, int);
static int ssltunnel_send_httpheader(struct arms_schedule *, int);
static int ssltunnel_recv_httpheader(struct arms_schedule *, int);
static int ssltunnel_confirm(struct arms_schedule *, int);
static int new_ssltunnel(const char *, int);
static void ssltunnel_finish_transaction(struct ssltunnel *);
static int ssltunnel_retry(struct arms_schedule *, struct ssltunnel *);
static int parse_response_header(struct ssltunnel *, const char *);
static int ssltunnel_rw_loop(struct arms_schedule *, int);
static int ssltunnel_receive(struct arms_schedule *);
static int ssltunnel_send(struct arms_schedule *);
static int ssltunnel_proxy_connect(struct arms_schedule *, int);
static int ssltunnel_proxy_response(struct arms_schedule *, int);

static struct axp_schema arms_param[] = {
	{ARMS_TAG_DISTID, "distribution-id", AXP_TYPE_TEXT,
		NULL, NULL, NULL},
	{ARMS_TAG_TRANSACTION_ID, "transaction-id", AXP_TYPE_INT,
		NULL, NULL, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};

static char *arms_type_attr[] = {
	"type", NULL,
	NULL
};

static struct axp_schema arms_req_res[] = {
	{ARMS_TAG_REQ, "arms-request", AXP_TYPE_CHILD,
		arms_type_attr, NULL, arms_param},
	{ARMS_TAG_RES, "arms-response", AXP_TYPE_CHILD,
		arms_type_attr, NULL, arms_param},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct axp_schema arms_msg[] = {
	{ARMS_TAG_MSG, "arms-message", AXP_TYPE_CHILD,
		NULL, NULL, arms_req_res},
	{0, NULL, 0, NULL, NULL, NULL}
};

static struct tunnel_list tunnel_list =
	LIST_HEAD_INITIALIZER(tunnel_list);

/*
 * for check-transaction
 */
struct tunnel_list *
get_tunnel_list(void)
{
	return &tunnel_list;
}

static transaction *
ssltunnel_find_tr_with_chunk(struct ssltunnel *tunnel, int chunkid)
{
	transaction *tr;

	LIST_FOREACH(tr, &tunnel->tr_list, next) {
		if (tr->chunk_id == chunkid)
			return tr;
	}
	return NULL;
}

static transaction *
ssltunnel_find_transaction(struct ssltunnel *tunnel, int tr_id)
{
	transaction *tr;

	LIST_FOREACH(tr, &tunnel->tr_list, next) {
		if (tr->tr_ctx.id == tr_id)
			return tr;
	}
	return NULL;
}

static int
ssltunnel_setup(struct ssltunnel *tunnel, int fd, arms_context_t *res)
{
	EVP_PKEY *mykey;
	X509 *mycert;
	X509_STORE *store;

	tunnel->ssl_ctx = arms_ssl_ctx_new(ARMS_SSL_CLIENT_METHOD);
	if (tunnel->ssl_ctx == NULL)
		return -1;

	store = arms_ssl_ctx_get_cert_store(tunnel->ssl_ctx);
	arms_x509_store_add_cert(store, arms_ssl_cacert());
	arms_ssl_ctx_set_verify_depth(tunnel->ssl_ctx, SSL_VERIFY_DEPTH);
	tunnel->ssl = arms_ssl_new(tunnel->ssl_ctx);
	if (tunnel->ssl == NULL) {
		libarms_log(ARMS_LOG_ESSL,
		    "tunnel#%d: SSL_new failed.", tunnel->num);
		return -1;
	}
	arms_ssl_set_fd(tunnel->ssl, fd); 

	mycert = arms_ssl_mycert();
	mykey =  arms_ssl_mykey();
	if (mycert) {
		if (arms_ssl_use_certificate(tunnel->ssl, mycert) != 1) {
			libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d: SSL_use_certificate failed.",
			    tunnel->num);
			return -1;
		}
	}
	if (mykey) {
		if (arms_ssl_use_privatekey(tunnel->ssl, mykey) != 1) {
			libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d: SSL_use_PrivateKey failed.",
			    tunnel->num);
			return -1;
		}
		if (arms_ssl_check_private_key(tunnel->ssl) != 1) {
			return -1;
		}
	}
	arms_ssl_set_ex_data(tunnel->ssl, 0, NULL);
	arms_ssl_set_verify(tunnel->ssl, SSL_VERIFY_PEER,
	    arms_ssl_servercert_verify_cb);

	return 0;
}

static transaction *
ssltunnel_finish_tr_but_configure(struct ssltunnel *tunnel)
{
	transaction *tr, *conf_tr;

	conf_tr = NULL;
	LIST_FOREACH(tr, &tunnel->tr_list, next) {
		/*
		 * configure transaction has rollback function.
		 */
		if (tr->tr_ctx.pm && tr->tr_ctx.pm->pm_rollback) {
			LIST_REMOVE(tr, next);
			conf_tr = tr;
			switch (tr->state) {
			case TR_START_RESPONSE:
				/* reset to send configure-start response */
				tr->len = 0;
				tr->state = TR_START_RESPONSE;
				tr->tr_ctx.write_done = TR_WANT_WRITE;
				SET_TR_BUILDER(tr, arms_res_builder);
				break;
			case TR_DONE_REQUEST:
			case TR_DONE_RESPONSE:
				/* reset to send configure-done request */
				tr->len = 0;
				tr->state = TR_DONE_REQUEST;
				tr->tr_ctx.write_done = TR_WANT_WRITE;
				SET_TR_BUILDER(tr, arms_req_builder);
				tunnel->write_tr = tr;
				break;
			default:
				/* TR_START_REQUEST: */
				/* finish transaction */
				arms_tr_reset_callback_state(tr);
				arms_tr_ctx_free(&tr->tr_ctx);
				arms_transaction_free(tr);
				break;
			}
			break;
		}
	}
	ssltunnel_finish_transaction(tunnel);

	return conf_tr;
}

static void
ssltunnel_finish_transaction(struct ssltunnel *tunnel)
{
	transaction *tr;

	while ((tr = LIST_FIRST(&tunnel->tr_list)) != NULL) {
		/* work in progress transaction is removed. */
		libarms_log(ARMS_LOG_DEBUG,
			    "tunnel#%d: transaction is removed id=%d",
			    tunnel->num, tr->tr_ctx.id);
		tunnel->write_tr = NULL;
		arms_tr_reset_callback_state(tr);
		LIST_REMOVE(tr, next);
		arms_tr_ctx_free(&tr->tr_ctx);
		arms_transaction_free(tr);
	}
	tunnel->write_tr = NULL;
	tunnel->p = NULL;
	tunnel->id = 0;
	tunnel->wid = 0;
}

static void
ssltunnel_close(struct ssltunnel *tunnel, int force)
{
	arms_context_t *res = arms_get_context();

	if (tunnel->ssl) {
		/* skip SSL_shutdown if force closing */
		if (force == 0 && res->result != ARMS_EPUSH) {
			arms_ssl_chunk_write_zero(tunnel->ssl);
			arms_ssl_shutdown(tunnel->ssl);
		}
		arms_ssl_free(tunnel->ssl);
		tunnel->ssl = NULL;
	}
	if (tunnel->ssl_ctx) {
		arms_ssl_ctx_free(tunnel->ssl_ctx);
		tunnel->ssl_ctx = NULL;
	}
	if (tunnel->echo != NULL) {
		struct arms_schedule *echoobj = tunnel->echo;

		echoobj->userdata = NULL;
		tunnel->echo = NULL;
		finish_arms_schedule(echoobj);
	}
	libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: closed.", tunnel->num);
}

/*
 * for (i = 0; i < nssl; i++) {
 * 	new_ssl_tunnel(); // register schedule
 * }
 * arms_scheduler(); // run
 * // at exit scheduler, all tunnel is closed (and retry timeout).
 * // if reboot requested from RS, return ARMS_EREBOOT.
 * // if all tunnel is timeout, return ARMS_EPULL.
 *
 * 1.ssltunnel_connect
 * - new socket, new ssl, connect socket
 * 2.ssltunnel_connect_ssl
 * - connect ssl (retry self if soft failed)
 * 3.ssltunnel_send_httpheader
 * 4.ssltunnel_recv_httpheader
 * 5.ssltunnel_send_confirm_start_req
 * - new transaction
 * 6.ssltunnel_recv_confirm_start_res
 * 7.ssltunnel_recv_confirm_done_req
 * 8.ssltunnel_send_confirm_done_res
 * - delete transaction
 *
 * ssltunnel_push_loop
 *
 * ssltunnel_recv_chunk
 * - new transaction
 * - req or res? ...
 *
 */

/*
 * setup schedule and run
 *  urls: array of tunnel-url
 *
 * number of tunnel is managed by scheduler.
 */
int
arms_ssltunnel_loop(arms_context_t *res, int nurl, char *urls[])
{
	int i, rs, n;

	arms_ssl_register_cacert(
		acmi_get_cert_idx(res->acmi, ACMI_CONFIG_CONFSOL, 0));

	if (res->rs_tunnel_1st == -1)
		n = 0;
	else
		n = res->rs_tunnel_1st;
	for (i = nurl - 1; i >= 0; i--) {
		/* calc rs index. */
		rs = (i + n) % nurl;
		/* register tunnel operation */
		new_ssltunnel(urls[rs], rs);
	}
	res->rs_tunnel_1st = -1;
	res->trigger = "retry is over";
	res->result = ARMS_ETIMEOUT;
	/* go */
	libarms_log(ARMS_LOG_IPROTO_CONFIRM_START,
	    "Start push confirmation");
	arms_set_global_state(ARMS_ST_PUSH_SENDREADY);
	arms_scheduler();
	libarms_log(ARMS_LOG_DEBUG,
	    "%s: finished. result %d", __func__, res->result);
	arms_set_global_state(ARMS_ST_PUSH_REBOOT);

	return res->result;
}

static int
ssltunnel_finish(struct arms_schedule *obj, int event)
{
	return SCHED_FINISHED_SCHEDULER;
}

static void
register_ssltunnel_stopper(void)
{
	struct timeval timo;

	if (!arms_scheduler_wants_stop()) {
		arms_scheduler_mark_as_stop();
		arms_get_time_remaining(&timo, 1); /* run after 1sec. */
		new_arms_schedule(SCHED_TYPE_EXEC, -1,
				  &timo, ssltunnel_finish, 0);
	}
}

/*
 * setup and register tunnel state machine.
 */
static int
new_ssltunnel(const char *url, int num)
{
	arms_context_t *res = arms_get_context();
	struct ssltunnel *tunnel;
	struct timeval timo;
	int scheme;

	tunnel = CALLOC(1, sizeof(struct ssltunnel));
	if (tunnel == NULL) {
		return -1;
	}
	tunnel->num = num;
	scheme = arms_parse_url(url,
				tunnel->host, sizeof(tunnel->host),
				tunnel->port, sizeof(tunnel->port),
				tunnel->path, sizeof(tunnel->path));

	/* invalid URL, retry */
	if (scheme == URL_ERROR) {
		libarms_log(ARMS_LOG_EURL,
		    "tunnel#%d: invalid url: %s",
		    tunnel->num, url);
		FREE(tunnel);
		return -1;
	}
	if (scheme != URL_SCHEME_HTTPS) {
		libarms_log(ARMS_LOG_EURL,
		    "tunnel#%d: %s: scheme is not https, cannot access",
		    tunnel->num, url);
		FREE(tunnel);
		return -1;
	}
	tunnel->retry_interval =
			acmi_retry_interval(res->acmi, ACMI_CONFIG_CONFSOL);
	tunnel->retry_max =
			acmi_retry_max(res->acmi, ACMI_CONFIG_CONFSOL);
	arms_get_time_remaining(&timo, 0); /* run immediately */
	tunnel->obj = new_arms_schedule(SCHED_TYPE_EXEC, -1,
			  &timo, ssltunnel_connect, tunnel);
	LIST_INSERT_HEAD(&tunnel_list, tunnel, next);
	return 0;
}

static int
ssltunnel_connect(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	struct addrinfo hints, *re, *dst_re, *proxy_re;
	int s, r, on;

	switch (event) {
	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 1);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	default:
		break;
	}

	dst_re = NULL;
	proxy_re = NULL;
	memset(&hints, 0, sizeof(hints));
#ifdef USE_INET6
	hints.ai_family = PF_UNSPEC;	/* any protocol such as IPv6 */
#else
	hints.ai_family = AF_INET;
#endif
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	r = getaddrinfo(tunnel->host, tunnel->port, &hints, &dst_re);
	if (r != 0 || dst_re == NULL) {
		libarms_log(ARMS_LOG_EHOST,
		    "tunnel#%d: failed to get host information: %s:%s",
		    tunnel->num, tunnel->host, tunnel->port);
		goto soft_err;
	}
	if (res->sa_af && res->sa_af != dst_re->ai_family) {
		libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: address family mismatched: %s",
		    tunnel->num, tunnel->host);
		goto err;
	}
	tunnel->sa_af = dst_re->ai_family;
	if (res->proxy_is_available) {
		char host[80], port[8];

		arms_parse_url(res->proxy_url,
			       host, sizeof(host),
			       port, sizeof(port), NULL, 0);
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = dst_re->ai_family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST;
		r = getaddrinfo(host, port, &hints, &proxy_re);
		if (r != 0 || proxy_re == NULL) {
			libarms_log(ARMS_LOG_DEBUG,
			    "tunnel#%d: no web proxy available", tunnel->num);
			goto err;
		}
		re = proxy_re;
	} else {
		re = dst_re;
	}
	libarms_log(ARMS_LOG_DEBUG,
	    "tunnel#%d: try to connect %s:%s",
	    tunnel->num, tunnel->host, tunnel->port);
	s = arms_socket(re->ai_family, re->ai_socktype, re->ai_protocol);
	if (s == -1) {
		/* fatal. */
		libarms_log(ARMS_LOG_ESOCKET,
		    "tunnel#%d: socket(2) failed.", tunnel->num);
		goto err;
	}
#ifdef HAVE_FCNTL
	fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
	on = 1;
	ioctl(s, FIONBIO, &on);
	obj->fd = s;
	libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: socket prepared. connecting...", tunnel->num);
	r = arms_connect(obj->fd, re->ai_addr, re->ai_addrlen);
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);
	proxy_re = NULL;
	dst_re = NULL;
	if (r == 0 || errno == EINPROGRESS || errno == EINTR) {
		if (res->proxy_is_available) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssltunnel_proxy_connect);
			arms_get_time_remaining(&obj->timeout, 30);
			if (r == 0)
				return obj->method(obj, EVENT_TYPE_EXEC);
			return SCHED_CONTINUE_THIS;
		}
		if (ssltunnel_setup(tunnel, obj->fd, res) == 0) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssltunnel_connect_ssl);
			arms_get_time_remaining(&obj->timeout, 30);
			return obj->method(obj, EVENT_TYPE_EXEC);
		} else {
		}
		/* SSL_new is failed... */
	}
	libarms_log(ARMS_LOG_ECONNECT,
	    "tunnel#%d: connect error (%d).", tunnel->num, errno); 
 soft_err:
	/* failed to connect. retry? */
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);
	return ssltunnel_retry(obj, tunnel);

 err:
	if (res->proxy_is_available && proxy_re != NULL)
		freeaddrinfo(proxy_re);
	if (dst_re != NULL)
		freeaddrinfo(dst_re);

	ssltunnel_close(tunnel, 1);
	ssltunnel_finish_transaction(tunnel);
	LIST_REMOVE(tunnel, next);
	FREE(tunnel);
	/* finish scheduler if running tunnel does not exist. */
	if (LIST_EMPTY(&tunnel_list))
		register_ssltunnel_stopper();
	return SCHED_FINISHED_THIS;
}

/*
 * call from scheduler directly.
 */
static int
ssltunnel_proxy_connect(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	int rv;
	socklen_t optlen;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d timeout.", tunnel->num);
		return ssltunnel_retry(obj, tunnel);
	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	case EVENT_TYPE_READ:
		tunnel->rlen = 0;
	default:
		break;
	}

	optlen = sizeof(rv);
	if (arms_getsockopt(obj->fd, SOL_SOCKET, SO_ERROR, &rv, &optlen) != 0) {
		return ssltunnel_retry(obj, tunnel);
	}
	if (rv != 0) {
		libarms_log(ARMS_LOG_ECONNECT,
		    "tunnel#%d: web proxy connect error (%d).",
		    tunnel->num, rv); 
		return ssltunnel_retry(obj, tunnel);
	}
	libarms_log(ARMS_LOG_IHTTP_PROXY_CONNECTED,
	    "tunnel#%d: Connected to web proxy %s.",
	    tunnel->num, res->proxy_url);
	/* fill data by builder, and write. */
	if (tunnel->rlen > 0) {
	} else {
		/* build HTTP CONNECT request */
#ifdef USE_INET6
		if (tunnel->sa_af == AF_INET6) {
			tunnel->rlen = snprintf(tunnel->rbuf,
			    sizeof(tunnel->rbuf),
			    "CONNECT [%s]:%s HTTP/1.1\r\n"
			    "Host: [%s]:%s\r\n\r\n",
			    tunnel->host, tunnel->port,
			    tunnel->host, tunnel->port);
		} else
#endif
		{
			tunnel->rlen = snprintf(tunnel->rbuf,
			    sizeof(tunnel->rbuf),
			    "CONNECT %s:%s HTTP/1.1\r\n"
			    "Host: %s:%s\r\n\r\n",
			    tunnel->host, tunnel->port,
			    tunnel->host, tunnel->port);
		}
		if (tunnel->rlen < 0)
			return ssltunnel_retry(obj, tunnel);

		tunnel->rp = tunnel->rbuf;
	}
	do {
		rv = arms_write(obj->fd, tunnel->rp, tunnel->rlen);
		if (rv > 0) {
			arms_get_time_remaining(&obj->timeout, 30);
			tunnel->rp += rv;
			tunnel->rlen -= rv;
			/*refill or send */
		}
	} while (tunnel->rlen > 0 && rv > 0);
	if (tunnel->rlen == 0) {
		/* sent request.  prepare for receive response */
		obj->type = SCHED_TYPE_IOR;
		SET_NEW_METHOD(obj, ssltunnel_proxy_response);
		arms_get_time_remaining(&obj->timeout, 30);
		return SCHED_CONTINUE_THIS;
	}
	if (rv >= 0) {
		/* no error. */
		return SCHED_CONTINUE_THIS;
	}

	return ssltunnel_retry(obj, tunnel);
}

/*
 * call from scheduler directly.
 */
static int
ssltunnel_proxy_response(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
		libarms_log(ARMS_LOG_ESSL,
		    "tunnel#%d timeout.", tunnel->num);
		return ssltunnel_retry(obj, tunnel);
	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
	default:
		break;
	}

	tunnel->rlen = arms_read(obj->fd, tunnel->rbuf,
	    sizeof(tunnel->rbuf) - 1);
	if (tunnel->rlen > 0) {
		int n, major, minor, result;

		tunnel->rbuf[tunnel->rlen] = '\0';
		n = sscanf(tunnel->rbuf, "HTTP/%u.%u %u",
			   &major, &minor, &result);
		if (n != 3 || result < 200 || result > 299)
			return ssltunnel_retry(obj, tunnel);

		if (ssltunnel_setup(tunnel, obj->fd, res) == 0) {
			obj->type = SCHED_TYPE_IO;
			SET_NEW_METHOD(obj, ssltunnel_connect_ssl);
			arms_get_time_remaining(&obj->timeout, 30);
			return obj->method(obj, EVENT_TYPE_EXEC);
		} else {
		}
		/* SSL_new is failed... */
		libarms_log(ARMS_LOG_ECONNECT,
		    "tunnel#%d: connect error (%d).", tunnel->num, errno); 
		/* failed to connect. retry? */
		return ssltunnel_retry(obj, tunnel);
	}
	return SCHED_CONTINUE_THIS;
}

static int
ssltunnel_connect_ssl(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	int rv;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		/* failed to connect. retry? */
		libarms_log(ARMS_LOG_ESSL,
		    "tunnel#%d timeout.", tunnel->num);
		return ssltunnel_retry(obj, tunnel);
	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	case EVENT_TYPE_EXEC:
		libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: socket connected.", tunnel->num);
		break;
	default:
		break;
	}

	rv = arms_ssl_connect(tunnel->ssl);
	if (rv == 1) {
		obj->type = SCHED_TYPE_IO;
		tunnel->p = NULL;
		libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: SSL connection established.", tunnel->num);
		SET_NEW_METHOD(obj, ssltunnel_send_httpheader);
		return ssltunnel_send_httpheader(obj, EVENT_TYPE_WRITE);
	}
	if (rv == 0) {
		obj->type = SCHED_TYPE_IO;
		return SCHED_CONTINUE_THIS;
	}
	/* rv < 0 */
	libarms_log(ARMS_LOG_ESSL,
	    "tunnel#%d: SSL Connection reset by peer.", tunnel->num);
	/* retry? */
	return ssltunnel_retry(obj, tunnel);
}

static int
ssltunnel_retry(struct arms_schedule *obj, struct ssltunnel *tunnel)
{
	transaction *tr;
	arms_context_t *res = arms_get_context();

	libarms_log(ARMS_LOG_DEBUG,
	    "tunnel#%d: closing ssl tunnel and retry.", tunnel->num);
	ssltunnel_close(tunnel, 1);
	CLOSE_FD(obj->fd);
	if ((tunnel->retry_inf && !arms_is_running_configure(res)) ||
	    ++tunnel->retry <= tunnel->retry_max) {
		if (tunnel->retry_inf && !arms_is_running_configure(res)) {
			libarms_log(ARMS_LOG_ITUNNEL_RETRY,
			    "tunnel#%d: retry, wait %d sec.",
			    tunnel->num,
			    tunnel->retry_interval);
		} else {
			libarms_log(ARMS_LOG_ITUNNEL_RETRY,
			    "tunnel#%d: retry(%d/%d), wait %d sec.",
			    tunnel->num,
			    tunnel->retry, tunnel->retry_max,
			    tunnel->retry_interval);
		}
		arms_get_time_remaining(&obj->timeout, tunnel->retry_interval);
		obj->type = SCHED_TYPE_EXEC;
		SET_NEW_METHOD(obj, ssltunnel_connect);
		return SCHED_CONTINUE_THIS;
	}
	/* retry is over. */
	libarms_log(ARMS_LOG_ERETRY,
		    "tunnel#%d: retry is over.", tunnel->num);
	LIST_FOREACH(tr, &tunnel->tr_list, next) {
		if (tr->tr_ctx.pm && tr->tr_ctx.pm->pm_rollback) {
			/*
			 * configure method is found in running transaction.
			 */
			if (!tr->rollbacked &&
			    !tr->tr_ctx.pm->pm_rollback(tr)) {
				/*
				 * rollback is succeeded.
				 *  tr->rollbacked = 1 in pm_rollback().
				 */
				tunnel->retry = 0;
				arms_get_time_remaining(&obj->timeout,
				    tunnel->retry_interval);
				obj->type = SCHED_TYPE_EXEC;
				SET_NEW_METHOD(obj, ssltunnel_connect);
				return SCHED_CONTINUE_THIS;
				/*NOTREACHED*/
			} else {
				/*
				 * rollback failure.
				 * fatal.  reboot.
				 */
				res->trigger = "rollback failure";
				res->result = ARMS_EPULL;
				libarms_log(ARMS_LOG_EROLLBACK,
				    "rollback failure.");
				register_ssltunnel_stopper();
				break;
			}
		}
	}
	/*
	 * not found configure transaction still not rollbacked.
	 */
	ssltunnel_finish_transaction(tunnel);
	LIST_REMOVE(tunnel, next);
	FREE(tunnel);
	/* finish scheduler if running tunnel does not exist. */
	if (LIST_EMPTY(&tunnel_list))
		register_ssltunnel_stopper();
	return SCHED_FINISHED_THIS;
}

static const char arms_http_post_v11_chunked[] =
	"POST /%s HTTP/1.1\r\n"
	"Host: %s:%s\r\n"
	"Connection: close\r\n"
	"Content-Type: text/xml\r\n"
	"Transfer-Encoding: chunked\r\n"
	"Authorization: Basic %s\r\n"
	"\r\n";

static int
ssltunnel_send_httpheader(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	static char buf[256];
	static char encbuf[256];
	int rv;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_EHTTP,
		    "tunnel#%d: write http header timeout.",
		    tunnel->num);
		return ssltunnel_retry(obj, tunnel);

	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	if (tunnel->p == NULL) {
		/* initial setup */
		/* make userpass */
		snprintf(buf, sizeof(buf),
		    "%s:%s", strdistid(&res->dist_id), res->rs_preshared_key);
		memset(encbuf, 0, sizeof(encbuf));
		arms_base64_encode(encbuf, sizeof(encbuf), buf, strlen(buf));
		tunnel->wlen = snprintf(tunnel->buf, sizeof(tunnel->buf),
					arms_http_post_v11_chunked,
					tunnel->path,
					tunnel->host, tunnel->port,
					encbuf);
		tunnel->p = tunnel->buf;
	}

	rv = arms_ssl_write(tunnel->ssl, tunnel->p, tunnel->wlen);
	if (rv < 0) {
		return ssltunnel_retry(obj, tunnel);
	}
	arms_get_time_remaining(&obj->timeout, 30);
	tunnel->p += rv;
	tunnel->wlen -= rv;
	if (tunnel->wlen == 0) {
		SET_NEW_METHOD(obj, ssltunnel_recv_httpheader);
		obj->type = SCHED_TYPE_IOR;
		tunnel->p = NULL;
		tunnel->rp = NULL;
		libarms_log(ARMS_LOG_DEBUG,
		    "tunnel#%d: sent http header.", tunnel->num);
	}
	return SCHED_CONTINUE_THIS;
}

/*
 * receive and parse http header (response)
 */
static int
ssltunnel_recv_httpheader(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	transaction *conf_tr;
	struct timeval timo;
	int rv;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_EHTTP,
		    "tunnel#%d: read http header timeout.", tunnel->num);
		return ssltunnel_retry(obj, tunnel);

	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	if (tunnel->rp == NULL) {
		/* initial setup */
		tunnel->rp = tunnel->rbuf;
		tunnel->rlen = sizeof(tunnel->rbuf) - 1;
		memset(tunnel->rbuf, 0, sizeof(tunnel->rbuf));
	}
	rv = arms_ssl_read(tunnel->ssl, tunnel->rp, tunnel->rlen);
	if (rv < 0) {
		return ssltunnel_retry(obj, tunnel);
	} else if (rv == 0) {
		return SCHED_CONTINUE_THIS;
	}
	tunnel->rp += rv;
	tunnel->rlen -= rv;
	rv = parse_response_header(tunnel, tunnel->rbuf);
	/*
	 * received all headers?
	 */
	if (rv == TR_WANT_READ) {
		/* wait for read */
		return SCHED_CONTINUE_THIS;
	}
	/*
	 * valid header? 20x?
	 */
	if (rv != 200) {
		libarms_log(ARMS_LOG_EHTTP,
		    "tunnel#%d: http response (%d)", tunnel->num, rv);
		return ssltunnel_retry(obj, tunnel);
	}
	libarms_log(ARMS_LOG_DEBUG,
	    "tunnel#%d: received http header.", tunnel->num);
	/* register (periodic) sending echo schedule */
	arms_get_time_remaining(&timo, res->tunnel_echo_interval);
	tunnel->echo = new_arms_schedule(SCHED_TYPE_TIMER, -1,
					 &timo, arms_chunk_send_echo, obj);
	/*
	 * NOTE: if tunnel state is in-configure,
	 *  1. continue configure transaction
	 *  2. confirmation
	 * instead of confirmation at first.
	 */
	conf_tr = ssltunnel_finish_tr_but_configure(tunnel);
	if (conf_tr == NULL) {
		/*
		 * configure transaction is not found.
		 * finish transaction if exist, and confirmation.
		 */
		SET_NEW_METHOD(obj, ssltunnel_confirm);
		tunnel->write_tr = NULL;
		obj->type = SCHED_TYPE_IOW;
	} else {
		LIST_INSERT_HEAD(&tunnel->tr_list, conf_tr, next);
		SET_NEW_METHOD(obj, ssltunnel_rw_loop);
		obj->type = SCHED_TYPE_IO;
	}
	return SCHED_CONTINUE_THIS;
}

/*
 * tunnel->chunklen: remaining chunk len.
 */
static int
ssltunnel_buf_parser(struct arms_schedule *obj,
		     transaction *tr, char *readbuf, int readlen)
{
	struct ssltunnel *tunnel = obj->userdata;
	char *chunkbuf;
	int parselen, skiplen;
	int hlen, id, type, trail, rv;

	if (tunnel->chunklen == 0) {
		/* parse header */
		hlen = arms_ssl_chunk_parse_header(
				tunnel,
				readbuf, readlen,
				&type, &id, &chunkbuf,
				&tunnel->chunklen, &trail);
		if (hlen < 0) {
			tunnel->rp += readlen;
			tunnel->rlen -= readlen;
			return TR_WANT_READ;
		}
		tunnel->rp = chunkbuf;
		tunnel->rlen -= chunkbuf - readbuf;
		readlen -= chunkbuf - readbuf;
		if (type == ARMS_CHUNK_EOM) {
			/* received zero chunk.  disconnect (and retry?) */
			libarms_log(ARMS_LOG_DEBUG,
			    "tunnel#%d: received last chunk.", tunnel->num);
			return TR_WANT_RETRY;
		}
		/* record current chunk */
		tunnel->id = id;

		/* add for trailing CRLF */
		tunnel->chunklen += 2;
	} else {
		type = 0;
		chunkbuf = readbuf;
	}
	/* parse body */
	/*
	 * chunklen:
	 *  - includes CRLF (+= 2 above)
	 * readlen:
	 *  - includes CRLF
	 *  - includes CR
	 *  - don't includes CRLF
	 */
	if (tunnel->chunklen == 1) {
		/* includes LF only... */
		parselen = 0;
		skiplen = 1;
	} else if (readlen >= tunnel->chunklen) {
		/* includes CRLF */
		parselen = tunnel->chunklen - 2;
		skiplen = tunnel->chunklen;
	} else if (readlen == tunnel->chunklen - 1) {
		/* includes CR */
		parselen = tunnel->chunklen - 2;
		skiplen = tunnel->chunklen - 1;
	} else {
		/* don't includes CRLF */
		parselen = readlen;
		skiplen = readlen;
	}
	/*
	 * return: tunnel->rp: next data
	 *         tunnel->rlen: remaining len
	 */
	tunnel->rp += skiplen;
	tunnel->rlen -= skiplen;
	tunnel->chunklen -= skiplen;

	/* if echo, ignore it. */
	if (type == ARMS_CHUNK_ECHO ||
	    type == ARMS_CHUNK_ECHO_REPLY) {
		tunnel->echo_state = ARMS_ECHO_NONE;
		tunnel->chunklen = 0;
		return TR_WANT_READ;
	}
	if (tr == NULL) {
		/*
		 * 1. continuous message related chunk id
		 * 2. new message related existing transaction
		 * 3. new message for new transaction
		 */
		if (tunnel->id != 0)
			tr = ssltunnel_find_tr_with_chunk(tunnel, tunnel->id);
		if (tr == NULL) {
			/* peek transaction-id */
			AXP *axp;
			int tr_id, err;

			axp = axp_create(arms_msg, "US-ASCII", 0, 0);
			axp_parse(axp, chunkbuf, parselen);
			tr_id = 0;
			err = axp_refer(axp, ARMS_TAG_TRANSACTION_ID, &tr_id);
			axp_destroy(axp);
			if (err == 0 && tr_id != 0)
				tr = ssltunnel_find_transaction(tunnel, tr_id);
		}
		if (tr == NULL) {
			/* create new transaction. */
			tr = CALLOC(1, sizeof(transaction));
			if (tr == NULL) {
				/* XXX set trigger */
				return TR_WANT_STOP;
			}
			tr->chunk_id = tunnel->id;
			SET_TR_PARSER(tr, arms_req_parser);
			tr->state = TR_START_REQUEST;
			TAILQ_INIT(&tr->head);
			arms_transaction_setup(tr);
			LIST_INSERT_HEAD(&tunnel->tr_list, tr, next);
		}
	}
	rv = tr->parser(tr, chunkbuf, parselen);
	switch (rv) {
	case TR_PARSE_ERROR:
	case TR_READ_DONE:
		tunnel->id = 0;
		tr->chunk_id = 0;
		/* finish transaction if received done-response (2way) */
		if (tr->state == TR_DONE_RESPONSE) {
			LIST_REMOVE(tr, next);
			arms_tr_ctx_free(&tr->tr_ctx);
			arms_transaction_free(tr);
		} else if (tr->state == TR_CONFIRM_START_RESPONSE) {
			tr->state = TR_CONFIRM_DONE_REQUEST;
			SET_TR_PARSER(tr, arms_req_parser);
			SET_TR_BUILDER(tr, arms_res_builder);
			obj->type = SCHED_TYPE_IOR;
		} else {
			/* received start-request.  response */
			tr->len = 0;
			if (tr->tr_ctx.pm != NULL &&
			    tr->tr_ctx.pm->pm_done != NULL)
				tr->state = TR_START_RESPONSE;
			else
				tr->state = TR_RESPONSE;
			tr->tr_ctx.write_done = TR_WANT_WRITE;
			SET_TR_BUILDER(tr, arms_res_builder);
			/* want write */
			obj->type = SCHED_TYPE_IO;
		}
		break;
	case TR_WANT_ROLLBACK:
		if (!tr->rollbacked &&
		    tr->tr_ctx.pm && tr->tr_ctx.pm->pm_rollback) {
			if (!tr->tr_ctx.pm->pm_rollback(tr)) {
				/* need to reconnect tunnel. */
				break;
			}
		}
		if (tr->rollbacked) {
			arms_context_t *res = arms_get_context();
			/*
			 * rollback failure.
			 * fatal.  reboot.
			 */
			res->trigger = "rollback failure";
			res->result = ARMS_EPULL;
			libarms_log(ARMS_LOG_EROLLBACK,
				    "rollback failure.");
			rv = TR_WANT_STOP;
		}
	default:
		break;
	}
	return rv;
}

static int
ssltunnel_confirm(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	transaction *tr;
	int rv, sent;

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		libarms_log(ARMS_LOG_ESSL,
		    "tunnel#%d: confirmation timeout.", tunnel->num);
		return ssltunnel_retry(obj, tunnel);

	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;
	default:
		break;
	}
	/*
	 * only one transaction.
	 */
	if (tunnel->write_tr == NULL) {
		/*
		 * first call.
		 * new transaction and setup message build function
		 */
		tr = CALLOC(1, sizeof(transaction));
		if (tr == NULL) {
			return ssltunnel_retry(obj, tunnel);
		}
		tr->state = TR_CONFIRM_START_REQUEST;
		arms_transaction_setup(tr);
		tr->tr_ctx.write_done = TR_WANT_WRITE;
		LIST_INSERT_HEAD(&tunnel->tr_list, tr, next);
		SET_TR_BUILDER(tr, arms_req_builder);
		tunnel->wid = 0;
		tunnel->id = 0;
		tunnel->write_tr = tr;
		tunnel->state = BUILD_CONFIRM_REQ;
		memset(tunnel->rbuf, 0, sizeof(tunnel->rbuf));
	} else {
		tr = tunnel->write_tr;
	}
	rv = TR_WANT_WRITE; /* for SEND_CONFIRM_START_REQ */
	switch (tunnel->state) {
	case BUILD_CONFIRM_REQ:
		if (tunnel->wid == 0) {
			tunnel->wid = random();
			rv = tr->builder(tr, tr->buf, sizeof(tr->buf),
					 &tr->len);
		}
		/* want write */
		obj->type = SCHED_TYPE_IOW;
		/* send chunk header */
		sent = arms_ssl_chunk_write_header(tunnel->ssl,
						   tunnel->wid, tr->len, 1);
		if (sent < 0) {
			/* failed to send push-confirmation-start */
			return ssltunnel_retry(obj, tunnel);
		}
		if (sent == 0) {
			/* wait for writing and retry */
			return SCHED_CONTINUE_THIS;
		}
		arms_get_time_remaining(&obj->timeout, 60/*?*/);
		tunnel->state = SEND_CONFIRM_START_REQ;
		/*FALLTHROUGH*/
	case SEND_CONFIRM_START_REQ:
		if (tr->len > 0) {
			sent = arms_ssl_chunk_write_body(
				tunnel->ssl, tr->buf, tr->len);
			arms_get_time_remaining(&obj->timeout, 60/*?*/);
			if (sent < 0) {
				/* failed to send push-confirmation-start */
				return ssltunnel_retry(obj, tunnel);
			}
			tr->len -= sent;
			if (tr->len > 0)
				return SCHED_CONTINUE_THIS;
		}
		/* all data sent. */
		sent = arms_ssl_chunk_write_trail(tunnel->ssl);
		if (sent < 0) {
			/* failed to send push-confirmation-start */
			return ssltunnel_retry(obj, tunnel);
		}
		if (sent == 0) {
			/* wait for writing and retry */
			return SCHED_CONTINUE_THIS;
		}

		SET_TR_PARSER(tr, arms_res_parser);
		tunnel->state = RECV_CONFIRM_START_RES;
		tunnel->id = 0;
		tunnel->rlen = 0;
		memset(tunnel->rbuf, 0, sizeof(tunnel->rbuf));
		tr->state = TR_CONFIRM_START_RESPONSE;
		obj->type = SCHED_TYPE_IOR;
		return SCHED_CONTINUE_THIS;

	case RECV_CONFIRM_START_RES:
rerun_s:
		/*
		 * read
		 *  1st chunk
		 *  2nd chunk
		 * read
		 *  3rd chunk
		 *    :
		 *  trail chunk
		 * --> next state
		 *  1st chunk
		 */
		arms_get_time_remaining(&obj->timeout, 60/*?*/);
	  	if (tunnel->rlen == 0) {
			tunnel->rp = tunnel->rbuf;
			tunnel->rlen = arms_ssl_read(tunnel->ssl,
						     tunnel->rp,
						     sizeof(tunnel->rbuf) - 1);
			if (tunnel->rlen < 0) {
				/* failed to recv push-confirmation-start */
				return ssltunnel_retry(obj, tunnel);
			}
			if (tunnel->rlen == 0) {
				arms_get_time_remaining(&obj->timeout,
				    res->tunnel_echo_interval);
				return SCHED_CONTINUE_THIS;
			}
			/* terminated by NUL */
			tunnel->rp[tunnel->rlen] = '\0';
		}
		/* data is prepared.  parse it. */
		do {
			rv = ssltunnel_buf_parser(obj, tr,
						  tunnel->rp, tunnel->rlen);
		} while (tunnel->rlen > 0 && rv == TR_WANT_READ);
		/* all data parsed. */
		switch (rv) {
		case TR_WANT_READ:
			/* if read data is partially, continue this. */
			if (arms_ssl_pending(tunnel->ssl) > 0)
				goto rerun_s;
			arms_get_time_remaining(&obj->timeout, 30);
			return SCHED_CONTINUE_THIS;

		case TR_READ_DONE:
			/*
			 * all data parsed. response is received.
			 * next, wait for push-confirmation-done-request.
			 * don't free tr (== tunnel->write_tr).
			 */
			arms_tr_ctx_free(&tr->tr_ctx);

			tunnel->state = RECV_CONFIRM_DONE_REQ;
			arms_get_time_remaining(&obj->timeout, 30);
			tr->tr_ctx.pm = &confirm_done_methods;
			arms_transaction_setup(tr);
			tr->tr_ctx.write_done = TR_WANT_WRITE;
			tr->chunk_id = 0;
			tunnel->id = 0;
			if (tunnel->rlen == 0) {
				return SCHED_CONTINUE_THIS;
			}
			break;
		case TR_WANT_STOP:
			return SCHED_FINISHED_SCHEDULER;
		default:
			/* failed to send push-confirmation-start */
			return ssltunnel_retry(obj, tunnel);
		}
		/*FALLTHROUGH*/
	case RECV_CONFIRM_DONE_REQ:
rerun_d:
		arms_get_time_remaining(&obj->timeout, 60/*?*/);
	  	if (tunnel->rlen == 0) {
			tunnel->rp = tunnel->rbuf;
			tunnel->rlen = arms_ssl_read(tunnel->ssl,
						     tunnel->rp,
						     sizeof(tunnel->rbuf) - 1);
			if (tunnel->rlen < 0) {
				/* failed to send push-confirmation-start */
				return ssltunnel_retry(obj, tunnel);
			}
			if (tunnel->rlen == 0) {
				return SCHED_CONTINUE_THIS;
			}
			/* terminated by NUL */
			tunnel->rp[tunnel->rlen] = '\0';
		}
		/* data is prepared.  parse it. */
		do {
			rv = ssltunnel_buf_parser(obj, tr,
						  tunnel->rp, tunnel->rlen);
		} while (tunnel->rlen > 0 && rv == TR_WANT_READ);
		/* all data parsed. */
		switch (rv) {
		case TR_WANT_READ:
			/* if read data is partially, continue this. */
			if (arms_ssl_pending(tunnel->ssl) > 0)
				goto rerun_d;
			return SCHED_CONTINUE_THIS;

		case TR_READ_DONE:
			tunnel->id = 0;
			tunnel->state = BUILD_CONFIRM_DONE_RES;
			tunnel->wlen = 0;
			tr = ssltunnel_find_tr_with_chunk(tunnel, tunnel->id);
			tunnel->write_tr = tr;
			tunnel->wid = random();
			/* want write */
			obj->type = SCHED_TYPE_IOW;
			break;
		default:
			return SCHED_CONTINUE_THIS;
		}
		/*FALLTHROUGH*/
	case BUILD_CONFIRM_DONE_RES:
		if (tunnel->wlen == 0) {
			rv = tr->builder(tr, tr->buf,
					 sizeof(tr->buf), &tunnel->wlen);
		}
		sent = arms_ssl_chunk_write_header(tunnel->ssl,
						   tunnel->wid,
						   tunnel->wlen, 1);
		if (sent < 0) {
			/* failed to send push-confirmation-done */
			return ssltunnel_retry(obj, tunnel);
		}
		if (sent == 0) {
			/* wait for writing and retry */
			return SCHED_CONTINUE_THIS;
		}
		tunnel->state = SEND_CONFIRM_DONE_RES;
		/*FALLTHROUGH*/
	case SEND_CONFIRM_DONE_RES:
		if (tunnel->wlen > 0) {
			sent = arms_ssl_chunk_write_body(tunnel->ssl,
						 tr->buf, tunnel->wlen);
			if (sent < 0) {
				return ssltunnel_retry(obj, tunnel);
			}
			tunnel->wlen -= sent;
			if (tunnel->wlen > 0)
				return SCHED_CONTINUE_THIS;
		}
		/* all data sent. remove transaction. */
		sent = arms_ssl_chunk_write_trail(tunnel->ssl);
		if (sent < 0) {
			/* failed to send push-confirmation-done */
			return ssltunnel_retry(obj, tunnel);
		}
		if (sent == 0) {
			/* wait for writing and retry */
			return SCHED_CONTINUE_THIS;
		}
		tunnel->write_tr  = NULL;
		LIST_REMOVE(tr, next);
		arms_tr_ctx_free(&tr->tr_ctx);
		arms_transaction_free(tr);

		/* reset retry counter. */
		tunnel->retry = 0;

		tunnel->echo_state = ARMS_ECHO_NONE;
		tunnel->id = 0;
		tunnel->rlen = 0;
		tunnel->chunklen = 0;
		tunnel->p = NULL;
		obj->type = SCHED_TYPE_IOR;
		arms_get_time_remaining(&obj->timeout, 10/*?*/);
		SET_NEW_METHOD(obj, ssltunnel_rw_loop);
		/* set global state */
		libarms_log(ARMS_LOG_IPROTO_CONFIRM_DONE,
		    "Done push confirmation");
		arms_set_global_state(ARMS_ST_PUSH_WAIT);
		libarms_log(ARMS_LOG_ITUNNEL_READY_TO_PUSH,
		    "tunnel#%d: ready to push.", tunnel->num);
		res->retry_inf = arms_keep_push_wait(res);
		tunnel->retry_inf = res->retry_inf;
		if (res->rs_tunnel_1st == -1)
			res->rs_tunnel_1st = tunnel->num;
		return SCHED_CONTINUE_THIS;
	}
	return SCHED_CONTINUE_THIS;
}

static int
ssltunnel_rw_loop(struct arms_schedule *obj, int event)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();

	switch (event) {
	case EVENT_TYPE_TIMEOUT:
		if (tunnel->write_tr != NULL) {
			libarms_log(ARMS_LOG_ESSL,
			    "tunnel#%d: timeout: not ready for writing data",
			    tunnel->num);
			return ssltunnel_retry(obj, tunnel);
		}
		if (tunnel->echo == NULL) {
			/* no echo response */
			return ssltunnel_retry(obj, tunnel);
		}
		arms_get_time_remaining(&obj->timeout,
					res->tunnel_echo_interval);
		return SCHED_CONTINUE_THIS;
	case EVENT_TYPE_FINISH:
		ssltunnel_close(tunnel, 0);
		ssltunnel_finish_transaction(tunnel);
		LIST_REMOVE(tunnel, next);
		FREE(tunnel);
		CLOSE_FD(obj->fd);
		/* finish scheduler if running tunnel does not exist. */
		if (LIST_EMPTY(&tunnel_list))
			register_ssltunnel_stopper();
		return SCHED_FINISHED_THIS;

	case EVENT_TYPE_READ:
		return ssltunnel_receive(obj);

	case EVENT_TYPE_WRITE:
		return ssltunnel_send(obj);
	default:
		break;
	}
	return SCHED_CONTINUE_THIS;
}

static int
ssltunnel_receive(struct arms_schedule *obj)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	int rv;

rerun:
	/* read chunk (multiple call?) */
	if (tunnel->rlen == 0) {
		memset(tunnel->rbuf, 0, sizeof(tunnel->rbuf));
		tunnel->rp = tunnel->rbuf;
		/* read raw data (w/ chunk header) */
		tunnel->rlen = arms_ssl_read(tunnel->ssl,
				     tunnel->rp,
				     sizeof(tunnel->rbuf) - 1);
		if (tunnel->rlen < 0) {
			/* failed to read from SSL */
		 	return ssltunnel_retry(obj, tunnel);
		}
		if (tunnel->rlen == 0) {
			arms_get_time_remaining(&obj->timeout,
						res->tunnel_echo_interval);
			return SCHED_CONTINUE_THIS;
		}
		/* terminated by NUL */
		tunnel->rp[tunnel->rlen] = '\0';
	}
	/* data is prepared.  parse it. */
#ifdef ARMS_DEBUG
	printf("parse_body(len:%d):<<<%s>>>\n", tunnel->rlen, tunnel->rp);
#endif
	do {
		rv = ssltunnel_buf_parser(obj, NULL,
					  tunnel->rp, tunnel->rlen);
	} while (tunnel->rlen > 0 &&
		 (rv == TR_WANT_READ || rv == TR_READ_DONE));
	switch (rv) {
	case TR_WANT_STOP:
		/*
		 * res->result == ARMS_EPUSH and rv == TR_WANT_STOP,
		 * tunnel is in-configure state (done-response result:ok).
		 * if in-configure state,
		 * scheduler shouldn't stopped, and run confirmation.
		 */
		if (res->result == ARMS_EPUSH) {
			/*
			 * all tunnel needs confirmation.
			 */
			LIST_FOREACH(tunnel, &tunnel_list, next) {
				ssltunnel_finish_transaction(tunnel);
				obj = tunnel->obj;
				arms_get_time_remaining(&obj->timeout,
				    res->tunnel_echo_interval);
				SET_NEW_METHOD(obj, ssltunnel_confirm);
				tunnel->write_tr = NULL;
				obj->type = SCHED_TYPE_IOW;
			}
			return SCHED_CONTINUE_THIS;
		}
		return SCHED_FINISHED_SCHEDULER;

	case TR_PARSE_ERROR:
	case TR_READ_DONE:
		if (tunnel->rlen != 0) {
			/* debug ? */
			libarms_log(ARMS_LOG_DEBUG,
			    "trailing garbage %d bytes dropped.",
			    tunnel->rlen);
			tunnel->rlen = 0;
		}
		break;

	case TR_WANT_ROLLBACK:
	case TR_WANT_RETRY:
		return ssltunnel_retry(obj, tunnel);
		break;

	case TR_WANT_READ:
		if (arms_ssl_pending(tunnel->ssl) > 0)
			goto rerun;
	default:
		break;
	}

	arms_get_time_remaining(&obj->timeout,
				res->tunnel_echo_interval);
	return SCHED_CONTINUE_THIS;
}

static int
ssltunnel_post_write(struct arms_schedule *obj, transaction *tr)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();

	/*
	 * sent (done-)request: wait response.
	 * sent response: done or exec. (depend on msg type)
	 */
	if (TR_DIR(tr->state) == TR_REQUEST) {
		/* sent request.  prepare for receive response */
		SET_TR_PARSER(tr, arms_res_parser);
		tr->state = TR_DONE_RESPONSE;
		tr->chunk_id = 0;
		arms_get_time_remaining(&obj->timeout,
					res->tunnel_echo_interval);
		return SCHED_CONTINUE_THIS;
	}
	/* sent response */
	if ((tr->tr_ctx.pm != NULL &&
	     tr->tr_ctx.pm->pm_done == NULL) ||
	    tr->tr_ctx.result != 100 ||
	    TR_TYPE(tr->state) != TR_START) {
		/*
		 * sync method.
		 *  or async method with error,
		 *  or sent done-response.
		 * transaction will finished.
		 */
		LIST_REMOVE(tr, next);
		arms_tr_ctx_free(&tr->tr_ctx);
		arms_transaction_free(tr);
		tunnel->write_tr = NULL;
		return 0;
	}

	/*
	 * sent start-response (success).
	 * exec and done.
	 */
	/*
	 * if execution method is available,
	 * call it.
	 */
	if (tr->tr_ctx.pm != NULL &&
	    tr->tr_ctx.pm->pm_exec) {
		/* disconnect tunnel before exec configure */
		if (tr->tr_ctx.pm->pm_type == ARMS_TR_CONFIGURE) {
			ssltunnel_close(tunnel, 1);
			CLOSE_FD(obj->fd);
		}

		if (tr->tr_ctx.pm->pm_exec(tr) != 0) {
			/* exec & rollback err. */
			res->trigger = "rollback failure";
			res->result = ARMS_EPULL;
			libarms_log(ARMS_LOG_EROLLBACK,
				    "rollback failure.");
			ssltunnel_close(tunnel, 1);
			ssltunnel_finish_transaction(tunnel);
			LIST_REMOVE(tunnel, next);
			FREE(tunnel);
			CLOSE_FD(obj->fd);
			register_ssltunnel_stopper();
			return SCHED_FINISHED_THIS;
		}
	}
	/*
	 * prepare for done-req.
	 */
	tr->len = 0;
	tr->state = TR_DONE_REQUEST;
	tr->tr_ctx.write_done = TR_WANT_WRITE;
	SET_TR_BUILDER(tr, arms_req_builder);
	SET_TR_PARSER(tr, arms_res_parser);
	/* want write */
	obj->type = SCHED_TYPE_IO;
	tunnel->id = 0;
	arms_get_time_remaining(&obj->timeout,
				res->tunnel_echo_interval);
	if (tr->tr_ctx.pm &&
	    tr->tr_ctx.pm->pm_type == ARMS_TR_CONFIGURE &&
	    tr->tr_ctx.pm->pm_exec) {
		/* connect tunnel before configure-done request */
		arms_get_time_remaining(&obj->timeout, 1);
		obj->type = SCHED_TYPE_EXEC;
		SET_NEW_METHOD(obj, ssltunnel_connect);
	}

	return SCHED_CONTINUE_THIS;
}

static int
ssltunnel_send(struct arms_schedule *obj)
{
	struct ssltunnel *tunnel = obj->userdata;
	arms_context_t *res = arms_get_context();
	transaction *tr;
	int rv;

rerun:
	/* get active transaction. */
	if (tunnel->write_tr == NULL) {
		LIST_FOREACH(tr, &tunnel->tr_list, next) {
			if (TR_OUT(tr->state))
				break;
		}
		/* if no pending transaction, nothing to do. */
		if (tr == NULL) {
#ifdef ARMS_DEBUG
			printf("active (want to write) transaction is not found.\n");
#endif
			obj->type = SCHED_TYPE_IOR;
			arms_get_time_remaining(&obj->timeout,
						res->tunnel_echo_interval);
			return SCHED_CONTINUE_THIS;
		}
#ifdef ARMS_DEBUG
		printf("found transction id=%d\n", tr->tr_ctx.id);
#endif
		tunnel->write_tr = tr;
		tunnel->wid = random();
	} else {
		tr = tunnel->write_tr;
	}

	if (tr->len == 0) {
		/* writer buffer empty.  fill it. */
		if (tr->builder == NULL) {
			/* all data sent. */
#ifdef ARMS_DEBUG
			printf("all data sent.\n");
#endif
			tunnel->write_tr = NULL;

			rv = ssltunnel_post_write(obj, tr);
			if (rv != 0)
				return rv;
			/* done-response finished.  run next transaction. */
			goto rerun;
		}
		/* fill buffer */
#ifdef ARMS_DEBUG
		printf("(re)fill.\n");
#endif
		tr->wp = tr->buf;
		rv = tr->builder(tr, tr->buf, sizeof(tr->buf) - 1, &tr->len);
		switch (tr->tr_ctx.write_done) {
		case TR_WANT_STOP:
			register_ssltunnel_stopper();
			/*FALLTHROUGH*/
		case TR_WRITE_DONE:
			/* no more data. */
			SET_TR_BUILDER(tr, NULL);
#ifdef ARMS_DEBUG
			printf("chunk: trail\n");
#endif
			tunnel->wflag = FLAG_WRITE_CHUNK_HEADER_TRAIL;
			break;
		case TR_WANT_WRITE:
			/* block to write zero chunk. */
			if (tr->len == 0)
				goto rerun;
#ifdef ARMS_DEBUG
			printf("chunk:\n");
#endif
			tunnel->wflag = FLAG_WRITE_CHUNK_HEADER;
			break;
		default:
			/* error? */
			break;
		}
	}
	/* 1st, write chunk header. */
	switch (tunnel->wflag) {
	case FLAG_WRITE_CHUNK_HEADER:
		rv = arms_ssl_chunk_write_header(tunnel->ssl,
						 tunnel->wid, tr->len, 0);
		if (rv < 0) {
			return ssltunnel_retry(obj, tunnel);
		}
		if (rv == 0) {
			/* retry to write header */
			arms_get_time_remaining(&obj->timeout,
						res->tunnel_echo_interval);
			return SCHED_CONTINUE_THIS;
		}
		tunnel->wflag = FLAG_WRITE_CHUNK_BODY;
		break;
	case FLAG_WRITE_CHUNK_HEADER_TRAIL:
		rv = arms_ssl_chunk_write_header(tunnel->ssl,
						 tunnel->wid, tr->len, 1);
		if (rv < 0) {
			return ssltunnel_retry(obj, tunnel);
		}
		if (rv == 0) {
			/* retry to write header */
			arms_get_time_remaining(&obj->timeout,
						res->tunnel_echo_interval);
			return SCHED_CONTINUE_THIS;
		}
		tunnel->wflag = FLAG_WRITE_CHUNK_BODY;
		/*FALLTHROUGH*/
	case FLAG_WRITE_CHUNK_BODY:
		do {
			rv = arms_ssl_chunk_write_body(tunnel->ssl,
						       tr->wp, tr->len);
			if (rv > 0) {
				tr->wp += rv;
				tr->len -= rv;
				/*refill or send */
			}
		} while (tr->len > 0 && rv > 0);
		/* rv == 0: SSL_ERROR_WANT_WRITE. */
		if (rv < 0) {
			return ssltunnel_retry(obj, tunnel);
		}
		if (rv == 0) {
			break;
		}
		if (tr->len != 0)
			break;
		tunnel->wflag = FLAG_WRITE_CHUNK_CRLF;
		/*FALLTHROUGH*/
	case FLAG_WRITE_CHUNK_CRLF:
		/* write trailing CRLF of chunk */
		rv = arms_ssl_chunk_write_trail(tunnel->ssl);
		if (rv < 0) {
			return ssltunnel_retry(obj, tunnel);
		}
		if (rv == 0) {
			tr->len = -1;/* skip next build */
			break;
		}
		tr->len = 0;
		if (tr->tr_ctx.write_done != TR_WANT_WRITE) {
			/* message is sent.  reset chunk id. */
			tunnel->wid = 0;
		}
		/* all data sent. refill */
		goto rerun;
		break;
	}
#ifdef ARMS_DEBUG
	printf("write_body:<<<%s>>>\n", tr->wp);
#endif

	arms_get_time_remaining(&obj->timeout,
				res->tunnel_echo_interval);
	return SCHED_CONTINUE_THIS;
}

/*
 * parsing HTTP response header.
 * buf: zero terminated http header string (includes CRLF)
 */
static int
parse_response_header(struct ssltunnel *tunnel, const char *buf)
{
	int n;
	int result;

	if (strstr(buf, "\r\n") == NULL)
		return TR_WANT_READ;
	n = sscanf(buf, "HTTP/1.1 %d", &result);
	if (n != 1) {
		return -1;
	}

	return result;
}
