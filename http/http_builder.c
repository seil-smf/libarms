/*	$Id: http_builder.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include <libarms_log.h>
#include <libarms/queue.h>

#include <libarms_resource.h>
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <http/http.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

#include "compat.h"

#define CHUNK_SUPPORT
/*
 * http request builder
 * - pull request
 * - push-raedy request
 * - done-start request
 */

static const char arms_http_post_v10[] =
	"POST /%s HTTP/1.0\r\n"
	"Content-Type: text/xml\r\n"
	"Content-Length: %d\r\n"
	"Authorization: Basic %s\r\n"
	"\r\n";

#ifdef CHUNK_SUPPORT
static const char arms_http_post_v11_chunked[] =
	"POST /%s HTTP/1.1\r\n"
	"Host: %s:%s\r\n"
	"Connection: close\r\n"
	"Content-Type: text/xml\r\n"
	"Transfer-Encoding: chunked\r\n"
	"Authorization: Basic %s\r\n"
	"\r\n";
#endif

static const char arms_http_post_v11[] =
	"POST /%s HTTP/1.1\r\n"
	"Host: %s:%s\r\n"
	"Connection: close\r\n"
	"Content-Type: text/xml\r\n"
	"Content-Length: %d\r\n"
	"Authorization: Basic %s\r\n"
	"\r\n";

/*
 * release tr->data and related resource.
 * XXX copy from http_pasrer.c
 */
static int
http_release(transaction *tr)
{
	if (tr->data != NULL) {
		FREE(tr->data);
	}
	return 0;
}

/*
 * http is already created and attached to tr.,
 */
int
http_request_builder(transaction *tr, char *buf, int len, int *wrote)
{
	static char authstr[256];
	static char authencbuf[256];
	struct http *http;
	arms_context_t *res = arms_get_context();
	static char host[80], port[8], path[80];
	struct mem_block *block;
	const char *url;
	int scheme;

	if (TR_TYPE(tr->state) == TR_DONE) {
		url = res->rs_endpoint;
	} else {
		url = tr->uriinfo[tr->cur_uri];
	}
	scheme = arms_parse_url(url,
				host, sizeof(host),
				port, sizeof(port),
				path, sizeof(path));
	if (scheme != URL_SCHEME_HTTPS) {
		libarms_log(ARMS_LOG_EHTTP,
		    "%s: scheme is not https, cannot access.", url);
		return TR_FATAL_ERROR;
	}

	if (tr->release_data == NULL) {
		int rv, total = 0;

		/*
		 * initial call.  setup
		 *  tr->data: application used,
		 *  and release by tr->release_data().
		 */
		tr->data = http = CALLOC(1, sizeof(*http));
		if (http == NULL) {
			return TR_FATAL_ERROR;
		}
		tr->release_data = http_release;
		http->state = HTTP_BUILD_HEADER;
		http->authenticated = 0;
		http->result = 0;
		memset(authencbuf, 0, sizeof(authencbuf));
		snprintf(authstr, sizeof(authstr), "%s:%s",
			 tr->user, tr->passwd);
		arms_base64_encode(authencbuf, sizeof(authencbuf),
				   authstr, strlen(authstr));
#ifdef CHUNK_SUPPORT
		/* XXX retransmit code is broken orz */
		if (res->http_preferred_version >= 1) {
			*wrote = snprintf(buf, len, arms_http_post_v11_chunked,
					  path,
					  host, port,
					  authencbuf);
			http->state = HTTP_CHUNK_WRITE;
			SET_TR_BUILDER(tr, http_req_chunk_builder);
			return TR_WANT_WRITE;
		}
#endif
		/*
		 * umm, HTTP/1.0 POST w/contents requires Content-length.
		 */
		if (TAILQ_EMPTY(&tr->head)) {
			/* true iniital call, got data from callback. */
			do {
				block = CALLOC(1, sizeof(struct mem_block));
				if (block == NULL) {
					return TR_FATAL_ERROR;
				}
				block->len = sizeof(block->buf);
				block->wrote = 0;
				TAILQ_INSERT_TAIL(&tr->head, block, next);
				rv = arms_req_builder(tr, block->buf,
						      block->len,
						      &block->wrote);
				total += block->wrote;
			} while (rv == TR_WANT_WRITE);
			tr->total = total;
		} else {
			libarms_log(ARMS_LOG_IHTTP_RETRY,
			    "retry to send request.");
		}
		tr->block = TAILQ_FIRST(&tr->head);

		http->llen = 0;
	} else {
		/*
		 * continuous call.
		 */
		http = tr->data;
	}

	switch (http->state) {
	case HTTP_BUILD_HEADER:
		if (res->http_preferred_version >= 1)
			*wrote = snprintf(
				buf, len, arms_http_post_v11,
				path,
				host, port,
				tr->total, authencbuf);
		else
			*wrote = snprintf(
				buf, len, arms_http_post_v10,
				path,
				tr->total, authencbuf);
		http->state = HTTP_BUILD_BODY;
		return TR_WANT_WRITE;
	case HTTP_BUILD_BODY:
		block = tr->block;
		if (block == NULL) {
			/* all body sent. */
#if 0 /* don't free for retry */
			while ((block = TAILQ_FIRST(&tr->head))) {
				TAILQ_REMOVE(&tr->head, block, next);
				FREE(block);
			}
#endif
			http->state = HTTP_PARSE_STATUS_LINE;
			SET_TR_PARSER(tr, http_response_parser);
			return TR_WRITE_DONE;
		}
		memcpy(buf, block->buf, block->wrote);
		*wrote = block->wrote;
		tr->block = TAILQ_NEXT(block, next);

		return TR_WANT_WRITE;
	default:
		break;
	}
	return TR_FATAL_ERROR;
}

struct http_header_string {
	int result;
	const char *header;
};

static const struct http_header_string http_res_header_v10[] = {
	{ 200,
	  "HTTP/1.0 200 OK\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 401,
	  "HTTP/1.0 401 Authorization Required\r\n"
	  "WWW-Authenticate: Basic realm=\"\"\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 400,
	  "HTTP/1.0 400 Bad Request\r\n"
	  "WWW-Authenticate: Basic realm=\"\"\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 0, NULL }
};

static const struct http_header_string http_res_header_v11[] = {
	{ 200,
	  "HTTP/1.0 200 OK\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "Transfer-Encoding: chunked\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 401,
	  "HTTP/1.0 401 Authorization Required\r\n"
	  "WWW-Authenticate: Basic realm=\"\"\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "Transfer-Encoding: chunked\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 400,
	  "HTTP/1.0 400 Bad Request\r\n"
	  "WWW-Authenticate: Basic realm=\"\"\r\n"
	  "Server: armsd\r\n"
	  "Connection: close\r\n"
	  "Content-Type: text/xml\r\n"
	  "Transfer-Encoding: chunked\r\n"
	  "\r\n"
	  "<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n" },
	{ 0, NULL }
};

static const char *
find_header(int result, const struct http_header_string *headers)
{
	const struct http_header_string *h;

	for (h = headers; h->result != 0; h++) {
		if (h->result == result)
			return h->header;
	}
	return NULL;
}

int
http_response_builder(transaction *tr, char *buf, int len, int *wrote)
{
	struct http *http = tr->data;
	const char *hdr;

	if (http->result == 0)
		http->result = 200;
	if (http->chunked) {
		hdr = find_header(http->result, http_res_header_v11);
	} else {
		hdr = find_header(http->result, http_res_header_v10);
	}
	if (hdr == NULL) {
		/* unknown http status.  hmm, bug? */
		hdr = "HTTP/1.0 500 Internal Server Error\r\n"
			"Server: armsd\r\n"
			"Connection: close\r\n"
			"Content-Type: text/xml\r\n"
			"\r\n"
			"<?xml version=\"1.0\" encoding=\"US-ASCII\" ?>\r\n";
	}
	/* buf is 8192byte, don' failed... */
	*wrote = strlcpy(buf, hdr, len) - 1;
	if (http->result == 200) {
		if (http->chunked) {
			http->state = HTTP_CHUNK_WRITE;
			SET_TR_BUILDER(tr, http_res_chunk_builder);
		} else {
			SET_TR_BUILDER(tr, arms_res_builder);
			tr->tr_ctx.write_done = TR_WANT_WRITE;
		}
		return TR_WANT_WRITE;
	} else {
		SET_TR_BUILDER(tr, arms_res_builder);
		tr->tr_ctx.write_done = TR_WRITE_DONE;
		return TR_WANT_WRITE;
	}
}
