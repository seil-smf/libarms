/*	$Id: http_parser.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

/*
 * parse HTTP header, with authentication
 */

#include "config.h"

#include <inttypes.h>
#include <string.h>

#include <libarms_log.h>
#include <libarms/queue.h>

#include <axp_extern.h>
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>
#include <http/http.h>

/*
 * release tr->data and related resource.
 */
static int
http_release(transaction *tr)
{
	if (tr->data != NULL)
		FREE(tr->data);
	return 0;
}

static int
http_parse_auth(struct http *http, const char *u, const char *p)
{
#define AUTH_HDR "Authorization: Basic "
	if (!strncmp(http->linebuf, AUTH_HDR, sizeof(AUTH_HDR)-1)) {
		const char *userpass = &http->linebuf[sizeof(AUTH_HDR)-1];
		char *user, *pass;
		static char buf[512];
		memset(buf, 0, sizeof(buf));
		arms_base64_decode(buf, sizeof(buf),
				   userpass, strlen(userpass));
		user = buf;
		pass = strchr(buf, ':');
		if (!pass)
			return 0;
		*pass++ = '\0';
		if (strcmp(u, user))
			return 0;
		if (strcmp(p, pass))
			return 0;
		/* authenticated. */
		return 1;
	}
	return 0;
}

static int
http_parse_chunked(const char *linebuf)
{
	const int len = sizeof("Transfer-Encoding") - 1;

	if (strncmp(linebuf, "Transfer-Encoding", len) != 0)
		return 0;
	
	if (strstr(&linebuf[len], "chunked") == NULL)
		return 0;

	return 1;
}

/*
 * error code.  positive value as length of line includes LF
 */
#define TOO_LONG_LINE -1
#define LF_NOT_FOUND  -2

/*
 * copy part of buf, with LF (not terminated by NUL)
 */
int
http_get_one_line(char *dst, int dstlen, const char *buf, int buflen)
{
	char *lfp;
	int copylen;

	if (!(lfp = memchr(buf, '\n', buflen))) {
		if (dstlen < buflen)
			return TOO_LONG_LINE;
		memcpy(dst, buf, buflen);
		return LF_NOT_FOUND;
	}
	/* lfp points '\n' */
	copylen = lfp - buf + 1;
	if (copylen > dstlen)
		return TOO_LONG_LINE;
	/* dst includes \n */
	memcpy(dst, buf, copylen);
	return copylen;
}

static int
http_parse_req_line(struct http *http)
{
	int n;
	char methodbuf[7 + 1];

	/*
	 * XXX: magic numbers...
	 * 7 for Method: longest method on HTTP/1.1 is "OPTIONS"
	 * 80 for Request-URI: nantonaku...
	 */
	n = sscanf(http->linebuf, "%7s %80s HTTP/%u.%u",
		   methodbuf, http->uri, &http->major, &http->minor);
	if (n != 4)
		return -1;
	if (strcasecmp(methodbuf, "get") == 0)
		http->method = HTTP_METHOD_GET;
	else if (strcasecmp(methodbuf, "post") == 0)
		http->method = HTTP_METHOD_POST;
	else
		return -1;
	return 0;
}

static int
http_parse_status_line(struct http *http)
{
	int n;

	n = sscanf(http->linebuf, "HTTP/%u.%u %u",
		   &http->major, &http->minor, &http->result);
	if (n != 3)
		return -1;
	return 0;
}

/*
 * HTTP request parser.
 */
int
http_request_parser(transaction *tr, const char *buf, int len)
{
	struct http *http;
	int rv;

	if (tr->release_data == NULL) {
		/*
		 * initial call.  setup
		 *  tr->data: application used,
		 *  and release by tr->release_data().
		 */
		tr->release_data = http_release;
		tr->data = http = CALLOC(1, sizeof(*http));
		if (http == NULL) {
			return TR_FATAL_ERROR;
		}
		http->state = HTTP_PARSE_REQUEST_LINE;
		http->authenticated = 0;
		http->result = 200;

		http->llen = 0;
	} else {
		/*
		 * continuous call.
		 */
		http = tr->data;
	}

	for(; len != 0;) {
		/* get 1 line */
		rv = http_get_one_line(&http->linebuf[http->llen],
				       sizeof(http->linebuf) - http->llen,
				       buf, len);
		switch (rv) {
		case TOO_LONG_LINE:
			http->result = 400;/*Bad Request*/
			return TR_PARSE_ERROR;
		case LF_NOT_FOUND:
			http->llen += len;
			return TR_WANT_READ;
		default:
			buf += rv;
			http->llen += rv;
			len -= rv;
		}
		if (!memcmp(http->linebuf, "\r\n", 2)) {
			/* header terminated. */
			if (!http->authenticated) {
				http->result = 401;/*Unauthorized*/
				return TR_HTTP_AUTH_ERROR;
			}
			http->result = 200;
			/* change parser to body xml parser */
			if (http->chunked) {
				http->state = HTTP_CHUNK_HEADER;
				SET_TR_PARSER(tr,  http_req_chunk_parser);
			} else {
				http->state = HTTP_PARSE_BODY;
				SET_TR_PARSER(tr, arms_req_parser);
			}
			/* parse remaining buffer */
			return tr->parser(tr, buf, len);
		}

		/* make NUL terminated string */
		http->linebuf[--http->llen] = '\0'; /* LF -> NUL */
		if (http->linebuf[http->llen] == '\r') {
			http->linebuf[--http->llen] = '\0'; /* CR -> NUL */
		}
		/* reset llen for next line */
		http->llen = 0;
		/* http->linebuf[] as complete line w/o CRLF */
		switch (http->state) {
		case HTTP_PARSE_REQUEST_LINE:
			if (http_parse_req_line(http) < 0)
				return TR_PARSE_ERROR;
			http->state = HTTP_PARSE_HEADER;
			continue;
		case HTTP_PARSE_HEADER:
			if (http_parse_chunked(http->linebuf)) {
				http->chunked = 1;
			}
			if (http_parse_auth(http, tr->user, tr->passwd)) {
				http->authenticated = 1;
			}
			continue;
		}
	}
	return TR_WANT_READ;
}

/*
 * HTTP response parser.
 */
int
http_response_parser(transaction *tr, const char *buf, int len)
{
	struct http *http;
	int rv;

	http = tr->data;

	for(; len != 0;) {
		/* get 1 line */
		rv = http_get_one_line(&http->linebuf[http->llen],
				       sizeof(http->linebuf) - http->llen,
				       buf, len);
		switch (rv) {
		case TOO_LONG_LINE:
			return TR_PARSE_ERROR;
		case LF_NOT_FOUND:
			http->llen += len;
			return TR_WANT_READ;
		default:
			buf += rv;
			http->llen += rv;
			len -= rv;
		}
		if (!memcmp(http->linebuf, "\r\n", 2)) {
			/* header terminated. */
			http->llen = 0;

			/* change parser to body xml parser */
			if (http->chunked) {
				http->state = HTTP_CHUNK_HEADER;
				SET_TR_PARSER(tr, http_res_chunk_parser);
			} else {
				SET_TR_PARSER(tr, arms_res_parser);
			}
			if (len > 0)
				/* parse remaining buffer */
				return tr->parser(tr, buf, len);
			return TR_WANT_READ;
		}

		/* make NUL terminated string */
		if (http->linebuf[http->llen - 1] == '\n') {
			http->linebuf[--http->llen] = '\0'; /* LF -> NUL */
		}
		if (http->linebuf[http->llen - 1] == '\r') {
			http->linebuf[--http->llen] = '\0'; /* CR -> NUL */
		}
		/* reset llen for next line */
		http->llen = 0;
		/* http->linebuf[] as complete line w/o CRLF */
		switch (http->state) {
		case HTTP_PARSE_STATUS_LINE:
			if (http_parse_status_line(http) < 0)
				return TR_PARSE_ERROR;
			if (http->result >= 400) {
				/* HTTP level access error */
				libarms_log(ARMS_LOG_EHTTP,
				    "http response (%d)", http->result);
				return TR_PARSE_ERROR;
			}
			http->state = HTTP_PARSE_HEADER;
			continue;
		case HTTP_PARSE_HEADER:
			if (http_parse_chunked(http->linebuf)) {
				http->chunked = 1;
			}
			continue;
		}
	}
	return TR_WANT_READ;
}
