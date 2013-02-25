/*	$Id: chunk.c 23434 2013-02-07 10:39:00Z m-oki $	*/

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

#include <http/http.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * chunk.
 */

static int
http_chunk_parser(transaction *, const char *, int,
		  int (*)(transaction *, const char *, int),
		  int (*)(transaction *, char *, int, int *));
static int
http_chunk_builder(transaction *, char *, int, int *,
		   int (*)(transaction *, char *, int, int *),
		   int (*)(transaction *, const char *, int));

#define min(a,b) ((a) < (b) ? (a) : (b))
/*
 * error code.  positive value as size.
 */
#define CHUNK_SIZE_TERMINATED -1
#define CHUNK_SIZE_ERROR      -2
/*
 * parse chunk-size.
 */
static int
http_parse_chunk_size(struct http *http)
{
	static const char hex[] = "0123456789abcdef";
	const char *p = http->linebuf;
	const char *off;
	char ch;
	int size;

	if (!strcmp(p, "0"))
		return CHUNK_SIZE_TERMINATED;
	if (strchr(&hex[1], *p) == NULL)
		return CHUNK_SIZE_ERROR;

	size = 0;
	while ((ch = *p++) != '\0') {
		if (ch >= 'A' && ch <= 'F')
			ch += 'a' - 'A';
		if ((off = strchr(hex, ch)) != NULL) {
			if (size > size * 16) {
				/* overflow. */
				return CHUNK_SIZE_ERROR;
			}
			size *= 16;
			size += off - hex;
		} else if (ch == ';') {
			break;
		} else {
			/* syntax error. */
			return CHUNK_SIZE_ERROR;
		}
	}
	return size;
}

int
http_req_chunk_parser(transaction *tr, const char *buf, int len)
{
	return http_chunk_parser(tr, buf, len,
				 arms_req_parser,
				 http_response_builder);
}

int
http_res_chunk_parser(transaction *tr, const char *buf, int len)
{
	return http_chunk_parser(tr, buf, len,
				 arms_res_parser,
				 NULL);
}

/*
 * generic chunk-body parser.
 */
static int
http_chunk_parser(transaction *tr, const char *buf, int len,
		  int (*body_parser)(transaction *, const char *, int),
		  int (*builder)(transaction *, char *, int, int *))
{
	struct http *http = tr->data;
	int rv;

loop:
	switch(http->state) {
	case HTTP_CHUNK_HEADER:
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

		/* linebuf should be terminated with "\n" */
		if (!strncmp(http->linebuf, "\r\n", 2) ||
		    !strncmp(http->linebuf, "\n", 1) ) {
			/* skip empty line */
			http->llen = 0;
			goto loop;
		}
		/* make NUL terminated string */
		/* FORTIFY:HOT (Buffer Overflow) */
		http->linebuf[http->llen - 1] = '\0'; /* LF -> NUL */
		if (http->linebuf[http->llen - 2] == '\r') {
			/* FORTIFY:HOT (Buffer Overflow) */
			http->linebuf[http->llen - 2] = '\0'; /* CR -> NUL */
		}
		/* http->linebuf[] as complete line w/o CRLF */
		http->chunk_size = http_parse_chunk_size(http);
		http->llen = 0;
		http->chunk_remaining = http->chunk_size;
		if (http->chunk_size == CHUNK_SIZE_TERMINATED) {
			/*
			 * zero chunk.  end of request.
			 * XXX?
			 */
			SET_TR_BUILDER(tr, builder);
			return body_parser(tr, NULL, 0);
		} else if (http->chunk_size == CHUNK_SIZE_ERROR) {
			http->result = 400;/*Bad Request*/
			return TR_PARSE_ERROR;
		}
		http->state = HTTP_CHUNK_BODY;
		/*FALLTHROUGH*/
	case HTTP_CHUNK_BODY:
		/* call XML parser. */
		rv = body_parser(tr, buf, min(http->chunk_remaining, len));

		switch (rv) {
		case TR_WANT_ROLLBACK:
		case TR_READ_DONE:
		case TR_PARSE_ERROR:
			if (http->chunk_remaining > len) {
				/* parser is done, but more data available. */
			} else {
				/* chunked-body footer and CRLF */
			}
			if (builder) {
				http->result = 200;
				http->state = HTTP_BUILD_HEADER;
				SET_TR_BUILDER(tr, builder);
			}
			return rv;
		case TR_WANT_READ:
			if (http->chunk_remaining > len) {
				http->chunk_remaining -= len;
				return rv;
			}
			buf -= http->chunk_remaining;
			len -= http->chunk_remaining;
			if (len < 2) {
				http->state = HTTP_CHUNK_CRLF;
				memcpy(http->linebuf, buf, len);
				return TR_WANT_READ;
			}
			break;
		case TR_WANT_STOP:
			return TR_WANT_STOP;
		}
		/*FALLTHROUGH*/
	case HTTP_CHUNK_CRLF:
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
			http->state = HTTP_CHUNK_HEADER;
			goto loop;
		}
		http->result = 400;/*Bad Request*/
		return TR_PARSE_ERROR;
	}
	return TR_FATAL_ERROR;
}

int
http_req_chunk_builder(transaction *tr, char *buf, int len, int *wrote)
{
	return http_chunk_builder(tr, buf, len, wrote,
				  arms_req_builder,
				  http_response_parser);
}

int
http_res_chunk_builder(transaction *tr, char *buf, int len, int *wrote)
{
	return http_chunk_builder(tr, buf, len, wrote,
				  arms_res_builder,
				  NULL);
}

/*
 * generic chunk-body builder.
 */
static int
http_chunk_builder(transaction *tr, char *buf, int len, int *wrote,
		   int (*body_builder)(transaction *, char *, int, int *),
		   int (*parser)(transaction *, const char *, int))
{
	static char tmpbuf[8192];/*XXX*/
	int wrote_body;
	int rv, size;
	struct http *http = tr->data;

	switch (http->state) {
	case HTTP_CHUNK_WRITE:
		rv = body_builder(tr, tmpbuf, sizeof(tmpbuf), &wrote_body);
		if (rv == TR_WRITE_DONE || rv == TR_WANT_STOP) {
			tr->tr_ctx.write_done = rv;
			http->state = HTTP_CHUNK_END;
		}
		if (wrote_body == 0) {
			/* don't write last chunk if tmpbuf is "". */
			*wrote = 0;
			return TR_WANT_WRITE;
		}
		size = snprintf(buf, len, "%x\r\n", wrote_body);
		buf += size;
		len -= size;
		if (wrote_body > len)
			return TR_FATAL_ERROR;
		if (wrote_body > 0) {
			memcpy(buf, tmpbuf, wrote_body);
			buf += wrote_body;
			len -= wrote_body;
			size += wrote_body;
		}
		snprintf(buf, len, "\r\n");
		size += 2;

		*wrote = size;
		return  TR_WANT_WRITE;

	case HTTP_CHUNK_END:
		*wrote = snprintf(buf, len, "0\r\n\r\n");
		if (tr->tr_ctx.write_done != TR_WANT_STOP) {
			if (parser != NULL) {
				SET_TR_PARSER(tr, parser);
			}
			http->state = HTTP_BUILD_END;
			return TR_WANT_WRITE;
		}
		/*FALLTHROUGH*/
	case HTTP_BUILD_END:
		http->state = HTTP_PARSE_STATUS_LINE;
		return tr->tr_ctx.write_done;
	}
	return TR_FATAL_ERROR;
}
