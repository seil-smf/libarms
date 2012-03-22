/*	$Id: http.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __HTTP_HTTP_H__
#define __HTTP_HTTP_H__

#include <transaction/transaction.h>

struct http {
	int state; /* REQ_LINE or HEADER, or ... */
	int authenticated;
	int chunked;
	int chunk_size;
	int chunk_remaining;

	/* request line */
	int method; /* GET or POST */
	int major;
	int minor;
	char uri[80 + 1];

	/* http status code */
	int result;

	int llen;
	char linebuf[1024];
};

#define HTTP_METHOD_GET  1
#define HTTP_METHOD_POST 2

enum {
	HTTP_PARSE_REQUEST_LINE,
	HTTP_PARSE_STATUS_LINE,
	HTTP_PARSE_HEADER,
	HTTP_PARSE_BODY,

	HTTP_CHUNK_HEADER,
	HTTP_CHUNK_BODY,
	HTTP_CHUNK_CRLF,
	HTTP_CHUNK_END,
	HTTP_CHUNK_WRITE,

	HTTP_BUILD_HEADER,
	HTTP_BUILD_BODY,
	HTTP_BUILD_END,
};

#define TOO_LONG_LINE -1
#define LF_NOT_FOUND  -2

/* arms_parse_url scheme */
#define URL_SCHEME_HTTP  1
#define URL_SCHEME_HTTPS 2
#define URL_ERROR        -1

/* URL functions */
int arms_parse_url(const char *, char *, int, char *, int, char *, int);
const char *hostname_from_uri(const char *);

/* HTTP parser functions. */
int http_request_parser(transaction *, const char *, int);
int http_response_parser(transaction *, const char *, int);
int http_get_one_line(char *, int, const char *, int);

/* HTTP builder functions. */
int http_request_builder(transaction *, char *, int, int *);
int http_response_builder(transaction *, char *, int, int *);

/* HTTP/1.1 chunk functions. */
int http_req_chunk_parser(transaction *, const char *, int);
int http_res_chunk_parser(transaction *, const char *, int);
int http_req_chunk_builder(transaction *, char *, int, int *);
int http_res_chunk_builder(transaction *, char *, int, int *);

#endif /* __HTTP_HTTP_H__ */
