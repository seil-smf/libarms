/*	$Id: tunnel_chunk.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <stdio.h>
#include <string.h>
#include <libarms/ssl.h>
#include <sys/socket.h>
#include <compat.h>

#include <transaction/ssltunnel.h>

int
arms_ssl_chunk_write_header(SSL *ssl, int id, int len, int trail)
{
	static char buf[32];
	int wlen, rv;

	if (len > 65535) {
		/* not supported.  note: generally len <= 8192 in libarms. */
		return 0;
	}
	wlen = snprintf(buf, sizeof(buf),
			"%x;id=%d%s\r\n",
			len, id, trail ? ";trail" : "");
	rv = arms_ssl_write(ssl, buf, wlen);
	return rv;
}

int
arms_ssl_chunk_write_body(SSL *ssl, char *buf, int len)
{
	return arms_ssl_write(ssl, buf, len);
}

int
arms_ssl_chunk_write_trail(SSL *ssl)
{
	return arms_ssl_write(ssl, "\r\n", 2);
}

int
arms_ssl_chunk_write_zero(SSL *ssl)
{
	return arms_ssl_write(ssl,"0\r\n\r\n", 5);
}

int
arms_ssl_chunk_parse_header(struct ssltunnel *tunnel,
			    char *rawbuf, int rawlen,
			    int *type, int *id, char **bufp, int *len,
			    int *trail)
{
	static char line[256]; /* chunk header line */
	char *p, *last;
	int hlen;

	if ((p = strstr(rawbuf, "\r\n")) == NULL) {
		/* CRLF is not found. */
		return -1;
	}
	if (p - rawbuf > sizeof(line) - 1) {
		/* too long line. */
		return -1;
	}
	*bufp = &p[2];
	memcpy(line, rawbuf, p - rawbuf);
	line[p - rawbuf] = '\0';
	hlen = *bufp - rawbuf;

	p = strtok_r(line, ";", &last);
	if (p == NULL) {
		/* token is not found.  ??? */
		return -1;
	}
	*id = 0;
	*type = 0;
	*trail = 0;

	/* first token, is byte of chunk. */
	sscanf(p, "%x", len);
	while ((p = strtok_r(NULL, ";", &last)) != NULL) {
		if (!strncmp(p, "id=", 3)) {
			/* id is string XXX */
			*id = atoi(&p[3]);
		}
		if (!strcmp(p, "trail")) {
			*trail = 1;
		}
		if (!strcmp(p, "echo")) {
			*type = ARMS_CHUNK_ECHO;
		}
		if (!strcmp(p, "echo-response")) {
			*type = ARMS_CHUNK_ECHO_REPLY;
		}
	}
	if (*len == 0)
		*type = ARMS_CHUNK_EOM;
	return hlen;
}
