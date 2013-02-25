/*	$Id: getaddrinfo.c 23153 2012-11-12 10:13:46Z m-oki $	*/

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

#if !HAVE_GETADDRINFO

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libarms/malloc.h>

#include "compat.h"

/*
 * implementation of getaddrinfo(3), it's subset for libarms.
 * - don't use hints
 * - AF_INET only
 * - SOCK_STREAM only
 */

int
getaddrinfo(const char *host, const char *port,
	    const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo *re;
	struct sockaddr_in *s;

	re = *res = CALLOC(1, sizeof(struct addrinfo));
	if (re == NULL)
		return EAI_MEMORY;
	re->ai_addr = CALLOC(1, sizeof(struct sockaddr_in));
	if (re->ai_addr == NULL) {
		FREE(re);
		*res = NULL;
		return EAI_MEMORY;
	}
	s = (struct sockaddr_in *)re->ai_addr;

	re->ai_family = AF_INET;
	re->ai_socktype = SOCK_STREAM;
	re->ai_protocol = 0;
	re->ai_addrlen = sizeof(struct sockaddr_in);
	s->sin_family = AF_INET;
	s->sin_port = htons(atoi(port));
	if (host != NULL)
		s->sin_addr.s_addr = inet_addr(host);
	if (s->sin_addr.s_addr == INADDR_NONE)
		FREE(ai->ai_addr);
		FREE(re);
		*res = NULL;
		return EAI_NODATA;
	return 0;
}

void
freeaddrinfo(struct addrinfo *ai)
{
	FREE(ai->ai_addr);
	FREE(ai);
}
#endif
