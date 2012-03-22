/*	$Id: getnameinfo.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#if !HAVE_GETNAMEINFO

#include <sys/types.h>

#include <unistd.h>
#include <netdb.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "compat.h"

/*
 * implementation of getnameinfo(3), it's subset for libarms.
 * - AF_INET (sockaddr_in) only
 * - ignore flags
 */

int
getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
	    size_t hostlen, char *serv, size_t servlen, int flags)
{
	char *h;
	struct sockaddr_in *si;

	si = (struct sockaddr_in *)sa;
	if (host != NULL) {
		h = inet_ntoa(si->sin_addr);
		if (h == NULL) {
			return -1;
		}
		strlcpy(host, h, hostlen);
	}
	if (serv != NULL) {
		snprintf(serv, servlen, "%d", ntohs(si->sin_port));
	}
	return 0;
}
#endif
