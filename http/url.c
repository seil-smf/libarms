/*	$Id: url.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include "compat.h"

int
arms_parse_url(const char *url,
	       char *hbuf, int hlen,
	       char *pbuf, int plen,
	       char *pathbuf, int pathlen)
{
	int len, scheme;
	const char *p, *service, *ep, *ppath;

	if (url == NULL) {
		/* invalid pointer */
		return URL_ERROR;
	}
	p = url;
	if (strncasecmp(url, "http://", 7) == 0) {
		p += 7;
		scheme = URL_SCHEME_HTTP;
		service = "80";
	} else if (strncasecmp(url, "https://", 8) == 0) {
		p += 8;
		scheme = URL_SCHEME_HTTPS;
		service = "443";
	} else {
		/* scheme not supported */
		return URL_ERROR;
	}

	/* p: hostname:port/path  p[n]: :port/path or /path */
	/* look for path */
	ppath = strchr(p, '/');
	if (ppath == NULL) {
		if (pathbuf != NULL)
			pathbuf[0] = '\0';
		ppath = p + strlen(p) + 1;
	} else
		if (pathbuf != NULL)
			/* strip ^/ */
			if (strlcpy(pathbuf, ppath+1, pathlen) >= pathlen)
				return URL_ERROR;

	/* look for hostname */
	if (p[0] == '[') {
		p++;
		if ((ep = strchr(p, ']')) == NULL ||
		    (ep[1] != '/' && ep[1] != ':')) {
			return URL_ERROR;	/* invalid url */
		}
		/* XXX: no check hbuf is ipv6 address */
		if (hbuf != NULL) {
			len = ep - p;
			if (len + 1 > hlen)
				return URL_ERROR;	/* no space */
			memcpy(hbuf, p, len);
			hbuf[len] = '\0';
		}
		if (ep != NULL)
			p = ep + 1;
	} else {
		if ((ep = strchr(p, ':')) != NULL)
			len = ep - p;
		else
			len = ppath - p;
		if (hbuf != NULL) {
			if (len + 1 > hlen)
				return URL_ERROR;	/* no space */
			memcpy(hbuf, p, len);
			hbuf[len] = '\0';
		}
		if (ep != NULL)
			p = ep;
	}
	/* look for [:port] */
	if (p[0] == ':') {
		p++;
		/* ppath is not NULL */
		len = ppath - p;
		if (pbuf != NULL) {
			if (len +1 > plen)
				return URL_ERROR;	/* no space */
			memcpy(pbuf, p, len);
			pbuf[len] = '\0';
		}
	} else
		if (pbuf != NULL)
			strlcpy(pbuf, service, plen);

	return scheme;
}

const char *
hostname_from_uri(const char *url)
{
	static char host[80];
	int scheme;

	scheme = arms_parse_url(url, host, sizeof(host), NULL, 0, NULL, 0);
	if (scheme == URL_ERROR) {
		return "";
	}
	return host;
}
