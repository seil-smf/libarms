/*	$Id: lsconfig.c 21546 2012-03-08 04:26:16Z m-oki $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/des.h>
#include <openssl/crypto.h>

#define LINE_LEN (256 + 1)
#include <lsconfig.h>

#ifdef USE_KEY
#include "lsconf/lsconfig_crypt.c"
#endif

/*
 * plain lsconfig format:
 *	(syntax)	(example)
 *	--------------------------------------------------
 *	URL1\n		https://...../		(LS url)
 *	  :		     :
 *	URLn\n		https://...../		(max 5 urls)
 *	\n
 *	RETRY_SEC\n	10
 *	RETRY_MAX\n	5
 *	\n
 * (optional lines)
 *	pppoe_id\n	foobar@example.jp	(anonymous)
 *	pppoe_pass\n	pass1234
 *	pppoev6_id\n	foobar@example.jp	(anonymous)
 *	pppoev6_pass\n	pass1234
 *	\n
 *	tel_no\n	09012345678		(anonymous)
 *	cid		1
 *	APN\n		iijmobile.jp
 *	pdp-type\n	ip			("ip" or "ppp")
 *	ppp_id\n	foobar@example.jp
 *	ppp_pass\n	pass1234
 */

static int
delete_nl(char *buf)
{
	char *sentinel = buf + LINE_LEN;

	if (buf == NULL)
		return -1;

	while (buf != sentinel && *buf != '\n')
		buf++;
	*buf = '\0';

	return 0;
}

static char *
linebuf_read(char **bufp, size_t *len)
{
	char *lbuf;
	int i, left;

	if (bufp == NULL) {
		return NULL;
	}
	if (len == NULL || *len == 0) {
		return 0;
	}

	lbuf = (char *)malloc(LINE_LEN);
	if (lbuf == NULL) {
		return NULL;
	}
	memset(lbuf, 0, LINE_LEN);

	/* below means; left = min(*len, LINE_LEN - 1) */
	left = *len;
	if (left > (LINE_LEN - 1))
		left = (LINE_LEN - 1);

	for (i = 0; i < left; i++) {
		lbuf[i] = **bufp;
		(*bufp)++;
		(*len)--;

		if (lbuf[i] == '\n') {
			break;
		}
	}

	return lbuf;
}

#define READ_INT(member) \
	line = linebuf_read(&bufp, &len);\
	if (line == NULL) {\
		/* no more line */\
		free_lsconfig(ls_conf);\
		return NULL;\
	}\
	delete_nl(line);\
	ls_conf->member = atoi(line);\
	free(line);

#define READ_OPTIONAL_NEWLINE() \
	line = linebuf_read(&bufp, &len);\
	if (line == NULL) {\
		/* no more line, no exist optional config */\
		return ls_conf;\
	}\
	if (line[0] != '\n') {\
		free(line);\
		free_lsconfig(ls_conf);\
		return NULL;\
	}\
	free(line);

#define READ_OPTIONAL_LINE(member) \
	line = linebuf_read(&bufp, &len);\
	if (line == NULL) {\
		/* no more line, no exist optional config */\
		return ls_conf;\
	}\
	delete_nl(line);\
	ls_conf->member = line

#define READ_OPTIONAL_LINE_OR_NEWLINE(member) \
	line = linebuf_read(&bufp, &len);\
	if (line == NULL) {\
		/* no more line, no exist optional config */\
		return ls_conf;\
	}\
	if (line[0] == '\n') {\
		free(line);\
		line = NULL;\
	}\
	delete_nl(line);\
	ls_conf->member = line

ls_config_t *
parse_lsconfig(char *buf, size_t len)
{
	ls_config_t *ls_conf;
	char *bufp;
	char *line;
	int nurl = 0;
	int found = 0;

	if (buf == NULL)
		return NULL;
	if (len == 0)
		return NULL;
	bufp = buf;
	ls_conf = (ls_config_t *)calloc(1, sizeof(*ls_conf));
	if (ls_conf == NULL)
		return NULL;

	/* ls_addrs */
	line = NULL;
	do {
		line = linebuf_read(&bufp, &len);
		if (line == NULL) {
			free_lsconfig(ls_conf);
			return NULL;
		}
		if (line[0] == '\n') {
			/* null line is terminator */
			found = 1;
			free(line);
			line = NULL;
			break;
		}
		delete_nl(line);
		ls_conf->url[nurl] = line; 
		line = NULL;
		nurl++;
	} while (nurl < MAX_URL && len > 0);
	if (!found || nurl == 0) {
		if (line)
			free(line);
		free_lsconfig(ls_conf);
		return NULL;
	}
	ls_conf->num_url = nurl;
	line = NULL;

	/* retry interval */
	READ_INT(retry_int);
	/* retry max */
	READ_INT(retry_max);

	/****** optional parameter ******/

	/* check delimiter */
	READ_OPTIONAL_NEWLINE();
	/* anonid */
	READ_OPTIONAL_LINE(anonid);
	/* anonpass */
	READ_OPTIONAL_LINE(anonpass);
	/* annonid for ipv6 or delimiter (optional) */
	READ_OPTIONAL_LINE_OR_NEWLINE(v6anonid);
	if (line != NULL) {
		/* anonpass for ipv6 */
		READ_OPTIONAL_LINE(v6anonpass);
		/* check delimiter */
		READ_OPTIONAL_NEWLINE();
	}

	/* mobile configuration, optional. */
	/* telno */
	READ_OPTIONAL_LINE(telno);
	/* cid */
	READ_OPTIONAL_LINE(cid);
	/* apn */
	READ_OPTIONAL_LINE(apn);
	/* pdp-type */
	READ_OPTIONAL_LINE(pdp_type);
	/* pppid */
	READ_OPTIONAL_LINE(pppid);
	/* ppppass */
	READ_OPTIONAL_LINE(ppppass);

	return ls_conf;
}
#undef READ_INT
#undef READ_OPTIONAL_NEWLINE
#undef READ_OPTIONAL_LINE
#undef READ_OPTIONAL_LINE_OR_NEWLINE

#define FREEM(member) if (ls_conf->member) free(ls_conf->member)
void
free_lsconfig(ls_config_t *ls_conf)
{
	int i;

	for (i = 0;  i < MAX_URL; i++) {
		FREEM(url[i]);
	}
	FREEM(anonid);
	FREEM(anonpass);
	FREEM(v6anonid);
	FREEM(v6anonpass);
	FREEM(telno);
	FREEM(cid);
	FREEM(apn);
	FREEM(pdp_type);
	FREEM(pppid);
	FREEM(ppppass);

	free(ls_conf);
}
#undef FREEM
