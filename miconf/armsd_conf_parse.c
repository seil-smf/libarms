/*	$Id: armsd_conf_parse.c 22136 2012-06-13 06:32:51Z m-oki $	*/

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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include <libarms.h>
#include <armsd_conf.h>

#include "armsd_miconf_private.h"
#include "armsd_conf_parse.h"

#include "compat.h"

#ifndef NELEMS
#define NELEMS(x) (sizeof(x)/sizeof(x[0]))
#endif /* NELEMS */

static char *
skip_ws(char *src)
{
	if (src == NULL) {
		return NULL;
	}

	for (;;) {
		switch (*src) {
			case '\n':
			case '\r':
			case '\t':
			case ';': /* ignore semicolon(backward compat.) */
			case ' ':
				src++;
				break;
			case '\0':
				return NULL;
				break;
			default:
				return src;
				break;
		}
	}

	/* NOTREACHED */
	return src;
}

static int
get_line(char *src, char *dst, int len)
{
	char *p;

	if (src == NULL) {
		return -1;
	}
	if (dst == NULL) {
		return -1;
	}
	if (len < 0) {
		return -1;
	}

	p = skip_ws(src); /* ignore headding spaces */

	if (p == NULL)
		return 0;

	while (*p != '\n' && *p != '\0') {
		*dst =  *p;
		dst++; p++;
	}
	*dst = '\0';

	return (p - src);
}

static int
tokenize(char *src, int len, char **dst, int nmem)
{
	int i;

	if (src == NULL) {
		return -1;
	}
	if (dst == NULL) {
		return -1;
	}
	if (nmem < 0) {
		return -1;
	}

	i = 0;
	for (;;) {
		/*
		 * 1. check if double-quote
		 * 2. begin to record
		 * 3. search space, delimiter, double-quote or EOS
		 * 4. end to record
		 * 5. skip space and delimiter
		 */
		*dst = src;
		i++;
		if ( (--nmem) == 0)
			break;

		while (len > 0) {
			src++;
			len--;
			/* stop if delimiter found */
			if (*src == ' ' || *src == '\0' || *src == ';')
				break;
		}

		if (*src == '\0')
			break;
		if (len == 0)
			break;
		*src = '\0'; /* split string */
		src++;
		if ( (src = skip_ws(src)) == NULL)
			break;
		dst++;
	}

	return i;
}

static int
cmp_token(const char *str, char *obj)
{
	if (strlen(str) != strlen(obj)) /* strlen may not safe? */
		return -1;

	if (strncmp(str, obj, strlen(str)) == 0)
		return 0;

	return -1;
}

static enum miconf_tokens
tok2num(char *tok)
{
	/* there is room for optimization... */
	if (cmp_token("{", tok) == 0) {
		return TOK_OC;
	}
	else if (cmp_token("}", tok) == 0) {
		return TOK_CC;
	}
	else if (cmp_token(";", tok) == 0) {
		return TOK_SC;
	}
	else if (cmp_token("ifindex", tok) == 0) {
		return TOK_IFINDEX;
	}
	else if (cmp_token("account", tok) == 0) {
		return TOK_ACCOUNT;
	}
	else if (cmp_token("password", tok) == 0) {
		return TOK_PASSWD;
	}
	else if (cmp_token("telno", tok) == 0) {
		return TOK_TELNO;
	}
	else if (cmp_token("cid", tok) == 0) {
		return TOK_CID;
	}
	else if (cmp_token("apn", tok) == 0) {
		return TOK_APN;
	}
	else if (cmp_token("pdp-type", tok) == 0) {
		return TOK_PDP;
	}
	else if (cmp_token("ipaddress", tok) == 0) {
		return TOK_IPADDR;
	}
	else if (cmp_token("line-dhcp", tok) == 0) {
		return TOK_LDHCP;
	}
	else if (cmp_token("line-pppoe", tok) == 0) {
		return TOK_LPPPOE;
	}
	else if (cmp_token("line-pppoe-ipv6", tok) == 0) {
		return TOK_LPPPOE_IPV6;
	}
	else if (cmp_token("line-mobile", tok) == 0) {
		return TOK_LMOBILE;
	}
	else if (cmp_token("line-static", tok) == 0) {
		return TOK_LSTATIC;
	}
	else if (cmp_token("line-ra", tok) == 0) {
		return TOK_LRA;
	}
	else if (cmp_token("rs-certificate", tok) == 0) {
		return TOK_RSCERT;
	}
	else if (cmp_token("-----BEGIN", tok) == 0) {
		return TOK_BEGIN_CERT;
	}
	else if (cmp_token("-----END", tok) == 0) {
		return TOK_END_CERT;
	}
	else if (cmp_token("CERTIFICATE-----", tok) == 0) {
		return TOK_CERT;
	}

	return TOK_INVAL;
}

static char *
append_cert(char *p, char *tok)
{
	int l;

	l = strlen(tok);
	memcpy(p, tok, l);
	p += l;
	*p = '\n';
	p++;

	return p;
}

#define TYPEIS(n) (config->line_defs[config->num_line].type == (ARMS_LINE_##n))
static int
parse_tokens(acmi_config_t *config, int idx, enum miconf_parse_st *st, char *tok)
{
	static char *p;
	arms_line_conf_pppoe_t *pppoeconf;
	arms_line_conf_mobile_t *mobileconf;
	arms_line_conf_static_t *staticconf;
	enum miconf_tokens tokn;

	tokn = tok2num(tok);
	pppoeconf = &config->line_defs[config->num_line].conf.pppoe;
	mobileconf = &config->line_defs[config->num_line].conf.mobile;
	staticconf = &config->line_defs[config->num_line].conf.staticip;

	switch (*st) {
	case ST_INITIAL:
		/*
		 * line configuration storage has no (server) index.
		 *  then, idx > 0 should be ignored.  sigh...
		 */
		switch (tokn) {
		case TOK_APPPOE:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_ANONPPPOE;
				*st = ST_LINE;
			}
			break;
		case TOK_LPPPOE:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_PPPOE;
				*st = ST_LINE;
			}
			break;
		case TOK_APPPOE_IPV6:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_ANONPPPOE_IPV6;
				*st = ST_LINE;
			}
			break;
		case TOK_LPPPOE_IPV6:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_PPPOE_IPV6;
				*st = ST_LINE;
			}
			break;
		case TOK_LDHCP:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_DHCP;
				*st = ST_LINE;
			}
			break;
		case TOK_AMOBILE:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_ANONMOBILE;
				*st = ST_LINE;
			}
			break;
		case TOK_LMOBILE:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_MOBILE;
				*st = ST_LINE;
			}
			break;
		case TOK_LSTATIC:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_STATIC;
				*st = ST_LINE;
			}
			break;
		case TOK_LRA:
			if (idx == 0) {
				config->line_defs[config->num_line].type = 
					ARMS_LINE_RA;
				*st = ST_LINE;
			}
			break;
		case TOK_RSCERT:
			*st = ST_RSCERT;
			p = config->server_defs[idx].cacert;
			config->server_defs[idx].have_cert = 1;
			break;
		default:
			break;
		}
		break;
	case ST_LINE:
		switch (tokn) {
		case TOK_IFINDEX:
			*st = ST_LINE_IFINDEX;
			break;
		case TOK_ACCOUNT:
			*st = ST_LINE_ACCOUNT;
			break;
		case TOK_PASSWD:
			*st = ST_LINE_PASSWD;
			break;
		case TOK_TELNO:
			*st = ST_LINE_TELNO;
			break;
		case TOK_CID:
			*st = ST_LINE_CID;
			break;
		case TOK_APN:
			*st = ST_LINE_APN;
			break;
		case TOK_PDP:
			*st = ST_LINE_PDP;
			break;
		case TOK_IPADDR:
			*st = ST_LINE_IPADDR;
			break;
		case TOK_OC:
			/* ignore */
			break;
		case TOK_CC:
			*st = ST_INITIAL;
			config->num_line++;
			break;
		default:
			break;
		}
		break;
	case ST_LINE_IFINDEX:
		/* offset 0 of all types: ifindex */
		pppoeconf->ifindex = atoi(tok);
		*st = ST_LINE;
		break;
	case ST_LINE_ACCOUNT:
		if (TYPEIS(PPPOE) || TYPEIS(PPPOE_IPV6))
			strlcpy(pppoeconf->id, tok, MAX_PPP_ID);
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->id, tok, MAX_MOBILE_PPP_ID);
		*st = ST_LINE;
		break;
	case ST_LINE_PASSWD:
		if (TYPEIS(PPPOE) || TYPEIS(PPPOE_IPV6))
			strlcpy(pppoeconf->pass, tok, MAX_PPP_PASS);
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->pass, tok, MAX_MOBILE_PPP_PASS);
		*st = ST_LINE;
		break;
	case ST_LINE_TELNO:
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->telno, tok, MAX_MOBILE_TEL_LEN);
		*st = ST_LINE;
		break;
	case ST_LINE_CID:
		if (TYPEIS(MOBILE))
			mobileconf->cid = atoi(tok);
		*st = ST_LINE;
		break;
	case ST_LINE_APN:
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->apn, tok, MAX_MOBILE_APN_LEN);
		*st = ST_LINE;
		break;
	case ST_LINE_PDP:
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->pdp, tok, MAX_MOBILE_PDP_LEN);
		*st = ST_LINE;
		break;
	case ST_LINE_IPADDR:
		if (TYPEIS(MOBILE))
			strlcpy(mobileconf->ipaddr, tok, 48);
		if (TYPEIS(STATIC))
			strlcpy(staticconf->ipaddr, tok, 48);
		*st = ST_LINE;
		break;
	case ST_RSCERT:
		switch (tokn) {
		case TOK_BEGIN_CERT:
			p = append_cert(p, "-----BEGIN CERTIFICATE-----");
			/* ignore */
			break;
		case TOK_END_CERT:
			p = append_cert(p, "-----END CERTIFICATE-----");
			/* ignore */
			break;
		case TOK_CERT:
			/* ignore */
			break;
		case TOK_OC:
			break;
		case TOK_CC:
			*st = ST_INITIAL;
			break;
		default:
			p = append_cert(p, tok);
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}
#undef TYPEIS

int
text_config_parse(ACMI *acmi, int idx, char *src, int len)
{
	acmi_config_t *config;
	enum miconf_parse_st st;
	char lbuf[256];
	char *srcp;
	char *tok[256];
	int l;
	int i;
	int j;

	if (acmi == NULL) {
		return -1;
	}
	if (src == NULL) {
		return -1;
	}
	if (len < 0) {
		return -1;
	}

	config = &acmi->mi_config[ACMI_CONFIG_CONFSOL];
	st = ST_INITIAL;
	/* reset line info */
	if (idx == 0)
		config->num_line = 0;

	srcp = src;
	for (;;) {
		l = get_line(srcp, lbuf, NELEMS(lbuf));
		if (l <= 0)
		       	break;
		len -= l; srcp += l;
		i = tokenize(lbuf, l, tok, NELEMS(tok));
		for (j = 0; j < i; j++) {
			parse_tokens(config, idx, &st, tok[j]);
		}
	}

	return 0;
}
