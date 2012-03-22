/*	$Id: armsd_conf_parse.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __ARMSD_CONF_PARSE_H__
#define __ARMSD_CONF_PARSE_H__
enum miconf_tokens {
	TOK_INVAL = 0,
	TOK_APPPOE, /* line-apppoe */
	TOK_LPPPOE, /* line-pppoe */
	TOK_LDHCP,  /* line-dhcp */
	TOK_AMOBILE,/* line-amobile */
	TOK_LMOBILE,/* line-mobile */
	TOK_LSTATIC,/* line-static */
	TOK_LRA,    /* line-ra */

	TOK_IFINDEX, /* ifindex */
	TOK_ACCOUNT, /* account */
	TOK_PASSWD, /* password */

	TOK_TELNO,  /* tel number */
	TOK_CID,    /* cid */
	TOK_APN,    /* apn */
	TOK_PDP,    /* PDP type */
	TOK_IPADDR, /* IP address */

	TOK_RSCERT, /* rs-certificate */

	TOK_OC, /* { */
	TOK_CC, /* } */
	TOK_SC, /* ; */

	TOK_BEGIN_CERT, /* -----BEGIN */
	TOK_END_CERT, /* -----END */
	TOK_CERT, /* CERTIFICATE----- */
};

enum miconf_parse_st {
	ST_INITIAL = 0,
	ST_LINE,
	ST_LINE_IFINDEX,
	ST_LINE_ACCOUNT,
	ST_LINE_PASSWD,
	ST_LINE_TELNO,
	ST_LINE_CID,
	ST_LINE_APN,
	ST_LINE_PDP,
	ST_LINE_IPADDR,
	ST_RSCERT,
};

int text_config_parse(ACMI *acmi, int idx, char *src, int len);
#endif /* __ARMSD_CONF_PARSE_H__ */
