/*	$Id: libarms_param.h 20961 2012-01-31 05:31:02Z m-oki $	*/

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

#ifndef __LIBARMS_PARAM_H__
#define __LIBARMS_PARAM_H__

#if defined(ARMS_DEBUG)
#define LOG_BUFSIZ		4096
#else /* defined(ARMS_DEBUG) */
#define LOG_BUFSIZ		128
#endif /* defined(ARMS_DEBUG) */
#define LOG_RING_SIZE		256
#define AXP_BUILD_BUFSIZ	1024 * 1024
#define	SEND_BUFSIZ		1024
#define RECV_BUFSIZ		1024
#define	MAX_RS_LIST		5
#define	MAX_LS_MDCONFIG		2048
#define	CDATA_HDR		"<![CDATA["
#define	CDATA_TRAIL		"]]>"
#define DEFAULT_XML_SIZE	1024
#define	RDESC_LEN		256
#define	SA_ADDR_LEN		256
#define	RS_ADDR_LEN		256
#define	TR_MAX_ARG		256
#define PUSH_MAX_MSG		64
#define TR_LIMIT		10

#define	LS_RETRY_MAX		3
#define	LS_RETRY_INT		3
#ifndef LLTIMEOUT
#define	LLTIMEOUT		30
#endif

#define	TMP_MAX_FACTOR		1
#define	TMP_INT_FACTOR		1
#define	SHORT_MAX_FACTOR	500
#define	SHORT_INT_FACTOR	120
#define	LONG_MAX_FACTOR		30
#define	LONG_INT_FACTOR		120

#define	LS_PULL_RETRY_MAX	3
#define	LS_PULL_RETRY_INT	10

#define	MAX_DISTIDSTR		256

#define	EVT_TICK_RES		1
#define	MAX_EVENT		1024
#define	HTTPBUFSIZE		8192

/* lsconfig */
#define	MAX_CONFIG_LEN		5192
#define	LINE_LEN		(256+1)

/* miconf */
#define CONF_MAX_LS_LIST	5
#ifndef CONF_MAX_LINE_LIST
#define	CONF_MAX_LINE_LIST	5
#endif
#define	CONF_MAX_STR_LEN	256

/* PUSH Transaction */
#define	TR_MAX_ARG		256
#define PUSH_READY_RMAX		30
#define PUSH_READY_RINT		1

/* ARMS BUFFER */
#define ABUF_TMP_SIZ		1024
#define ABUF_REALLOC_EXTRA_CHUNK 512

/* MD command */
#define RESULT_LEN		1024

#endif /* __LIBARMS_PARAM_H__ */
