/*$Id: hb_api.c 23530 2013-02-28 02:15:12Z m-oki $*/

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

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libarms.h"
#include "libarms_resource.h"
#include "hb_routine.h"
#include "errcode.h"
#include "libarms/sock.h"

/*
 * internal routines
 */
int
hb_library_ver_major(void) {
	return LIBHB_LIBRARY_VER_MAJOR;
}

int
hb_library_ver_minor(void) {
	return LIBHB_LIBRARY_VER_MINOR;
}

const char *
hb_library_ver_string(void)
{
        static char verstr[HB_MAX_DESC_LEN + 1];

        memset(verstr, 0, sizeof(verstr));
        snprintf(verstr, sizeof(verstr), "%01d.%02d (%s)",
		 LIBHB_LIBRARY_VER_MAJOR,
		 LIBHB_LIBRARY_VER_MINOR,
		 LIBHB_LIBRARY_VER_DESCRIPTION);

        return (const char *)verstr;
}

int
hb_protocol_ver_major(void) {
	return LIBHB_PROTOCOL_VER_MAJOR;
}

int
hb_protocol_ver_minor(void) {
	return LIBHB_PROTOCOL_VER_MINOR;
}

static int
hb_init_common(hb_context_t *ctx, int buflen, int buflen_max)
{
	if (ctx == NULL) {
		return ARMS_EFATAL;
	}
	if (buflen < 0) {
		return ARMS_EINVAL;
	}
	if (buflen < buflen_max) {
		return ARMS_EINVAL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->msgbuf = (uint8_t *)malloc(buflen);
	ctx->buflen = buflen;
	ctx->numsvr = 0;
	
	return 0;
}

int 
arms_hb_init(hb_context_t *ctx, int buflen, distribution_id_t id)
{
	int error;

	error = hb_init_common(ctx, buflen, HB_NEED_LEN);
	if (error)
		return error;

	ctx->id = id;
	arms_hb_clear(ctx);

	return 0;
}

static int
hb_clear_common(hb_context_t *ctx)
{
	if (ctx == NULL) {
		return ARMS_EFATAL;
	}
	if (ctx->msgbuf == NULL) {
		return ARMS_EFATAL;
	}
	memset(ctx->msgbuf, 0, ctx->buflen);
	ctx->freeptr = 0;

	return 0;
}

int
arms_hb_clear(hb_context_t *ctx)
{
	int error;

	error = hb_clear_common(ctx);
	if (error)
		return error;

	if (buf_space(ctx) <= (HB_TL_LEN + HB_LEN_HMAC_SHA1)) {
		return ARMS_ESIZE;
	}
	set16b(ctx, HB_TYPE_HMAC);
	set16b(ctx, HB_LEN_HMAC_SHA1);
	ctx->freeptr += HB_LEN_HMAC_SHA1;

	if (buf_space(ctx) <= (HB_TL_LEN + HB_LEN_DIST_ID)) {
		return ARMS_ESIZE;
	}
	set16b(ctx, HB_TYPE_DIST_ID);
	set16b(ctx, HB_LEN_DIST_ID);
	set16b(ctx, ctx->id.version);
	set32b(ctx, ctx->id.vendor_code);
	set16b(ctx, ctx->id.sa_type);
	set64b(ctx, ctx->id.sa_code);

	return 0;
}

static int 
hb_update_server_common(hb_context_t *ctx, void *svr, int num)
{
	if (ctx == NULL)
		return ARMS_EFATAL;
	if (ctx->msgbuf == NULL)
		return ARMS_EFATAL;
	if (svr == NULL)
		return ARMS_EINVAL;
	if ((num > HB_MAX_SERVER) || (num <= 0))
		return ARMS_EINVAL;
	return 0;
}

int 
arms_hb_update_server(hb_context_t *ctx, arms_hbt_info_t *svr, int num)
{
	int error;

	error = hb_update_server_common(ctx, svr, num);
	if (error)
		return error;

	ctx->numsvr = 0;
	{
		int i, n;
		int  count = 0;
		for (i = 0; i < num; i++) {
			if ((svr[i].host == NULL) ||
			    (strlen(svr[i].host) >= HB_MAX_HOSTLEN) || 
			    (svr[i].port < 0) ||
			    (svr[i].port > 65535) ||
			    (svr[i].passphrase == NULL) ||
			    (strlen(svr[i].passphrase) >= HB_MAX_PASSLEN)) {
				ctx->numsvr = 0;
				return ARMS_EINVAL;
			}
			if (count == 0) {
				count = svr[i].interval;
			} else {
				if (count != svr[i].interval) {
					ctx->numsvr = 0;
					return ARMS_EINVAL;
				}
			}
			n = sizeof(ctx->server[i].host);
			strncpy(ctx->server[i].host, svr[i].host, n - 1);
			ctx->server[i].host[n - 1] = '\0';
			ctx->server[i].port = svr[i].port;
			n = sizeof(ctx->server[i].passphrase);
			strncpy(ctx->server[i].passphrase, svr[i].passphrase, n);
			ctx->server[i].passphrase[n - 1] = '\0';
			ctx->server[i].passlen = strlen(svr[i].passphrase);
			ctx->numsvr++;
		}
	}
	return 0;
}

int
arms_hb_send(hb_context_t *ctx, int af, hb_send_result_t *result)
{
        int error, sock, i, err_count;
        struct addrinfo in, *out;
        char portbuf[6];
	
	if (ctx == NULL) {
		return ARMS_EFATAL;
	}
	if (ctx->msgbuf == NULL) {
		return ARMS_EFATAL;
	}
	if (ctx->numsvr <= 0) {
		return ARMS_EINVAL;
	}
	if (result !=  NULL) {
		result->err_count = 0;
	}
	err_count = 0;
	for (i = 0; i < ctx->numsvr; i++) {
		set_hmac(ctx, i);

		memset(&in, 0, sizeof(in));
#ifdef USE_INET6
		in.ai_family = AF_UNSPEC;
#else
		in.ai_family = AF_INET;
#endif
		in.ai_socktype = SOCK_DGRAM;
		snprintf(portbuf, sizeof(portbuf), "%u", ctx->server[i].port);

		error = getaddrinfo(ctx->server[i].host, portbuf, &in, &out);
		if (error) {
			if (result != NULL) {
				result->err_count++;
				result->server[i].stage = HB_ESEND_GAI;
				result->server[i].code = error;
			}
			err_count++;
			continue;
		}
		if (af != out->ai_family) {
			/* address family mismatch, not error */
			result->server[i].stage = HB_ESEND_GAI;
			result->server[i].code = EAI_FAMILY;
			continue;
		}
		sock = arms_socket(out->ai_family, out->ai_socktype,
		    out->ai_protocol);
		if (sock < 0) {
			if (result != NULL) {
				result->err_count++;
				result->server[i].stage = HB_ESEND_SOCK;
				result->server[i].code = errno;
			}
			arms_close(sock);
			freeaddrinfo(out);
			err_count++;
			continue;
		}
		if (arms_sendto(sock, ctx->msgbuf, ctx->freeptr, 0,
			   out->ai_addr, out->ai_addrlen) < 0) {
			if (result != NULL) {
				result->err_count++;
				result->server[i].stage = HB_ESEND_SENDTO;
				result->server[i].code = errno;
			}
			arms_close(sock);
			freeaddrinfo(out);
			err_count++;
			continue;
		} else {
			if (result != NULL) {
				result->server[i].stage = 0;
				result->server[i].code = 0;
			}
		}
		arms_close(sock);
		freeaddrinfo(out);
	}
	if (err_count) {
		return HB_ESEND;
	}
        return 0;
}

int
arms_hb_end(hb_context_t *ctx)
{
	if (ctx ==  NULL) {
		return ARMS_EFATAL;
	}
	if (ctx->msgbuf == NULL) {
		return ARMS_EFATAL;
	}
	memset(ctx->msgbuf, 0, ctx->buflen);
	free(ctx->msgbuf);
	ctx->msgbuf = NULL;
	memset(ctx, 0, sizeof(ctx));
 	return 0;
}

/*
 * public APIs
 */

int
arms_hb_set_cpu_usage(arms_context_t *acx, uint16_t idx, uint8_t utilization)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
		return ARMS_EFATAL;
	}
        if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_CPU)) {
                return ARMS_ESIZE;
        }
	if (find_multiplex_index(ctx, HB_TYPE_CPU, HB_LEN_CPU, idx)) {
		return ARMS_EEXIST;
	}
	set16b(ctx, HB_TYPE_CPU);
	set16b(ctx, HB_LEN_CPU);
	set16b(ctx, idx);
	set8b(ctx, utilization);

       	return 0;
}

int
arms_hb_set_cpu_detail_usage(arms_context_t *acx, 
			uint16_t idx, uint8_t idle, 
			uint8_t interrupt, uint8_t user,
			uint8_t sys, uint8_t other)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
                return ARMS_EFATAL;
        }
        if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_CPU_DETAIL)) {
                return ARMS_ESIZE;
        }
        if (find_multiplex_index(ctx, HB_TYPE_CPU_DETAIL, HB_LEN_CPU_DETAIL, idx)) {
                return ARMS_EEXIST;
        }
	set16b(ctx, HB_TYPE_CPU_DETAIL);
	set16b(ctx, HB_LEN_CPU_DETAIL);
	set16b(ctx, idx);
	set8b(ctx, idle);
	set8b(ctx, interrupt);
	set8b(ctx, user);
	set8b(ctx, sys);
	set8b(ctx, other);
	return 0;
}

int
arms_hb_set_mem_usage(arms_context_t *acx, uint16_t idx, 
		 uint64_t used, uint64_t avail)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
                return ARMS_EFATAL;
        }
        if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_MEM)) {
                return ARMS_ESIZE;
        }
        if (find_multiplex_index(ctx, HB_TYPE_MEM, HB_LEN_MEM, idx)) {
                return ARMS_EEXIST;
        }
	set16b(ctx, HB_TYPE_MEM);
	set16b(ctx, HB_LEN_MEM);
	set16b(ctx, idx);
	set64b(ctx, used);
	set64b(ctx, avail);		
	return 0;
}

int
arms_hb_set_disk_usage(arms_context_t *acx, uint16_t idx, 
		  uint64_t used, uint64_t avail)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
                return ARMS_EFATAL;
        }
        if (buf_space(ctx) < (4 + HB_LEN_DISK)) {
                return ARMS_ESIZE;
        }
        if (find_multiplex_index(ctx, HB_TYPE_DISK, HB_LEN_DISK, idx)) {
                return ARMS_EEXIST;
        }
	set16b(ctx, HB_TYPE_DISK);
	set16b(ctx, HB_LEN_DISK);
	set16b(ctx, idx);
	set64b(ctx, used);
	set64b(ctx, avail);
	return 0;
}

int
arms_hb_set_traffic_count(arms_context_t *acx, uint16_t ifidx, 
		     uint64_t in_octet, uint64_t out_octet, 
		     uint64_t in_packet, uint64_t out_packet, 
		     uint64_t in_error, uint64_t out_error)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
                return ARMS_EFATAL;
        }
        if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_TRAFFIC_COUNT)) {
                return ARMS_ESIZE;
        }
        if (find_multiplex_index(ctx, HB_TYPE_TRAFFIC_COUNT, HB_LEN_TRAFFIC_COUNT, ifidx)) {
                return ARMS_EEXIST;
        }
	set16b(ctx, HB_TYPE_TRAFFIC_COUNT);
	set16b(ctx, HB_LEN_TRAFFIC_COUNT);
	set16b(ctx, ifidx);
	set64b(ctx, in_octet);
	set64b(ctx, out_octet);
	set64b(ctx, in_packet);
	set64b(ctx, out_packet);
	set64b(ctx, in_error);
	set64b(ctx, out_error);
	return 0;
}

int
arms_hb_set_traffic_rate(arms_context_t *acx, uint16_t ifidx,
                     uint64_t in_octet, uint64_t out_octet,
                     uint64_t in_packet, uint64_t out_packet,
                     uint64_t in_error, uint64_t out_error)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
                return ARMS_EFATAL;
        }
        if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_TRAFFIC_RATE)) {
                return ARMS_ESIZE;
        }
        if (find_multiplex_index(ctx, HB_TYPE_TRAFFIC_RATE, HB_LEN_TRAFFIC_RATE, ifidx)) {
                return ARMS_EEXIST;
        }
	set16b(ctx, HB_TYPE_TRAFFIC_RATE);
	set16b(ctx, HB_LEN_TRAFFIC_RATE);
	set16b(ctx, ifidx);
	set64b(ctx, in_octet);
	set64b(ctx, out_octet);
	set64b(ctx, in_packet);
	set64b(ctx, out_packet);
	set64b(ctx, in_error);
	set64b(ctx, out_error);
	return 0;
}

int
arms_hb_set_radiowave(arms_context_t *acx, uint16_t ifidx, 
		  uint8_t misc, uint8_t max, 
		  uint8_t min, uint8_t avg)
{
	hb_context_t *ctx;

	if (acx == NULL) {
                return ARMS_EFATAL;
        }
	ctx = &acx->hb_ctx;
	if (ctx->msgbuf == NULL) {
		return ARMS_EFATAL;
	}
	if (buf_space(ctx) < (HB_TL_LEN + HB_LEN_RADIO_WAVE)) {
		return ARMS_ESIZE;
	}
	if (find_multiplex_index(ctx, HB_TYPE_RADIO_WAVE, HB_LEN_RADIO_WAVE, ifidx)) {
		return ARMS_EEXIST;
	}
	set16b(ctx, HB_TYPE_RADIO_WAVE); 
	set16b(ctx, HB_LEN_RADIO_WAVE); 
	set16b(ctx, ifidx); 
	set8b(ctx, misc); 
	set8b(ctx, max); 
	set8b(ctx, min); 
	set8b(ctx, avg); 
	return 0; 
}
