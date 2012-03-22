/*$Id: hb_routine.c 20842 2012-01-23 06:50:17Z m-oki $*/

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <openssl/hmac.h>

#include "libarms.h"
#include "libhb.h"
#include "hb_routine.h"
#include "errcode.h"

int
set8b(hb_context_t *ctx, uint8_t val)
{
        if (buf_space(ctx) < 8/8) {
                return HB_EBUF_OVER;
        }
        *((uint8_t *)(ctx->msgbuf + ctx->freeptr)) = val;
        ctx->freeptr += 1;
        return 0;
}

int
set16b(hb_context_t *ctx, uint16_t val)
{
        if (buf_space(ctx) < 16/8) {
                return HB_EBUF_OVER;
        }
        set8b(ctx, (val >> 8));
        set8b(ctx, val&0xff);
        return 0;
}

int
set32b(hb_context_t *ctx, uint32_t val)
{
        if (buf_space(ctx) < 32/8) {
                return HB_EBUF_OVER;
        }
        set16b(ctx, (val >> 16));
        set16b(ctx, val&0xffff);
        return 0;
}

int
set64b(hb_context_t *ctx, uint64_t val)
{
        if (buf_space(ctx) < 64/8) {
                return HB_EBUF_OVER;
        }
        set32b(ctx, (val >> 32));
        set32b(ctx, val&0xffffffff);
        return 0;
}

int 
set_hmac(hb_context_t *ctx, int svr_num)
{
        uint md_len;
        u_char md[HB_LEN_HMAC_SHA1];
        const EVP_MD *evp_md = EVP_sha1();

        md_len = HB_LEN_HMAC_SHA1;

        memset((ctx->msgbuf + 4), 0, md_len);
	HMAC(evp_md,
	     ctx->server[svr_num].passphrase, ctx->server[svr_num].passlen,
             ctx->msgbuf, ctx->freeptr,
	     md, &md_len);
        memcpy((ctx->msgbuf + 4), md, md_len);

        return 0;
}

int
buf_space(hb_context_t *ctx)
{
        return (ctx->buflen - ctx->freeptr);
}

int
find_multiplex_index(hb_context_t *ctx, uint16_t type, uint16_t len, uint16_t idx) {
	int ptr = 0;
	while (1) {
		if ((ctx->msgbuf[ptr] == (uint8_t)(type >> 8)) &&
		    (ctx->msgbuf[ptr+1] == (uint8_t)(type&0xff))) {
			ptr +=2;
			if ((ctx->msgbuf[ptr] == (uint8_t)(len >> 8)) &&
			    (ctx->msgbuf[ptr+1] == (uint8_t)(len&0xff))){
				ptr += 2;
				if ((ctx->msgbuf[ptr] == (uint8_t)(idx >> 8)) &&
				    (ctx->msgbuf[ptr+1] == (uint8_t)(idx&0xff))){
					return 1;
				} else {
					ptr += len;
					if (ptr >= ctx->freeptr) {
						break;
					}
				}
			} else {
				ptr += (2 + ctx->msgbuf[ptr+1]);
				if (ptr >= ctx->freeptr) {
					break;
				}
			}
		} else {
			ptr += (4 + ctx->msgbuf[ptr+3]);
			if (ptr >= ctx->freeptr) {
				break;
			}
		}
	}
	return 0;
}
