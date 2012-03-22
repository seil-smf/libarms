/*$Id: hb_routine.h 20822 2012-01-23 04:56:43Z m-oki $*/

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

#define HB_TYPE_INVALID       0x0000
#define HB_TYPE_HMAC          0x0001
#define HB_TYPE_DIST_ID       0x0011
#define HB_TYPE_CPU           0x0033
#define HB_TYPE_CPU_DETAIL    0x0034
#define HB_TYPE_MEM           0x0035
#define HB_TYPE_DISK          0x0037
#define HB_TYPE_TRAFFIC_COUNT 0x0038
#define HB_TYPE_TRAFFIC_RATE  0x0039

#define HB_LEN_INVALID       0
#define HB_LEN_HMAC_SHA1     20
#define HB_LEN_DIST_ID       16
#define HB_LEN_CPU           3
#define HB_LEN_CPU_DETAIL    7
#define HB_LEN_MEM           18
#define HB_LEN_DISK          18
#define HB_LEN_TRAFFIC_COUNT 50
#define HB_LEN_TRAFFIC_RATE  50

#define HB_NEED_LEN     44
#define HB_TL_LEN       4
#define HB_MAX_SERVER   5
#define HB_MAX_HOSTLEN  256
#define HB_MAX_PASSLEN  1025

#define HB_ESEND_GAI    1
#define HB_ESEND_SOCK   2
#define HB_ESEND_SENDTO 3

#ifdef SMFV1
#define HB_NEED_LEN_V1  44		/* XXX */
#endif

int set8b(hb_context_t *, uint8_t);
int set16b(hb_context_t *, uint16_t);
int set32b(hb_context_t *, uint32_t);
int set64b(hb_context_t *, uint64_t);
int set_hmac(hb_context_t *, int);
int buf_space(hb_context_t *);
int find_multiplex_index(hb_context_t *, uint16_t, uint16_t, uint16_t);
#ifdef SMFV1
void set_num_tlv_v1(hb_context_v1_t *ctxv1);
#endif
