/*
 * $Id: libhb.h 20800 2012-01-19 05:13:45Z m-oki $ 
 *
 * Heartbeat Client Library
 */

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

/* 
 * library version
 */
#define LIBHB_LIBRARY_VER_MAJOR         1
#define LIBHB_LIBRARY_VER_MINOR         1
#define LIBHB_LIBRARY_VER_DESCRIPTION   "beta1"
#define LIBHB_PROTOCOL_VER_MAJOR        2
#define LIBHB_PROTOCOL_VER_MINOR        0

/*
 * status type
 */
#define HB_TYPE_INVALID       0x0000
#define HB_TYPE_HMAC          0x0001
#define HB_TYPE_DIST_ID       0x0011
#define HB_TYPE_RADIO_WAVE    0x002c
#define HB_TYPE_CPU           0x0033
#define HB_TYPE_CPU_DETAIL    0x0034
#define HB_TYPE_MEM           0x0035
#define HB_TYPE_DISK          0x0037
#define HB_TYPE_TRAFFIC_COUNT 0x0038
#define HB_TYPE_TRAFFIC_RATE  0x0039

/*
 * heartbeat protocol related macro
 */
#define HB_LEN_INVALID       0
#define HB_LEN_HMAC_SHA1     20
#define HB_LEN_DIST_ID       16
#define HB_LEN_CPU           3
#define HB_LEN_CPU_DETAIL    7
#define HB_LEN_MEM           18
#define HB_LEN_DISK          18
#define HB_LEN_TRAFFIC_COUNT 50
#define HB_LEN_TRAFFIC_RATE  50
#define HB_LEN_RADIO_WAVE    6
#define HB_MAX_DESC_LEN 32
#define HB_TL_LEN       4
#define HB_MAX_SERVER   5
#define HB_MAX_HOSTLEN  256
#define HB_MAX_PASSLEN  1025

/* 
 * error code 
 */
#define HB_ESEND_GAI		1
#define HB_ESEND_SOCK		2
#define HB_ESEND_SENDTO		3

#define HB_EBUF_OVER		10001
#define HB_ECTX_NULL		10002
#define HB_EINVAL		10003
#define HB_ESEND		10004
#define HB_ESVR_INFO		10006
#define HB_EEXIST		10007
#define HB_ENOT_INIT		10010
#define HB_ELEN_TOO_SHORT	10011
#define HB_EDIF_INTERVAL	10012

/*
 * data types
 */
struct hb_server_info {
        char host[HB_MAX_HOSTLEN];
        int port;
        char passphrase[HB_MAX_PASSLEN];
	unsigned int passlen;
};
typedef struct hb_server_info hb_server_info_t;

struct hb_send_result {
        int err_count;
        struct {
                int stage;
                int code;
        } server[HB_MAX_SERVER];
};
typedef struct hb_send_result hb_send_result_t;

struct hb_context {
        hb_server_info_t server[HB_MAX_SERVER];
        int numsvr;
        int freeptr;
        uint8_t *msgbuf;
        int buflen;
        distribution_id_t id; /* require libarms.h */
};
typedef struct hb_context hb_context_t;

/* 
 * APIs 
 */
int hb_library_ver_major(void);
int hb_library_ver_minor(void);
const char *hb_library_ver_string(void);
int hb_protocol_ver_major(void);
int hb_protocol_ver_minor(void);

int arms_hb_init(hb_context_t *, int, distribution_id_t);
int arms_hb_clear(hb_context_t *);
int arms_hb_update_server(hb_context_t *, arms_hbt_info_t *, int);
int arms_hb_send(hb_context_t *, int, hb_send_result_t *);
int arms_hb_end(hb_context_t *);
