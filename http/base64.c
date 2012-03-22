/*	$Id: base64.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <time.h>
#include <libarms.h>
#include <libarms_log.h>

#include <libarms/base64.h>

/*
 * base64 implementation from xmpp_util.cpp by ebisawa@.
 */
static char Base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
arms_base64_encode(char *dest, int destmax, const char *buf, int buflen)
{
	int idx, rlen = 0;

	while (buflen >= 3) {
		if (destmax < 4)
			return -1;

		/* (1) */
		idx = (buf[0] & 0xfc) >> 2;
		*dest++ = Base64Table[idx];

		/* (2) */
		idx = ((buf[0] & 0x03) << 4) | ((buf[1] & 0xf0) >> 4);
		*dest++ = Base64Table[idx];
        
		/* (3) */
		idx = ((buf[1] & 0x0f) << 2) | ((buf[2] & 0xc0) >> 6);
		*dest++ = Base64Table[idx];

		/* (4) */
		idx = (buf[2] & 0x3f);
		*dest++ = Base64Table[idx];

		rlen += 4;
		destmax -= 4;
		buflen -= 3;
		buf += 3;
	}
    
	/* the final quantum */
	if (buflen >= 2) {
		if (destmax < 4)
			return -1;

		/* (1) */
		idx = (buf[0] & 0xfc) >> 2;
		*dest++ = Base64Table[idx];
        
		/* (2) */
		idx = ((buf[0] & 0x03) << 4) | ((buf[1] & 0xf0) >> 4);
		*dest++ = Base64Table[idx];
        
		/* (3) */
		idx = ((buf[1] & 0x0f) << 2);
		*dest++ = Base64Table[idx];
        
		*dest++ = '=';
        
		rlen += 4;
	} else if (buflen >= 1) {
		if (destmax < 4)
			return -1;

		/* (1) */
		idx = (buf[0] & 0xfc) >> 2;
		*dest++ = Base64Table[idx];
        
		/* (2) */
		idx = ((buf[0] & 0x03) << 4);
		*dest++ = Base64Table[idx];
        
		*dest++ = '=';
		*dest++ = '=';
        
		rlen += 4;
	}
    
	return rlen;
}

static char modbuf[4];
static int modlen;

static void
arms_base64_reset_state(void)
{
	/* note: need to keep modbuf. */
	modlen = 0;
}

int
arms_base64_decode_stream(arms_base64_stream_t *obj, char *dest, int destmax,
			  const char *buf, int buflen)
{
	int len, rlen = 0;

	/* using like streaming. decode previous modulo and current buf */
	while (obj->modlen > 0) {
		int cplen;

		/* to decode, at least need to read 4 byte data. */
		if (obj->modlen + buflen < sizeof(obj->modbuf)) {
			memcpy(&obj->modbuf[obj->modlen], buf, buflen);
			obj->modlen += buflen;
			return 0;
		}
		/* fill modbuf */
		cplen = sizeof(obj->modbuf) - obj->modlen;
		memcpy(&obj->modbuf[obj->modlen], buf, cplen);
		buf += cplen;
		buflen -= cplen;
		/* decode 4 bytes */
		len = arms_base64_decode(dest, destmax, obj->modbuf, 4);
		if (len < 0) {
			arms_base64_reset_state();
			return -1;
		}
		/*
		 * 1: len == 0 and modlen > 0
		 * 2: len > 0 and modlen == 0
		 */
		if (len > 0) {
			rlen += len;
			dest += len;
			destmax -= len;
			break;
		}
		memcpy(obj->modbuf, modbuf, sizeof(obj->modbuf));
		obj->modlen = modlen;
	}

	len = arms_base64_decode(dest, destmax, buf, buflen);
	if (len < 0) {
		arms_base64_reset_state();
		return -1;
	}
	memcpy(obj->modbuf, modbuf, sizeof(obj->modbuf));
	obj->modlen = modlen;

	return rlen + len;
}

int
arms_base64_decode(char *dest, int destmax, const char *buf, int buflen)
{
	char *p;
	int idx, rlen = 0;

	arms_base64_reset_state();

	while (buflen >= 4) {
		if (destmax < 3) {
			libarms_log(ARMS_LOG_DEBUG,
			    "base64: no space available");
			return -1;
		}

		if (buf[0] == '\r' || buf[0] == '\n') {
			buf++;
			buflen--;
			continue;
		}
		/* (1) */
		if ((p = strchr(Base64Table, buf[0])) == NULL) {
			libarms_log(ARMS_LOG_DEBUG,
			    "base64: invalid char 0x%x", buf[0]);
			return -1;
		}

		idx = (int) (p - Base64Table);
		dest[0] = idx << 2;
        
		/* (2) */
		while (buf[1] == '\r' || buf[1] == '\n') {
			buf++;
			buflen--;
			if (buflen < 4) {
				libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid input data");
				return -1;
			}
		}
		if ((p = strchr(Base64Table, buf[1])) == NULL) {
			libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid char 0x%x", buf[1]);
			return -1;
		}

		idx = (int) (p - Base64Table);
		dest[0] |= idx >> 4;
		dest[1]  = (idx << 4) & 0xf0;

		/* (3) */
		while (buf[2] == '\r' || buf[2] == '\n') {
			buf++;
			buflen--;
			if (buflen < 4) {
				libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid input data");
				return -1;
			}
		}
		if (buf[2] != '=') {
			if ((p = strchr(Base64Table, buf[2])) == NULL) {
				libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid char 0x%x", buf[2]);
				return -1;
			}
            
			idx = (int) (p - Base64Table);
			dest[1] |= idx >> 2;
			dest[2]  = (idx << 6) & 0xc0;
		} else {
			rlen += 1;
			buflen = 0;
			break;
		}

		/* (4) */
		while (buf[3] == '\r' || buf[3] == '\n') {
			buf++;
			buflen--;
			if (buflen < 4) {
				libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid input data");
				return -1;
			}
		}
		if (buf[3] != '=') {
			if ((p = strchr(Base64Table, buf[3])) == NULL) {
				libarms_log(ARMS_LOG_DEBUG,
				    "base64: invalid char 0x%x", buf[3]);
				return -1;
			}
            
			idx = (int) (p - Base64Table);
			dest[2] |= idx & 0x3f;
		} else {
			rlen += 2;
			buflen = 0;
			break;
		}

		rlen += 3;
		buflen -= 4;
		buf += 4;
		destmax -= 3;
		dest += 3;
	}

	/* modulo data is copied to static buffer */
	modlen = buflen;
	memcpy(modbuf, buf, modlen);

	return rlen;
}
