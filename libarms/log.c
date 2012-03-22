/*	$Id: log.c 20894 2012-01-25 12:47:57Z m-oki $	*/

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
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include <libarms.h>
#include <libarms_resource.h>
#include <libarms_log.h>

/*
 *
 */
static const char *
libarms_strlog(int type)
{
	static char estr[256];
	static const char *str = NULL;
	static char defstr[256];

	switch (type) {
		/* Basic log */
		case ARMS_LOG_EFALLBACK:
			str = "Fallback to previous state";
			break;
		case ARMS_LOG_ILS_ACCESS_START:
			str = "Connecting to LS";
			break;
		case ARMS_LOG_ILS_ACCESS_END:
			str = "LS Access Done";
			break;
		case ARMS_LOG_ELS_ACCESS_FAIL:
			str = "Failed to get location config from LS";
			break;
		case ARMS_LOG_IRS_ACCESS_START:
			str = "Connecting to RS";
			break;
		case ARMS_LOG_IRS_ACCESS_END:
			str = "RS Access Done";
			break;
		case ARMS_LOG_ERS_ACCESS_FAIL:
			str = "Failed to get configuration from RS";
			break;
		/* Line */
		case ARMS_LOG_ELINE_AUTH_FAIL:
			str = "Line Authentication Failure";
			break;
		case ARMS_LOG_ELINE_TIMEOUT:
			str = "Line Timeout";
			break;
		/* HTTP */
		case ARMS_LOG_IHTTP_CONNECT_START:
			str = "Connecting to ARMS Service";
			break;
		case ARMS_LOG_IHTTP_CONNECT_END:
			str = "Connected to ARMS Service";
			break;
		case ARMS_LOG_IHTTP_LISTEN_START:
			str = "Ready to answer PUSH Request";
			break;
		case ARMS_LOG_IHTTP_ACCEPT:
			str = "Accepting PUSH Request";
			break;
		case ARMS_LOG_IHTTP_CLOSE:
			str = "PUSH Request done.";
			break;
		/* Network Log */
		case ARMS_LOG_EURL:
			str = "Invalid URL";
			break;
		case ARMS_LOG_EHOST:
			str = "Unknown HOST";
			break;
		case ARMS_LOG_ESOCKET:
			str = "Socket Level Error";
			break;
		case ARMS_LOG_ECONNECT:
			str = "IP/TCP/SSL Level Error";
			break;
		case ARMS_LOG_ENETNOMEM:
			str = "Memroy Exhausted(Network)";
			break;
		case ARMS_LOG_EHTTP:
			str = "HTTP Level Error";
			break;
		case ARMS_LOG_ECERTIFICATE:
			str = "Invalid Server Certificate";
			break;
		case ARMS_LOG_ENETTIMEOUT:
			str = "Network Timeout";
			break;
		case ARMS_LOG_ECALLBACK:
			str = "Callback Function Error";
			break;
		case ARMS_LOG_DEBUG:
			str = "DEBUG";
			break;
		default:
			memset(estr, 0, sizeof(estr));
			snprintf(estr, sizeof(estr),
				 "No library default string(%d)", type);
			str = estr;
			break;
	}

	if (str == NULL) {
		memset(defstr, 0, sizeof(defstr));
		snprintf(defstr, sizeof(defstr), "No String(%d)", type);
		return defstr;
	}

	return str;
}

/*
 *
 */
int
libarms_log(int type, const char *fmt, ...)
{
	va_list ap;
	char buf[LOG_BUFSIZ + 1];
	const char *str;
	int err = 0;
	arms_context_t *res = arms_get_context();

	if (res == NULL)
		return err;

	if (fmt) {
		memset(buf, 0, sizeof(buf));
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);
		str = buf;
	}
	else {
		str = libarms_strlog(type);
	}

	if (res->callbacks.log_cb) {
		int log_code;

		log_code = ARMS_LOG_CODE(0, 0, type);
		err = res->callbacks.log_cb(log_code, str, res->udata);
	}

	return err;
}
