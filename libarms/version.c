/*	$Id: version.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <libarms.h>

/*
 * libarms exported API (version)
 */
int
arms_library_ver_major(void)
{
	return ARMS_LIBPULL_VERSION_MAJOR;
}

int
arms_library_ver_minor(void)
{
	return ARMS_LIBPULL_VERSION_MINOR;
}

const char *
arms_library_ver_string(void)
{
	static char verstr[ARMS_MAX_DESC_LEN + 1];

	memset(verstr, 0, sizeof(verstr));
	snprintf(verstr, sizeof(verstr), "%01d.%02d (%s)",
			ARMS_LIBPULL_VERSION_MAJOR,
			ARMS_LIBPULL_VERSION_MINOR,
			ARMS_LIBPULL_VERSION_DESC);

	return (const char *)verstr;
}

int
arms_protocol_ver_major(void)
{
	return ARMS_PROTOCOL_VERSION_MAJOR;
}

int
arms_protocol_ver_minor(void)
{
	return ARMS_PROTOCOL_VERSION_MINOR;
}
