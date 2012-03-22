/*	$Id: time.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <time.h>
#include <sys/time.h>

#include <libarms/time.h>

/*
 * monotime implementation from armsd_event.c
 */
int
arms_monotime(struct timeval *monotime)
{
#if defined(HAVE_NECI_GETUPTIME)
	monotime->tv_sec = getuptime();
	monotime->tv_usec = 0;
#elif !defined(HAVE_CLOCK_GETTIME)
	gettimeofday(monotime, NULL);
#else
	struct timespec ts;
	int err;

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (err < 0) {
		/* syscall error */
		return -1;
	}
	monotime->tv_sec = ts.tv_sec;
	monotime->tv_usec = ts.tv_nsec / 1000;

#ifdef BROKEN_USEC
	monotime->tv_usec = 0;
#endif
#endif/* vendor == neci */
	return 0;
}

/* relative time to absolute time */
void
arms_get_time_remaining(struct timeval *timo, int sec)
{
	struct timeval now;

	timerclear(timo);
	timo->tv_sec = sec;
	arms_monotime(&now);
	timeradd(timo, &now, timo);
}

/* relative time to absolute time */
void
arms_get_timeval_remaining(struct timeval *timo, const struct timeval *tim)
{
	struct timeval now;

	*timo = *tim;
	arms_monotime(&now);
	timeradd(timo, &now, timo);
}
