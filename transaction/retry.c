/*	$Id: retry.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <time.h>

#include <sys/queue.h>

#include <libarms_param.h>

#include <axp_extern.h>
#include <transaction/transaction.h>
/*
 * watchdog for server not responding timeout
 * timeout value: rs-retry-interval * TMP_INT_FACTOR.
 * see 4.8 generic error recovery of ARMS protorol specs.
 * (RETRY_TMP_ERR_INT) 
 */

/* wait time for retry calcuration: see 4.8 of ARMS protocol spec. */

int
arms_retry_wait(transaction *tr)
{
	int result = tr->tr_ctx.result;

	/* base value */
	int retry_interval = tr->retry_interval;
	int count = tr->retry; /* 1st retry: 1, ... */

	/*
	 * RETRY_LONG_ERR_INT = interval * 120
	 */
	if (result >= 200 && result <= 299)
		return retry_interval * LONG_INT_FACTOR;

	/*
	 * RETRY_TMP_ERR_INT = interval
	 */
	if (result >= 300 && result <= 399)
		return retry_interval * (count * count);

	/*
	 * RETRY_SHORT_ERR_INT = interval * 20
	 */
	if (result >= 400 && result <= 499)
		return retry_interval;

	/*
	 * Hmm, server indicates fatal error.  or no error.
	 */
	return retry_interval;
}
