/*	$Id: armsd_miconf_binary.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libarms.h>

#include <armsd_conf.h>
#include "armsd_miconf_private.h"
#include "armsd_conf_parse.h"

int
acmi_clear_conf_buffer(void *dst, int type)
{
       acmi_config_obj_t *acmi = (acmi_config_obj_t *)dst;
       acmi_config_t *conf = (acmi_config_t *)&acmi->mi_config[type];

       if (dst == NULL)
               return -1;
       if (type < ACMI_CONFIG_RSSOL || type > ACMI_CONFIG_CONFSOL)
               return -1;

       memset(conf, 0, sizeof(*conf));

       return 0;
}

/* XXX: void * is not good */
int
acmi_load_conf_buffer(void *dst, int idx, char *src, int type, size_t len)
{
	acmi_config_obj_t *acmi = (acmi_config_obj_t *)dst;

	if (dst == NULL || src == NULL)
		return -1;
	if (len <= 0)
		return -1;
	if (type < ACMI_CONFIG_RSSOL || type > ACMI_CONFIG_CONFSOL)
		return -1;

	/* XXX: check buffer is US-ASCII text */

	return text_config_parse(acmi, idx, src, len);
}
