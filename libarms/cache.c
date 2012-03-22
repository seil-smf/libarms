/*	$Id: cache.c 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#include <openssl/md5.h>

#include <libarms_resource.h>
#include <libarms/malloc.h>

/* update version value if changed struct arms_dumped_state */
#define ARMS_STATE_VERSION	1

/*
 * state (ls config cache): part of arms_res_t
 */
struct arms_dumped_state {
	/* state version info */
	int state_version;

	/* client parameter */
	char rs_endpoint[128];
	int retry_max, retry_int;
	time_t lltimeout;

	struct line_define line_defs[CONF_MAX_LINE_LIST];
	int num_line;
	int last_line;

	/* shared RS parameter */
	char rs_preshared_key[64+1];

	/* each RS(for pull) parameter */
	struct dumped_rsinfo {
		char url[URL_MAX_LEN + 1];
		char cert[ARMS_MAX_PEM_LEN];
	} rsinfo[5];/*XXX*/
	int current_server;

	int result;

	/* MD5 digest: 128bits, and last member */
	unsigned char digest[16];
};

size_t
arms_size_of_state(void)
{
	return sizeof(struct arms_dumped_state);
}

#define DUMP(member) \
 memcpy(newstate->member, res->member, sizeof(newstate->member))
#define HDUMP(member) \
 if (res->member != NULL) \
    memcpy(newstate->member, res->member, sizeof(newstate->member)); \
 else \
    memset(newstate->member, 0, sizeof(newstate->member))
#define RESTORE(member) \
 memcpy(res->member, newstate->member, sizeof(res->member))
#define HRESTORE(member) \
 if (res->member != NULL) FREE((void *)res->member); \
 res->member = STRDUP(newstate->member)

int
arms_dump_state(arms_context_t *res, char *state, size_t size)
{
	struct arms_dumped_state *newstate;
	MD5_CTX md5ctx;
	int i;

	/* check size */
	if (size < arms_size_of_state())
		return ARMS_ESIZE;

	newstate = CALLOC(1, sizeof(struct arms_dumped_state));
	if (newstate == NULL)
		return ARMS_EFATAL;

	/* create new state array */
	memset(newstate, 0, sizeof(*newstate));
	newstate->state_version = ARMS_STATE_VERSION;
	DUMP(rs_endpoint);
	DUMP(rs_preshared_key);
	/* acmi (RS list) */
	for (i = 0; i < 5; i++) {
		char *cert;

		acmi_get_url_idx(res->acmi, ACMI_CONFIG_CONFSOL,
				 newstate->rsinfo[i].url,
				 URL_MAX_LEN + 1, i);
		cert = acmi_get_cert_idx(res->acmi, ACMI_CONFIG_CONFSOL, i);
		if ((cert != NULL) && (strlen(cert) < sizeof(newstate->rsinfo[i].cert)) ) {
			strncpy(newstate->rsinfo[i].cert, cert, sizeof(newstate->rsinfo[i].cert));
		}
	}
	newstate->current_server = acmi_get_current_server(res->acmi,
						ACMI_CONFIG_CONFSOL);
	newstate->retry_max = acmi_get_rmax(res->acmi,
						 ACMI_CONFIG_CONFSOL);
	newstate->retry_int = acmi_get_rint(res->acmi,
						 ACMI_CONFIG_CONFSOL);
	newstate->lltimeout = acmi_get_lltimeout(res->acmi,
						 ACMI_CONFIG_CONFSOL);
	newstate->result = res->result;

	newstate->num_line = 
		acmi_get_lines(res->acmi, ACMI_CONFIG_CONFSOL,
			       newstate->line_defs);
	newstate->last_line = res->last_line;
#if 0
	/* compare with previus state array */
	if (!memcmp(&newstate, state, sizeof(*newstate)))
		return ARMS_ENOCHANGE;
#endif
	MD5_Init(&md5ctx);
	MD5_Update(&md5ctx, newstate,
		  sizeof(*newstate) - sizeof(newstate->digest));
	MD5_Final(newstate->digest, &md5ctx);

	/* copy new array to specified address */
	memcpy(state, newstate, sizeof(*newstate));
	FREE(newstate);

	return 0;
}

int
arms_restore_state(arms_context_t *res, const char *state, size_t size)
{
	const struct arms_dumped_state *newstate;
	const struct dumped_rsinfo *rsinfo;
	MD5_CTX md5ctx;
	unsigned char digest[16];
	int i;

	/* check size */
	if (size < arms_size_of_state()) {
		return ARMS_ESIZE;
	}

	/* restore res from state array */
	newstate = (const struct arms_dumped_state *)state;
	MD5_Init(&md5ctx);
	MD5_Update(&md5ctx, newstate,
		  sizeof(*newstate) - sizeof(newstate->digest));
	MD5_Final(digest, &md5ctx);
	if (memcmp(digest, newstate->digest, sizeof(digest)) != 0) {
		/* digest is not valid, invalid state */
		return ARMS_EINVAL;
	}
	if (newstate->state_version != ARMS_STATE_VERSION) {
		/* version mismatch, cannot use state data. */
		return ARMS_EINVAL;
	}

	RESTORE(rs_endpoint);
	RESTORE(rs_preshared_key);
	/* acmi (RS list) */
	acmi_reset_server(res->acmi, ACMI_CONFIG_CONFSOL);
	for (i = 0; i < 5; i++) {
		rsinfo = &newstate->rsinfo[i];
		if (rsinfo->url[0] != '\0') {
			acmi_set_url(res->acmi, ACMI_CONFIG_CONFSOL,
				     rsinfo->url, URL_MAX_LEN, i);
			if (rsinfo->cert[0] == '\0')
				continue;
			acmi_set_cert(res->acmi, ACMI_CONFIG_CONFSOL,
				rsinfo->cert, strlen(rsinfo->cert) + 1, i);
		}
	}
	acmi_set_current_server(res->acmi,
				ACMI_CONFIG_CONFSOL, newstate->current_server);
	acmi_set_rmax(res->acmi, ACMI_CONFIG_CONFSOL, newstate->retry_max);
	acmi_set_rint(res->acmi, ACMI_CONFIG_CONFSOL, newstate->retry_int);
	acmi_set_lltimeout(res->acmi, ACMI_CONFIG_CONFSOL, newstate->lltimeout);
	acmi_put_lines(res->acmi, ACMI_CONFIG_CONFSOL,
		       newstate->line_defs, newstate->num_line);
	res->last_line = newstate->last_line;
	res->result = newstate->result;

#if defined(ARMS_DEBUG) && defined (DEBUG_ENABLE)
        acmi_dump(res->acmi);
#endif
	return 0;
}
