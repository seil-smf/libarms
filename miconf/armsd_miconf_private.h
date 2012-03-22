/*	$Id: armsd_miconf_private.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __ARMSD_MICONF_PRIVATE_H__
#define __ARMSD_MICONF_PRIVATE_H__
#include <sys/time.h>
#include <libarms_param.h>

#define ACMI_DEFAULT_CONF_HANDLER acmi_load_conf_buffer

/**
 * コンフィグ構造体。Initial config, LS config　について必要。
 */
typedef struct armsd_mi_config {
	/* Hidden Anonymous PPPoE Configuration */
	char *anon_account;
	char *anon_password;

	/* Hidden Anonymous Mobile Configuration */
	char *m_telno;
	char *m_cid;
	char *m_apn;
	char *m_pdp;
	char *m_anon_account;
	char *m_anon_password;

	/* Client parameters */
	struct client_define {
		int retry_max;
		struct timeval retry_int;
		time_t lltimeout;
	} client_def;
	int have_client;

	/* Server parameters */
	struct server_define {
		url_t server_url;
		int have_cert;
		char cacert[ARMS_MAX_PEM_LEN];
	} server_defs[CONF_MAX_LS_LIST];
	int num_server;
	int current_server;

	/* Line parameters */
	struct line_define line_defs[CONF_MAX_LINE_LIST];
	int num_line;
	int current_line;

} acmi_config_t;

/**
 *
 */
typedef struct acmi_config_object {
	acmi_config_type_t conf_type;

	distribution_id_t distid;
	char sa_desc[ARMS_MAX_DESC_LEN];
	char sa_version[ARMS_MAX_VER_LEN];

	acmi_config_t mi_config[ACMI_CONFIG_NONE];
} acmi_config_obj_t; /* == ACMI */

/**
 * For text formatted config
 */
extern int acmi_load_tconf_buffer(void *dst, char *src, size_t len);

/*
 * for binary config
 */
int acmi_clear_conf_buffer(void *, int);
int acmi_load_conf_buffer(void *, int, char *, int, size_t);

#endif /* __ARMSD_MICONF_PRIVATE_H__ */
