/*	$Id: armsd_miconf.c 22687 2012-08-13 06:36:52Z m-oki $	*/

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
#include <libarms/malloc.h>

#include "armsd_miconf_private.h"

#include "compat.h"

/** \file
 * �������¸����ե������ؿ�����
 * LS ���������뵡�����¸�Υ���ե������갷����
 */

#undef DEBUG

#ifdef DEBUG
#define DPRINTF(...) libarms_log(ARMS_LOG_DEBUG, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#if 0
#define INFO_LOG(...)
#define ERROR_LOG(...)
#define DEBUG_LOG(...)
#else
#define INFO_LOG printf
#define ERROR_LOG printf
#define DEBUG_LOG printf
char *str_int64(uint64_t n);
#endif

/**
 * �����Х�ǡ������
 */
static int
acmi_assert(ACMI *acmi, int type)
{
	if (acmi == NULL) {
		return -1;
	}
	if (type < ACMI_CONFIG_RSSOL) {
		return -1;
	}
	if (type > ACMI_CONFIG_NONE) {
		return -1;
	}

	return 0;
}


/**
 * ����ե������֥������Ȥμ���
 */
ACMI *
acmi_create(void)
{
	return CALLOC(1, sizeof(ACMI));
}

/**
 * ����ե������֥������Ȥγ���
 */
void
acmi_destroy(ACMI *acmi)
{
	int i;

	if (acmi == NULL) {
		return;
	}

	for (i = 0; i < ACMI_CONFIG_NONE; i++) {
		acmi_config_t *conf;

		conf = &acmi->mi_config[i];
		if (conf == NULL)
			continue;
	}

	FREE(acmi);
}

/**
 * ���֥������Ȥ���Ͽ���줿����ե����Υ��ꥢ
 */
int
acmi_clear(ACMI *acmi, acmi_config_type_t type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	if (acmi_clear_conf_buffer(acmi, type) < 0) {
		return -1;
	}

	acmi_reset_server(acmi, type);

	return 0;
}

/**
 * �������򤵤�Ƥ��륵���Ф��Ŀʤ��
 */
int
acmi_next_server(ACMI *acmi, acmi_config_type_t type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	acmi->mi_config[type].current_server++;
	if (acmi->mi_config[type].current_server >=
		       acmi->mi_config[type].num_server) {
		acmi->mi_config[type].current_server--;
		return -1;
	}

	return 0;
}

void
acmi_set_current_line(ACMI *acmi, acmi_config_type_t type, int idx)
{
	acmi->mi_config[type].current_line = idx;
}

int
acmi_get_max_line(ACMI *acmi, acmi_config_type_t type)
{
	return acmi->mi_config[type].num_line;
}

/**
 * �������򤵤�Ƥ���������Ŀʤ��
 */
int
acmi_next_line(ACMI *acmi, acmi_config_type_t type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	acmi->mi_config[type].current_line++;
	if (acmi->mi_config[type].current_line >=
			acmi->mi_config[type].num_line) {
		acmi->mi_config[type].current_line--;
		return -1;
	}

	return 0;
}

/**
 * �ǽ�Υ����Ф����򤹤�
 */
int
acmi_reset_server(ACMI *acmi, acmi_config_type_t type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	acmi->mi_config[type].current_server = 0;

	return 0;
}

/**
 * �ǽ�β��������򤹤�
 */
int
acmi_reset_line(ACMI *acmi, acmi_config_type_t type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	acmi->mi_config[type].current_line = 0;

	return 0;
}

/*
 *	get number of servers.
 */
int
acmi_get_num_server(ACMI *acmi, int type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	else {
		return (acmi->mi_config[type].num_server);
	}
}

/*
 *	get current server index.
 */
int
acmi_get_current_server(ACMI *acmi, int type)
{
	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	else {
		return (acmi->mi_config[type].current_server);
	}
}

/*
 *	set current server index.
 */
int
acmi_set_current_server(ACMI *acmi, int type, int idx)
{
	int	error = 0;

	if (acmi_assert(acmi, type) < 0) {
		error = -1;
	}
	else if (idx < 0 || acmi->mi_config[type].num_server <= idx) {
	/* error, invalid index number */
		error = -1;
	}
	else {
		acmi->mi_config[type].current_server = idx;
	}

	return (error);
}

/*
 *	shift current server index.
 */
int
acmi_shift_current_server(ACMI *acmi, int type, int idx)
{
	int	error = 0;

	if (acmi_assert(acmi, type) < 0) {
		error = -1;
	}
	else {
		acmi->mi_config[type].current_server = ACMI_MODULO_SHIFT(acmi->mi_config[type].current_server, idx, acmi->mi_config[type].num_server);
	}

	return (error);
}

/**
 * ������Υ����о�������
 */
static struct server_define *
acmi_find_server(ACMI *acmi, int type)
{
	acmi_config_t *db;
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];
	server = &db->server_defs[db->current_server];

	return server;
}

/**
 * ���ꤵ�줿�����о�������
 */
static struct server_define *
acmi_find_server_idx(ACMI *acmi, int type, int idx)
{
	acmi_config_t *db;
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}
	if (idx > CONF_MAX_LS_LIST) {
		return NULL;
	}

	db = &acmi->mi_config[type];
	server = &db->server_defs[idx];

	return server;
}

/**
 * ������ξ��������Ͽ����Ƥ��ʤ������о�������
 */
static struct server_define *
acmi_find_server_nocert(ACMI *acmi, int type)
{
	acmi_config_t *db;
	struct server_define *server;
	int i;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];
	for (i = 0; i < db->num_server; i++) {
		server = &db->server_defs[i];
		if (server->have_cert == 0) {
			/* found. */
			return server;
		}
	}

	return NULL;
}

/**
 * ������Υ��饤����Ⱦ�������
 */
static struct client_define *
acmi_find_client(ACMI *acmi, int type)
{
	acmi_config_t *db;
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];
	client = &db->client_def;

	return client;
}

/**
 * ������β�����������
 */
static struct line_define *
acmi_find_line(ACMI *acmi, int type)
{
	acmi_config_t *db;
	struct line_define *line;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];
	line = &db->line_defs[db->current_line];

	return line;
}

/**
 * �����Ф� URL �򥻥åȤ���
 */
int
acmi_set_url(ACMI *acmi, int type, const char *src, size_t len, int idx)
{
	struct server_define *server;
	int n;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	if (src == NULL) {
		return -1;
	}
	if (len > URL_MAX_LEN + 1) {
		return -1;
	}

	server = acmi_find_server_idx(acmi, type, idx);
	if (server == NULL) {
		return -1;
	}

	strlcpy(server->server_url.string, src, len);
	n = acmi->mi_config[type].num_server;
	if (n < (idx + 1))
		acmi->mi_config[type].num_server = idx + 1;

	return 0;
}

/**
 * �����Ф� URL ���������
 */
int
acmi_get_url(ACMI *acmi, int type, char *dst, size_t len)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	if (dst == NULL) {
		return -1;
	}
	if (len < URL_MAX_LEN + 1) {
		return -1;
	}

	server = acmi_find_server(acmi, type);
	if (server == NULL) {
		return -1;
	}

	strlcpy(dst, server->server_url.string, len);

	return 0;
}

/**
 * �����Ф� URL ��������� (idx����)
 */
int
acmi_get_url_idx(ACMI *acmi, int type, char *dst, size_t len, int idx)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	if (dst == NULL) {
		return -1;
	}
	if (len < URL_MAX_LEN + 1) {
		return -1;
	}

	server = acmi_find_server_idx(acmi, type, idx);
	if (server == NULL) {
		return -1;
	}

	strlcpy(dst, server->server_url.string, len);

	return 0;
}

/**
 * �����Ф� URL �򻲾Ȥ��� (idx����)
 */
const char *
acmi_refer_url(ACMI *acmi, int type, int idx)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}
	server = acmi_find_server_idx(acmi, type, idx);
	if (server == NULL) {
		return NULL;
	}

	return server->server_url.string;
}

/**
 * Retry Max �򥻥åȤ���
 */
int
acmi_set_rmax(ACMI *acmi, int type, int rmax)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	client->retry_max = rmax;

	return 0;
}

/**
 * Retry Max ���ɤ߽Ф�
 */
int
acmi_retry_max(ACMI *acmi, int type)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	
	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	return client->retry_max;
}

/**
 * Retry Interval �򥻥å�
 */
int
acmi_set_rint(ACMI *acmi, int type, int rint)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	client->retry_int.tv_sec = rint;
	client->retry_int.tv_usec = 0;

	return 0;
}

/**
 * Retry Interval ���ɤ߽Ф�
 */
int
acmi_retry_interval(ACMI *acmi, int type)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	
	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	return client->retry_int.tv_sec;
}

void
acmi_put_lines(ACMI *acmi, int type, const struct line_define *line_defs, int num_line)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return;
	}

	db = &acmi->mi_config[type];
	memcpy(db->line_defs, line_defs, sizeof(db->line_defs));
	db->num_line = num_line;
}

int
acmi_get_lines(ACMI *acmi, int type, struct line_define *line_defs)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return 0;
	}

	db = &acmi->mi_config[type];
	memcpy(line_defs, db->line_defs, sizeof(db->line_defs));
	return db->num_line;
}


/**
 * line �����ޤȤ����Ͽ����
 */
int
acmi_set_lines(ACMI *acmi, int type, arms_line_desc_t *lines)
{
	static char *anon_account[] = {
		/* dummy anonymous account for unit test */
		"anonymous@test.iij.ad.jp",
		"anonymous"
	};
	acmi_config_t *conf;
	void *line_conf;
	int ltype;
	int i = 0;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	conf = &acmi->mi_config[type];

	conf->num_line = 0;
	for (i = 0; i < CONF_MAX_LINE_LIST; i++) {
		ltype = lines[i].type;
		line_conf = lines[i].line_conf;
		if (ltype == ARMS_LINE_NONE) {
			conf->line_defs[i].type = ARMS_LINE_NONE;
			break;
		}
		if (line_conf == NULL) {
			continue;
		}
		conf->line_defs[i].type = ltype;
		conf->num_line++;
		DPRINTF("line_conf[%d] ", i);
		switch (ltype) {
		case ARMS_LINE_ANONPPPOE:
			DPRINTF(" anonpppoe --> %s, %s",
				conf->anon_account, conf->anon_password);

			conf->line_defs[i].type = ARMS_LINE_PPPOE;

			conf->line_defs[i].conf.apppoe.ifindex =
			    ((arms_line_conf_anonpppoe_t *)line_conf)->ifindex;
			if (conf->anon_account)
				strlcpy(conf->line_defs[i].conf.pppoe.id,
					conf->anon_account, MAX_PPP_ID);
			else
				strlcpy(conf->line_defs[i].conf.pppoe.id,
					anon_account[0], MAX_PPP_ID);

			if (conf->anon_password)
				strlcpy(conf->line_defs[i].conf.pppoe.pass,
					conf->anon_password, MAX_PPP_PASS);
			else
				strlcpy(conf->line_defs[i].conf.pppoe.pass,
					anon_account[1], MAX_PPP_PASS);
			break;
		case ARMS_LINE_ANONPPPOE_IPV6:
			DPRINTF(" anonpppoev6 --> %s, %s",
				conf->anon_account_v6, conf->anon_password_v6);

			conf->line_defs[i].type = ARMS_LINE_PPPOE_IPV6;
			conf->line_defs[i].conf.apppoe.ifindex =
			    ((arms_line_conf_anonpppoe_t *)line_conf)->ifindex;
			if (conf->anon_account_v6)
				strlcpy(conf->line_defs[i].conf.pppoe.id,
					conf->anon_account_v6, MAX_PPP_ID);
			else
				strlcpy(conf->line_defs[i].conf.pppoe.id,
					anon_account[0], MAX_PPP_ID);

			if (conf->anon_password_v6)
				strlcpy(conf->line_defs[i].conf.pppoe.pass,
					conf->anon_password_v6, MAX_PPP_PASS);
			else
				strlcpy(conf->line_defs[i].conf.pppoe.pass,
					anon_account[1], MAX_PPP_PASS);
			break;
		case ARMS_LINE_PPPOE:
		case ARMS_LINE_PPPOE_IPV6:
			switch (ltype) {
			case ARMS_LINE_PPPOE:
				DPRINTF(" specified pppoe");
				break;
			case ARMS_LINE_PPPOE_IPV6:
				DPRINTF(" specified pppoe(IPv6)");
				break;
			}
			memcpy(&conf->line_defs[i].conf.pppoe,
			       line_conf,
			       sizeof(conf->line_defs[i].conf.pppoe));
			break;
		case ARMS_LINE_DHCP:
			DPRINTF(" DHCP");
			memcpy(&conf->line_defs[i].conf.dhcp,
			       line_conf,
			       sizeof(conf->line_defs[i].conf.dhcp));
			break;
		case ARMS_LINE_ANONMOBILE:
			DPRINTF(" anonmobile --> %s, %s",
				conf->anon_account, conf->anon_password);

			conf->line_defs[i].type = ARMS_LINE_MOBILE;
			conf->line_defs[i].conf.amobile.ifindex =
			    ((arms_line_conf_anonmobile_t *)line_conf)->ifindex;
			if (conf->m_telno)
				strlcpy(conf->line_defs[i].conf.mobile.telno,
					conf->m_telno, MAX_MOBILE_TEL_LEN);
			if (conf->m_cid)
				conf->line_defs[i].conf.mobile.cid =
				    atoi(conf->m_cid);
			if (conf->m_apn)
				strlcpy(conf->line_defs[i].conf.mobile.apn,
					conf->m_apn, MAX_MOBILE_APN_LEN);
			if (conf->m_pdp)
				strlcpy(conf->line_defs[i].conf.mobile.pdp,
					conf->m_pdp, MAX_MOBILE_PDP_LEN);
			if (conf->m_anon_account)
				strlcpy(conf->line_defs[i].conf.mobile.id,
					conf->m_anon_account, MAX_MOBILE_PPP_ID);
			if (conf->anon_password)
				strlcpy(conf->line_defs[i].conf.mobile.pass,
					conf->m_anon_password, MAX_MOBILE_PPP_PASS);
			break;
		case ARMS_LINE_MOBILE:
			DPRINTF(" MOBILE");
			memcpy(&conf->line_defs[i].conf.mobile,
			       line_conf,
			       sizeof(conf->line_defs[i].conf.mobile));
			break;
		case ARMS_LINE_STATIC:
			DPRINTF(" STATIC");
			memcpy(&conf->line_defs[i].conf.staticip,
			       line_conf,
			       sizeof(conf->line_defs[i].conf.staticip));
			break;
		default:
			break;
		}
	}

	return 0;
}

/**
 * Line Type �򥻥åȤ���
 */
int
acmi_set_ltype(ACMI *acmi, int type, int ltype)
{
	struct line_define *line;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	line = acmi_find_line(acmi, type);
	if (line == NULL) {
		return -1;
	}

	line->type = ltype;

	return 0;

}

/**
 * Line Type ���ɤ߽Ф�
 */
int
acmi_get_ltype(ACMI *acmi, int type)
{
	struct line_define *line;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	line = acmi_find_line(acmi, type);
	if (line == NULL) {
		return -1;
	}

	return line->type;
}

/**
 * Line Conf �򥻥åȤ���
 */
int
acmi_set_lconf(ACMI *acmi, int type, char *src, size_t len)
{
	struct line_define *line;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	line = acmi_find_line(acmi, type);
	if (line == NULL) {
		return -1;
	}

	if (len > sizeof(line->conf)) {
		return -1;
	}

	memset(&line->conf, 0, sizeof(line->conf));
	memcpy(&line->conf, src, len);

	return 0;
}

/**
 * Line Conf ���ɤ߽Ф�
 */
int
acmi_get_lconf(ACMI *acmi, int type, void **dst)
{
	struct line_define *line;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	line = acmi_find_line(acmi, type);
	if (line == NULL) {
		return -1;
	}

	*dst = &line->conf;

	return 0;
}


/**
 * Lower Layer Timeout �򥻥åȤ���
 */
int
acmi_set_lltimeout(ACMI *acmi, int type, int tout)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	client->lltimeout = tout;

	return 0;
}

/**
 * Lower Layer Timeout ���ɤ߽Ф�
 */
int
acmi_get_lltimeout(ACMI *acmi, int type)
{
	struct client_define *client;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	
	client = acmi_find_client(acmi, type);
	if (client == NULL) {
		return -1;
	}

	return client->lltimeout;
}

/**
 * register Anonymous PPPoE account
 */
int
acmi_set_anonpppoe(ACMI *acmi, int type, char *id, char *pass)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	DPRINTF("acmi_set_anonpppoe: id %s, pass %s", id, pass);
	db = &acmi->mi_config[type];
	db->anon_account = id;
	db->anon_password = pass;

	return 0;
}

/**
 * register Anonymous PPPoE account for IPv6
 */
int
acmi_set_anonpppoe_ipv6(ACMI *acmi, int type, char *id, char *pass)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	DPRINTF("acmi_set_anonpppoe: id %s, pass %s", id, pass);
	db = &acmi->mi_config[type];
	db->anon_account_v6 = id;
	db->anon_password_v6 = pass;

	return 0;
}

/**
 * register Anonymous mobile account
 */
int
acmi_set_anonmobile(ACMI *acmi, int type,
		    char *telno, char *cid, char *apn,
		    char *pdp, char *id, char *pass)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	DPRINTF("%s: id %s, pass %s", __func__, id, pass);
	db = &acmi->mi_config[type];
	db->m_telno = telno;
	db->m_cid = cid;
	db->m_apn = apn;
	db->m_pdp = pdp;
	db->m_anon_account = id;
	db->m_anon_password = pass;

	return 0;
}

/**
 * Anonymous PPPoE ID ���ɤ߽Ф�
 */
char *
acmi_get_anon_id(ACMI *acmi, int type)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];

	return db->anon_account;
}

/**
 * Anonymous PPPoE �ѥ���ɤ��ɤ߽Ф�
 */
char *
acmi_get_anon_pass(ACMI *acmi, int type)
{
	acmi_config_t *db;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	db = &acmi->mi_config[type];

	return db->anon_password;
}

/**
 * �����о�������ɲ�
 */
int
acmi_add_cert(ACMI *acmi, int type, char *cert, int certlen)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	if (cert == NULL) {
		return -1;
	}
	if (certlen > ARMS_MAX_PEM_LEN) {
		return -1;
	}

	server = acmi_find_server_nocert(acmi, type);
	if (server == NULL) {
		return -1;
	}

	memset(server->cacert, 0, ARMS_MAX_PEM_LEN);
	memcpy(server->cacert, cert, certlen);
	server->have_cert = 1;

	return 0;
}

/**
 * ������Ͽ����Ƥ��륵���Ф��б��������������
 */
char *
acmi_get_cert(ACMI *acmi, int type)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	server = acmi_find_server(acmi, type);
	if (server == NULL) {
		return NULL;
	}

	if (server->have_cert == 0) {
		return NULL;
	}

	return server->cacert;
}

/**
 * idx ����ǥ����о����������
 */
int
acmi_set_cert(ACMI *acmi, int type, const char *cert, int certlen, int idx)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}
	if (cert == NULL) {
		return -1;
	}
	if (certlen > ARMS_MAX_PEM_LEN) {
		return -1;
	}

	server = acmi_find_server_idx(acmi, type, idx);
	if (server == NULL) {
		return -1;
	}

	memset(server->cacert, 0, ARMS_MAX_PEM_LEN);
	memcpy(server->cacert, cert, certlen);
	server->have_cert = 1;

	return 0;
}

/**
 * idx ����ǥ����Ф��б��������������
 */
char *
acmi_get_cert_idx(ACMI *acmi, int type, int idx)
{
	struct server_define *server;

	if (acmi_assert(acmi, type) < 0) {
		return NULL;
	}

	server = acmi_find_server_idx(acmi, type, idx);
	if (server == NULL) {
		return NULL;
	}

	if (server->have_cert == 0) {
		return NULL;
	}

	return server->cacert;
}

/**
 * LS ���������ä� Text config �����
 */
int
acmi_set_textconf(ACMI *acmi, int type, int idx, char *conf, size_t len)
{
	int err;

	if (acmi_assert(acmi, type) < 0) {
		return -1;
	}

	err = acmi_load_conf_buffer(acmi, idx, conf, type, len);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/**
 * ��������ե�������Υ����
 */
void
acmi_dump(ACMI *acmi)
{
#ifdef ARMS_DEBUG
	distribution_id_t *distid;
	struct server_define *serv;
	struct line_define *line;
	int i, j = 0;

	if (acmi == NULL) {
		ERROR_LOG("acmi == NULL");
		return;
	}
	distid = &acmi->distid;
	INFO_LOG("[Global Configuration]");
	INFO_LOG("+-DistributionID:");
	INFO_LOG("| +-Version = %u", distid->version);
	INFO_LOG("| +-Vendor Code = %u", distid->vendor_code);
	INFO_LOG("| +-SA Type = %u", distid->sa_type);
	INFO_LOG("| +-SA Code = %llu", distid->sa_code);
	INFO_LOG("+-Description = %s", acmi->sa_desc);
	INFO_LOG("+-Version = %s", acmi->sa_version);
	INFO_LOG(" ");
	for(i = 0; i < ACMI_CONFIG_NONE; i++) {
		acmi_config_t *conf;

		conf = &acmi->mi_config[i];
		if (conf == NULL)
			continue;

		INFO_LOG("[Configuration Set %d]", i);
		INFO_LOG("Client Definitions");
		INFO_LOG("+-Retry Parameters:");
		INFO_LOG("  +-Retry MAX = %u", conf->client_def.retry_max);
		INFO_LOG("  +-Retry Interval= %u.%u[s]",
			(int)conf->client_def.retry_int.tv_sec,
			(int)conf->client_def.retry_int.tv_usec);
		INFO_LOG("  +-LL Timeout = %d", (int)conf->client_def.lltimeout);
		INFO_LOG("%d Server(s) Registered", conf->num_server);
		INFO_LOG(" ");

		for (j = 0; j < conf->num_server; j++) {
			INFO_LOG("Server Difinition %d:", j);
			serv = &conf->server_defs[j];
			INFO_LOG("+-Server URL: %s:%p", serv->server_url.string,
					serv->server_url.string);
			INFO_LOG("+-Server have cert: %d", serv->have_cert);
			INFO_LOG("+-Server Cert@%p: <begin-cert>%s<end-cert>",
					serv->cacert, serv->cacert);
		}

		INFO_LOG(" ");
		INFO_LOG("%d line(s) Registered", conf->num_line);
		INFO_LOG("Line Infomation:");
		for (j = 0; j < conf->num_line; j++) {
			line = &conf->line_defs[j];
			INFO_LOG("+-Type: %d", line->type);
			switch (line->type) {
				case ARMS_LINE_PPPOE:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.pppoe.ifindex);
					INFO_LOG("  +-ID: %s",
						line->conf.pppoe.id);
					INFO_LOG("  +-PASS: %s",
						line->conf.pppoe.pass);
					break;
				case ARMS_LINE_ANONPPPOE:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.apppoe.ifindex);
					break;
				case ARMS_LINE_DHCP:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.dhcp.ifindex);
					break;
				case ARMS_LINE_ANONMOBILE:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.mobile.ifindex);
					break;
				case ARMS_LINE_MOBILE:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.mobile.ifindex);
					INFO_LOG("  +-TELNO: %s",
						line->conf.mobile.telno);
					INFO_LOG("  +-APN: %s",
						line->conf.mobile.apn);
					INFO_LOG("  +-ID: %s",
						line->conf.mobile.id);
					INFO_LOG("  +-PASS: %s",
						line->conf.mobile.pass);
					INFO_LOG("  +-IPADDR: %s",
						line->conf.mobile.ipaddr);
					break;
				case ARMS_LINE_STATIC:
					INFO_LOG("  +-Ifidx: %d",
						line->conf.staticip.ifindex);
					INFO_LOG("  +-IPADDR: %s",
						line->conf.staticip.ipaddr);
					break;
				default:
					INFO_LOG("  +-Unknown type");
					break;
			}
		}
		INFO_LOG(" ");
	}
#endif
}

#if 0
char *
str_int64(uint64_t n)
{
	uint16_t val16[4];
	static char buff[256]; /* XXX */

	memcpy(val16, &n, sizeof(val16));
	snprintf(buff, 256, "%x:%x:%x:%x",
		       	val16[0], val16[1], val16[2], val16[3]);

	return buff;
}
#endif
