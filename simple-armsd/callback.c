/*	$Id: callback.c 20912 2012-01-27 04:07:17Z yamazaki $	*/

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

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libarms.h>

#include "callback.h"

static int exec_clear_status(uint32_t, const char *, size_t, char *, size_t);
static int exec_ping(const char *, size_t, char *, size_t);
static int exec_traceroute(const char *, size_t, char *, size_t);
static int exec_md_command(uint32_t, const char *, size_t, char *, size_t,
    int *);
static int exec_dump_debug(const char *, size_t, char *, size_t);
static char *get_filename(int, uint32_t);

static char *arms_status[] = {
	"Initial",
	"LS-Pull",
	"RS-Pull",
	"Pull-Done",
	"Boot-Fail",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"Push-Initial",
	"Push-Send-Ready",
	"Push-Wait",
	"Push-Add-Trans",
	"Push-Exec-Trans",
	"Push-Term",
	"Push-Reboot"
};

FILE *read_config_fp = NULL;

static int
exec_clear_status(uint32_t id, const char *buff, size_t buff_len, char *result,
    size_t result_len)
{
	printf("    id: %u\n", id);
	printf("    buff: %s\n", buff);
	printf("    buff_len: %zd\n", buff_len);
	printf("    result_len: %zd\n", result_len);

	snprintf(result, result_len, "clear_status(id=%d): done", id);

	return 0;
}

static int
exec_ping(const char *buff, size_t buff_len, char *result_buff,
    size_t result_len)
{
	arms_ping_arg_t *arg = (arms_ping_arg_t *)buff;
	arms_ping_report_t *report = (arms_ping_report_t *)result_buff;

	printf("    dst: %s\n", arg->dst);
	printf("    count: %d\n", arg->count);
	printf("    size: %d\n", arg->size);

	report->success = arg->count;
	report->failure = 0;

	return 0;
}

static int
exec_traceroute(const char *buff, size_t buff_len, char *result_buff,
    size_t result_len)
{
	arms_traceroute_arg_t *arg = (arms_traceroute_arg_t *)buff;
	arms_traceroute_info_t *info = (arms_traceroute_info_t *)result_buff;

	printf("    addr: %s\n", arg->addr);
	printf("    count: %d\n", arg->count);
	printf("    maxhop: %d\n", arg->maxhop);

	info[0].hop = 1;
	snprintf(info[0].addr, ARMS_TR_STRSIZE, "192.168.0.1 0.747 ms");
	info[1].hop = 2;
	snprintf(info[1].addr, ARMS_TR_STRSIZE, "172.16.0.1 0.806 ms");
	info[2].hop = 3;
	snprintf(info[2].addr, ARMS_TR_STRSIZE, "%s 53.016 ms", arg->addr);

	return 0;
}

static int
exec_md_command(uint32_t id, const char *buff, size_t buff_len,
    char *result_buff, size_t result_len, int *next)
{
	printf("    id: %u\n", id);
	printf("    buff: %s\n", buff);
	printf("    buff_len: %zd\n", buff_len);
	printf("    result_len: %zd\n", result_len);

	*next |= ARMS_FRAG_FINISHED;
	snprintf(result_buff, result_len, "md_command(id=%u): done", id);

	return 0;
}

static int
exec_dump_debug(const char *buff, size_t buff_len, char *result_buff,
    size_t result_len)
{
	printf("    buff       = %s\n", buff);
	printf("    buff_len   = %zd\n", buff_len);
	printf("    result_len = %zd\n", result_len);

	snprintf(result_buff, result_len, "dump_debug: done");

	return 0;
}

int
command_cb(uint32_t id, int action, const char *buff, size_t buff_len,
    char *result_buff, size_t result_len, int *next, void *u)
{
	int result = 0;

	printf("[%s:0x%x]\n", __func__, *(int *)u);

	printf("  action   = %d\n", action);
	printf("  buff_len = %zd\n", buff_len);

	switch (action) {
	case ARMS_PUSH_CLEAR_STATUS:
		printf("  action: clear-status\n");
		result = exec_clear_status(id, buff, buff_len, result_buff,
		    result_len);
		break;
	case ARMS_PUSH_PING:
		printf("  action: ping\n");
		result = exec_ping(buff, buff_len, result_buff, result_len);
		break;
	case ARMS_PUSH_TRACEROUTE:
		printf("  action: traceroute\n");
		result = exec_traceroute(buff, buff_len, result_buff,
		    result_len);
		break;
	case ARMS_PUSH_MD_COMMAND:
		printf("  action: md-command\n");
		result = exec_md_command(id, buff, buff_len, result_buff,
		    result_len, next);
		break;
	case ARMS_PUSH_DUMP_DEBUG:
		printf("  action: dump-debug\n");
		result = exec_dump_debug(buff, buff_len, result_buff,
		    result_len);
		break;
	default:
		printf("error: unknown action\n");
		result = ARMS_ESYSTEM;
		break;
	}

	printf("[%s:0x%x] done\n", __func__, *(int *)u);

	return result;
}


static char *
get_filename(int type, uint32_t id)
{
	static char candidate[] = "config-candidate-XXXX.txt";
	static char running[] = "config-running-XXXX.txt";
	static char backup[] = "config-backup-XXXX.txt";
	char *filename;

	snprintf(candidate, sizeof(candidate), "config-candidate-%X.txt", id);
	snprintf(running, sizeof(running), "config-running-%X.txt", id);
	snprintf(backup, sizeof(backup), "config-backup-%X.txt", id);

	switch (type) {
	case ARMS_CONFIG_CANDIDATE:
		filename = candidate;
		break;
	case ARMS_CONFIG_RUNNING:
		filename = running;
		break;
	case ARMS_CONFIG_BACKUP:
		filename = backup;
		break;
	default:
		filename = NULL;
		break;
	}

	return filename;
}

int
config_cb(uint32_t id, const char *version, const char *info, int action,
		const char *buff, size_t buff_len, int next, void *u)
{
	FILE *fp;
	char *candidate, *running, *backup;
	char *mode;

	candidate = get_filename(ARMS_CONFIG_CANDIDATE, id);
	running = get_filename(ARMS_CONFIG_RUNNING, id);
	backup = get_filename(ARMS_CONFIG_BACKUP, id);

	printf("[%s:0x%x]\n", __func__, *(int *)u);

	printf("  id: %u\n", id);
	printf("  version: %s\n", version);
	printf("  infostring: %s\n", info);
	printf("  buff_len: %zd\n", buff_len);
	printf("  next: %d\n", next);
	printf("  buff: %s\n", buff);

	switch (action) {
	case ARMS_PULL_STORE_CONFIG:
		printf("  action: Pull Store Config\n");
		mode = (next & ARMS_FRAG_FIRST) ? "w" : "a";
		fp = fopen(candidate, mode);
		fwrite(buff, 1, buff_len, fp);
		fclose(fp);
		if (next & ARMS_FRAG_FINISHED) {
			rename(running, backup);
			rename(candidate, running);
		}
		break;
	case ARMS_PUSH_EXEC_STORED_CONFIG:
		printf("  action: Push Exec Stored Config\n");
		rename(running, backup);
		rename(candidate, running);
		break;
	case ARMS_PUSH_STORE_CONFIG:
		printf("  action: Push Store Config\n");
		mode = (next & ARMS_FRAG_FIRST) ? "w" : "a";
		fp = fopen(candidate, mode);
		fwrite(buff, 1, buff_len, fp);
		fclose(fp);
		break;
	case ARMS_PUSH_REVERT_CONFIG:
		printf("  action: Revert Config\n");
		rename(backup, running);
		break;
	case ARMS_REMOVE_MODULE:
		printf("  action: Remove Module\n");
		unlink(running);
		break;
	default:
		printf("  action: Unknown(%d)\n", action);
		break;
	}

	printf("[%s:0x%x] done\n", __func__, *(int *)u);

	return 0;
}

int
read_config_cb(uint32_t id, int type, char *result_buff, size_t result_len,
		int *next, void *u)
{
	size_t nread;
	char *filename;

	filename  = get_filename(type, id);

	printf("[%s:0x%x]\n", __func__, *(int *)u);

	printf("  id: %u\n", id);
	printf("  type: %d\n", type);
	printf("  result_len: %zd\n", result_len);

	switch (type) {
	case ARMS_CONFIG_CANDIDATE:
		printf("  type: candidate %d\n", type);
		break;
	case ARMS_CONFIG_RUNNING:
		printf("  type: running %d\n", type);
		break;
	case ARMS_CONFIG_BACKUP:
		printf("  type: backup %d\n", type);
		break;
	default:
		break;
	}

	if (*next & ARMS_FRAG_FIRST) {
		if (read_config_fp != NULL)
			fclose(read_config_fp);
		read_config_fp = fopen(filename, "r");
		if (read_config_fp == NULL) {
			result_buff[0] = '\0';
			*next |= ARMS_FRAG_FINISHED;
			return -1;
		}
	}
	memset(result_buff, '\0', result_len);
	nread = fread(result_buff, 1, result_len - 1, read_config_fp);
	if (nread < result_len - 1) {
		if (feof(read_config_fp)) {
			*next |= ARMS_FRAG_FINISHED;
		} else {
			result_buff[0] = '\0';
			*next |= ARMS_FRAG_FINISHED;
			fclose(read_config_fp);
			read_config_fp = NULL;
			return -1;
		}
	} else
		*next |= ARMS_FRAG_CONTINUE;

	if (*next & ARMS_FRAG_FINISHED) {
		fclose(read_config_fp);
		read_config_fp = NULL;
	}

	printf("[%s:0x%x] done\n", __func__, *(int *)u);

	return 0;
}

int
get_status_cb(uint32_t id, const char *buff, size_t buff_len,
    char *result_buff, size_t result_len, int *next, void *u)
{
	printf("[%s:0x%x]\n", __func__, *(int *)u);
	printf("  id: %u\n", id);
	printf("  buff: \"%s\"\n", buff);
	printf("  buff_len: %zd\n", buff_len);
	printf("  result_len: %zd\n", result_len);

	snprintf(result_buff, result_len, "id=%u: get_status_cb() result", id);
	*next |= ARMS_FRAG_FINISHED;

	printf("[%s:0x%x] done\n", __func__, *(int *)u);

	return 0;
}

int
line_ctrl_cb(int line_action, int line_type, void *line_conf, void *u)
{
	arms_line_conf_pppoe_t *pppoe;
	arms_line_conf_dhcp_t *dhcp;
	arms_line_conf_mobile_t *mobile;
	int ret = 0;

	printf("[%s:0x%x]\n", __func__, *(int *)u);

	switch (line_type) {
	case ARMS_LINE_PPPOE:
		pppoe = line_conf;
		printf("  requested type: PPPoE\n");
		printf("    ifindex: %d\n", pppoe->ifindex);
		printf("    id: %s\n", pppoe->id);
		printf("    pass: %s\n", pppoe->pass);
		break;
	case ARMS_LINE_DHCP:
		dhcp = line_conf;
		printf("  requested type: DHCP\n");
		printf("    ifindex: %d\n", dhcp->ifindex);
		break;
	case ARMS_LINE_MOBILE:
		mobile = line_conf;
		printf("  requested type: Mobile\n");
		printf("    ifindex: %d\n", mobile->ifindex);
		printf("    telno: %s\n", mobile->telno);
		printf("    cid: %d\n", mobile->cid);
		printf("    apn: %s\n", mobile->apn);
		printf("    pdp: %s\n", mobile->pdp);
		printf("    id: %s\n", mobile->id);
		printf("    pass: %s\n", mobile->pass);
		break;
	default:
		printf("  requested type: Unknown: %d\n", line_type);
		break;
	}

	switch (line_action) {
	case ARMS_LINE_ACT_CONNECT:
		printf("  requested action: CONNECT\n");
		printf("  returning status: CONNECTED\n");
		ret = ARMS_LINE_CONNECTED;
		break;
	case ARMS_LINE_ACT_DISCONNECT:
		printf("  requested action: DISCONNECT\n");
		printf("  returning status: DISCONNECTED\n");
		ret = ARMS_LINE_DISCONNECTED;
		break;
	case ARMS_LINE_ACT_STATUS:
		printf("  requested action: STATUS\n");
		printf("  returning status: DISCONNECTED\n");
		ret = ARMS_LINE_DISCONNECTED;
		break;
	default:
		printf("  requested action: UNKNOWN: %d\n", line_action);
		printf("  returning status: ERROR\n");
		ret = -1;
		break;
	}

	printf("[%s:0x%x] done\n", __func__, *(int *)u);

	return ret;
}

int
state_cb(int old, int new, void *u)
{
	printf("[%s:0x%x] %s(%d) ==> %s(%d)\n",
	    __func__, *(int *)u, arms_status[old], old, arms_status[new], new);

	return 0;
}

int
log_cb(int log_code, const char *str, void *u)
{
	printf("[%s:0x%x] %d %s\n",
	    __func__, *(int *)u, ARMS_LOG_TYPE(log_code), str);

	return 0;
}

int
app_event_cb(void *u)
{
	printf("[%s:0x%x] callbacked\n", __func__, *(int *)u);

	return 0;
}

int
hb_store_statistics_cb(arms_context_t *ctx, void *u)
{
	printf("[%s:0x%x] callbacked\n", __func__, *(int *)u);

	arms_hb_set_cpu_usage(ctx, 0, 50);
	arms_hb_set_mem_usage(ctx, 0, 64 * 1024, 32 * 1024);
	arms_hb_set_traffic_rate(ctx, 0, 1024, 2048, 1, 2, 0, 0);
	arms_hb_set_traffic_rate(ctx, 1, 2048, 1024, 2, 1, 0, 0);

	return 0;
}

