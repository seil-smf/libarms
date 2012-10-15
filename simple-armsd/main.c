/*	$Id: main.c 20883 2012-01-25 07:52:18Z yamazaki $	*/

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
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>

#include <libarms.h>

#include "callback.h"
#include "lines.h"

static void usage(const char *);
static int load_from_file(char *, char **);
static void dump_arms_info(arms_context_t *);
static arms_context_t *initialize_libarms(const char *, const char *);

#define CA_CERT "cacert.pem"
#define STATE "state_cache"

static arms_callback_tbl_t cb_tbl = {
	ARMS_API_VERSION,
	config_cb, /* config callback */
	line_ctrl_cb, /* line control callback */
	state_cb, /* state callback */
	log_cb,  /* log callback */
	read_config_cb, /* read config callback */
	get_status_cb, /* read status callback */
	command_cb, /* command callback */
	app_event_cb, /* event callback */
	hb_store_statistics_cb, /* heartbeat callback */
};

int
main(int argc, char *argv[])
{
	const char *progname = argv[0];
	int ch, error;
	char lskey[65];
	char distid_str[] = "0000-0000-0000-0000-0000-0000-0000-0000";
	int port = 0; /* default */
	int skip = 0; /* default */
	static int context = 0xdeadbeef;
	static char *state = NULL;
	const char *proxy = NULL;
	arms_context_t *ctx;

	while ((ch = getopt(argc, argv, "k:p:P:sfd:")) != -1) {
		switch(ch) {
		case 'p':
			port = atol(optarg);
			break;
		case 's':
			skip++;
			break;
		case 'P':
			proxy = optarg;
			break;
		case '?':
		default:
			usage(progname);
			exit(EXIT_SUCCESS);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage(progname);
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}
	
	strncpy(distid_str, argv[0], sizeof(distid_str) - 1);
	strncpy(lskey, argv[1], sizeof(lskey) - 1);

	printf("ARMS Client Sample Implementation\n");
	printf("  libarms Version %s\n", arms_library_ver_string());
	printf("  ARMS Protocol Version %d.%d\n",
	    arms_protocol_ver_major(), arms_protocol_ver_minor());

	if ((ctx = initialize_libarms(distid_str, lskey)) == NULL) {
		printf("[armsd] failed to initialize libarms\n");
		return EXIT_FAILURE;
	}
	printf("[armsd] libarms initialized.\n");

	if (proxy != NULL) {
		printf("[armsd] https proxy: %s\n", proxy);
		arms_set_https_proxy(ctx, proxy);
	}

	/* skip to LS access only at startup time */
	if (skip > 0) {
		int state_size = load_from_file(STATE, &state);
		/* -s,  skip LS access */
		if (state_size >= arms_size_of_state()) {
			printf("[armsd] restore state");
			error = arms_restore_state(ctx, state, state_size);
			if (error)
				fprintf(stderr, "can't restore state");
		} else
			printf("[armsd] skip restore state");
	}

pull:
	printf("[armsd] start arms_pull\n");
	error = arms_pull(ctx, 0, 0, &cb_tbl, lines, &context);
	if (error != 0) {
		printf("[armsd] arms_pull() failed\n");
		goto failure;
	} else
		printf("[armsd] arms_pull succeeded\n");

	if (state == NULL)
		state = malloc(arms_size_of_state());

	if (arms_dump_state(ctx, state, arms_size_of_state()) == 0) {
		FILE *fp;
		printf("[armsd] save state\n");
		fp = fopen(STATE, "w");
		fwrite(state, 1, arms_size_of_state(), fp);
		fclose(fp);
	} else {
		printf("[armsd] state is not saved.\n");
	}

	printf("[armsd] start push method query\n");
	error = arms_push_method_query(ctx, &cb_tbl, &context);
	if (error != 0) {
		printf("[armsd] arms_push_method_query() failed\n");
		goto failure;
	} else
		printf("[armsd] arms_push_method_query succeeded\n");

	dump_arms_info(ctx);

	printf("[armsd] start event loop\n");
	error = arms_event_loop(ctx, port, 1024, &cb_tbl, &context);
	printf("[armsd] end event loop: result=%d\n", error);

failure:
	switch (error) {
	case 0:
		break;
	case ARMS_EREBOOT:
		printf("[armsd] required REBOOT\n");
		break;
	case ARMS_EPULL:
		printf("[armsd] required PULL\n");
		goto pull;
		break;
	case ARMS_EDONTRETRY:
		printf("[armsd] required DONTRETRY\n");
		break;
	case ARMS_EINVAL:
		printf("[armsd] invalid arguments");
		break;
	default:
		printf("[armsd]  failed\n");
		printf("level = %d, type = %d, code = %d\n",
		    ARMS_ERR_LVL(error), ARMS_ERR_TYPE(error), error);
		break;
	}

	arms_end(ctx);

	return error;
}

static void
usage(const char *prog)
{
	printf("usage: %s [-s] [-p port] [-P url] Distribution-ID LS-SA-Key\n",
	    prog);
}

static int
load_from_file(char *fname, char **buffp)
{
	FILE *fp = NULL;
	char *buff = NULL;
	size_t len;
	int nread = -1;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		fprintf(stderr, "failed to open \"%s\": %s\n",
		    fname, strerror(errno));
		nread = -1;
		goto failure;
	}

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buff = malloc(len + 1);
	if (buff == NULL) {
		fprintf(stderr, "malloc(%ld) failed: %s\n",
		    (long)len + 1, strerror(errno));
		nread = -1;
		goto failure;
	}

	nread = fread(buff, 1, len, fp);
	if (nread < len && !feof(fp)) {
		fprintf(stderr, "fread() failed: %s\n", strerror(errno));
		nread = -1;
		goto failure;
	}
	*(buff + len) = '\0';

failure:
	if (buffp)
		*buffp = buff;
	if (fp)
		fclose(fp);

	return nread;
}

static void
dump_arms_info(arms_context_t *ctx)
{
	arms_rs_info_t rs[MAX_RS_INFO];
	arms_url_t url[MAX_RS_INFO];
	arms_connection_info_t info;
	const struct timeval *interval;
	int i, n;
	int error;

	printf("[armsd] getting arms information\n");

	n = arms_get_rsinfo(ctx, rs, sizeof(rs));
	for (i = 0; i < n; i++)
		printf("  RS Info[%d]: %s\n", i, rs[i].host);

	n = arms_get_rs_url(ctx, url, sizeof(url));
	for (i = 0; i < n; i++)
		printf("  RS URL[%d]: %s\n", i, url[i].url);

	n = arms_get_rs_tunnel_url(ctx, url, sizeof(url));
	for (i = 0; i < n; i++)
		printf("  RS Tunnel URL[%d]: %s\n", i, url[i].url);

	n = arms_get_proposed_push_port(ctx);
	printf("  Proposed Push Port: %d\n", n);

	n = arms_get_proposed_push_timeout(ctx);
	printf("  Proposed Push Timeout: %d\n", n);

	error = arms_get_connection_info(ctx, &info, sizeof(info));
	if (error) {
		printf("[armsd] arms_get_connection_info failed\n");
		return;
	}

	switch (info.af) {
	case AF_INET:
		printf("  RS Address Family: IPv4\n");
		break;
	case AF_INET6:
		printf("  RS Address Family: IPv6\n");
		break;
	default:
		printf("  RS Address Family: Unknown\n");
		break;
	}

	switch (info.method) {
	case ARMS_PUSH_METHOD_SIMPLE:
		printf("  Push Method: simple\n");
		printf("  SA Address: %s\n", info.un.simple_info.sa_address);
		printf("  SA Port: %d\n", info.un.simple_info.sa_port);
		break;
	case ARMS_PUSH_METHOD_TUNNEL:
		printf("  Push Method: tunnel\n");
		for (i = 0; i< MAX_RS_INFO; i++) {
			if (info.un.tunnel_info[i] == ARMS_TUNNEL_ACTIVE)
				printf("  tunnel[%d]: Active\n", i);
			else
				printf("  tunnel[%d]: Inactive\n", i);
		}
		break;
	default:
		printf("  Push Method: Unknown\n");
		break;
	}

	interval = arms_get_app_event_interval(ctx);
	printf("  app_event interval: %ld.%ld\n",
	    interval->tv_sec, interval->tv_usec);
}

static arms_context_t *
initialize_libarms(const char *distid_str, const char *lskey)
{
	arms_context_t *ctx;
	distribution_id_t distid;
	char desc[ARMS_MAX_DESC_LEN] = "libarms Test Client";
	char version[ARMS_MAX_VER_LEN] = "Version X.XX";
	char *cert = NULL;
	int error;
	int n;
	unsigned int t[8];

	memset(&distid, 0, sizeof(distid));
	n = sscanf(distid_str, "%x-%x-%x-%x-%x-%x-%x-%x", 
	    &t[0], &t[1], &t[2], &t[3], &t[4], &t[5], &t[6], &t[7]);
	if (n != 8) {
		fprintf(stderr, "invalid distribution-id format\n");
		return NULL;
	}

	distid.version = t[0];
	distid.vendor_code = (t[1] << 16) + t[2];
	distid.sa_type = t[3];
	distid.sa_code = ((uint64_t)t[4] << 48) + ((uint64_t)t[5] << 32) +
	    (t[6] << 16) + t[7];

	error = arms_init(&distid, &ctx);
	if (error != 0) {
		printf("[armsd] ERROR: arms_init return %d\n", error);
		goto failure;
	}

	if (load_from_file(CA_CERT, &cert) < 0) {
		fprintf(stderr, "cannot read file %s\n", CA_CERT);
		goto failure;
	}
	error = arms_register_cert(ctx, cert);
	if (error != 0) {
		printf("[armsd] ERROR: arms_register_cert return %d\n", error);
		goto failure;
	}
	free(cert);
	cert = NULL;

	error = arms_register_authkey(ctx, lskey);
	if (error != 0) {
		printf("[armsd] ERROR: arms_register_authkey return %d\n",
		    error);
		goto failure;
	}

	snprintf(version, sizeof(version), "Version %d.%02d",
	    arms_library_ver_major(), arms_library_ver_minor());
	if (arms_register_description(ctx, desc, version) != 0) {
		fprintf(stderr, "arms_register_description() failed.\n");
		goto failure;
	}

	return ctx;

failure:
	if(cert)
		free(cert);
	arms_end(ctx);
	return NULL;
}
