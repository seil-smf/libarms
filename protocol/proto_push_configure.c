/*	$Id: proto_push_configure.c 24217 2013-05-31 03:51:24Z yamazaki $	*/

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
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libarms.h>
#include <libarms_resource.h>

#include <axp_extern.h>
#include <arms_xml_tag.h>
#include <module_db_mi.h>

#include <libarms_log.h>
#include <libarms/base64.h>
#include <libarms/malloc.h>
#include <transaction/transaction.h>
#include <protocol/arms_methods.h>

/*
 * Callback Functions
 */
/* context alloc */
static void *configure_context(tr_ctx_t *tr_ctx);
/* copy argument */
static int
configure_cparg(AXP *, uint32_t, int, const char *, size_t, tr_ctx_t *);
/* execute */
static int
configure_exec(transaction *);
/* rollback */
static int
configure_rollback(transaction *);
/* done */
static int
configure_done(transaction *tr, char *buf, int len, int *wrote);
/* context free */
static void configure_release(tr_ctx_t *tr_ctx);
static int
configure_parse(transaction *tr, const char *buf, int len);

/*
 * XML Schema: configure-start-request
 */
static char *arms_push_conf_module_attr[] = {
	"id", NULL,
	"version", NULL,
	"install-order", NULL,
	NULL
};
static char *arms_push_conf_mdconf_attr[] = {
	"id", NULL,
	"commit-order", NULL,
	"encoding", NULL,
	NULL
};
static struct axp_schema arms_push_conf_start_sreq_body[] = {
	{ARMS_TAG_MODULE, "module", AXP_TYPE_TEXT,
		arms_push_conf_module_attr, push_default_hook, NULL},
	{ARMS_TAG_MDCONF, "md-config", AXP_TYPE_TEXT,
		arms_push_conf_mdconf_attr, push_default_hook, NULL},
	{0, NULL, 0, NULL, NULL, NULL}
};
static struct axp_schema configure_start_request = {
	ARMS_TAG_CONFIGURE_SREQ, "configure-start-request", AXP_TYPE_CHILD,
		NULL, push_default_hook, arms_push_conf_start_sreq_body
};

/*
 * Method defineition
 */
arms_method_t configure_methods = {
	ARMS_TR_CONFIGURE,	/* pm_type */
	"configure",		/* type string */
	&configure_start_request, /* schema */
	0,			/* pm_flags */
	build_generic_res,	/* pm_response */
	configure_done,		/* pm_done */
	configure_exec,		/* pm_exec */
	configure_cparg,	/* pm_copyarg */
	configure_rollback,	/* pm_rollback */
	configure_context,	/* pm_context */
	configure_release,	/* pm_release */
	configure_parse,	/* pm_parse */
};

/*
 * Method implementations
 */

struct configure_args {
	int cur_mod_id;
	int mod_id[10]; /* XXX enough? */
	int err_id[10]; /* XXX enough? */
	int errs;
	int commit_err;
	int already_running;
	int syncing;
	int first; /* fragment */
	char request[AXP_BUFSIZE * 3 / 4 + 2 + 1]; /* + 2: modulo bytes */
	char *catbuf;
	int catlen;
	arms_base64_stream_t base64;
};

static int already_running = 0;

static int purge_module(uint32_t id, const char *pkg_name, void *udata);

static module_cb_tbl_t configure_module_cb = {
	NULL,
	purge_module,
	NULL
};

int
arms_is_running_configure(arms_context_t *res)
{
	return already_running;
}

static int
purge_module(uint32_t id, const char *pkg_name, void *udata)
{
	arms_config_cb_t config_cb;
	arms_context_t *res = arms_get_context();
	int err = 0;

	res = udata;
	config_cb = res->callbacks.config_cb;
	if (config_cb) {
		err = (*config_cb) (id, "",
				    "",
				    ARMS_REMOVE_MODULE,
				    NULL, 0, 0,
				    res->udata);
	}
	return err;
}

/*
 * Context Alloc
 */
static void *
configure_context(tr_ctx_t *tr_ctx)
{
	struct configure_args *arg;

	arg = CALLOC(1, sizeof(*arg));
	if (arg != NULL) {
		if (already_running) {
			arg->already_running = already_running;
		} else {
			/* only one configure */
			already_running = 1;
		}
	} else {
		tr_ctx->result = 413;/*Resource Exhausted*/
	}
	return arg;
}

/*
 * Context Free
 */
static void
configure_release(tr_ctx_t *tr_ctx)
{
	struct configure_args *arg = tr_ctx->arg;

	if (arg) {
		if (!arg->already_running) {
			/* clear configure transaction lock. */
			already_running = 0;
		}
		if (arg->catbuf != NULL) {
			FREE(arg->catbuf);
		}
		FREE(tr_ctx->arg);
	}
}

/*
 * Execute
 */
static int
configure_exec(transaction *tr)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct configure_args *arg = tr_ctx->arg;
	arms_config_cb_t config_cb;
	int err = 0;

	if (arg->already_running) {
		return 0;
	}

	config_cb = res->callbacks.config_cb;

	libarms_log(ARMS_LOG_IPROTO_CONFIG_COMMIT,
	    "Execute configure commit");
	if (arg->errs) {
		arg->commit_err = 1;
		/* XXX DO NEED IMPLEMENT DISCARD callback? */
#if 0
		config_cb(arg->cur_mod_id, "" NULL,
			  ARMS_PUSH_DISCARD_CONFIG, NULL, 0, NULL);
#endif
		return 0;
	}

	err = config_cb(arg->cur_mod_id, "", "",
			ARMS_PUSH_EXEC_STORED_CONFIG, NULL, 0, 0,
			res->udata);
	if (err == ARMS_EMODSYNC) {
		arg->commit_err = 0;
		arg->syncing = 1;
		return 0;
	} else if (err != 0) {
		/* execute failure, rollback immediately */
		err = configure_rollback(tr);
		/*
		 * exec success     --> rollbacked=0,commit_err=0,err=0
		 * rollback success --> rollbacked=1,commit_err=0,err=0
		 * rollback failed  --> rollbacked=1,commit_err=1,err=!0
		 */
		if (err != 0) {
			arg->commit_err = 1;
			return err;
		}
	}
	arg->commit_err = 0;
	
	return 0;
}

/*
 * Rollback
 */
static int
configure_rollback(transaction *tr)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	arms_context_t *res = arms_get_context();
	struct configure_args *arg = tr_ctx->arg;
	arms_config_cb_t config_cb;
	int err;

	if (tr->rollbacked) {
		/* already rollbacked. */
		return -1;
	}
	libarms_log(ARMS_LOG_IPROTO_CONFIG_ROLLBACK,
	    "Execute configure rollback");

	config_cb = res->callbacks.config_cb;

	arg->commit_err = 0;
	tr->rollbacked = 1;
	err = config_cb(arg->cur_mod_id, "", "",
		  ARMS_PUSH_REVERT_CONFIG, NULL, 0, 0, res->udata);

	libarms_log(ARMS_LOG_DEBUG, "WAITING FOR ROLLBACK ESTABLISHED");
	/* clear send buffer */
	tr->len = 0;

	return err;
}

/*
 * Copy argument
 */
static int
configure_cparg(AXP *axp, uint32_t pm_type, int tag,
		const char *buf, size_t len, tr_ctx_t *tr_ctx)
{
	struct configure_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	uint32_t mod_id;
	const char *mod_ver = NULL;
	const char *mod_loc = NULL;
	arms_config_cb_t config_cb;
	int flag, err;
	static int module_added = 0;

	if (tr_ctx->result == 302)
		return 0;

	if (arg->already_running) {
		tr_ctx->result = 302;
		return 0;
	}

	config_cb = res->callbacks.config_cb;

	switch (tag) {
	case ARMS_TAG_START_CPARG:
		module_added = 1;
		arg->first = 1;
		break;
	case ARMS_TAG_END_CPARG:
		/* call sync_module if <md-config> is not included. */
		if (module_added) {
			configure_module_cb.udata = res;
			init_module_cb(&configure_module_cb);
			err = sync_module();
			if (err < 0) {
				tr_ctx->result = 411;/*Commit failure*/
				return -1;
			}
			module_added = 0;
		}
		break;
	case ARMS_TAG_MODULE:
		mod_id = get_module_id(axp, tag);
		mod_ver = get_module_ver(axp, tag);
		/* add module id to 'new' */
		err = add_module(mod_id, mod_ver, buf);
		if (err < 0) {
			tr_ctx->result = 411;/*Commit failure*/
			return -1;
		}
		break;
	case ARMS_TAG_MDCONF:
		if (module_added) {
			/*
			 * move module id from 'new' to 'current'
			 */
			configure_module_cb.udata = res;
			init_module_cb(&configure_module_cb);
			err = sync_module();
			if (err < 0) {
				tr_ctx->result = 411;/*Commit failure*/
				return -1;
			}
			module_added = 0;
		}
		mod_id = get_module_id(axp, tag);
		if (!arms_module_is_exist(mod_id)) {
			/*
			 * <md-config> found, but <module> not found.
			 */
			tr_ctx->result = 415;/*System Error*/
			return -1;
		}
		mod_ver = lookup_module_ver(mod_id);
		mod_loc = lookup_module_location(mod_id);
		if (mod_loc == NULL)
			mod_loc = "";
		if (config_cb == NULL)
			break;
		if (arms_get_encoding(axp, tag) == ARMS_DATA_BINARY) {
			/* decode base64 */
			len = arms_base64_decode_stream(&arg->base64,
			    arg->request, sizeof(arg->request) - 1,
			    buf, len);
			arg->request[len] = '\0';
			buf = arg->request;
		}
		/*
		 * buf, len is prepared.
		 * if res->fragment == 0 and AXP_PARSE_CONTENT,
		 * buffered part of config.
		 */
		if (res->fragment == 0) {
			arg->catbuf = REALLOC(arg->catbuf, arg->catlen + len);
			if (arg->catbuf == NULL) {
				/*Resource Exhausted*/
				tr_ctx->result = 413;
				return -1;
			}
			memcpy(arg->catbuf + arg->catlen, buf, len);
			arg->catlen += len;
			if (tr_ctx->parse_state == AXP_PARSE_CONTENT) {
				/* wait for next data */
				return 0;
			}
			/* AXP_PARSE_END */
			buf = arg->catbuf;
			len = arg->catlen;
		}
		/* set fragment flag */
		flag = 0;
		if (arg->first) {
			flag |= ARMS_FRAG_FIRST;
			arg->first = 0;
		}
		/* continued' config */
		if (tr_ctx->parse_state == AXP_PARSE_CONTENT) {
			flag |= ARMS_FRAG_CONTINUE;
		}

		/* callback it */
		do {
			int slen;
			/* call config callback */
			if (res->fragment != 0 && len > res->fragment) {
				slen = res->fragment;
			} else {
				slen = len;
				/* if last fragment */
				if (tr_ctx->parse_state == AXP_PARSE_END) {
					flag |= ARMS_FRAG_FINISHED;
					/* prepare for next md-config */
					arg->first = 1;
				}
			}
			err = (*config_cb) (mod_id, mod_ver,
					    mod_loc,
					    ARMS_PUSH_STORE_CONFIG,
					    buf, slen, flag,
					    res->udata);
			if (err) {
				arg->errs++;
				tr_ctx->result = 410;
				return -1;
			}
			buf += slen;
			len -= slen;
			flag &= ~ARMS_FRAG_FIRST;
			flag |= ARMS_FRAG_CONTINUE;
		} while(len > 0);
		if (arg->catbuf != NULL) {
			/* reset for next module id */
			FREE(arg->catbuf);
			arg->catbuf = NULL;
			arg->catlen = 0;
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Done
 *
 * <configure-done-request><result-code></result-code>...
 */
static int
configure_done(transaction *tr, char *buf, int len, int *wrote)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct configure_args *arg = tr_ctx->arg;
	int size, total;
	int r;
	const char *desc;
	
	libarms_log(ARMS_LOG_DEBUG, "Generate configure-done");

	if (arg->commit_err) {
		if (tr->rollbacked) {
			r = 508;
			desc = "Rollback failure";
		} else {
			r = 411;
			desc = "Commit failure";
		}
	} else if (tr->rollbacked) {
		r = 414;
		desc = "Rollbacked";
	} else if (arg->syncing) {
		r = 303;
		desc = "Module syncing";
	} else {
		r = 100;
		desc = "Success";
	}

	tr->tr_ctx.result = r;
	total = size = arms_write_begin_message(tr, buf, len);
	buf += size;
	len -= size;

	total += arms_write_end_message(tr, buf, len);
	*wrote = total;
	return TR_WRITE_DONE;
}

extern struct axp_schema arms_generic_done_res_msg[];

/*
 * configure-done-response parser
 */
static int
configure_parse(transaction *tr, const char *buf, int len)
{
	tr_ctx_t *tr_ctx = &tr->tr_ctx;
	struct configure_args *arg = tr_ctx->arg;
	arms_context_t *res = arms_get_context();
	AXP *axp;
	int rcode = 100;
	int err;

	/* check result code */
	axp = axp_create(arms_generic_done_res_msg, "US-ASCII", tr_ctx, 0);
	MSETPOS(axp);
	if (axp == NULL)
		err = 1;
	else 
		err = axp_parse(axp, buf, len);

	if (err == 0) {
		err = axp_refer(axp, ARMS_TAG_RCODE, &rcode);
	}
	axp_destroy(axp);

	if (err != 0)
		return TR_WANT_RETRY;

	tr_ctx->res_result = rcode;
	if (rcode >= 500) {
		res->result = ARMS_EREBOOT;
		switch (rcode) {
		case 501:
			res->result = ARMS_EDONTRETRY;
			res->trigger = "received 501 Out of service";
			break;
		case 502:
			res->result = ARMS_EPULL;
			res->trigger = "received 502 Push failed";
			break;
		case 503:
			res->result = ARMS_EREBOOT;
			res->trigger = "received 503 Need reboot";
			break;
		case 508:
			/* State Mismatch. */
			res->result = ARMS_EPULL;
			break;
		}
		return TR_WANT_STOP;
	}
	if (rcode < 100 || rcode >= 200) {
		/* result code: failure*/
		if (tr->rollbacked) {
				/*
				 * retry to send done-req(rollbacked)
				 * if temporary error
				 */
				if (rcode >= 300) {
					return TR_WANT_RETRY;
				}
				/* rollback failure, need to reboot. */
				libarms_log(ARMS_LOG_EROLLBACK,
					    "rollback failure.");
				res->result = ARMS_EPULL;
				res->trigger = "rollback failure";
				return TR_WANT_STOP;
		} else {
			/*
			 * failure from server.
			 * rollback configuration.
			 */
			return TR_WANT_ROLLBACK;
		}
	}
	/* Success. */
	/* force clear rollback flag. */
	tr->rollbacked = 0;

	/*
	 * return ARMS_EREBOOT if "Module syncing"
	 */
	if (arg->syncing) {
		res->result = ARMS_EREBOOT;
		return TR_WANT_STOP;
	}
	/*
	 * after configure, send push-confirmation
	 *  to notify new ip address, and limit retry of push-confirmation.
	 */
	res->result = ARMS_EPUSH;
	res->retry_inf = 0;
	return TR_WANT_STOP;
}
