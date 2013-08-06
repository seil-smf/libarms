/*	$Id: libarms.h 24455 2013-07-02 07:31:54Z yamazaki $	*/

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

/*
 * ARMS Client Library
 */
#ifndef __LIBARMS_H__
#define __LIBARMS_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <sys/time.h>

/* ARMS Global Parameters: Only for reference, DON'T CHANGE */

/*
 * API spec.
 *  1: initial version.  pull only.
 *  2: push operation supported.
 *  3: app_event_cb supported.
 *  4: 'next' parameter in command_cb supported.
 *  5: need to call arms_push_method_query before arms_event_loop
 *  -  binary support (upper compatible with 5. no change version)
 *  6: get_status_cb request parameter is added.
 *  -: ipv6 support and some information function is added.
 *  7: store_statistics_cb supported.
 */
#define ARMS_API_VERSION		7

/*
 * library version
 */
#define ARMS_LIB_VERSION_MAJOR		5
#define ARMS_LIB_VERSION_MINOR		31
#define ARMS_LIB_VERSION_DESC		"Release"

/*
 * compatibility macro.
 */
#define ARMS_LIBPULL_VERSION		ARMS_API_VERSION
#define ARMS_LIBPULL_VERSION_MAJOR	ARMS_LIB_VERSION_MAJOR
#define ARMS_LIBPULL_VERSION_MINOR	ARMS_LIB_VERSION_MINOR
#define ARMS_LIBPULL_VERSION_DESC	ARMS_LIB_VERSION_DESC

/*
 * ARMS prococol related macro.
 */

/*
 * about major version of the protocol:
 *  1: pull only (initial release)
 *  2: push support
 *  3: https-tunnel support (not used)
 *  4: binary data support
 */
#define ARMS_PROTOCOL_VERSION_MAJOR	4
#define ARMS_PROTOCOL_VERSION_MINOR	0
#define ARMS_PROTOCOL_VERSION		ARMS_PROTOCOL_VERSION_MAJOR

#define ARMS_MAX_TIMEOUT	60 * 60 * 24 * 1 /* 1 day */
#define ARMS_DEFAULT_TIMEOUT	60 * 60 * 6      /* 6 hours */
#define ARMS_MIN_TIMEOUT	60               /* 60 sec. */
#define ARMS_MAX_LINE		5		/* number of line config */
#define ARMS_MAX_PEM_LEN	5 * 1024	/* bytes */
#define ARMS_MAX_DESC_LEN	32		/* bytes */
#define ARMS_MAX_VER_LEN	32		/* bytes */
#define ARMS_DISTID_LEN		128 / 8		/* bytes */

/* SSL/TCP/IP level timeout value (sec) */
#define ARMS_WAIT_FOR_SENDING	30

/* PPPoE Parameters */
#define MAX_PPP_ID		36
#define MAX_PPP_PASS		36

/* Mobile Parameters */
#define MAX_MOBILE_TEL_LEN      40
#define MAX_MOBILE_APN_LEN      100
#define MAX_MOBILE_PDP_LEN      8	/* "ppp" or "ip" */
#define MAX_MOBILE_PPP_ID	128
#define MAX_MOBILE_PPP_PASS	128

/* Result */
#define ARMS_RV_TYPE_SHIFT(t)	((t)<<24)
#define ARMS_RV_DATA_MASK(rv)	((rv)&0x00ffffff)
#define ARMS_RV_TYPE_ERROR	0
#define ARMS_RV_TYPE_BYTES	1
#define ARMS_RESULT_BYTES(n)	(ARMS_RV_TYPE_SHIFT(ARMS_RV_TYPE_BYTES) |\
 				 ARMS_RV_DATA_MASK(n))

#define ARMS_RV_TYPE(rv)	(((rv)&0xff000000)>>24)
#define ARMS_RESULT_IS_ERROR(n)	((n) != 0 &&\
				 ARMS_RV_TYPE(n) != ARMS_RV_TYPE_BYTES)
#define ARMS_RESULT_IS_BYTES(n)	(ARMS_RV_TYPE(n) == ARMS_RV_TYPE_BYTES)

/* Error Code */
#define ARMS_ERR_LVL_MASK	0xff00
#define ARMS_ERR_CODE_MASK	0x00ff
#define ARMS_ERR_LVL(code)	( ((code) & ARMS_ERR_LVL_MASK) >> 8)
#define ARMS_ERR_TYPE(code)	( ((code) & ARMS_ERR_CODE_MASK) )
#define ARMS_ERR_CODE(lvl, type) ( ((lvl) << 8) | (type) )
/* Error Level */
#define _ARMS_ELVL_NOERR		0
#define _ARMS_ELVL_LOW			1
#define _ARMS_ELVL_MID			2
#define _ARMS_ELVL_HIGH			3
#define _ARMS_ELVL_FATAL		4

/* Internal Error Type */
#define _ARMS_EUNDEF		0
/* protocol errors */
#define _ARMS_EPROTO_MAXRETRY	101
#define _ARMS_EPROTO_DONTRETRY	102
#define _ARMS_EPROTO_TIMEOUT	103
#define _ARMS_EPROTO_REBOOT	104
#define _ARMS_EPROTO_PULL	105
#define _ARMS_EPROTO_UPDATE	106
#define _ARMS_EPROTO_PUSH	108

/* line errors */
#define _ARMS_ELINE_TIMEOUT	201
#define _ARMS_ELINE_AUTH	202

/* library errors */
#define _ARMS_ELIB_CALLBACK	251
#define _ARMS_ELIB_INVAL	252
#define _ARMS_ELIB_SYSTEM	253
#define _ARMS_ELIB_SIZE		254
#define _ARMS_ELIB_NOCHANGE	255
#define _ARMS_ELIB_EXIST	256

/* heartbeat errors */

/* application errors */
#define _ARMS_EAPP_MODSYNC	300	/* module syncing */
#define _ARMS_EAPP_EXEC		301	/* cannot execute */

/* External error codes */

/* Protocol error(library -> application) */
#define ARMS_EFATAL \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_EUNDEF)
#define ARMS_ETIMEOUT \
	ARMS_ERR_CODE(_ARMS_ELVL_LOW, _ARMS_EPROTO_TIMEOUT)
#define ARMS_EMAXRETRY \
	ARMS_ERR_CODE(_ARMS_ELVL_MID, _ARMS_EPROTO_MAXRETRY)
#define ARMS_EDONTRETRY \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_EPROTO_DONTRETRY)
#define ARMS_ECALLBACK \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_ELIB_CALLBACK)
#define ARMS_ESYSTEM \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_ELIB_SYSTEM)
#define ARMS_EINVAL \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_ELIB_INVAL)
#define ARMS_EREBOOT \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_EPROTO_REBOOT)
#define ARMS_EPULL \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_EPROTO_PULL)
#define ARMS_ESIZE \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_ELIB_SIZE)
#define ARMS_ENOCHANGE \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_ELIB_NOCHANGE)
#define ARMS_EPUSH \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_EPROTO_PUSH)
#define ARMS_EEXIST \
	ARMS_ERR_CODE(_ARMS_ELVL_FATAL, _ARMS_ELIB_EXIST)

/* application error(application -> library) */
#define ARMS_EMODSYNC \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_EAPP_MODSYNC)
#define ARMS_EAPPEXEC \
	ARMS_ERR_CODE(_ARMS_ELVL_NOERR, _ARMS_EAPP_EXEC)


/* Log Code */
#define ARMS_LOG_OLD_ST_MASK	0xff0000
#define ARMS_LOG_NEW_ST_MASK	0x00ff00
#define ARMS_LOG_TYPE_MASK	0x0000ff
#define ARMS_LOG_OLD_ST(code)	( ((code) & ARMS_LOG_OLD_ST_MASK) >> 16)
#define ARMS_LOG_NEW_ST(code)	( ((code) & ARMS_LOG_NEW_ST_MASK) >> 8)
#define ARMS_LOG_TYPE(code)	( ((code) & ARMS_LOG_TYPE_MASK) )
#define ARMS_LOG_CODE(old_st, new_st, type) \
	( ((old_st) << 16) | ((new_st) << 8) | (type) )

/* State */
#define ARMS_ST_INITIAL		0
#define ARMS_ST_LSPULL		1
#define ARMS_ST_RSPULL		2
#define ARMS_ST_PULLDONE	3
#define ARMS_ST_BOOT_FAIL	4

#define ARMS_ST_PUSH_INITIAL	10
#define ARMS_ST_PUSH_SENDREADY	11
#define ARMS_ST_PUSH_WAIT	12
#define ARMS_ST_PUSH_ADDTRANS	13
#define ARMS_ST_PUSH_EXECTRANS	14
#define ARMS_ST_PUSH_TERM	15
#define ARMS_ST_PUSH_REBOOT	16

/*
 * log type and coes
 */
#define ARMS_LOG_INFO			  0 /* 0 - 99 */
#define ARMS_LOG_ERROR			100 /* 100 - 199 */
#define ARMS_LOG_DEBUG			200

/* STM Information Log */
#define ARMS_LOG_EFALLBACK		1 /* Fallback to previous state */

/* LS and RS access */
#define ARMS_LOG_ILS_ACCESS_START	2 /* Connecting to LS */
#define ARMS_LOG_ILS_ACCESS_END		3 /* LS Access done. */

#define ARMS_LOG_IRS_ACCESS_START	5 /* Connecting to RS */
#define ARMS_LOG_IRS_ACCESS_END		6 /* RS Access done */

#define ARMS_LOG_ILS_ACCESS_RETRY	8 /* LS retry */
#define ARMS_LOG_IRS_ACCESS_RETRY	9 /* RS retry */

/* Line Configuration */
#define ARMS_LOG_ILINE_CONNECTED	21 /* line connected */
#define ARMS_LOG_ILINE_DISCONNECTED	25 /* line connected */

/* HTTP Access */
#define ARMS_LOG_IHTTP_CONNECT_START	30 /* Connecting to httpd */
#define ARMS_LOG_IHTTP_CONNECT_END	31 /* httpd Connected */
#define ARMS_LOG_IHTTP_LISTEN_START	32 /* Ready to answer push */
#define ARMS_LOG_IHTTP_ACCEPT		33 /* Accept connection */
#define ARMS_LOG_IHTTP_CLOSE		34 /* Done push */
#define ARMS_LOG_IHTTP_RETRY		35 /* retry to send */
#define ARMS_LOG_IHTTP_PROXY_CONNECTED	36 /* connected to proxy */

/* SSL */
#define ARMS_LOG_ISSL_CONNECTED		40 /* connection established */

/* ARMS transaction */
#define ARMS_LOG_ITRANSACTION_RETRY	50 /* retry transaction */

/* tunnel */
#define ARMS_LOG_ITUNNEL_CONNECTED	60 /* connection established */
#define ARMS_LOG_ITUNNEL_CLOSED		61 /* clsoed */
#define ARMS_LOG_ITUNNEL_RETRY		62 /* retry */
#define ARMS_LOG_ITUNNEL_READY_TO_PUSH	63 /* ready to push */

/* protocol */
#define ARMS_LOG_IPROTO_CONFIRM_START	70 /* start confirmation */
#define ARMS_LOG_IPROTO_CONFIRM_DONE	71 /* done confirmation */
#define ARMS_LOG_IPROTO_CONFIRM_FAILED	72 /* confirmation failed */
#define ARMS_LOG_IPROTO_CONFIG_COMMIT	73 /* commit config */
#define ARMS_LOG_IPROTO_CONFIG_ROLLBACK	74 /* rollback config */

/* heartbeat */
#define ARMS_LOG_IHEARTBEAT_START	80 /* start heartbeat */
#define ARMS_LOG_IHEARTBEAT_STOP	81 /* stop heartbeat */
#define ARMS_LOG_IHEARTBEAT_SERVER	82 /* heartbeat server */

/* Push methods */
#define ARMS_LOG_IPUSH_METHOD_SIMPLE	90 /* push method: simple */
#define ARMS_LOG_IPUSH_METHOD_TUNNEL	91 /* push method: tunnel */

#define ARMS_LOG_IPUSH_ENDPOINT_CHANGED	92 /* push endpoint changed */

/* Errors (old_st = 0, new_st = 0, level = high) */
#define ARMS_LOG_EURL			100 /* Invalid URL */
#define ARMS_LOG_EHOST			101 /* Unknown host */
#define ARMS_LOG_ESOCKET		102 /* socket() error */
#define ARMS_LOG_ECONNECT		103 /* connect() error */
#define ARMS_LOG_ENETNOMEM		104 /* memory exhautsted */
#define ARMS_LOG_EHTTP			105 /* http level error */
#define ARMS_LOG_ECERTIFICATE		106 /* ssl cetificate error */
#define ARMS_LOG_ENETTIMEOUT		107 /* network layer timeout */
#define ARMS_LOG_ECALLBACK		108 /* error from callback func. */
#define ARMS_LOG_ESSL			109 /* OpenSSL error */

#define ARMS_LOG_EROLLBACK		110 /* rollback failure */
#define ARMS_LOG_ERETRY			111 /* retry is over */

#define ARMS_LOG_EFATAL			112 /* fatal error */
#define ARMS_LOG_EBASE64_DECODE		113 /* base64 decode error */
#define ARMS_LOG_EINITIAL_CONFIG	114 /* initial config error */

#define ARMS_LOG_ELINE_AUTH_FAIL	120 /* Authentication failure */
#define ARMS_LOG_ELINE_TIMEOUT		121 /* Timeout */
#define ARMS_LOG_ELINE_NOTAVAIL		122 /* not available line */

#define ARMS_LOG_ELS_ACCESS_FAIL	130 /* Cannot access to LS */
#define ARMS_LOG_ERS_ACCESS_FAIL	131 /* Cannot access to RS */
#define ARMS_LOG_EHB_NO_ALGORITHM	132 /* invalid algorithm */

/* Config Callback */
#define	ARMS_FRAG_CONTINUE		0x00
#define ARMS_FRAG_FIRST			0x01
#define ARMS_FRAG_FINISHED		0x02

/* Config callback action */
#define ARMS_PULL_STORE_CONFIG		1
#define ARMS_PUSH_STORE_CONFIG		2
#define ARMS_PUSH_EXEC_STORED_CONFIG	3
#define ARMS_PUSH_REVERT_CONFIG		4
#define ARMS_REMOVE_MODULE		5

/* Read config callback type */
#define ARMS_CONFIG_CANDIDATE		1
#define ARMS_CONFIG_RUNNING		2
#define ARMS_CONFIG_BACKUP		3

/* Command callback action */
#define ARMS_PUSH_CLEAR_STATUS		1
#define ARMS_PUSH_PING			2
#define ARMS_PUSH_TRACEROUTE		3
#define ARMS_PUSH_DUMP_DEBUG		4
#define ARMS_PUSH_MD_COMMAND		5

/* Trigger values */
#define ARMS_TRIGGER_CONFIG_ERROR	1
#define ARMS_TRIGGER_SYNC_FAILED	2

/*
 * Data types
 */

/* ARMS context structure for state machine (opaque for user) */
typedef struct arms_context arms_context_t;

/* Distribution ID (not packed: needs care of alignment) */
typedef struct arms_distribution_id {
	uint16_t	version;
	uint32_t	vendor_code;
	uint16_t	sa_type;
	uint64_t	sa_code;
} distribution_id_t;

/* Methods */
enum arms_push_method_type {
	ARMS_PUSH_METHOD_UNKNOWN,
	ARMS_PUSH_METHOD_SIMPLE,
	ARMS_PUSH_METHOD_TUNNEL,

	ARMS_PUSH_METHOD_LAST,
};

/* Line management */
enum arms_line_types {
	ARMS_LINE_NONE = 0,
	ARMS_LINE_ANONPPPOE,
	ARMS_LINE_PPPOE,
	ARMS_LINE_DHCP,
	ARMS_LINE_ANONMOBILE,
	ARMS_LINE_MOBILE,
	ARMS_LINE_STATIC,
	ARMS_LINE_RA,
	ARMS_LINE_PPPOE_IPV6,
	ARMS_LINE_ANONPPPOE_IPV6,

	ARMS_LINE_LAST
};

enum arms_line_actions {
	ARMS_LINE_ACT_NONE = 0,
	ARMS_LINE_ACT_CONNECT,
	ARMS_LINE_ACT_DISCONNECT,
	ARMS_LINE_ACT_STATUS,

	ARMS_LINE_ACT_LAST
};

enum arms_line_result {
	ARMS_LINE_NEEDPOLL = 0,	/* now conncting, need polling */
	ARMS_LINE_CONNECTED, 	/* connected */
	ARMS_LINE_DISCONNECTED, /* disconnected */
	ARMS_LINE_TIMEOUT,	/* failed because of timeout */
	ARMS_LINE_AUTHFAIL,	/* failed because of authentication */
	ARMS_LINE_NOTAVAILABLE,	/* failed because of not available */
};

enum arms_tunnel_status {
	ARMS_TUNNEL_INACTIVE = 0,
	ARMS_TUNNEL_ACTIVE
};

enum arms_hb_mobile_status {
	ARMS_HB_MOBILE_RUNNING = 0,
	ARMS_HB_MOBILE_NOSIGNAL,
	ARMS_HB_MOBILE_INVALIDDATA,
	ARMS_HB_MOBILE_NODEVICE,
	ARMS_HB_MOBILE_ERROR
};

/* configuration data for anonymous PPPoE connection */
typedef struct arms_line_conf_anonpppoe {
	int ifindex;
} arms_line_conf_anonpppoe_t;

/* configuration data for PPPoE connection */
typedef struct arms_line_conf_pppoe {
	int ifindex;
	char id[MAX_PPP_ID];
	char pass[MAX_PPP_PASS];
} arms_line_conf_pppoe_t;

/* configuration data for DHCP connection */
typedef struct arms_line_conf_dhcp {
	int ifindex;
} arms_line_conf_dhcp_t;

/* configuration data for anonymous mobile connection */
typedef struct arms_line_conf_anonmobile {
	int ifindex;
} arms_line_conf_anonmobile_t;

/* configuration data for mobile connection */
typedef struct arms_line_conf_mobile {
	int ifindex;
	char telno[MAX_MOBILE_TEL_LEN];
	int cid;
	char apn[MAX_MOBILE_APN_LEN];
	char pdp[MAX_MOBILE_PDP_LEN];
	char id[MAX_MOBILE_PPP_ID];
	char pass[MAX_MOBILE_PPP_PASS];
	char ipaddr[48]; /* note: IPv6 strlen == 46 */
} arms_line_conf_mobile_t;

/* configuration data for static connection */
typedef struct arms_line_conf_static {
	int ifindex;
	char ipaddr[48]; /* note: IPv6 strlen == 46 */
} arms_line_conf_static_t;

/* configuration data for IPv6 RA/SLAAC,RA/DHCPv6-PD */
typedef struct arms_line_conf_ra {
	int ifindex;
} arms_line_conf_ra_t;


/* data type for API */
typedef struct arms_line_description {
	int type;
	void *line_conf;
} arms_line_desc_t;

/* for command callback */
typedef struct arms_ping_arg {
	const char *dst;
	int count;
	int size;
} arms_ping_arg_t;

typedef struct arms_ping_report {
	int success;
	int failure;
} arms_ping_report_t;


typedef struct arms_traceroute_arg {
	const char *addr;
	int count;
	int maxhop;
} arms_traceroute_arg_t;

#define MAX_HOP 256	/* Generally, IP_TTL + 1 */
#define ARMS_TR_STRSIZE 256
typedef struct arms_traceroute_info {
	int hop;
	char addr[ARMS_TR_STRSIZE];
} arms_traceroute_info_t;

#define MAX_HBT_INFO		5
#define MAX_HBT_ALGORITHMS	3
typedef struct arms_hbt_info {
	const char *host;
	int port;
	const char *passphrase;
	int interval;
	int numalg;			/* number of algorithms */
	const char *algorithm[MAX_HBT_ALGORITHMS];
} arms_hbt_info_t;

#define MAX_LS_INFO	5
#define MAX_RS_INFO	5
typedef struct arms_rs_info {
	const char *host;
} arms_rs_info_t;

typedef struct arms_url {
	const char *url;
} arms_url_t;

typedef struct arms_connection_info {
	int method;
	int af;
	union {
		/* simple info */
		struct {
			char sa_address[128];
			int sa_port;
		} simple_info;
		/* tunnel info */
		int tunnel_info[MAX_RS_INFO];
	} un;
} arms_connection_info_t;

/*
 * Prototypes for Callback functions
 */
typedef int (*arms_config_cb_t)(uint32_t, const char *, const char *, int, const char *, size_t, int, void *);
typedef int (*arms_line_ctrl_cb_t)(int, int, void *, void *);
typedef int (*arms_state_cb_t)(int, int, void *);
typedef int (*arms_log_cb_t)(int, const char *, void *);
typedef int (*arms_read_config_cb_t)(uint32_t, int, char *, size_t, int *, void *);
typedef int (*arms_get_status_cb_t)(uint32_t, const char *, size_t, char *, size_t, int *, void *);
typedef int (*arms_command_cb_t)(uint32_t, int, const char *, size_t, char *, size_t, int *, void *);
typedef int (*arms_app_event_cb_t)(void *);
typedef int (*arms_hb_store_statistics_t)(arms_context_t *, void *);

typedef struct arms_callback_tbl {
	int			version; /* = ARMS_API_VERSION */
	arms_config_cb_t	config_cb;
	arms_line_ctrl_cb_t	line_ctrl_cb;
	arms_state_cb_t		state_cb;
	arms_log_cb_t		log_cb;
	arms_read_config_cb_t	read_config_cb;
	arms_get_status_cb_t	get_status_cb;
	arms_command_cb_t	command_cb;
	arms_app_event_cb_t	app_event_cb;
	arms_hb_store_statistics_t hb_store_statistics_cb;
} arms_callback_tbl_t;

/*
 * API functions
 */

/* prepare and finalize */
int arms_init(distribution_id_t *, arms_context_t **);
int arms_load_config(arms_context_t *, const char *, size_t);
int arms_register_cert(arms_context_t *, const char *);
int arms_register_description(arms_context_t *, const char *, const char *);
int arms_register_authkey(arms_context_t *, const char *);
int arms_set_pull_trigger(arms_context_t *, int);
void arms_end(arms_context_t *);

/* pull */
int arms_pull(arms_context_t *, time_t, size_t, arms_callback_tbl_t *, arms_line_desc_t *, void *);

/* state dump/restore */
size_t arms_size_of_state(void);
int arms_dump_state(arms_context_t *, char *, size_t);
int arms_restore_state(arms_context_t *, const char *, size_t);

/* info */
int arms_get_hbtinfo(arms_context_t *, arms_hbt_info_t *, int);
int arms_get_rsinfo(arms_context_t *, arms_rs_info_t *, int);
int arms_get_proposed_push_port(arms_context_t *);
int arms_get_proposed_push_timeout(arms_context_t *);
int arms_get_ls_url(arms_context_t *, arms_url_t *, int);
int arms_get_rs_url(arms_context_t *, arms_url_t *, int);
int arms_get_rs_tunnel_url(arms_context_t *, arms_url_t *, int);
int arms_get_connection_info(arms_context_t *, arms_connection_info_t *, int);

/* push */
int arms_push_method_query(arms_context_t *, arms_callback_tbl_t *, void *);
int arms_event_loop(arms_context_t *, int, size_t, arms_callback_tbl_t *, void *);

/* app_event */
const struct timeval *arms_get_app_event_interval(arms_context_t *);
int arms_set_app_event_interval(arms_context_t *, const struct timeval *);

/* http proxy */
int arms_set_https_proxy(arms_context_t *, const char *);

/* heartbeat */
void arms_hb_start(arms_context_t *);
void arms_hb_stop(arms_context_t *);
int arms_hb_is_running(arms_context_t *);
int arms_hb_set_cpu_usage(arms_context_t *, uint16_t, uint8_t);
int arms_hb_set_cpu_detail_usage(arms_context_t *,
                            uint16_t, uint8_t,
                            uint8_t, uint8_t,
                            uint8_t, uint8_t);
int arms_hb_set_mem_usage(arms_context_t *, uint16_t, uint64_t, uint64_t);
int arms_hb_set_disk_usage(arms_context_t *, uint16_t, uint64_t, uint64_t);
int arms_hb_set_traffic_count(arms_context_t *, uint16_t,
                         uint64_t, uint64_t,
                         uint64_t, uint64_t,
                         uint64_t, uint64_t);
int arms_hb_set_traffic_rate(arms_context_t *, uint16_t,
                        uint64_t, uint64_t,
                        uint64_t, uint64_t,
                        uint64_t, uint64_t);
int arms_hb_set_radiowave(arms_context_t *, uint16_t,
                        uint8_t, uint8_t, 
                        uint8_t, uint8_t);

/* misc functions */
int arms_library_ver_major(void);
int arms_library_ver_minor(void);
const char * arms_library_ver_string(void);
int arms_protocol_ver_major(void);
int arms_protocol_ver_minor(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __LIBARMS_H__ */
