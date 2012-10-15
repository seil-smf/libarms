/*
 * :$Id: armsd_conf.h 22796 2012-08-27 11:00:02Z m-oki $
 * ARMS Client Daemon
 * (c) 2005 Internet Initiative Japan, Inc. All rights reserved.
 */
#ifndef __ARMSD_CONF_H__
#define __ARMSD_CONF_H__

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/types.h>

#include <netinet/in.h>

/* URL data type */
#define URL_RPOTO_NONE		0
#define URL_PROTO_HTTP		1
#define URL_PROTO_HTTPS		2
#define URL_MAX_LEN		256
typedef struct url_define {
	char			string[URL_MAX_LEN + 1];
	/* other attributes? */
} url_t;

/* configuration types (for RS solicitation, Config solicitation) */
typedef enum acmi_config_types {
	ACMI_CONFIG_RSSOL,
	ACMI_CONFIG_CONFSOL,
	ACMI_CONFIG_NONE,
} acmi_config_type_t;

struct line_define {
	int type;
	union line_conf_u {
		arms_line_conf_anonpppoe_t apppoe;
		arms_line_conf_pppoe_t pppoe;
		arms_line_conf_dhcp_t dhcp;
		arms_line_conf_anonmobile_t amobile;
		arms_line_conf_mobile_t mobile;
		arms_line_conf_static_t staticip;
	} conf;
};

/* opaque configuration object (ACMI) */
struct acmi_config_object;
typedef struct acmi_config_object ACMI;

/* create ACMI object */
ACMI *acmi_create(void);

/* destroy ACMI object */
void acmi_destroy(ACMI *);

/* clear ACMI config stores */
int acmi_clear(ACMI *, acmi_config_type_t);

/* change current server/line config */
int acmi_next_server(ACMI *, acmi_config_type_t);
int acmi_next_line(ACMI *, acmi_config_type_t);
int acmi_reset_server(ACMI *, acmi_config_type_t);
int acmi_reset_line(ACMI *, acmi_config_type_t);
void acmi_put_lines(ACMI *, int, const struct line_define *, int);
int acmi_get_lines(ACMI *, int, struct line_define *);

extern int acmi_get_num_server(ACMI *, int);
extern int acmi_get_current_server(ACMI *, int);
extern int acmi_set_current_server(ACMI *, int, int);
extern int acmi_shift_current_server(ACMI *, int, int);
#define	ACMI_MODULO_SHIFT(x,s,m)	(((((x) + (s)) % (m)) + (m)) % (m))

void acmi_set_current_line(ACMI *, acmi_config_type_t, int);
int acmi_get_max_line(ACMI *i, acmi_config_type_t);

/* set/get server url */
int acmi_set_url(ACMI *, int, const char *, size_t, int);
int acmi_get_url(ACMI *, int, char *, size_t);
int acmi_get_url_idx(ACMI *, int, char *, size_t, int);
const char *acmi_refer_url(ACMI *, int, int);

/* set/get retry max */
int acmi_set_rmax(ACMI *, int, int);
int acmi_get_rmax(ACMI *, int);
#define acmi_retry_max acmi_get_rmax

/* set/get retry interval */
int acmi_set_rint(ACMI *, int, int);
int acmi_get_rint(ACMI *, int);
#define acmi_retry_interval acmi_get_rint

/* set/get line type */
int acmi_set_lines(ACMI *, int, arms_line_desc_t *);
int acmi_set_ltype(ACMI *, int, int);
int acmi_get_ltype(ACMI *, int);

/* set/get line config */
int acmi_set_lconf(ACMI *, int, char *, size_t);
int acmi_get_lconf(ACMI *, int, void **);

/* set/get lower layer timeout */
int acmi_set_lltimeout(ACMI *, int, int);
int acmi_get_lltimeout(ACMI *, int);

/* set/get anonymous pppoe account */
int acmi_set_anonpppoe(ACMI *, int, char *, char *);
int acmi_set_anonpppoe_ipv6(ACMI *, int, char *, char *);
int acmi_set_anonmobile(ACMI *, int, char *, char *, char *, char *, char *, char *);
char *acmi_get_anon_id(ACMI *, int);
char *acmi_get_anon_pass(ACMI *, int);

/* set/get certificate */
int acmi_add_cert(ACMI *, int, char *, int);
char *acmi_get_cert(ACMI *, int);
int acmi_set_cert(ACMI *, int, const char *, int, int);
char *acmi_get_cert_idx(ACMI *, int, int);

int acmi_set_textconf(ACMI *, int, int, char *, size_t);

void acmi_dump(ACMI *);

#endif /* __ARMSD_CONF_H__ */
