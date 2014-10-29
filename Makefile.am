#	$Id: Makefile.am 25423 2014-10-24 04:54:56Z yamazaki $

# current:revision:age
# current: increment if interface change.
# revision: increment if source change.
# age: increment if function add.

libarms_la_LDFLAGS= -version-info 0:3:0

ACLOCAL_AMFLAGS=-I m4
AM_CPPFLAGS= -Wall

lib_LTLIBRARIES=libarms.la
libarms_la_SOURCES=$(LIBARMS_SRCS)
include_HEADERS=include/libarms.h

LIBARMS_SRCS=	${LIB_SRCS} ${WRAPPER_SRCS} ${COMPAT_SRCS} ${MICONF_SRCS} \
		${MODULE_SRCS} ${SCHED_SRCS} ${SERVER_SRCS} ${TRANS_SRCS} \
		${PROTOCOL_SRCS} ${XML_SRCS} ${HTTP_SRCS} ${PORT_SRCS} \
		${HB_SRCS}

LIB_SRCS=	libarms/arms_context.c \
		libarms/arms_pull.c \
		libarms/cache.c \
		libarms/arms_push_method_query.c \
		libarms/arms_event_loop.c \
		libarms/malloc.c \
		libarms/proxy.c \
		libarms/time.c \
		libarms/libarms.c \
		libarms/lsconfig.c \
		libarms/log.c \
		libarms/version.c

WRAPPER_SRCS=	libarms/sock.c \
		libarms/ssl.c

COMPAT_SRCS=	compat/getaddrinfo.c \
		compat/getnameinfo.c \
		compat/strtok_r.c \
		compat/strlcpy.c

MICONF_SRCS=	miconf/armsd_miconf.c \
		miconf/armsd_conf_parse.c \
		miconf/armsd_miconf_binary.c

MODULE_SRCS=	module/module_db_mi.c

SCHED_SRCS=	scheduler/scheduler.c

SERVER_SRCS=	server/server.c

TRANS_SRCS=	transaction/transaction.c \
		transaction/state.c \
		transaction/retry.c \
		transaction/line.c \
		transaction/echo.c \
		transaction/tunnel_chunk.c \
		transaction/ssltunnel.c

PROTOCOL_SRCS=	protocol/arms_methods.c \
		protocol/arms_req_builder.c \
		protocol/arms_req_parser.c \
		protocol/arms_res_builder.c \
		protocol/arms_res_parser.c \
		protocol/proto_error.c \
		protocol/proto_pull_ls.c \
		protocol/proto_pull_rs.c \
		protocol/proto_push_ready.c \
		protocol/proto_push_check_transaction.c \
		protocol/proto_push_clear_status.c \
		protocol/proto_push_configure.c \
		protocol/proto_push_confirmation.c \
		protocol/proto_push_dump_debug.c \
		protocol/proto_push_method_query.c \
		protocol/proto_push_md_command.c \
		protocol/proto_push_ping.c \
		protocol/proto_push_pull_config.c \
		protocol/proto_push_read_module_list.c \
		protocol/proto_push_read_status.c \
		protocol/proto_push_read_storage.c \
		protocol/proto_push_reboot.c \
		protocol/proto_push_traceroute.c \
		protocol/util.c \
		protocol/arms_xml_tag.c

XML_SRCS=	xml/axp.c \
		xml/handler.c

HTTP_SRCS=	http/chunk.c \
		http/base64.c \
		http/http_parser.c \
		http/http_builder.c \
		http/url.c

HB_SRCS=	libarms/hb_api.c \
		libarms/hb_routine.c

dist_noinst_DATA= \
include/arms_xml_tag.h \
include/armsd_conf.h \
include/axp_extern.h \
include/compat.h \
include/errcode.h \
include/hb_routine.h \
include/libarms_log.h \
include/libarms_param.h \
include/libarms_resource.h \
include/libhb.h \
include/lsconfig.h \
include/module_db_mi.h \
http/http.h \
libarms/base64.h \
libarms/malloc.h \
libarms/queue.h \
libarms/sock.h \
libarms/ssl.h \
libarms/time.h \
miconf/armsd_conf_parse.h \
miconf/armsd_miconf_private.h \
protocol/arms_methods.h \
scheduler/scheduler.h \
server/server.h \
transaction/ssltunnel.h \
transaction/transaction.h \
xml/axp_internal.h \
simple-armsd/Makefile \
simple-armsd/cacert.pem \
simple-armsd/callback.c \
simple-armsd/callback.h \
simple-armsd/lines.h \
simple-armsd/main.c \
lsconf/lsconfig_crypt.c \
lsconf/lsconfig_crypt.h

nobase_dist_doc_DATA= \
doc/api/api_top.html \
doc/api/arms_app_event_cb_t.html \
doc/api/arms_command_cb_t.html \
doc/api/arms_config_cb_t.html \
doc/api/arms_dump_state.html \
doc/api/arms_end.html \
doc/api/arms_event_loop.html \
doc/api/arms_get_app_event_interval.html \
doc/api/arms_get_connection_info.html \
doc/api/arms_get_hbtinfo.html \
doc/api/arms_get_proposed_push.html \
doc/api/arms_get_rs_tunnel_url.html \
doc/api/arms_get_rs_url.html \
doc/api/arms_get_rsinfo.html \
doc/api/arms_init.html \
doc/api/arms_get_status_cb_t.html \
doc/api/arms_hb_is_running.html \
doc/api/arms_hb_set_cpu_detail_usage.html \
doc/api/arms_hb_set_cpu_usage.html \
doc/api/arms_hb_set_disk_usage.html \
doc/api/arms_hb_set_mem_usage.html \
doc/api/arms_hb_set_radiowave.html \
doc/api/arms_hb_set_traffic_rate.html \
doc/api/arms_hb_start.html \
doc/api/arms_hb_stop.html \
doc/api/arms_hb_store_statistics_cb_t.html \
doc/api/arms_library_ver.html \
doc/api/arms_library_ver_string.html \
doc/api/arms_line_ctrl_cb_t.html \
doc/api/arms_load_config.html \
doc/api/arms_log_cb_t.html \
doc/api/arms_protocol_ver.html \
doc/api/arms_pull.html \
doc/api/arms_push_method_query.html \
doc/api/arms_read_config_cb_t.html \
doc/api/arms_register_authkey.html \
doc/api/arms_register_cert.html \
doc/api/arms_register_description.html \
doc/api/arms_restore_state.html \
doc/api/arms_set_app_event_interval.html \
doc/api/arms_set_https_proxy.html \
doc/api/arms_set_pull_trigger.html \
doc/api/arms_size_of_state.html \
doc/api/arms_state_cb_t.html \
doc/api/error_code.html \
doc/api/struct.html \
doc/armsd/armsd_top.html \
doc/_sources/api/api_top.txt \
doc/_sources/api/arms_app_event_cb_t.txt \
doc/_sources/api/arms_command_cb_t.txt \
doc/_sources/api/arms_config_cb_t.txt \
doc/_sources/api/arms_dump_state.txt \
doc/_sources/api/arms_end.txt \
doc/_sources/api/arms_event_loop.txt \
doc/_sources/api/arms_get_app_event_interval.txt \
doc/_sources/api/arms_get_connection_info.txt \
doc/_sources/api/arms_get_hbtinfo.txt \
doc/_sources/api/arms_get_proposed_push.txt \
doc/_sources/api/arms_get_rs_tunnel_url.txt \
doc/_sources/api/arms_get_rs_url.txt \
doc/_sources/api/arms_get_rsinfo.txt \
doc/_sources/api/arms_get_status_cb_t.txt \
doc/_sources/api/arms_hb_is_running.txt \
doc/_sources/api/arms_hb_set_cpu_detail_usage.txt \
doc/_sources/api/arms_hb_set_cpu_usage.txt \
doc/_sources/api/arms_hb_set_disk_usage.txt \
doc/_sources/api/arms_hb_set_mem_usage.txt \
doc/_sources/api/arms_hb_set_radiowave.txt \
doc/_sources/api/arms_hb_set_traffic_rate.txt \
doc/_sources/api/arms_hb_start.txt \
doc/_sources/api/arms_hb_stop.txt \
doc/_sources/api/arms_hb_store_statistics_cb_t.txt \
doc/_sources/api/arms_init.txt \
doc/_sources/api/arms_library_ver.txt \
doc/_sources/api/arms_library_ver_string.txt \
doc/_sources/api/struct.txt \
doc/_sources/api/arms_line_ctrl_cb_t.txt \
doc/_sources/api/arms_load_config.txt \
doc/_sources/api/arms_log_cb_t.txt \
doc/_sources/api/arms_protocol_ver.txt \
doc/_sources/api/arms_pull.txt \
doc/_sources/api/arms_push_method_query.txt \
doc/_sources/api/arms_read_config_cb_t.txt \
doc/_sources/api/arms_register_authkey.txt \
doc/_sources/api/arms_register_cert.txt \
doc/_sources/api/arms_register_description.txt \
doc/_sources/api/arms_restore_state.txt \
doc/_sources/api/arms_set_app_event_interval.txt \
doc/_sources/api/arms_set_https_proxy.txt \
doc/_sources/api/arms_set_pull_trigger.txt \
doc/_sources/api/arms_size_of_state.txt \
doc/_sources/api/arms_state_cb_t.txt \
doc/_sources/api/error_code.txt \
doc/_sources/appendix/appendix_top.txt \
doc/_sources/arch/arch_top.txt \
doc/_sources/arch/config.txt \
doc/_sources/arch/pull.txt \
doc/_sources/arch/push.txt \
doc/_sources/arch/heartbeat.txt \
doc/_sources/impl/finalize.txt \
doc/_sources/impl/event.txt \
doc/_sources/impl/impl_top.txt \
doc/_sources/impl/information.txt \
doc/_sources/impl/initialize.txt \
doc/_sources/impl/pull.txt \
doc/_sources/impl/push.txt \
doc/_sources/impl/heartbeat.txt \
doc/_sources/index.txt \
doc/_sources/contents.txt \
doc/_sources/download.txt \
doc/_sources/intro/intro_top.txt \
doc/appendix/appendix_top.html \
doc/arch/arch_top.html \
doc/arch/config.html \
doc/arch/pull.html \
doc/arch/push.html \
doc/arch/heartbeat.html \
doc/impl/event.html \
doc/impl/finalize.html \
doc/impl/impl_top.html \
doc/impl/information.html \
doc/impl/initialize.html \
doc/impl/pull.html \
doc/impl/push.html \
doc/impl/heartbeat.html \
doc/index.html \
doc/contents.html \
doc/download.html \
doc/intro/intro_top.html \
doc/genindex.html \
doc/search.html \
doc/_images/libarms-push.png \
doc/_images/libarms-system.png \
doc/_images/libarms-pull.png \
doc/_images/armsd-push.png \
doc/_images/armsd-pull.png \
doc/_static/pygments.css \
doc/_static/basic.css \
doc/_static/doctools.js \
doc/_static/file.png \
doc/_static/jquery.js \
doc/_static/logo.png \
doc/_static/minus.png \
doc/_static/plus.png \
doc/_static/searchtools.js \
doc/_static/underscore.js \
doc/_static/nature.css \
doc/_static/arrow.png \
doc/_static/bg_x.gif \
doc/_static/bg_y.gif \
doc/_static/h1.gif \
doc/_static/h2.gif \
doc/_static/h3.gif \
doc/_static/head.gif \
doc/_static/point.png \
doc/_static/point2.png \
doc/_static/point3.png \
doc/_static/to_top.png \
doc/.buildinfo \
doc/objects.inv \
doc/searchindex.js
