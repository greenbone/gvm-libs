/* OpenVAS
 * $Id$
 * Description: Header file for module plugutils.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_PLUGUTILS_H
#define OPENVAS_PLUGUTILS_H

#include "arglists.h"

void scanner_add_port(struct arglist*, int, char *);

/*
 * Arglist management at plugin-level
 */

void plug_set_name(struct arglist *, const char *);
char*plug_get_name(struct arglist*);

void plug_set_path(struct arglist *, const char *);
char*plug_get_path(struct arglist *);

void plug_set_fname(struct arglist *, const char *);
char*plug_get_fname(struct arglist *);

void plug_set_cachefile(struct arglist *, const char *);
char*plug_get_cachefile(struct arglist *);

void plug_set_version(struct arglist *, const char *);
char*plug_get_version(struct arglist *);

void plug_set_timeout(struct arglist *, int);
int  plug_get_timeout(struct arglist *);

void plug_set_launch(struct arglist *, int);
int plug_get_launch(struct arglist *);

void plug_set_summary(struct arglist *, const char *);
char*plug_get_summary(struct arglist *);

void plug_set_description(struct arglist *, const char *);
char*plug_get_description(struct arglist *);

void plug_set_category(struct arglist *, int);
int  plug_get_category(struct arglist *);

void plug_set_copyright(struct arglist *, const char *);
char*plug_get_copyright(struct arglist *);

void plug_set_family(struct arglist * , const char *);
char*plug_get_family(struct arglist *);

void plug_set_dep(struct arglist *, const char *);
struct arglist * plug_get_deps(struct arglist*);

#define LEGACY_OID "1.3.6.1.4.1.25623.1.0."

void plug_set_id(struct arglist *, int);
int  plug_get_id(struct arglist *);

void plug_set_oid(struct arglist *, char *);
char*plug_get_oid(struct arglist *);

void plug_set_cve_id(struct arglist *, char *);
char*plug_get_cve_id(struct arglist *);

void plug_set_bugtraq_id(struct arglist *, char *);
char*plug_get_bugtraq_id(struct arglist *);

void plug_set_xref(struct arglist *, char *, char *);
char * plug_get_xref(struct arglist *);

void plug_set_tag(struct arglist *, char *, char *);
char * plug_get_tag(struct arglist *);

void plug_set_sign_key_ids(struct arglist*, char*);
char* plug_get_sign_key_ids(struct arglist*);

void plug_set_ssl_cert(struct arglist*, char*);
void plug_set_ssl_key(struct arglist*, char*);
void plug_set_ssl_pem_password(struct arglist*, char*);


const char * plug_get_hostname(struct arglist *);
const char * plug_get_host_fqdn(struct arglist *);
void plug_add_host(struct arglist *, struct arglist *);
unsigned int plug_get_host_open_port(struct arglist * desc);

void plug_set_port_transport (struct arglist *, int, int);

char* plug_get_cve_id(struct arglist*);
char* plug_get_bugtraq_id(struct arglist*);

void plug_require_key(struct arglist *, const char *);
struct arglist * plug_get_required_keys(struct arglist *);

void plug_mandatory_key(struct arglist *, const char *);
struct arglist * plug_get_mandatory_keys(struct arglist *);

void plug_exclude_key(struct arglist *, const char *);
struct arglist * plug_get_excluded_keys(struct arglist *);

void plug_require_port(struct arglist *, const char *);
struct arglist * plug_get_required_ports(struct arglist *);

void plug_require_udp_port(struct arglist*, const char *);
struct arglist * plug_get_required_udp_ports(struct arglist *);
int plug_get_port_transport(struct arglist*, int);

/*
 * Reporting functions
 */
void proto_post_hole(struct arglist *, int, const char *, const char *);
void post_hole(struct arglist *, int, const char *);
void post_hole_udp(struct arglist *, int, const char *);
#define post_hole_tcp post_hole

void proto_post_info(struct arglist *, int, const char *, const char *);
void post_info(struct arglist *, int, const char *);
void post_info_udp(struct arglist *, int, const char *);
#define post_info_tcp post_info

void proto_post_note(struct arglist *, int, const char *, const char *);
void post_note(struct arglist *, int, const char *);
void post_note_udp(struct arglist *, int, const char *);
#define post_note_tcp post_note

void proto_post_debug(struct arglist *, int, const char *, const char *);
void post_debug(struct arglist *, int, const char *);
void post_debug_udp(struct arglist *, int, const char *);
#define post_debug_tcp post_debug

void proto_post_log(struct arglist *, int, const char *, const char *);
void post_log(struct arglist *, int, const char *);
void post_log_udp(struct arglist *, int, const char *);
#define post_log_tcp post_log

/*
 * Management of the portlists
 */

void host_add_port(struct arglist *, int, int);
void host_add_port_udp(struct arglist *, int, int);
int host_get_port_state(struct arglist *, int);
int host_get_port_state_udp(struct arglist *, int);
/* Not implemented
char * host_get_port_banner(struct arglist *, int);
*/

/*
 * Inter Plugins Communication functions
 */
void plug_set_key(struct arglist *, char *, int, void *);
void plug_replace_key(struct arglist *, char *, int, void *);
void * plug_get_fresh_key(struct arglist *, char *, int *);
struct kb_item ** plug_get_kb(struct arglist *);
void * plug_get_key(struct arglist *, char *, int *);

char* nessuslib_version();
void nessus_lib_version(int *, int *, int *);
char* addslashes(char*);
char* rmslashes(char*);

struct in6_addr * plug_get_host_ip(struct arglist *);
char * get_preference(struct arglist *, const char *);
void add_plugin_preference(struct arglist *, const char *, const char *, const char *);
char *get_plugin_preference(struct arglist *, const char *);
const char *get_plugin_preference_fname(struct arglist*, const char*);

char* find_in_path(char*, int);

int shared_socket_register ( struct arglist *, int, char *);
int shared_socket_acquire  ( struct arglist *, char * );
int shared_socket_release  ( struct arglist *, char * );
int shared_socket_destroy  ( struct arglist *, char * );

/* in fact, these defines might better be in
 * a separate files. They are inserted here
 * simply because plugutils uses them a lot.
 */
#define INTERNAL_COMM_MSG_TYPE_CTRL (1 << 16)
#define INTERNAL_COMM_MSG_TYPE_KB (1 << 17)
#define INTERNAL_COMM_MSG_TYPE_DATA (1 << 18)
#define INTERNAL_COMM_MSG_SHARED_SOCKET (1 << 19)

#define INTERNAL_COMM_KB_REPLACE 1
#define INTERNAL_COMM_KB_GET 2
#define INTERNAL_COMM_KB_SENDING_INT 4
#define INTERNAL_COMM_KB_SENDING_STR 8
#define INTERNAL_COMM_KB_ERROR 16


#define INTERNAL_COMM_CTRL_FINISHED 1
#define INTERNAL_COMM_CTRL_ACK      2

#define INTERNAL_COMM_SHARED_SOCKET_REGISTER 1
#define INTERNAL_COMM_SHARED_SOCKET_ACQUIRE 2
#define INTERNAL_COMM_SHARED_SOCKET_RELEASE 4
#define INTERNAL_COMM_SHARED_SOCKET_DESTROY 8

#define INTERNAL_COMM_SHARED_SOCKET_DORECVMSG 16
#define INTERNAL_COMM_SHARED_SOCKET_BUSY  32
#define INTERNAL_COMM_SHARED_SOCKET_ERROR 64

/*
 * Type of "transport layer", for encapsulated connections
 * Only SSL is supported at this time.
 * (Bad) examples of other layers could be SOCKS, httptunnel, icmptunnel,
 * RMI over HTTP, DCOM over HTTP, TCP over TCP, etc.
 */
#define NESSUS_ENCAPS_IP 1
#define NESSUS_ENCAPS_SSLv23 2 /* Ask for compatibility options */
#define NESSUS_ENCAPS_SSLv2 3
#define NESSUS_ENCAPS_SSLv3 4
#define NESSUS_ENCAPS_TLSv1 5

#define IS_ENCAPS_SSL(x) ((x) >= NESSUS_ENCAPS_SSLv23 && (x) <= NESSUS_ENCAPS_TLSv1)

#endif
