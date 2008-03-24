/* OpenVAS
 * $Id$
 * Description: Aggregation of C-headers for libopenvas.
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _LIBOPENVAS_H
#define _LIBOPENVAS_H

#ifndef ExtFunc
#define ExtFunc
#endif


#include "arglists.h"
#include "bpf_share.h"
#include "ftp_funcs.h"
#include "kb.h"
#include "network.h"
#include "popen.h"
#include "proctitle.h"
#include "rand.h"
#include "resolv.h"
#include "scanners_utils.h"
#include "services1.h"
#include "share_fd.h"
#include "store.h"
#include "system.h"
#include "www_funcs.h"


/*
 * Plugin standard function templates
 */

typedef int(*plugin_init_t)(struct arglist *);
typedef int(*plugin_run_t)(struct arglist *);      





/*
 * Network-related functions
 */

/* Plugin specific network functions */

ExtFunc int ping_host(struct in_addr);


ExtFunc void plug_set_see_also(struct arglist *, char *);
ExtFunc struct arglist * plug_get_see_also(struct arglist *);


ExtFunc void plug_add_dep(struct arglist *, char *, char *);

ExtFunc void plug_add_port(struct arglist *, int);

/* returns a full duplex data file stream */
ExtFunc FILE * ptyexecvp (const char *file, const char **argv, pid_t *child);

ExtFunc void (*pty_logger(void(*)(const char *, ...)))(const char *, ...);

/* 
 * Management of the portlists
 */

/* plugutils.c */
ExtFunc void host_add_port(struct arglist *, int, int);
ExtFunc void host_add_port_udp(struct arglist *, int, int);
ExtFunc int host_get_port_state(struct arglist *, int);
ExtFunc int host_get_port_state_udp(struct arglist *, int);
/* Not implemented
char * host_get_port_banner(struct arglist *, int);
*/






/*
 * Miscellaneous functions
 */
 
ExtFunc char * plug_get_host_name(struct arglist *);
#define PREF_CHECKBOX "checkbox"
#define PREF_ENTRY "entry"
#define PREF_RADIO "radio"
#define PREF_PASSWORD "password"
#define PREF_FILE "file"

/*
 * Pcap utils
 */
#include <pcap.h>
 
/* 
 * Misc. defines
 */
/* Actions types of the plugins */
#define ACT_LAST		ACT_END
#define ACT_FIRST		ACT_INIT

#define ACT_END			10
#define ACT_FLOOD		9
#define ACT_KILL_HOST		8
#define ACT_DENIAL 		7
#define ACT_DESTRUCTIVE_ATTACK 	6
#define ACT_MIXED_ATTACK 	5
#define ACT_ATTACK 		4
#define ACT_GATHER_INFO 	3
#define ACT_SETTINGS		2
#define ACT_SCANNER 		1
#define ACT_INIT		0



#define	LAUNCH_DISABLED 0
#define LAUNCH_RUN	1
#define LAUNCH_SILENT	2

int ovas_open_server_socket(ovas_server_context_t);

/*-----------------------------------------------------------------*/

struct http_msg {
	int type;		/* Who should read this message  */
	pid_t owner;		/* Process who sent that message */
	unsigned short port;
	int total_len;
	int transport;
	int data_len;
	char data[1];
	};
	
int http_share_exists(struct arglist *);	
struct http_msg * http_share_mkmsg(int, int, int, char*);
void http_share_freemsg(struct http_msg*);
struct http_msg * http_share_send_recv_msg(struct arglist *, struct http_msg *);
	
	
pid_t http_share_init(struct arglist *);
int http_share_close(struct arglist *, pid_t);


int internal_finished(int);

#endif
