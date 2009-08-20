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

/**
 * \mainpage
 *
 * \section Introduction
 * \verbinclude README
 *
 * \section copying License Information
 * \verbinclude COPYING
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
#include "pcap_openvas.h"
#include "plugutils.h"
#include "popen.h"
#include "proctitle.h"
#include "rand.h"
#include "resolve.h"
#include "scanners_utils.h"
#include "services1.h"
#include "share_fd.h"
#include "store.h"
#include "system.h"
#include "www_funcs.h"


/**
 * Plugin standard function template to init a plugin (nasl/nes/oval).
 */
typedef int(*plugin_init_t)(struct arglist *);
/**
 * Plugin standard function template to run a plugin (nasl/nes/oval).
 */
typedef int(*plugin_run_t)(struct arglist *);

/*
 * Network-related functions
 */

/* Plugin specific network functions */

int ping_host(struct in_addr);


void plug_set_see_also(struct arglist *, char *);
struct arglist * plug_get_see_also(struct arglist *);


void plug_add_dep(struct arglist *, char *, char *);

void plug_add_port(struct arglist *, int);

/* returns a full duplex data file stream */
FILE * ptyexecvp (const char *file, const char **argv, pid_t *child);

void (*pty_logger(void(*)(const char *, ...)))(const char *, ...);

/*
 * Miscellaneous functions
 */

char * plug_get_host_name(struct arglist *);

/* Plugin preference types (influence gui in client) */
#define PREF_CHECKBOX "checkbox"
#define PREF_ENTRY "entry"
#define PREF_RADIO "radio"
#define PREF_PASSWORD "password"
#define PREF_FILE "file"
/*#define PREF_SSH_CREDENTIALS "sshcredentials"*/

/*
 * Pcap utils
 */
#include <pcap.h>

/**
 * 'Categories', influence execution order of NVTs.
 */

/** Last plugins actions type. */
#define ACT_LAST                ACT_END
/** First plugins actions type. */
#define ACT_FIRST               ACT_INIT

#define ACT_END                 10
#define ACT_FLOOD               9
#define ACT_KILL_HOST           8
#define ACT_DENIAL              7
#define ACT_DESTRUCTIVE_ATTACK  6
#define ACT_MIXED_ATTACK        5
#define ACT_ATTACK              4
#define ACT_GATHER_INFO         3
#define ACT_SETTINGS            2
#define ACT_SCANNER             1
#define ACT_INIT                0

/**
 * States of scheduler_plugin.
 */
#define LAUNCH_DISABLED 0
#define LAUNCH_RUN      1
#define LAUNCH_SILENT   2

#endif /* _LIBOPENVAS_H */
