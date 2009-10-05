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


/* Plugin preference types (influence gui in client) */
#define PREF_CHECKBOX "checkbox"
#define PREF_ENTRY "entry"
#define PREF_RADIO "radio"
#define PREF_PASSWORD "password"
#define PREF_FILE "file"
/*#define PREF_SSH_CREDENTIALS "sshcredentials"*/

#endif /* _LIBOPENVAS_H */
