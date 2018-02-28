/* openvas-libraries/base
 * $Id$
 * Description: API (structs and protos) for NVT Info Cache
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file nvticache.h
 * @brief Protos and data structures for NVT Information Cache.
 *
 * This file contains the protos for \ref nvticache.c
 */

#ifndef _NVTICACHE_H
#define _NVTICACHE_H

/* for gchar */
#include <glib.h>

/* for nvtis_t */
#include "nvti.h"
#include "kb.h"

int
nvticache_init (const char *, const char *);

kb_t
nvticache_get_kb ();

void
nvticache_reset ();

int
nvticache_initialized (void);

int
nvticache_check (const gchar *);

int
nvticache_add (const nvti_t *, const char *);

nvti_t *
nvticache_get_by_oid_full (const char *);

nvti_t *
nvticache_get_by_name_full (const char *);

char *
nvticache_get_src (const char *);

char *
nvticache_get_oid (const char *);

char *
nvticache_get_name (const char *);

char *
nvticache_get_tags (const char *);

GSList *
nvticache_get_prefs (const char *);

char *
nvticache_get_version (const char *);

char *
nvticache_get_copyright (const char *);

char *
nvticache_get_cves (const char *);

char *
nvticache_get_bids (const char *);

char *
nvticache_get_xrefs (const char *);

char *
nvticache_get_family (const char *);

char *
nvticache_get_filename (const char *);

char *
nvticache_get_required_keys (const char *);

char *
nvticache_get_mandatory_keys (const char *);

char *
nvticache_get_excluded_keys (const char *);

char *
nvticache_get_required_ports (const char *);

char *
nvticache_get_required_udp_ports (const char *);

int
nvticache_get_category (const char *);

int
nvticache_get_timeout (const char *);

char *
nvticache_get_dependencies (const char *);

void
nvticache_free (void);

GSList *
nvticache_get_names (void);

GSList *
nvticache_get_oids (void);

#endif /* not _NVTICACHE_H */
