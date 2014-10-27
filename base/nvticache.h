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

/**
 * @brief The structure for a NVTI Cache.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct nvticache
{
  gchar *cache_path;    ///< The directory where the cache is located
  gchar *src_path;      ///< The directory where the primary source is located
  GHashTable *nvtis;    ///< Collection of NVT Information cached in memory
} nvticache_t;

void
nvticache_init (const gchar *, const gchar *);

int
nvticache_initialized ();

void
nvticache_free ();

nvti_t *
nvticache_get (const gchar *);

int
nvticache_add (const nvti_t *, const char *);

nvti_t *
nvticache_get_by_oid_full (const char *);

const char *
nvticache_get_src (const char *);
#endif /* not _NVTICACHE_H */
