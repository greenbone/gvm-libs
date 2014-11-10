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
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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
  gchar *cache_path;            ///< The directory where the cache is located
  gchar *src_path;              ///< The directory where the primary source is located
  nvtis_t *nvtis;               ///< Collection of NVT Information cached in memory
} nvticache_t;

nvticache_t *nvticache_new (const gchar *, const gchar *);
void nvticache_free (const nvticache_t *);
nvti_t *nvticache_get (const nvticache_t *, const gchar *);
int nvticache_add (const nvticache_t *, nvti_t *, gchar *);
nvti_t * nvticache_get_by_oid (const nvticache_t *, const gchar *);
gchar * nvticache_get_src_by_oid (const nvticache_t *, const gchar *);
void nvticache_free (const nvticache_t *);

#endif /* not _NVTICACHE_H */
