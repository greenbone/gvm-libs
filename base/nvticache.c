/* openvas-libraries/base
 * $Id$
 * Description: Implementation of API to handle NVT Info Cache
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
 * @file nvticache.c
 * @brief Implementation of API to handle NVT Info Cache
 *
 * This file contains all methods to handle NVT Information Cache
 * (nvticache_t).
 *
 * The module consequently uses glib datatypes and api for memory
 * management etc.
 */

/* for struct stat */
#include <sys/stat.h>

/* for nvticache_t */
#include "nvticache.h"

#include <string.h> // for strlen

/**
 * @brief Create a new nvticache structure initialized with a path.
 *
 * @param path The directory where the cache is to be stored.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else a nvticache structure which needs to be
 *         released using @ref nvticache_free .
 */
nvticache_t *
nvticache_new (const gchar * cache_path, const gchar * src_path)
{
  nvticache_t *cache = g_malloc0 (sizeof (nvticache_t));

  if (!cache)
    return NULL;

  if (cache_path)
    cache->cache_path = g_strdup (cache_path);
  if (src_path)
    cache->src_path = g_strdup (src_path);

  cache->nvtis = nvtis_new ();

  return (cache);
}

/**
 * @brief Free memory of a nvticache structure.
 *
 * @param cache The structure to be freed.
 */
void
nvticache_free (const nvticache_t * cache)
{
  if (cache->cache_path)
    g_free (cache->cache_path);
  if (cache->src_path)
    g_free (cache->src_path);
  nvtis_free (cache->nvtis);
  g_free ((nvticache_t *) cache);
}

/**
 * @brief Retrieve NVT Information from a cache for the given filename.
 *
 * @param cache    The NVTI Cache to use
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return NULL in case the data could not be delivered.
 *         Else a nvti structure which needs to be
 *         released using @ref nvti_free .
 */
nvti_t *
nvticache_get (const nvticache_t * cache, const gchar * filename)
{
  nvti_t *n = NULL, *n2;
  gchar *src_file = g_build_filename (cache->src_path, filename, NULL);
  gchar *dummy = g_build_filename (cache->cache_path, filename, NULL);
  gchar *cache_file = g_strconcat (dummy, ".nvti", NULL);
  struct stat src_stat;
  struct stat cache_stat;

  g_free (dummy);

  if (src_file && cache_file && stat (src_file, &src_stat) >= 0
      && stat (cache_file, &cache_stat) >= 0
      && (cache_stat.st_mtime >= src_stat.st_mtime))
    {
      n = nvti_from_keyfile (cache_file);
    }

  if (src_file)
    g_free (src_file);
  if (cache_file)
    g_free (cache_file);

  if (!n || !(nvti_oid (n))) return NULL;

  n2 = nvtis_lookup (cache->nvtis, nvti_oid (n));
  if (n2)
    {
// TODO: Shouldn't we remove the old one with the same OID now
// and use the the new one
// Like: nvtis_remove (cache->nvtis, n2); // <- this function is missing yet
      return nvti_clone (n2);
    }
  else
    {
      n2 = nvti_clone (n);
      nvti_shrink (n);
      nvtis_add (cache->nvtis, n);
      return n2;
    }
}

/**
 * @brief Add a NVT Information to the cache.
 *
 * @param cache    The NVTI Cache to use
 *
 * @param nvti     The NVT Information to add
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return 0 in case of success, anything else indicates an error.
 */
int
nvticache_add (const nvticache_t * cache, nvti_t * nvti, gchar * filename)
{
  gchar *dummy = g_build_filename (cache->cache_path, filename, NULL);
  gchar *cache_file = g_strconcat (dummy, ".nvti", NULL);
  int result = nvti_to_keyfile (nvti, cache_file);

  g_free (dummy);
  g_free (cache_file);

  return result;
}

/**
 * @brief Get a NVT Information from the cache by OID.
 *
 * @param cache    The NVTI Cache to use
 *
 * @param oid      The OID to look up
 *
 * @return A copy of the NVTI object or NULL if not found.
 */
nvti_t *
nvticache_get_by_oid (const nvticache_t * cache, const gchar * oid)
{
  nvti_t * nvti;

  if (!cache || !cache->nvtis)
    return NULL;

  nvti = nvtis_lookup (cache->nvtis, oid);
  if (! nvti)
    return NULL;

  gchar * filename = nvti_src (nvti);
  int l = strlen (cache->src_path);
  filename += l;

  gchar *dummy = g_build_filename (cache->cache_path, filename, NULL);
  gchar *cache_file = g_strconcat (dummy, ".nvti", NULL);

  g_free (dummy);

  nvti_t * n = nvti_from_keyfile (cache_file);

  g_free (cache_file);

  return n;
}

/**
 * @brief Get the src element of a NVT Information from the
 * cache by OID.
 *
 * @param cache    The NVTI Cache to use
 *
 * @param oid      The OID to look up
 *
 * @return A copy of the src or NULL if not found. This needs to
 *         to be free'd.
 */
gchar *
nvticache_get_src_by_oid (const nvticache_t * cache, const gchar * oid)
{
  nvti_t * nvti = nvtis_lookup (cache->nvtis, oid);

  return g_strdup (nvti_src (nvti));
}
