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
#include "../misc/openvas_logging.h"

#include <string.h> // for strlen

/**
 * @brief nvti cache variable.
 */
nvticache_t *nvticache = NULL;

/**
 * @brief Initializes the nvti cache.
 *
 * @param cache_path    The directory where the cache is to be stored.
 * @param src_path      The directory that contains the nvt files.
 */
void
nvticache_init (const gchar *cache_path, const gchar *src_path)
{
  nvticache = g_malloc0 (sizeof (nvticache_t));

  if (cache_path)
    nvticache->cache_path = g_strdup (cache_path);
  if (src_path)
    nvticache->src_path = g_strdup (src_path);

  nvticache->nvtis = nvtis_new ();
}

/**
 * @brief Free the nvti cache.
 */
void
nvticache_free ()
{
  if (nvticache->cache_path)
    g_free (nvticache->cache_path);
  if (nvticache->src_path)
    g_free (nvticache->src_path);
  nvtis_free (nvticache->nvtis);
  g_free (nvticache);
}

/**
 * @brief Retrieve NVT Information from the nvt cache for the given filename.
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return NULL in case the data could not be delivered.
 *         Else a nvti structure.
 */
const nvti_t *
nvticache_get (const gchar *filename)
{
  nvti_t *n = NULL, *n2;
  gchar *src_file = g_build_filename (nvticache->src_path, filename, NULL);
  gchar *dummy = g_build_filename (nvticache->cache_path, filename, NULL);
  gchar *cache_file = g_strconcat (dummy, ".nvti", NULL);
  struct stat src_stat;
  struct stat cache_stat;

  g_free (dummy);

  if (src_file && cache_file && stat (src_file, &src_stat) >= 0
      && stat (cache_file, &cache_stat) >= 0
      && (cache_stat.st_mtime >= src_stat.st_mtime))
    n = nvti_from_keyfile (cache_file);

  if (src_file)
    g_free (src_file);
  if (cache_file)
    g_free (cache_file);

  if (!n || !(nvti_oid (n))) return NULL;

  /* Check for duplicate OID. */
  n2 = nvtis_lookup (nvticache->nvtis, nvti_oid (n));
  if (n2)
    {
      log_legacy_write ("NVT with duplicate OID %s will be replaced with %s\n",
                        nvti_oid (n), filename);
      nvtis_remove (nvticache->nvtis, n2);
    }
  nvti_shrink (n);
  nvtis_add (nvticache->nvtis, n);
  return n;
}

/**
 * @brief Add a NVT Information to the cache.
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
nvticache_add (nvti_t * nvti, gchar * filename)
{
  gchar *dummy = g_build_filename (nvticache->cache_path, filename, NULL);
  gchar *cache_file = g_strconcat (dummy, ".nvti", NULL);
  int result = nvti_to_keyfile (nvti, cache_file);

  g_free (dummy);
  g_free (cache_file);

  return result;
}

/**
 * @brief Get a full NVTI from the cache by OID.
 *
 * @param oid      The OID to look up
 *
 * @return A full copy of the NVTI object or NULL if not found.
 */
nvti_t *
nvticache_get_by_oid_full (const char * oid)
{
  const nvti_t * nvti;
  nvti_t *cache_nvti;
  char *dummy, *filename, *cache_file;

  if (!nvticache || !nvticache->nvtis)
    return NULL;

  if (!(nvti = nvtis_lookup (nvticache->nvtis, oid)))
    return NULL;

  /* Retrieve the full version from the on disk cache. */
  filename = nvti_src (nvti);
  filename += strlen (nvticache->src_path);

  dummy = g_build_filename (nvticache->cache_path, filename, NULL);
  cache_file = g_strconcat (dummy, ".nvti", NULL);
  cache_nvti = nvti_from_keyfile (cache_file);

  g_free (dummy);
  g_free (cache_file);
  return cache_nvti;
}

/**
 * @brief Get the src element of a NVT Information from the
 * cache by OID.
 *
 * @param oid      The OID to look up
 *
 * @return A copy of the src or NULL if not found. This needs to
 *         to be free'd.
 */
gchar *
nvticache_get_src_by_oid (const gchar * oid)
{
  nvti_t * nvti = nvtis_lookup (nvticache->nvtis, oid);

  return g_strdup (nvti_src (nvti));
}
