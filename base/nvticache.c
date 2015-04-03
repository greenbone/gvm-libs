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
#include <assert.h>

char *cache_path = NULL;    /* The directory of the cache files. */
char *src_path = NULL;      /* The directory of the source files. */
GHashTable *nvtis = NULL;

/**
 * @brief Return whether the nvt cache is initialized.
 *
 * @return 1 if cache is initialized, 0 otherwise.
 */
int
nvticache_initialized (void)
{
 return !!nvtis;
}

/**
 * @brief Initializes the nvti cache.
 *
 * @param cache_path    The directory where the cache is to be stored.
 * @param src_path      The directory that contains the nvt files.
 */
void
nvticache_init (const gchar *cache, const gchar *src)
{
  assert (!nvtis);
  assert (cache);
  assert (src);

  cache_path = g_strdup (cache);
  src_path = g_strdup (src);

  nvtis = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

/**
 * @brief Free the nvti cache.
 */
void
nvticache_free (void)
{
  g_free (cache_path);
  g_free (src_path);
  g_hash_table_destroy (nvtis);
  nvtis = NULL;
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
 *         Else a nvti structure that should be freed with nvti_free().
 */
nvti_t *
nvticache_get (const gchar *filename)
{
  nvti_t *n = NULL;
  char *src_file, *dummy, *cache_file;
  struct stat src_stat;
  struct stat cache_stat;

  assert (nvtis);
  src_file = g_build_filename (src_path, filename, NULL);
  dummy = g_build_filename (cache_path, filename, NULL);
  cache_file = g_strconcat (dummy, ".nvti", NULL);
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
  if (g_hash_table_lookup (nvtis, nvti_oid (n)))
    {
      log_legacy_write ("NVT with duplicate OID %s will be replaced with %s\n",
                        nvti_oid (n), filename);
      g_hash_table_remove (nvtis, nvti_oid (n));
    }
  g_hash_table_insert (nvtis, g_strdup (nvti_oid (n)), g_strdup (filename));
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
nvticache_add (const nvti_t *nvti, const char *filename)
{
  gchar *cache_file, *dummy, *src_file;
  int result;

  assert (nvtis);

  src_file = g_build_filename (src_path, filename, NULL);
  dummy = g_build_filename (cache_path, filename, NULL);
  cache_file = g_strconcat (dummy, ".nvti", NULL);
  result = nvti_to_keyfile (nvti, src_file, cache_file);
  g_free (dummy);
  g_free (src_file);
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
nvticache_get_by_oid_full (const char *oid)
{
  nvti_t *cache_nvti;
  char *dummy, *cache_file;
  const char *filename;

  assert (nvtis);

  filename = g_hash_table_lookup (nvtis, oid);
  if (!filename)
    return NULL;

  /* Retrieve the full version from the on disk cache. */
  dummy = g_build_filename (cache_path, filename, NULL);
  cache_file = g_strconcat (dummy, ".nvti", NULL);
  cache_nvti = nvti_from_keyfile (cache_file);

  g_free (dummy);
  g_free (cache_file);
  return cache_nvti;
}

/**
 * @brief Get the full source filename of an OID.
 *
 * @param oid      The OID to look up.
 *
 * @return Filename with full path matching OID if found, NULL otherwise.
 */
char *
nvticache_get_src (const char *oid)
{
  assert (nvtis);

  return g_build_filename (src_path, g_hash_table_lookup (nvtis, oid), NULL);
}

/**
 * @brief Get the source filename of an OID without the
 *        NVT main directory path.
 *
 * @param oid      The OID to look up.
 *
 * @return Filename matching OID if found, NULL otherwise.
 *         The filename path does not cover the full path
 *         with the NVT main directory. Just the path below
 *         the NVT main directory.
 */
const char *
nvticache_get_filename (const char *oid)
{
  assert (nvtis);

  return g_hash_table_lookup (nvtis, oid);
}
