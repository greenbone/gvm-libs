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
#include "kb.h"
#include "../misc/openvas_logging.h"

#include <string.h> // for strlen
#include <assert.h>

#undef  G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  nvticache"

char *cache_path = NULL;    /* The directory of the cache files. */
char *src_path = NULL;      /* The directory of the source files. */
kb_t cache_kb = NULL;

/**
 * @brief Return whether the nvt cache is initialized.
 *
 * @return 1 if cache is initialized, 0 otherwise.
 */
int
nvticache_initialized (void)
{
 return !!cache_kb;
}

/**
 * @brief Initializes the nvti cache.
 *
 * @param cache         The directory where the cache is to be stored.
 * @param src           The directory that contains the nvt files.
 * @param kb_path       Path to kb socket.
 */
int
nvticache_init (const char *cache, const char *src, const char *kb_path)
{
  assert (!cache_kb);
  assert (cache);
  assert (src);

  cache_path = g_strdup (cache);
  src_path = g_strdup (src);

  if (kb_new (&cache_kb, kb_path))
    return -1;
  return 0;
}

/**
 * @brief Free the nvti cache.
 */
void
nvticache_free (void)
{
  g_free (cache_path);
  g_free (src_path);
  kb_delete (cache_kb);
  cache_kb = NULL;
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
  char *src_file, *dummy, *cache_file, pattern[2048], *oid;
  struct stat src_stat;
  struct stat cache_stat;

  assert (cache_kb);
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
  oid = nvti_oid (n);
  g_snprintf (pattern, sizeof (pattern), "oid:%s:name", oid);
  dummy = kb_item_get_str (cache_kb, pattern);
  if (dummy)
    {
      g_warning ("NVT %s with duplicate OID %s will be replaced with %s",
                 dummy, oid, filename);
      kb_del_items (cache_kb, pattern);
    }
  g_free (dummy);
  if (kb_item_add_str (cache_kb, pattern, filename))
    goto kb_fail;

  if (nvti_required_keys (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_keys (n)))
        goto kb_fail;
    }

  if (nvti_mandatory_keys (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:mandatory_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_mandatory_keys (n)))
        goto kb_fail;
    }

  if (nvti_excluded_keys (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:excluded_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_excluded_keys (n)))
        goto kb_fail;
    }

  if (nvti_required_udp_ports (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_udp_ports", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_udp_ports (n)))
        goto kb_fail;
    }

  if (nvti_required_ports (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_ports", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_ports (n)))
        goto kb_fail;
    }

  if (nvti_dependencies (n))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:dependencies", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_dependencies (n)))
        goto kb_fail;
    }

  g_snprintf (pattern, sizeof (pattern), "oid:%s:category", oid);
  if (kb_item_add_int (cache_kb, pattern, nvti_category (n)))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:timeout", oid);
  if (kb_item_add_int (cache_kb, pattern, nvti_timeout (n)))
    goto kb_fail;

  g_snprintf (pattern, sizeof (pattern), "name:%s:oid", filename);
  if (kb_item_add_str (cache_kb, pattern, oid))
    goto kb_fail;
  return n;

kb_fail:
  nvti_free (n);
  return NULL;
}

/**
 * @brief Reset connection to KB. To be called after a fork().
 */
void
nvticache_reset ()
{
  if (cache_kb)
    kb_lnk_reset (cache_kb);
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

  assert (cache_kb);

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
 * @brief Get a full NVTI from the cache file by filename.
 *
 * @param filename  Filename of nvti to lookup
 *
 * @return A full copy of the NVTI object or NULL if not found.
 */
nvti_t *
nvticache_get_by_name_full (const char *filename)
{
  char *dummy, *cache_file;
  nvti_t *cache_nvti;

  if (!filename)
    return NULL;

  dummy = g_build_filename (cache_path, filename, NULL);
  cache_file = g_strconcat (dummy, ".nvti", NULL);
  cache_nvti = nvti_from_keyfile (cache_file);

  g_free (dummy);
  g_free (cache_file);
  return cache_nvti;
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
  char *filename, pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:name", oid);
  filename = kb_item_get_str (cache_kb, pattern);
  if (!filename)
    return NULL;
  cache_nvti = nvticache_get_by_name_full (filename);

  g_free (filename);
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
  char *filename, *src, pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:name", oid);
  filename = kb_item_get_str (cache_kb, pattern);
  if (!filename)
    return NULL;
  src = g_build_filename (src_path, filename, NULL);
  g_free (filename);
  return src;
}

/**
 * @brief Get the OID from a plugin filename.
 *
 * @param filename      Filename to lookup.
 *
 * @return OID matching filename if found, NULL otherwise.
 */
char *
nvticache_get_oid (const char *filename)
{
  char *ret, pattern[2048];
  struct kb_item *kbi;

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "name:%s:oid", filename);
  ret = kb_item_get_str (cache_kb, pattern);
  if (ret)
    return ret;

  /* NVT filename in subfolder case. */
  g_snprintf (pattern, sizeof (pattern), "name:*/%s:oid", filename);
  kbi = kb_item_get_pattern (cache_kb, pattern);
  if (!kbi)
    return NULL;

  ret = g_strdup (kbi->v_str);
  kb_item_free (kbi);
  return ret;
}

/**
 * @brief Get the Required Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_required_keys (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:required_keys", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Mandatory Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Mandatory Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_mandatory_keys (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:mandatory_keys", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Excluded Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Excluded Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_excluded_keys (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:excluded_keys", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Required udp ports from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required udp ports matching OID, NULL otherwise.
 */
char *
nvticache_get_required_udp_ports (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:required_udp_ports", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Required ports from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required ports matching OID, NULL otherwise.
 */
char *
nvticache_get_required_ports (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:required_ports", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Dependencies from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Dependencies matching OID, NULL otherwise.
 */
char *
nvticache_get_dependencies (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:dependencies", oid);
  return kb_item_get_str (cache_kb, pattern);
}

/**
 * @brief Get the Category from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Category matching OID, -1 otherwise.
 */
int
nvticache_get_category (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:category", oid);
  return kb_item_get_int (cache_kb, pattern);
}

/**
 * @brief Get the Timeout from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Timeout matching OID, -1 otherwise.
 */
int
nvticache_get_timeout (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:timeout", oid);
  return kb_item_get_int (cache_kb, pattern);
}

/**
 * @brief Get the list of nvti filenames.
 *
 * @return Filenames list.
 */
GSList *
nvticache_get_names ()
{
  struct kb_item *kbi, *item;
  GSList *list = NULL;

  assert (cache_kb);

  kbi = item = kb_item_get_pattern (cache_kb, "oid:*:name");
  if (!kbi)
    return NULL;

  while (item)
    {
      list = g_slist_prepend (list, g_strdup (item->v_str));
      item = item->next;
    }
  kb_item_free (kbi);
  return list;
}

/**
 * @brief Get the list of nvti OIDs.
 *
 * @return OIDs list.
 */
GSList *
nvticache_get_oids ()
{
  struct kb_item *kbi, *item;
  GSList *list = NULL;

  assert (cache_kb);

  kbi = item = kb_item_get_pattern (cache_kb, "name:*:oid");
  if (!kbi)
    return NULL;

  while (item)
    {
      list = g_slist_prepend (list, g_strdup (item->v_str));
      item = item->next;
    }
  kb_item_free (kbi);
  return list;
}
