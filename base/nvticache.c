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

#include <string.h> // for strlen
#include <assert.h>
#include <stdlib.h>     /* for atoi */

#undef  G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  nvticache"

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
nvticache_init (const char *src, const char *kb_path)
{
  assert (src);

  if (src_path)
    g_free (src_path);
  src_path = g_strdup (src);
  if (cache_kb)
    kb_lnk_reset (cache_kb);
  cache_kb = kb_find (kb_path, "nvticache");
  if (cache_kb)
    return 0;

  if (kb_new (&cache_kb, kb_path) || kb_item_set_int (cache_kb, "nvticache", 1))
    return -1;
  return 0;
}

/**
 * @brief Return the nvticache kb.
 *
 * @return Cache kb.
 */
kb_t
nvticache_get_kb (void)
{
  assert (cache_kb);
  return cache_kb;
}

/**
 * @brief Check if the nvt for the given filename exists in cache.
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return 1 if nvt is in cache and up to date, 0 otherwise.
 */
int
nvticache_check (const gchar *filename)
{
  assert (cache_kb);
  char pattern[2048], *src_file;
  time_t timestamp;
  struct stat src_stat;

  src_file = g_build_filename (src_path, filename, NULL);
  g_snprintf (pattern, sizeof (pattern), "filename:%s:timestamp", filename);
  timestamp = kb_item_get_int (cache_kb, pattern);
  if (timestamp && src_file && stat (src_file, &src_stat) >= 0
      && timestamp > src_stat.st_mtime)
    {
      g_free (src_file);
      return 1;
    }
  g_free (src_file);
  return 0;
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
  char *oid, *dummy, pattern[4096];
  GSList *element;

  assert (cache_kb);

  /* Check for duplicate OID. */
  oid = nvti_oid (nvti);
  dummy = nvticache_get_filename (oid);
  if (dummy && strcmp (filename, dummy))
    g_warning ("NVT %s with duplicate OID %s will be replaced with %s",
               dummy, oid, filename);
  if (dummy)
    {
      g_snprintf (pattern, sizeof (pattern), "nvt:%s", oid);
      kb_del_items (cache_kb, pattern);
    }

  g_free (dummy);
  if (kb_nvt_add (cache_kb, nvti, filename))
    goto kb_fail;
  element = nvti->prefs;
  while (element)
    {
      char value[4096];
      nvtpref_t *pref = element->data;

      g_snprintf (pattern, sizeof (pattern), "oid:%s:prefs", oid);
      g_snprintf (value, sizeof (value), "%s|||%s|||%s", pref->name, pref->type,
                  pref->dflt);
      if (kb_item_add_str (cache_kb, pattern, value))
        goto kb_fail;
      element = element->next;
    }
  g_snprintf (pattern, sizeof (pattern), "filename:%s:timestamp", filename);
  if (kb_item_set_int (cache_kb, pattern, time (NULL)))
    goto kb_fail;

  return 0;

kb_fail:
  return -1;
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
  char *filename, *src;

  assert (cache_kb);

  filename = kb_nvt_get (cache_kb, oid, NVT_FILENAME_POS);
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

  g_snprintf (pattern, sizeof (pattern), "filename:%s:oid", filename);
  ret = kb_item_get_str (cache_kb, pattern);
  if (ret)
    return ret;

  /* NVT filename in subfolder case. */
  g_snprintf (pattern, sizeof (pattern), "filename:*/%s:oid", filename);
  kbi = kb_item_get_pattern (cache_kb, pattern);
  if (!kbi)
    return NULL;

  ret = g_strdup (kbi->v_str);
  kb_item_free (kbi);
  return ret;
}

/**
 * @brief Get the filename from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Filanem matching OID, NULL otherwise.
 */
char *
nvticache_get_filename (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_FILENAME_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_KEYS_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_MANDATORY_KEYS_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_EXCLUDED_KEYS_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_UDP_PORTS_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_PORTS_POS);
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
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_DEPENDENCIES_POS);
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
  int category;
  char *category_s;

  assert (cache_kb);
  category_s = kb_nvt_get (cache_kb, oid, NVT_CATEGORY_POS);
  category = atoi (category_s);
  g_free (category_s);
  return category;
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
  int timeout;
  char *timeout_s;

  assert (cache_kb);
  timeout_s = kb_nvt_get (cache_kb, oid, NVT_TIMEOUT_POS);
  timeout = atoi (timeout_s);
  g_free (timeout_s);
  return timeout;
}

/**
 * @brief Get the name from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Name matching OID, NULL otherwise.
 */
char *
nvticache_get_name (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_NAME_POS);
}

/**
 * @brief Get the version from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Version matching OID, NULL otherwise.
 */
char *
nvticache_get_version (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_VERSION_POS);
}

/**
 * @brief Get the copyright from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Copyright matching OID, NULL otherwise.
 */
char *
nvticache_get_copyright (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_COPYRIGHT_POS);
}

/**
 * @brief Get the cves from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return CVEs matching OID, NULL otherwise.
 */
char *
nvticache_get_cves (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_CVES_POS);
}

/**
 * @brief Get the bids from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return BIDs matching OID, NULL otherwise.
 */
char *
nvticache_get_bids (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_BIDS_POS);
}

/**
 * @brief Get the xrefs from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return XREFs matching OID, NULL otherwise.
 */
char *
nvticache_get_xrefs (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_XREFS_POS);
}

/**
 * @brief Get the family from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Family matching OID, NULL otherwise.
 */
char *
nvticache_get_family (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_FAMILY_POS);
}

/**
 * @brief Get the tags from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Tags matching OID, NULL otherwise.
 */
char *
nvticache_get_tags (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_TAGS_POS);
}

/**
 * @brief Get the prefs from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Prefs matching OID, NULL otherwise.
 */
GSList *
nvticache_get_prefs (const char *oid)
{
  char pattern[4096];
  struct kb_item *prefs, *element;
  GSList *list = NULL;

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:prefs", oid);
  prefs = element = kb_item_get_all (cache_kb, pattern);
  while (element)
  {
    nvtpref_t *np;
    char **array = g_strsplit (element->v_str, "|||", -1);

    assert (array[2]);
    assert (!array[3]);
    np = g_malloc0 (sizeof (nvtpref_t));
    np->name = array[0];
    np->type = array[1];
    np->dflt = array[2];
    list = g_slist_append (list, np);
    element = element->next;
  }
  kb_item_free (prefs);

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

  kbi = item = kb_item_get_pattern (cache_kb, "filename:*:oid");
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
