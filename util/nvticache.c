/* gvm-libs/util
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

#undef  G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  nvticache"

char *src_path = NULL;      /* The directory of the source files. */
kb_t cache_kb = NULL;
int cache_saved = 1;

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
 * @param src           The directory that contains the nvt files.
 * @param kb_path       Path to kb socket.
 */
int
nvticache_init (const char *src, const char *kb_path)
{
  assert (!cache_kb);
  assert (src);

  src_path = g_strdup (src);
  cache_kb = kb_find (kb_path, "nvticache");
  if (cache_kb)
    return 0;

  if (kb_new (&cache_kb, kb_path) || kb_item_set_int (cache_kb, "nvticache", 1))
    return -1;
  return 0;
}

/**
 * @brief Free the nvti cache.
 */
void
nvticache_free (void)
{
  g_free (src_path);
  kb_delete (cache_kb);
  cache_kb = NULL;
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
 * @brief Save the nvticache to disk.
 */
void
nvticache_save ()
{
  if (cache_kb && !cache_saved)
    {
      kb_save (cache_kb);
      cache_saved = 1;
    }
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
  char *oid, pattern[2048], *dummy;
  GSList *element;

  assert (cache_kb);
  /* Check for duplicate OID. */
  oid = nvti_oid (nvti);
  g_snprintf (pattern, sizeof (pattern), "oid:%s:filename", oid);
  dummy = kb_item_get_str (cache_kb, pattern);
  if (dummy && strcmp (filename, dummy))
    g_warning ("NVT %s with duplicate OID %s will be replaced with %s",
               dummy, oid, filename);
  g_free (dummy);
  g_snprintf (pattern, sizeof (pattern), "oid:%s:*", oid);
  kb_del_items (cache_kb, pattern);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:filename", oid);
  if (kb_item_add_str (cache_kb, pattern, filename, 0))
    goto kb_fail;
  if (nvti_required_keys (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_keys (nvti), 0))
        goto kb_fail;
    }
  if (nvti_mandatory_keys (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:mandatory_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_mandatory_keys (nvti), 0))
        goto kb_fail;
    }
  if (nvti_excluded_keys (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:excluded_keys", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_excluded_keys (nvti), 0))
        goto kb_fail;
    }
  if (nvti_required_udp_ports (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_udp_ports", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_udp_ports (nvti), 0))
        goto kb_fail;
    }
  if (nvti_required_ports (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:required_ports", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_required_ports (nvti), 0))
        goto kb_fail;
    }
  if (nvti_dependencies (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:dependencies", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_dependencies (nvti), 0))
        goto kb_fail;
    }
  if (nvti_tag (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:tags", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_tag (nvti), 0))
        goto kb_fail;
    }
  if (nvti_cve (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:cves", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_cve (nvti), 0))
        goto kb_fail;
    }
  if (nvti_bid (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:bids", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_bid (nvti), 0))
        goto kb_fail;
    }
  if (nvti_xref (nvti))
    {
      g_snprintf (pattern, sizeof (pattern), "oid:%s:xrefs", oid);
      if (kb_item_add_str (cache_kb, pattern, nvti_xref (nvti), 0))
        goto kb_fail;
    }
  g_snprintf (pattern, sizeof (pattern), "oid:%s:category", oid);
  if (kb_item_add_int (cache_kb, pattern, nvti_category (nvti)))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:timeout", oid);
  if (kb_item_add_int (cache_kb, pattern, nvti_timeout (nvti)))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:family", oid);
  if (kb_item_add_str (cache_kb, pattern, nvti_family (nvti), 0))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:copyright", oid);
  if (kb_item_add_str (cache_kb, pattern, nvti_copyright (nvti), 0))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:name", oid);
  if (kb_item_add_str (cache_kb, pattern, nvti_name (nvti), 0))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "oid:%s:version", oid);
  if (kb_item_add_str (cache_kb, pattern, nvti_version (nvti), 0))
    goto kb_fail;
  g_snprintf (pattern, sizeof (pattern), "filename:%s:oid", filename);
  if (kb_item_set_str (cache_kb, pattern, oid, 0))
    goto kb_fail;
  element = nvti->prefs;
  while (element)
    {
      char value[4096];
      nvtpref_t *pref = element->data;

      g_snprintf (pattern, sizeof (pattern), "oid:%s:prefs", oid);
      g_snprintf (value, sizeof (value), "%s|||%s|||%s", pref->name, pref->type,
                  pref->dflt);
      if (kb_item_add_str (cache_kb, pattern, value, 0))
        goto kb_fail;
      element = element->next;
    }
  g_snprintf (pattern, sizeof (pattern), "filename:%s:timestamp", filename);
  if (kb_item_set_int (cache_kb, pattern, time (NULL)))
    goto kb_fail;
  cache_saved = 0;

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
  char *filename, *src, pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:filename", oid);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:filename", oid);
  return kb_item_get_str (cache_kb, pattern);
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
 * @brief Get the name from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Name matching OID, NULL otherwise.
 */
char *
nvticache_get_name (const char *oid)
{
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:name", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:version", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:copyright", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:cves", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:bids", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:xrefs", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:family", oid);
  return kb_item_get_str (cache_kb, pattern);
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
  char pattern[2048];

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:tags", oid);
  return kb_item_get_str (cache_kb, pattern);
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
