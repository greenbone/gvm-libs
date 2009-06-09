/* openvas-libraries/libopenvascommon
 * $Id$
 * Description: Implementation of API to handle NVT Info datasets
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Matthew Mundell <matt@mundell.ukfsn.org>
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
 * @file nvti.c
 * @brief Implementation of API to handle NVT Info datasets
 *
 * This file contains all methods to handle NVT Information datasets
 * (nvti_t).
 *
 * The module consequently uses glib datatypes and api for memory
 * management etc.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include "nvti.h"

/**
 * @brief Create a new nvtpref structure filled with the given values.
 *
 * @param name The name to be set. A copy will created of this.
 *
 * @param type The type to be set. A copy will created of this.
 *
 * @param dflt The default to be set. A copy will created of this.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else a nvtpref structure which needs to be
 *         released using @ref nvtpref_free .
 */
nvtpref_t *
nvtpref_new (gchar * name, gchar * type, gchar * dflt)
{
  nvtpref_t * np = g_malloc0 (sizeof (nvtpref_t));

  if (! np) return NULL;

  if (name) np->name = g_strdup (name);
  if (type) np->type = g_strdup (type);
  if (dflt) np->dflt = g_strdup (dflt);

  return (np);
}

/**
 * @brief Free memory of a nvtpref structure.
 *
 * @param n The structure to be freed.
 */
void
nvtpref_free (nvtpref_t * np)
{
  if (np->name) g_free (np->name);
  if (np->type) g_free (np->type);
  if (np->dflt) g_free (np->dflt);
  g_free (np);
}

/**
 * @brief Get the Name of a NVT Preference.
 *
 * @param np The NVT Pref structure of which the Name should
 *           be returned.
 *
 * @return The name string. Don't free this.
 */
gchar *
nvtpref_name (const nvtpref_t * np)
{
  return (np->name);
}

/**
 * @brief Get the Type of a NVT Preference.
 *
 * @param np The NVT Pref structure of which the Type should
 *           be returned.
 *
 * @return The type string. Don't free this.
 */
gchar *
nvtpref_type (const nvtpref_t * np)
{
  return (np->type);
}

/**
 * @brief Get the Default of a NVT Preference.
 *
 * @param np The NVT Pref structure of which the Default should
 *           be returned.
 *
 * @return The default string. Don't free this.
 */
gchar *
nvtpref_default (const nvtpref_t * np)
{
  return (np->dflt);
}

/**
 * @brief Create a new (empty) nvti structure.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else an empty nvti structure which needs to be
 *         released using @ref nvti_free .
 *         The whole struct is initalized with 0's.
 */
nvti_t *
nvti_new (void)
{
  return ((nvti_t *) g_malloc0 (sizeof (nvti_t)));
}

/**
 * @brief Free memory of a nvti structure.
 *
 * @param n The structure to be freed.
 */
void
nvti_free (nvti_t * n)
{
  if (n->oid) g_free (n->oid);
  if (n->version) g_free (n->version);
  if (n->name) g_free (n->name);
  if (n->summary) g_free (n->summary);
  if (n->description) g_free (n->description);
  if (n->copyright) g_free (n->copyright);
  if (n->cve) g_free (n->cve);
  if (n->bid) g_free (n->bid);
  if (n->xref) g_free (n->xref);
  if (n->tag) g_free (n->tag);
  if (n->dependencies) g_free (n->dependencies);
  if (n->required_keys) g_free (n->required_keys);
  if (n->excluded_keys) g_free (n->excluded_keys);
  if (n->required_ports) g_free (n->required_ports);
  if (n->required_udp_ports) g_free (n->required_udp_ports);
  if (n->sign_key_ids) g_free (n->sign_key_ids);
  if (n->family) g_free (n->family);
  if (n->src) g_free (n->src);
  if (n->prefs) {
    guint len = g_slist_length(n->prefs);
    int i;
    for (i = 0;i < len;i ++)
      nvtpref_free(g_slist_nth_data(n->prefs, i));
    g_slist_free(n->prefs);
  }
  g_free (n);
}

/**
 * @brief Get the OID string.
 *
 * @param n The NVT Info structure of which the OID should
 *          be returned.
 *
 * @return The OID string. Don't free this.
 */
gchar *
nvti_oid (const nvti_t * n)
{
  return (n->oid);
}

/**
 * @brief Get the version.
 *
 * @param n The NVT Info structure of which the OID should
 *          be returned.
 *
 * @return The version string. Don't free this.
 */
gchar *
nvti_version (const nvti_t * n)
{
  return (n->version);
}

/**
 * @brief Get the name.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The name string. Don't free this.
 */
gchar *
nvti_name (const nvti_t * n)
{
  return (n->name);
}

/**
 * @brief Get the summary.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The summary string. Don't free this.
 */
gchar *
nvti_summary (const nvti_t * n)
{
  return (n->summary);
}

/**
 * @brief Get the description.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The description string. Don't free this.
 */
gchar *
nvti_description (const nvti_t * n)
{
  return (n->description);
}

/**
 * @brief Get the copyright notice.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The copyright string. Don't free this.
 */
gchar *
nvti_copyright (const nvti_t * n)
{
  return (n->copyright);
}

/**
 * @brief Get the CVE references.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The CVE list as string. Don't free this.
 */
gchar *
nvti_cve (const nvti_t * n)
{
  return (n->cve);
}

/**
 * @brief Get the bid references.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The bid list as string. Don't free this.
 */
gchar *
nvti_bid (const nvti_t * n)
{
  return (n->bid);
}

/**
 * @brief Get the xref's.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The xref string. Don't free this.
 */
gchar *
nvti_xref (const nvti_t * n)
{
  return (n->xref);
}

/**
 * @brief Get the tag.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The tags string. Don't free this.
 */
gchar *
nvti_tag (const nvti_t * n)
{
  return (n->tag);
}

/**
 * @brief Get the dependencies list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The dependencies string. Don't free this.
 */
gchar *
nvti_dependencies (const nvti_t * n)
{
  return (n->dependencies);
}

/**
 * @brief Get the required keys list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The required keys string. Don't free this.
 */
gchar *
nvti_required_keys (const nvti_t * n)
{
  return (n->required_keys);
}

/**
 * @brief Get the excluded keys list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The excluded keys string. Don't free this.
 */
gchar *
nvti_excluded_keys (const nvti_t * n)
{
  return (n->excluded_keys);
}

/**
 * @brief Get the required ports list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The required ports string. Don't free this.
 */
gchar *
nvti_required_ports (const nvti_t * n)
{
  return (n->required_ports);
}

/**
 * @brief Get the required udp ports list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The required udp ports string. Don't free this.
 */
gchar *
nvti_required_udp_ports (const nvti_t * n)
{
  return (n->required_udp_ports);
}

/**
 * @brief Get the sign key ids (fingerptints) list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The sign key ids string. Don't free this.
 */
gchar *
nvti_sign_key_ids (const nvti_t * n)
{
  return (n->sign_key_ids);
}

/**
 * @brief Get the family name.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The family name string. Don't free this.
 */
gchar *
nvti_family (const nvti_t * n)
{
  return (n->family);
}

/**
 * @brief Get the number of preferences of the NVT.
 *
 * @param n The NVT Info structure.
 *
 * @return The number of preferences.
 */
guint
nvti_pref_len (const nvti_t * n)
{
  return(g_slist_length(n->prefs));
}

/**
 * @brief Get the n'th preferences of the NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param p The position of the preference to return.
 *
 * @return The number of preferences. NULL if 
 */
nvtpref_t *
nvti_pref (const nvti_t * n, guint p)
{
  return(g_slist_nth_data(n->prefs, p));
}

/**
 * @brief Get the source URI of a NVT Info.
 *
 * @param n The NVT Info structure of which the source URI should
 *          be returned.
 *
 * @return The source URI string. This can be NULL if the NVT
 *         Info was created in memory. It can also be a file path.
 *         Don't free this.
 */
gchar *
nvti_src (const nvti_t * n)
{
  return (n->src);
}

/**
 * @brief Get the timeout for this NVT.
 *
 * @param n The NVT Info structure of which the timeout should
 *          be returned.
 *
 * @return The timeout integer number. A value <= 0 indicates it is not set.
 */
gint
nvti_timeout (const nvti_t * n)
{
  return (n->timeout);
}

/**
 * @brief Get the category for this NVT.
 *
 * @param n The NVT Info structure of which the timeout should
 *          be returned.
 *
 * @return The category integer code. A value <= 0 indicates it is not set.
 */
gint
nvti_category (const nvti_t * n)
{
  return (n->category);
}

/**
 * @brief Set the OID of a NVT Info.
 *
 * @param n The NVT Info structure.
 *
 * @param oid The OID to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_oid (nvti_t * n, const gchar * oid)
{
  if (n->oid)
    g_free (n->oid);
  n->oid = g_strdup (oid);
  return (0);
}

/**
 * @brief Set the version of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param version The version to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_version (nvti_t * n, const gchar * version)
{
  if (n->version)
    g_free (n->version);
  n->version = g_strdup (version);
  return (0);
}

/**
 * @brief Set the name of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param name The name to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_name (nvti_t * n, const gchar * name)
{
  if (n->name)
    g_free (n->name);
  n->name = g_strdup (name);
  return (0);
}

/**
 * @brief Set the summary of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param summary The summary to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_summary (nvti_t * n, const gchar * summary)
{
  if (n->summary)
    g_free (n->summary);
  n->summary = g_strdup (summary);
  return (0);
}

/**
 * @brief Set the description of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param description The description to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_description (nvti_t * n, const gchar * description)
{
  if (n->description)
    g_free (n->description);
  n->description = g_strdup (description);
  return (0);
}

/**
 * @brief Set the copyright of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param copyright The copyright to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_copyright (nvti_t * n, const gchar * copyright)
{
  if (n->copyright)
    g_free (n->copyright);
  n->copyright = g_strdup (copyright);
  return (0);
}

/**
 * @brief Set the CVE references of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param cve The cve list to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_cve (nvti_t * n, const gchar * cve)
{
  if (n->cve)
    g_free (n->cve);
  n->cve = g_strdup (cve);
  return (0);
}

/**
 * @brief Set the bid references of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param bid The bid to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_bid (nvti_t * n, const gchar * bid)
{
  if (n->bid)
    g_free (n->bid);
  n->bid = g_strdup (bid);
  return (0);
}

/**
 * @brief Set the xrefs of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param xref The xrefs to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_xref (nvti_t * n, const gchar * xref)
{
  if (n->xref)
    g_free (n->xref);
  if (xref && xref[0])
    n->xref = g_strdup (xref);
  else
    n->xref = NULL;
  return (0);
}

/**
 * @brief Set the tags of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param tag The tags to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_tag (nvti_t * n, const gchar * tag)
{
  if (n->tag)
    g_free (n->tag);
  if (tag && tag[0])
    n->tag = g_strdup (tag);
  else
    n->tag = NULL;
  return (0);
}

/**
 * @brief Set the dependencies of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param dependencies The dependencies to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_dependencies (nvti_t * n, const gchar * dependencies)
{
  if (n->dependencies)
    g_free (n->dependencies);
  if (dependencies && dependencies[0])
    n->dependencies = g_strdup (dependencies);
  else
    n->dependencies = NULL;
  return (0);
}

/**
 * @brief Set the required keys of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param required_keys The required keys to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_keys (nvti_t * n, const gchar * required_keys)
{
  if (n->required_keys)
    g_free (n->required_keys);
  if (required_keys && required_keys[0])
    n->required_keys = g_strdup (required_keys);
  else
    n->required_keys = NULL;
  return (0);
}

/**
 * @brief Set the excluded keys of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param excluded_keys The excluded keys to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_excluded_keys (nvti_t * n, const gchar * excluded_keys)
{
  if (n->excluded_keys)
    g_free (n->excluded_keys);
  if (excluded_keys && excluded_keys[0])
    n->excluded_keys = g_strdup (excluded_keys);
  else
    n->excluded_keys = NULL;
  return (0);
}

/**
 * @brief Set the required ports of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param required_ports The required ports to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_ports (nvti_t * n, const gchar * required_ports)
{
  if (n->required_ports)
    g_free (n->required_ports);
  if (required_ports && required_ports[0])
    n->required_ports = g_strdup (required_ports);
  else
    n->required_ports = NULL;
  return (0);
}

/**
 * @brief Set the required udp ports of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param required_udp_ports The required udp ports to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_udp_ports (nvti_t * n, const gchar * required_udp_ports)
{
  if (n->required_udp_ports)
    g_free (n->required_udp_ports);
  if (required_udp_ports && required_udp_ports[0])
    n->required_udp_ports = g_strdup (required_udp_ports);
  else
    n->required_udp_ports = NULL;
  return (0);
}

/**
 * @brief Set the sign key ids of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param sign_key_ids The sign key ids to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_sign_key_ids (nvti_t * n, const gchar * sign_key_ids)
{
  if (n->sign_key_ids)
    g_free (n->sign_key_ids);
  if (sign_key_ids && sign_key_ids[0])
    n->sign_key_ids = g_strdup (sign_key_ids);
  else
    n->sign_key_ids = NULL;
  return (0);
}

/**
 * @brief Set the family of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param family The family to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_family (nvti_t * n, const gchar * family)
{
  if (n->family)
    g_free (n->family);
  n->family = g_strdup (family);
  return (0);
}

/**
 * @brief Set the source identifier for the acutal NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param src The URI to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_src (nvti_t * n, const gchar * src)
{
  if (n->src)
    g_free (n->src);
  n->src = g_strdup (src);
  return (0);
}

/**
 * @brief Set the timout of a NVT Info.
 *
 * @param n The NVT Info structure.
 *
 * @param timout The timeout to set. Values <= 0 will indicate it is not set.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_timeout (nvti_t * n, const gint timeout)
{
  n->timeout = timeout;
  return (0);
}

/**
 * @brief Set the category type of a NVT Info.
 *
 * @param n The NVT Info structure.
 *
 * @param category The category to set. Values <= 0 will indicate it is not set.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_category (nvti_t * n, const gint category)
{
  n->category = category;
  return (0);
}

/**
 * @brief Add a preference to the NVT Info.
 *
 * @param n The NVT Info structure.
 *
 * @param np The NVT preference to add.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_add_pref (nvti_t * n, nvtpref_t * np)
{
  n->prefs = g_slist_append(n->prefs, np);
  return (0);
}

/**
 * @brief Create a human readable text representation of a NVT Info.
 *        This is mainly for debug purposes.
 *
 * @param n The NVT Info structure.
 *
 * @return A newly allocated string with multi-line text.
 *         The string needs to be freed with g_free().
 */
gchar *
nvti_as_text (const nvti_t * n)
{
  return (g_strconcat
          ("NVT Info for OID ", (n->oid ? n->oid : "(unset)"), ":\n\n",
           "\nVersion: ", (n->version ? n->version : "(unset, probably in-memory)"),
           "\nName: ", (n->name ? n->name : "(unset, probably in-memory)"),
           "\nSummary: ", (n->summary ? n->summary : "(unset, probably in-memory)"),
           "\nDescription: ", (n->description ? n->description : "(unset, probably in-memory)"),
           "\nCopyright: ", (n->copyright ? n->copyright : "(unset, probably in-memory)"),
           "\nCVE: ", (n->cve ? n->cve : "(unset, probably in-memory)"),
           "\nBID: ", (n->bid ? n->bid : "(unset, probably in-memory)"),
           "\nXref: ", (n->xref ? n->xref : "(unset, probably in-memory)"),
           "\nTag: ", (n->tag ? n->tag : "(unset, probably in-memory)"),
           "\nDependencies: ", (n->dependencies ? n->dependencies : "(unset, probably in-memory)"),
           "\nRequired Keys: ", (n->required_keys ? n->required_keys : "(unset, probably in-memory)"),
           "\nExcluded Keys: ", (n->excluded_keys ? n->excluded_keys : "(unset, probably in-memory)"),
           "\nRequired Ports: ", (n->required_ports ? n->required_ports : "(unset, probably in-memory)"),
           "\nRequired UDP ports: ", (n->required_udp_ports ? n->required_udp_ports : "(unset, probably in-memory)"),
           "\nSignKey IDs: ", (n->sign_key_ids ? n->sign_key_ids : "(unset, probably in-memory)"),
           "\nFamily: ", (n->family ? n->family : "(unset, probably in-memory)"),
           "\nSource: ", (n->src ? n->src : "(unset, probably in-memory)"),
//         "\nTimeout: ", (n->timeout <= 0 ? n->timeout : "(unset, probably in-memory)"),
//         "\nCategory: ", (n->category <= 0 ? n->category : "(unset, probably in-memory)"),
           "\n", NULL));
}

/**
 * @brief Create a single line representation of a NVT Info as
 *        used in "openvas_nvt_cache" files of OpenVAS-Client.
 *
 * @param n The NVT Info structure.
 *
 * @return A newly allocated string.
 *         The string needs to be freed with g_free().
 */
gchar *
nvti_as_openvas_nvt_cache_entry (const nvti_t * n)
{
  return (NULL);        // not implemented yet
}

/**
 * @brief Read NVT Info from a keyfile.
 *
 * @param fn The filename to read from.
 *
 * @return A newly allocated nvti_t object.
 *         The nvti_t needs to be freed with nvti_free().
 */
nvti_t *
nvti_from_keyfile (const gchar * fn)
{
  GKeyFile *keyfile = g_key_file_new ();
  nvti_t *n;
  GError *error = NULL;
  gchar **keys;
  int i;

  if (!g_key_file_load_from_file (keyfile, fn, G_KEY_FILE_NONE, &error))
    {
      g_error (error->message);
      return NULL;
    }

  n = nvti_new ();
  nvti_set_oid (n, g_key_file_get_string (keyfile, "NVT Info", "OID", NULL));
  nvti_set_version (n, g_key_file_get_string (keyfile, "NVT Info", "Version", NULL));
  nvti_set_name (n, g_key_file_get_string (keyfile, "NVT Info", "Name", NULL));
  nvti_set_summary (n, g_key_file_get_string (keyfile, "NVT Info", "Summary", NULL));
  nvti_set_description (n, g_key_file_get_string (keyfile, "NVT Info", "Description", NULL));
  nvti_set_copyright (n, g_key_file_get_string (keyfile, "NVT Info", "Copyright", NULL));
  nvti_set_cve (n, g_key_file_get_string (keyfile, "NVT Info", "CVEs", NULL));
  nvti_set_bid (n, g_key_file_get_string (keyfile, "NVT Info", "BIDs", NULL));
  nvti_set_xref (n, g_key_file_get_string (keyfile, "NVT Info", "XREFs", NULL));
  nvti_set_tag (n, g_key_file_get_string (keyfile, "NVT Info", "Tags", NULL));
  nvti_set_dependencies (n, g_key_file_get_string (keyfile, "NVT Info", "Dependencies", NULL));
  nvti_set_required_keys (n, g_key_file_get_string (keyfile, "NVT Info", "RequiredKeys", NULL));
  nvti_set_excluded_keys (n, g_key_file_get_string (keyfile, "NVT Info", "ExcludedKeys", NULL));
  nvti_set_required_ports (n, g_key_file_get_string (keyfile, "NVT Info", "RequiredPorts", NULL));
  nvti_set_required_udp_ports (n, g_key_file_get_string (keyfile, "NVT Info", "RequiredUDPPorts", NULL));
  nvti_set_sign_key_ids (n, g_key_file_get_string (keyfile, "NVT Info", "SignKeyIDs", NULL));
  nvti_set_family (n, g_key_file_get_string (keyfile, "NVT Info", "Family", NULL));
  nvti_set_src (n, g_key_file_get_string (keyfile, "NVT Info", "src", NULL));
  nvti_set_timeout (n, g_key_file_get_integer (keyfile, "NVT Info", "Timeout", NULL));
  nvti_set_category (n, g_key_file_get_integer (keyfile, "NVT Info", "Category", NULL));

  if (g_key_file_has_group(keyfile, "NVT Prefs")) {
    keys = g_key_file_get_keys(keyfile, "NVT Prefs", NULL, NULL);
    for (i = 0;keys[i];i ++) {
      gsize len;
      gchar ** items = g_key_file_get_string_list(keyfile, "NVT Prefs", keys[i], &len, NULL);
      if (len != 3) continue; // format error for this pref.
      nvtpref_t *np = nvtpref_new(items[0], items[1], items[2]);
      nvti_add_pref(n, np);
      g_strfreev(items);
    }
    g_strfreev(keys);
  }

  g_key_file_free (keyfile);

  return (n);
}

/**
 * @brief Store NVT Info into a keyfile.
 *
 * @param n The NVT Info object to store.
 *
 * @param fn The filename to write to.
 *
 * @return 0 on success. @TODO Anything else indicates an error.
 */
int
nvti_to_keyfile (const nvti_t * n, const gchar * fn)
{
  GKeyFile *keyfile = g_key_file_new ();
  gchar *text;
  GError *error = NULL;

  if (n->oid)
    g_key_file_set_string (keyfile, "NVT Info", "OID", n->oid);
  if (n->version)
    g_key_file_set_string (keyfile, "NVT Info", "Version", n->version);
  if (n->name)
    g_key_file_set_string (keyfile, "NVT Info", "Name", n->name);
  if (n->summary)
    g_key_file_set_string (keyfile, "NVT Info", "Summary", n->summary);
  if (n->description)
    g_key_file_set_string (keyfile, "NVT Info", "Description", n->description);
  if (n->copyright)
    g_key_file_set_string (keyfile, "NVT Info", "Copyright", n->copyright);
  if (n->cve)
    g_key_file_set_string (keyfile, "NVT Info", "CVEs", n->cve);
  if (n->bid)
    g_key_file_set_string (keyfile, "NVT Info", "BIDs", n->bid);
  if (n->xref)
    g_key_file_set_string (keyfile, "NVT Info", "XREFs", n->xref);
  if (n->tag)
    g_key_file_set_string (keyfile, "NVT Info", "Tags", n->tag);
  if (n->dependencies)
    g_key_file_set_string (keyfile, "NVT Info", "Dependencies", n->dependencies);
  if (n->required_keys)
    g_key_file_set_string (keyfile, "NVT Info", "RequiredKeys", n->required_keys);
  if (n->excluded_keys)
    g_key_file_set_string (keyfile, "NVT Info", "ExcludedKeys", n->excluded_keys);
  if (n->required_ports)
    g_key_file_set_string (keyfile, "NVT Info", "RequiredPorts", n->required_ports);
  if (n->required_udp_ports)
    g_key_file_set_string (keyfile, "NVT Info", "RequiredUDPPorts", n->required_udp_ports);
  if (n->sign_key_ids)
    g_key_file_set_string (keyfile, "NVT Info", "SignKeyIDs", n->sign_key_ids);
  if (n->family)
    g_key_file_set_string (keyfile, "NVT Info", "Family", n->family);
  if (n->src)
    g_key_file_set_string (keyfile, "NVT Info", "src", n->src);
  if (n->timeout > 0)
    g_key_file_set_integer (keyfile, "NVT Info", "Timeout", n->timeout);
  if (n->category > 0)
    g_key_file_set_integer (keyfile, "NVT Info", "Category", n->category);

  int i;
  for (i=0;i < nvti_pref_len(n);i ++) {
    nvtpref_t * np = nvti_pref(n, i);
    gchar * lst[3];
    gchar buf[10];
    lst[0] = ((nvtpref_t *)np)->name;
    lst[1] = ((nvtpref_t *)np)->type;
    lst[2] = ((nvtpref_t *)np)->dflt;

    g_snprintf(buf, 10, "P%d", i);
    g_key_file_set_string_list((GKeyFile *)keyfile, "NVT Prefs", buf, (const gchar **)lst, 3);
//    g_key_file_set_string_list((GKeyFile *)keyfile, "NVT Prefs", (gchar *)lst[0], (const gchar **)lst, 3);
  }

  text = g_key_file_to_data (keyfile, NULL, &error);
  if (error != NULL)
    {
      fprintf (stderr, "Error occured while preparing %s: %s\n",
               fn, error->message);
      g_error_free (error);
    }
  else
    {
      FILE *fp = fopen (fn, "w");
      if (! fp) { // second try: maybe the directory was missing.
        gchar * cache_dir = g_path_get_dirname(fn);
        if ((mkdir(cache_dir, 0755) < 0) && (errno != EEXIST)) {
          fprintf(stderr, "mkdir(%s) : %s\n", cache_dir, strerror(errno));
          g_free(text);
          g_key_file_free (keyfile);
	  return (1);
        }
        fp = fopen (fn, "w");
      }

      if (! fp) { // again failed
          fprintf(stderr, "fopen(%s) : %s\n", fn, strerror(errno));
          g_free(text);
          g_key_file_free (keyfile);
	  return (2);
      }

      fputs (text, fp);
      fclose (fp);
      g_free(text);
    }

  g_key_file_free (keyfile);

  return (0);
}


/* Collections of nvtis. */

/**
 * @brief Free an NVT Info, for g_hash_table_destroy.
 *
 * @param nvti The NVT Info.
 */
static void
free_nvti_for_hash_table (gpointer nvti)
{
  nvti_free ((nvti_t*) nvti);
}

/**
 * @brief Make a collection of NVT Infos.
 */
nvtis_t*
nvtis_new ()
{
  return g_hash_table_new_full (g_str_hash,
                                g_str_equal,
                                NULL,
                                free_nvti_for_hash_table);
}

/**
 * @brief Free a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 */
void
nvtis_free (nvtis_t* nvtis)
{
  if (nvtis) g_hash_table_destroy (nvtis);
}

/**
 * @brief Get the size of a collection of NVT Infos.
 *
 * @return The number of entries in the collection.
 */
guint
nvtis_size (nvtis_t* nvtis)
{
  return g_hash_table_size (nvtis);
}

/**
 * @brief Add an NVT Info to a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 */
void
nvtis_add (nvtis_t* nvtis, nvti_t* nvti)
{
  if (nvti)
    g_hash_table_insert (nvtis, (gpointer) nvti_oid (nvti), (gpointer) nvti);
}

/**
 * @brief Add an NVT Info to a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 * @param nvtis The OID of the NVT.
 *
 * @return The NVT Info, if found, else NULL.
 */
nvti_t*
nvtis_lookup (nvtis_t* nvtis, const char* oid)
{
  return g_hash_table_lookup (nvtis, oid);
}
