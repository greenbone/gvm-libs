/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

//  One of the files of gvm-libs needs to specify the meta data
//  for the doxygen documentation.

/**
 * \mainpage
 *
 * \section Introduction
 * \verbinclude README.md
 *
 * \section Installation
 * \verbinclude INSTALL.md
 *
 * \section copying License
 * \verbinclude COPYING
 */

/**
 * @file
 * @brief Implementation of API to handle NVT Info datasets
 *
 * This file contains all methods to handle NVT Information datasets
 * (nvti_t).
 *
 * The module consequently uses glib datatypes and api for memory
 * management etc.
 */

#include "nvti.h"

#include <stdio.h>
#include <string.h> // for strcmp

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  nvti"

/* VT references */

/**
 * @brief Create a new vtref structure filled with the given values.
 *
 * @param type The type to be set. A copy will created of this.
 *
 * @param ref_id The actual reference to be set. A copy will created of this.
 *
 * @param ref_text The optional text accompanying a reference. A copy will created of this.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else a vtref structure which needs to be
 *         released using @ref vtref_free .
 */
vtref_t *
vtref_new (gchar *type, gchar *ref_id, gchar *ref_text)
{
  vtref_t *ref = g_malloc0 (sizeof (vtref_t));

  if (!ref)
    return NULL;

  if (type)
    ref->type = g_strdup (type);
  if (ref_id)
    ref->ref_id = g_strdup (ref_id);
  if (ref_text)
    ref->ref_text = g_strdup (ref_text);

  return (ref);
}

/**
 * @brief Free memory of a vtref structure.
 *
 * @param np The structure to be freed.
 */
void
vtref_free (vtref_t *ref)
{
  if (!ref)
    return;

  g_free (ref->type);
  g_free (ref->ref_id);
  g_free (ref->ref_text);
  g_free (ref);
}

/**
 * @brief Add a reference to the VT Info.
 *
 * @param vt  The VT Info structure.
 *
 * @param ref The VT reference to add.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_add_ref (nvti_t *vt, vtref_t *ref)
{
  if (!vt)
    return (-1);

  vt->refs = g_slist_append (vt->refs, ref);
  return (0);
}

/* VT preferences */

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
nvtpref_new (int id, gchar *name, gchar *type, gchar *dflt)
{
  nvtpref_t *np = g_malloc0 (sizeof (nvtpref_t));

  if (!np)
    return NULL;

  np->id = id;
  if (name)
    np->name = g_strdup (name);
  if (type)
    np->type = g_strdup (type);
  if (dflt)
    np->dflt = g_strdup (dflt);

  return (np);
}

/**
 * @brief Free memory of a nvtpref structure.
 *
 * @param np The structure to be freed.
 */
void
nvtpref_free (nvtpref_t *np)
{
  if (!np)
    return;

  g_free (np->name);
  g_free (np->type);
  g_free (np->dflt);
  g_free (np);
}

/**
 * @brief Get the ID of a NVT Preference.
 *
 * @param np The NVT Pref structure of which the Name should
 *           be returned.
 *
 * @return The ID value.
 */
int
nvtpref_id (const nvtpref_t *np)
{
  return np ? np->id : -1;
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
nvtpref_name (const nvtpref_t *np)
{
  return (np ? np->name : NULL);
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
nvtpref_type (const nvtpref_t *np)
{
  return (np ? np->type : NULL);
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
nvtpref_default (const nvtpref_t *np)
{
  return (np ? np->dflt : NULL);
}

/**
 * @brief Create a new (empty) nvti structure.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else an empty nvti structure which needs to be
 *         released using @ref nvti_free .
 *         The whole struct is initialized with 0's.
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
nvti_free (nvti_t *n)
{
  if (!n)
    return;

  g_free (n->oid);
  g_free (n->name);
  g_free (n->tag);
  g_free (n->cvss_base);
  g_free (n->dependencies);
  g_free (n->required_keys);
  g_free (n->mandatory_keys);
  g_free (n->excluded_keys);
  g_free (n->required_ports);
  g_free (n->required_udp_ports);
  g_free (n->family);
  g_slist_free_full (n->refs, (void (*) (void *)) vtref_free);
  g_slist_free_full (n->prefs, (void (*) (void *)) nvtpref_free);
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
nvti_oid (const nvti_t *n)
{
  return (n ? n->oid : NULL);
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
nvti_name (const nvti_t *n)
{
  return (n ? n->name : NULL);
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
nvti_cve (const nvti_t *n)
{
  // @todo: actually, the returned string now needs to be free'd
  gchar *cves, *cves2;
  vtref_t * ref;
  guint i;

  if (! n) return (NULL);

  for (i = 0; i < g_slist_length (n->refs); i ++)
    {
      ref = g_slist_nth_data (n->refs, i);
      if (strcmp (ref->type, "cve") == 0)
        {
          if (cves)
            cves2 = g_strdup_printf ("%s,%s", cves, ref->ref_id);
	  else
            cves2 = g_strdup_printf ("%s", ref->ref_id);
	  g_free (cves);
	  cves = cves2;
        }
    }

  return (cves);
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
nvti_bid (const nvti_t *n)
{
  gchar *bids, *bids2;
  vtref_t * ref;
  guint i;

  if (! n) return (NULL);

  for (i = 0; i < g_slist_length (n->refs); i ++)
    {
      ref = g_slist_nth_data (n->refs, i);
      if (strcmp (ref->type, "bid") == 0)
        {
          if (bids)
            bids2 = g_strdup_printf ("%s,%s", bids, ref->ref_id);
	  else
            bids2 = g_strdup_printf ("%s", ref->ref_id);
	  g_free (bids);
	  bids = bids2;
        }
    }

  return (bids);
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
nvti_xref (const nvti_t *n)
{
  gchar *xrefs, *xrefs2;
  vtref_t * ref;
  guint i;

  if (! n) return (NULL);

  for (i = 0; i < g_slist_length (n->refs); i ++)
    {
      ref = g_slist_nth_data (n->refs, i);
      if ((strcmp (ref->type, "cve") != 0) &&
          (strcmp (ref->type, "bid") != 0))
        { // if it is neither cve nor bid, then it is some xref
          if (xrefs)
            xrefs2 = g_strdup_printf ("%s,%s:%s", xrefs, ref->type, ref->ref_id);
	  else
            xrefs2 = g_strdup_printf ("%s:%s", ref->type, ref->ref_id);
	  g_free (xrefs);
	  xrefs = xrefs2;
        }
    }

  return (xrefs);
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
nvti_tag (const nvti_t *n)
{
  return (n ? n->tag : NULL);
}

/**
 * @brief Get the CVSS base.
 *
 * @param n The NVT Info structure of which the CVSS base should
 *          be returned.
 *
 * @return The cvss_base string. Don't free this.
 */
gchar *
nvti_cvss_base (const nvti_t *n)
{
  return (n ? n->cvss_base : NULL);
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
nvti_dependencies (const nvti_t *n)
{
  return (n ? n->dependencies : NULL);
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
nvti_required_keys (const nvti_t *n)
{
  return (n ? n->required_keys : NULL);
}

/**
 * @brief Get the mandatory keys list.
 *
 * @param n The NVT Info structure of which the name should
 *          be returned.
 *
 * @return The mandatory keys string. Don't free this.
 */
gchar *
nvti_mandatory_keys (const nvti_t *n)
{
  return (n ? n->mandatory_keys : NULL);
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
nvti_excluded_keys (const nvti_t *n)
{
  return (n ? n->excluded_keys : NULL);
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
nvti_required_ports (const nvti_t *n)
{
  return (n ? n->required_ports : NULL);
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
nvti_required_udp_ports (const nvti_t *n)
{
  return (n ? n->required_udp_ports : NULL);
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
nvti_family (const nvti_t *n)
{
  return (n ? n->family : NULL);
}

/**
 * @brief Get the number of preferences of the NVT.
 *
 * @param n The NVT Info structure.
 *
 * @return The number of preferences.
 */
guint
nvti_pref_len (const nvti_t *n)
{
  return (n ? g_slist_length (n->prefs) : 0);
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
const nvtpref_t *
nvti_pref (const nvti_t *n, guint p)
{
  return (n ? g_slist_nth_data (n->prefs, p) : NULL);
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
nvti_timeout (const nvti_t *n)
{
  return (n ? n->timeout : -1);
}

/**
 * @brief Get the category for this NVT.
 *
 * @param n The NVT Info structure of which the category should be returned.
 *
 * @return The category integer code. A value <= 0 indicates it is not set.
 */
gint
nvti_category (const nvti_t *n)
{
  return (n ? n->category : -1);
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
nvti_set_oid (nvti_t *n, const gchar *oid)
{
  if (!n)
    return (-1);

  if (n->oid)
    g_free (n->oid);
  n->oid = g_strdup (oid);
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
nvti_set_name (nvti_t *n, const gchar *name)
{
  if (!n)
    return (-1);

  if (n->name)
    g_free (n->name);
  n->name = g_strdup (name);
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
nvti_set_cve (nvti_t *n, const gchar *cve)
{
  // @todo: Is this method expected to delete previous cve entries?
  return (nvti_add_cve (n, cve));
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
nvti_set_bid (nvti_t *n, const gchar *bid)
{
  // @todo: Is this method expected to delete previous bid entries?
  return (nvti_add_bid (n, bid));
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
nvti_set_xref (nvti_t *n, const gchar *xref)
{
  gchar **split, **item;

  if (!n)
    return (-1);

  split = g_strsplit (xref, ",", 0);
  item = split;
  while (*item)
    {
      gchar *type_and_id;
      gchar **split2;

      type_and_id = *item;
      g_strstrip (type_and_id);

      if ((strcmp (type_and_id, "") == 0) || (strcmp (type_and_id, "NOXREF")) == 0)
        {
          item++;
          continue;
        }

      split2 = g_strsplit (type_and_id, ":", 2);
      if (split2[0] && split2[1])
        nvti_add_ref (n, vtref_new (split2[0], split2[1], ""));

      item++;
    }
  g_strfreev (split);
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
nvti_set_tag (nvti_t *n, const gchar *tag)
{
  if (!n)
    return (-1);

  if (n->tag)
    g_free (n->tag);
  if (tag && tag[0])
    n->tag = g_strdup (tag);
  else
    n->tag = NULL;
  return (0);
}

/**
 * @brief Set the CVSS base of an NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param cvss_base The CVSS base to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_cvss_base (nvti_t *n, const gchar *cvss_base)
{
  if (!n)
    return (-1);

  if (n->cvss_base)
    g_free (n->cvss_base);
  if (cvss_base && cvss_base[0])
    n->cvss_base = g_strdup (cvss_base);
  else
    n->cvss_base = NULL;
  return (0);
}

/**
 * @brief Set the dependencies of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param dependencies The dependencies to set. A copy will be created from
 * this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_dependencies (nvti_t *n, const gchar *dependencies)
{
  if (!n)
    return (-1);

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
 * @param required_keys The required keys to set. A copy will be created from
 * this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_keys (nvti_t *n, const gchar *required_keys)
{
  if (!n)
    return (-1);

  if (n->required_keys)
    g_free (n->required_keys);
  if (required_keys && required_keys[0])
    n->required_keys = g_strdup (required_keys);
  else
    n->required_keys = NULL;
  return (0);
}

/**
 * @brief Set the mandatory keys of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param mandatory_keys The mandatory keys to set. A copy will be created from
 * this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_mandatory_keys (nvti_t *n, const gchar *mandatory_keys)
{
  if (!n)
    return (-1);

  if (n->mandatory_keys)
    g_free (n->mandatory_keys);
  if (mandatory_keys && mandatory_keys[0])
    n->mandatory_keys = g_strdup (mandatory_keys);
  else
    n->mandatory_keys = NULL;
  return (0);
}

/**
 * @brief Set the excluded keys of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param excluded_keys The excluded keys to set. A copy will be created from
 * this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_excluded_keys (nvti_t *n, const gchar *excluded_keys)
{
  if (!n)
    return (-1);

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
 * @param required_ports The required ports to set. A copy will be created from
 * this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_ports (nvti_t *n, const gchar *required_ports)
{
  if (!n)
    return (-1);

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
 * @param required_udp_ports The required udp ports to set. A copy will be
 * created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_udp_ports (nvti_t *n, const gchar *required_udp_ports)
{
  if (!n)
    return (-1);

  if (n->required_udp_ports)
    g_free (n->required_udp_ports);
  if (required_udp_ports && required_udp_ports[0])
    n->required_udp_ports = g_strdup (required_udp_ports);
  else
    n->required_udp_ports = NULL;
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
nvti_set_family (nvti_t *n, const gchar *family)
{
  if (!n)
    return (-1);

  if (n->family)
    g_free (n->family);
  n->family = g_strdup (family);
  return (0);
}

/**
 * @brief Set the timeout of a NVT Info.
 *
 * @param n The NVT Info structure.
 *
 * @param timeout The timeout to set. Values <= 0 will indicate it is not set.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_timeout (nvti_t *n, const gint timeout)
{
  if (!n)
    return (-1);

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
nvti_set_category (nvti_t *n, const gint category)
{
  if (!n)
    return (-1);

  n->category = category;
  return (0);
}

/**
 * @brief Add a single CVE ID of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param cve The CVE ID to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL, 2 if cve_id was NULL.
 */
int
nvti_add_cve (nvti_t *n, const gchar *cve)
{
  gchar **split, **item;

  if (!n)
    return (1);
  if (!cve)
    return (2);

  split = g_strsplit (cve, ",", 0);
  item = split;
  while (*item)
    {
      gchar *id;

      id = *item;
      g_strstrip (id);

      if ((strcmp (id, "") == 0) || (strcmp (id, "NOCVE")) == 0)
        {
          item++;
          continue;
        }

      nvti_add_ref (n, vtref_new ("cve", id, ""));

      item++;
    }
  g_strfreev (split);

  return (0);
}

/**
 * @brief Add a single BID ID of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param bid The BID ID to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if bid_id was NULL.
 */
int
nvti_add_bid (nvti_t *n, const gchar *bid)
{
  gchar **split, **item;

  if (!n)
    return (1);
  if (!bid)
    return (2);

  split = g_strsplit (bid, ",", 0);
  item = split;
  while (*item)
    {
      gchar *id;

      id = *item;
      g_strstrip (id);

      if ((strcmp (id, "") == 0) || (strcmp (id, "NOBID")) == 0)
        {
          item++;
          continue;
        }

      nvti_add_ref (n, vtref_new ("bid", id, ""));

      item++;
    }
  g_strfreev (split);

  return (0);
}

/**
 * @brief Add a required key of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param key The required key to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if key was NULL.
 */
int
nvti_add_required_keys (nvti_t *n, const gchar *key)
{
  gchar *old;

  if (!n)
    return (1);
  if (!key)
    return (2);

  old = n->required_keys;

  if (old)
    {
      n->required_keys = g_strdup_printf ("%s, %s", old, key);
      g_free (old);
    }
  else
    n->required_keys = g_strdup (key);

  return (0);
}

/**
 * @brief Add a mandatory key of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param key The mandatory key to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if key was NULL.
 */
int
nvti_add_mandatory_keys (nvti_t *n, const gchar *key)
{
  gchar *old;

  if (!n)
    return (1);
  if (!key)
    return (2);

  old = n->mandatory_keys;

  if (old)
    {
      n->mandatory_keys = g_strdup_printf ("%s, %s", old, key);
      g_free (old);
    }
  else
    n->mandatory_keys = g_strdup (key);

  return (0);
}

/**
 * @brief Add a excluded key of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param key The excluded key to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if key was NULL.
 */
int
nvti_add_excluded_keys (nvti_t *n, const gchar *key)
{
  gchar *old;

  if (!n)
    return (1);
  if (!key)
    return (2);

  old = n->excluded_keys;

  if (old)
    {
      n->excluded_keys = g_strdup_printf ("%s, %s", old, key);
      g_free (old);
    }
  else
    n->excluded_keys = g_strdup (key);

  return (0);
}

/**
 * @brief Add a required port of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param port The required port to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if port was NULL.
 */
int
nvti_add_required_ports (nvti_t *n, const gchar *port)
{
  gchar *old;

  if (!n)
    return (1);
  if (!port)
    return (2);

  old = n->required_ports;

  if (old)
    {
      n->required_ports = g_strdup_printf ("%s, %s", old, port);
      g_free (old);
    }
  else
    n->required_ports = g_strdup (port);

  return (0);
}

/**
 * @brief Add a required udp port of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param port The required udp port to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if port was NULL.
 */
int
nvti_add_required_udp_ports (nvti_t *n, const gchar *port)
{
  gchar *old;

  if (!n)
    return (1);
  if (!port)
    return (2);

  old = n->required_udp_ports;

  if (old)
    {
      n->required_udp_ports = g_strdup_printf ("%s, %s", old, port);
      g_free (old);
    }
  else
    n->required_udp_ports = g_strdup (port);

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
nvti_add_pref (nvti_t *n, nvtpref_t *np)
{
  if (!n)
    return (-1);

  n->prefs = g_slist_append (n->prefs, np);
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
  nvti_free ((nvti_t *) nvti);
}

/**
 * @brief Make a collection of NVT Infos.
 *
 * @return An empty collection of NVT Infos.
 */
nvtis_t *
nvtis_new (void)
{
  return g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
                                free_nvti_for_hash_table);
}

/**
 * @brief Free a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 */
void
nvtis_free (nvtis_t *nvtis)
{
  if (nvtis)
    g_hash_table_destroy (nvtis);
}

/**
 * @brief Add an NVT Info to a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 * @param nvti  The NVT Info to add.
 */
void
nvtis_add (nvtis_t *nvtis, nvti_t *nvti)
{
  if (nvti)
    g_hash_table_insert (nvtis, (gpointer) nvti_oid (nvti), (gpointer) nvti);
}

/**
 * @brief Add an NVT Info to a collection of NVT Infos.
 *
 * @param nvtis The collection of NVT Infos.
 * @param oid   The OID of the NVT.
 *
 * @return The NVT Info, if found, else NULL.
 */
nvti_t *
nvtis_lookup (nvtis_t *nvtis, const char *oid)
{
  return g_hash_table_lookup (nvtis, oid);
}
