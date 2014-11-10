/* openvas-libraries/base
 * $Id$
 * Description: Implementation of API to handle NVT Info datasets
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2011 Greenbone Networks GmbH
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
#include <stdlib.h>     /* for strtod   */
#include <math.h>       /* for HUGE_VAL */
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "nvti.h"
#include "cvss.h"  /* for get_cvss_score_from_base_metrics */
#include "../misc/openvas_logging.h"

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
  nvtpref_t *np = g_malloc0 (sizeof (nvtpref_t));

  if (!np)
    return NULL;

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
 * @param n The structure to be freed.
 */
void
nvtpref_free (nvtpref_t * np)
{
  if (!np)
    return;

  if (np->name)
    g_free (np->name);
  if (np->type)
    g_free (np->type);
  if (np->dflt)
    g_free (np->dflt);
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
nvtpref_type (const nvtpref_t * np)
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
nvtpref_default (const nvtpref_t * np)
{
  return (np ? np->dflt : NULL);
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
  if (!n)
    return;

  if (n->oid)
    g_free (n->oid);
  if (n->version)
    g_free (n->version);
  if (n->name)
    g_free (n->name);
  if (n->summary)
    g_free (n->summary);
  if (n->copyright)
    g_free (n->copyright);
  if (n->cve)
    g_free (n->cve);
  if (n->bid)
    g_free (n->bid);
  if (n->xref)
    g_free (n->xref);
  if (n->tag)
    g_free (n->tag);
  if (n->cvss_base)
    g_free (n->cvss_base);
  if (n->dependencies)
    g_free (n->dependencies);
  if (n->required_keys)
    g_free (n->required_keys);
  if (n->mandatory_keys)
    g_free (n->mandatory_keys);
  if (n->excluded_keys)
    g_free (n->excluded_keys);
  if (n->required_ports)
    g_free (n->required_ports);
  if (n->required_udp_ports)
    g_free (n->required_udp_ports);
  if (n->family)
    g_free (n->family);
  if (n->src)
    g_free (n->src);
  if (n->prefs)
    {
      guint len = g_slist_length (n->prefs);
      int i;
      for (i = 0; i < len; i++)
        nvtpref_free (g_slist_nth_data (n->prefs, i));
      g_slist_free (n->prefs);
    }
  g_free (n);
}

/**
 * @brief Free memory of all elements except src and oid.
 *
 * @param n The structure to be shrinked.
 */
void
nvti_shrink (nvti_t * n)
{
  if (!n)
    return;

  if (n->version)
    {
      g_free (n->version);
      n->version = NULL;
    }
  if (n->name)
    {
      g_free (n->name);
      n->name = NULL;
    }
  if (n->summary)
    {
      g_free (n->summary);
      n->summary = NULL;
    }
  if (n->copyright)
    {
      g_free (n->copyright);
      n->copyright = NULL;
    }
  if (n->cve)
    {
      g_free (n->cve);
      n->cve = NULL;
    }
  if (n->bid)
    {
      g_free (n->bid);
      n->bid = NULL;
    }
  if (n->xref)
    {
      g_free (n->xref);
      n->xref = NULL;
    }
  if (n->tag)
    {
      g_free (n->tag);
      n->tag = NULL;
    }
  if (n->cvss_base)
    {
      g_free (n->cvss_base);
      n->cvss_base = NULL;
    }
  if (n->dependencies)
    {
      g_free (n->dependencies);
      n->dependencies = NULL;
    }
  if (n->required_keys)
    {
      g_free (n->required_keys);
      n->required_keys = NULL;
    }
  if (n->mandatory_keys)
    {
      g_free (n->mandatory_keys);
      n->mandatory_keys = NULL;
    }
  if (n->excluded_keys)
    {
      g_free (n->excluded_keys);
      n->excluded_keys = NULL;
    }
  if (n->required_ports)
    {
      g_free (n->required_ports);
      n->required_ports = NULL;
    }
  if (n->required_udp_ports)
    {
      g_free (n->required_udp_ports);
      n->required_udp_ports = NULL;
    }
  if (n->family)
    {
      g_free (n->family);
      n->family = NULL;
    }
  if (n->prefs)
    {
      guint len = g_slist_length (n->prefs);
      int i;
      for (i = 0; i < len; i++)
        nvtpref_free (g_slist_nth_data (n->prefs, i));
      g_slist_free (n->prefs);
      n->prefs = NULL;
    }
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
  return (n ? n->oid : NULL);
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
  return (n ? n->version : NULL);
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
  return (n ? n->name : NULL);
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
  return (n ? n->summary : NULL);
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
  return (n ? n->copyright : NULL);
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
  return (n ? n->cve : NULL);
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
  return (n ? n->bid : NULL);
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
  return (n ? n->xref : NULL);
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
nvti_cvss_base (const nvti_t * n)
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
nvti_dependencies (const nvti_t * n)
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
nvti_required_keys (const nvti_t * n)
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
nvti_mandatory_keys (const nvti_t * n)
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
nvti_excluded_keys (const nvti_t * n)
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
nvti_required_ports (const nvti_t * n)
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
nvti_required_udp_ports (const nvti_t * n)
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
nvti_family (const nvti_t * n)
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
nvti_pref_len (const nvti_t * n)
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
nvtpref_t *
nvti_pref (const nvti_t * n, guint p)
{
  return (n ? g_slist_nth_data (n->prefs, p) : NULL);
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
  return (n ? n->src : NULL);
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
nvti_category (const nvti_t * n)
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
nvti_set_oid (nvti_t * n, const gchar * oid)
{
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

  if (n->summary)
    g_free (n->summary);
  n->summary = g_strdup (summary);
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
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
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
 * @param tag The CVSS base to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_cvss_base (nvti_t * n, const gchar * cvss_base)
{
  if (! n)
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
 * @param dependencies The dependencies to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_dependencies (nvti_t * n, const gchar * dependencies)
{
  if (! n)
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
 * @param required_keys The required keys to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_keys (nvti_t * n, const gchar * required_keys)
{
  if (! n)
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
 * @param mandatory_keys The mandatory keys to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_mandatory_keys (nvti_t * n, const gchar * mandatory_keys)
{
  if (! n)
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
 * @param excluded_keys The excluded keys to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_excluded_keys (nvti_t * n, const gchar * excluded_keys)
{
  if (! n)
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
 * @param required_ports The required ports to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_ports (nvti_t * n, const gchar * required_ports)
{
  if (! n)
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
 * @param required_udp_ports The required udp ports to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_required_udp_ports (nvti_t * n, const gchar * required_udp_ports)
{
  if (! n)
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
nvti_set_family (nvti_t * n, const gchar * family)
{
  if (! n)
    return (-1);

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
  if (! n)
    return (-1);

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
  if (! n)
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
nvti_set_category (nvti_t * n, const gint category)
{
  if (! n)
    return (-1);

  n->category = category;
  return (0);
}

/**
 * @brief Add a single CVE ID of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param cve_id The CVE ID to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL, 2 if cve_id was NULL.
 */
int
nvti_add_cve (nvti_t * n, const gchar * cve_id)
{
  gchar * old;

  if (! n) return (1);
  if (! cve_id) return (2);

  old = n->cve;

  if (old)
  {
    n->cve = g_strdup_printf ("%s, %s", old, cve_id);
    g_free (old);
  }
  else
    n->cve = g_strdup (cve_id);

  return (0);
}

/**
 * @brief Add a single BID ID of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param cve_id The BID ID to add. A copy will be created from this.
 *
 * @return 0 for success. 1 if n was NULL. 2 if bid_id was NULL.
 */
int
nvti_add_bid (nvti_t * n, const gchar * bid_id)
{
  gchar * old;

  if (! n) return (1);
  if (! bid_id) return (2);

  old = n->bid;

  if (old)
  {
    n->bid = g_strdup_printf ("%s, %s", old, bid_id);
    g_free (old);
  }
  else
    n->bid = g_strdup (bid_id);

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
nvti_add_required_keys (nvti_t * n, const gchar * key)
{
  gchar * old;

  if (! n) return (1);
  if (! key) return (2);

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
nvti_add_mandatory_keys (nvti_t * n, const gchar * key)
{
  gchar * old;

  if (! n) return (1);
  if (! key) return (2);

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
nvti_add_excluded_keys (nvti_t * n, const gchar * key)
{
  gchar * old;

  if (! n) return (1);
  if (! key) return (2);

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
nvti_add_required_ports (nvti_t * n, const gchar * port)
{
  gchar * old;

  if (! n) return (1);
  if (! port) return (2);

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
nvti_add_required_udp_ports (nvti_t * n, const gchar * port)
{
  gchar * old;

  if (! n) return (1);
  if (! port) return (2);

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
nvti_add_pref (nvti_t * n, nvtpref_t * np)
{
  if (! n)
    return (-1);

  n->prefs = g_slist_append (n->prefs, np);
  return (0);
}

/**
 * @brief Read NVT Info from a keyfile.
 *
 * @param keyfile Keyfile.
 * @param name    Key name.
 * @param nvti    NVTI.
 * @param set     Set function.
 */
static void
set_from_key (GKeyFile *keyfile, const gchar *name,
              nvti_t *nvti, int set (nvti_t * n, const gchar * oid))
{
  gchar *utf8;
  utf8 = g_key_file_get_string (keyfile, "NVT Info", name, NULL);
  if (utf8)
    {
      gsize size;
      gchar *iso;

      iso = g_convert (utf8, -1, "ISO_8859-1", "UTF-8", NULL, &size, NULL);
      set (nvti, iso);
      g_free (iso);
      g_free (utf8);
    }
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
      g_warning ("%s: %s", fn, error->message);
      return NULL;
    }

  n = nvti_new ();
  set_from_key (keyfile, "OID", n, nvti_set_oid);
  set_from_key (keyfile, "Version", n, nvti_set_version);
  set_from_key (keyfile, "Name", n, nvti_set_name);
  set_from_key (keyfile, "Summary", n, nvti_set_summary);
  set_from_key (keyfile, "Copyright", n, nvti_set_copyright);
  set_from_key (keyfile, "CVEs", n, nvti_set_cve);
  set_from_key (keyfile, "BIDs", n, nvti_set_bid);
  set_from_key (keyfile, "XREFs", n, nvti_set_xref);
  set_from_key (keyfile, "Tags", n, nvti_set_tag);
  set_from_key (keyfile, "Dependencies", n, nvti_set_dependencies);
  set_from_key (keyfile, "RequiredKeys", n, nvti_set_required_keys);
  set_from_key (keyfile, "MandatoryKeys", n, nvti_set_mandatory_keys);
  set_from_key (keyfile, "ExcludedKeys", n, nvti_set_excluded_keys);
  set_from_key (keyfile, "RequiredPorts", n, nvti_set_required_ports);
  set_from_key (keyfile, "RequiredUDPPorts", n, nvti_set_required_udp_ports);
  set_from_key (keyfile, "Family", n, nvti_set_family);
  set_from_key (keyfile, "src", n, nvti_set_src);
  nvti_set_timeout (n,
                    g_key_file_get_integer (keyfile, "NVT Info", "Timeout",
                                            NULL));
  nvti_set_category (n,
                     g_key_file_get_integer (keyfile, "NVT Info", "Category",
                                             NULL));

  if (g_key_file_has_group (keyfile, "NVT Prefs"))
    {
      keys = g_key_file_get_keys (keyfile, "NVT Prefs", NULL, NULL);
      for (i = 0; keys[i]; i++)
        {
          gsize len;
          gchar *name, *type, *dflt;
          gchar **items =
            g_key_file_get_string_list (keyfile, "NVT Prefs", keys[i], &len,
                                        NULL);
          if (len != 3)
            continue;           // format error for this pref.

          name = g_convert (items[0], -1, "ISO_8859-1", "UTF-8", NULL, &len,
                            NULL);
          type = g_convert (items[1], -1, "ISO_8859-1", "UTF-8", NULL, &len,
                            NULL);
          dflt = g_convert (items[2], -1, "ISO_8859-1", "UTF-8", NULL, &len,
                            NULL);

          nvtpref_t *np = nvtpref_new (name, type, dflt);
          nvti_add_pref (n, np);
          g_strfreev (items);
          g_free (name);
          g_free (type);
          g_free (dflt);
        }
      g_strfreev (keys);
    }

  g_key_file_free (keyfile);

  return (n);
}

/**
 * @brief Read NVT Info from a keyfile.
 *
 * @param keyfile Keyfile.
 * @param name    Key name.
 * @param nvti    NVTI.
 * @param value   Value.
 */
static void
set_from_nvti (GKeyFile *keyfile, const gchar *name, const nvti_t *nvti,
               const gchar *value)
{
  if (value)
    {
      gsize size;
      gchar *utf8;

      utf8 = g_convert (value, -1, "UTF-8", "ISO_8859-1", NULL, &size, NULL);
      g_key_file_set_string (keyfile, "NVT Info", name, utf8);
      g_free (utf8);
    }
}

/**
 * @brief Store NVT Info into a keyfile.
 *
 * @param n The NVT Info object to store.
 *
 * @param fn The filename to write to.
 *
 * @return 0 on success. @todo Anything else indicates an error.
 */
int
nvti_to_keyfile (const nvti_t * n, const gchar * fn)
{
  GKeyFile *keyfile = g_key_file_new ();
  gchar *text;
  GError *error = NULL;

  set_from_nvti (keyfile, "OID", n, n->oid);
  set_from_nvti (keyfile, "Version", n, n->version);
  set_from_nvti (keyfile, "Name", n, n->name);
  set_from_nvti (keyfile, "Summary", n, n->summary);
  set_from_nvti (keyfile, "Copyright", n, n->copyright);
  set_from_nvti (keyfile, "CVEs", n, n->cve);
  set_from_nvti (keyfile, "BIDs", n, n->bid);
  set_from_nvti (keyfile, "XREFs", n, n->xref);
  set_from_nvti (keyfile, "Tags", n, n->tag);
  set_from_nvti (keyfile, "Dependencies", n, n->dependencies);
  set_from_nvti (keyfile, "RequiredKeys", n, n->required_keys);
  set_from_nvti (keyfile, "MandatoryKeys", n, n->mandatory_keys);
  set_from_nvti (keyfile, "ExcludedKeys", n, n->excluded_keys);
  set_from_nvti (keyfile, "RequiredPorts", n, n->required_ports);
  set_from_nvti (keyfile, "RequiredUDPPorts", n, n->required_udp_ports);
  set_from_nvti (keyfile, "Family", n, n->family);
  set_from_nvti (keyfile, "src", n, n->src);
  if (n->timeout > 0)
    g_key_file_set_integer (keyfile, "NVT Info", "Timeout", n->timeout);
  if (n->category > 0)
    g_key_file_set_integer (keyfile, "NVT Info", "Category", n->category);

  int i;
  for (i = 0; i < nvti_pref_len (n); i++)
    {
      nvtpref_t *np = nvti_pref (n, i);
      gchar *lst[3];
      gchar buf[10];
      gsize size;

      lst[0] = g_convert (((nvtpref_t *) np)->name, -1, "UTF-8", "ISO_8859-1",
                          NULL, &size, NULL);
      lst[1] = g_convert (((nvtpref_t *) np)->type, -1, "UTF-8", "ISO_8859-1",
                          NULL, &size, NULL);
      lst[2] = g_convert (((nvtpref_t *) np)->dflt, -1, "UTF-8", "ISO_8859-1",
                          NULL, &size, NULL);

      g_snprintf (buf, 10, "P%d", i);
      g_key_file_set_string_list ((GKeyFile *) keyfile, "NVT Prefs", buf,
                                  (const gchar **) lst, 3);
//    g_key_file_set_string_list((GKeyFile *)keyfile, "NVT Prefs", (gchar *)lst[0], (const gchar **)lst, 3);

      g_free (lst[0]);
      g_free (lst[1]);
      g_free (lst[2]);
    }

  text = g_key_file_to_data (keyfile, NULL, &error);
  if (error != NULL)
    {
      log_legacy_write ("Error occured while preparing %s: %s", fn,
                        error->message);
      g_error_free (error);
    }
  else
    {
      FILE *fp = fopen (fn, "w");
      if (!fp)
        {                       // second try: maybe the directory was missing.
          gchar *cache_dir = g_path_get_dirname (fn);
          if ((g_mkdir_with_parents (cache_dir, 0755) < 0) && (errno != EEXIST))
            {
              log_legacy_write ("mkdir(%s) : %s", cache_dir,
                                strerror (errno));
              g_free (text);
              g_key_file_free (keyfile);
              return (1);
            }
          fp = fopen (fn, "w");
        }

      if (!fp)
        {                       // again failed
          log_legacy_write ("fopen(%s) : %s", fn, strerror (errno));
          g_free (text);
          g_key_file_free (keyfile);
          return (2);
        }

      fputs (text, fp);
      fclose (fp);

      /* Set timestamp of cache file to the timestamp of the original NVT, if
       * possible */
      if (n->src)
        {
          struct stat src_stat;
          if (stat (n->src, &src_stat) == 0)
            {
              struct utimbuf src_timestamp;
              src_timestamp.actime = src_stat.st_atime;
              src_timestamp.modtime = src_stat.st_mtime;
              if (utime (fn, &src_timestamp) != 0)
                log_legacy_write ("utime(%s) : %s", fn, strerror (errno));
            }
          else
            log_legacy_write ("stat(%s) : %s", n->src, strerror (errno));
        }

      g_free (text);
    }

  g_key_file_free (keyfile);

  return (0);
}

/**
 * @brief Create a full copy of a NVT Info.
 *
 * @param n The NVT Info object to clone.
 *
 * @return A pointer to the cloned NVT Info or NULL in case of an error.
 */
nvti_t *
nvti_clone (const nvti_t * n)
{
  nvti_t * new_nvti;

  if (! n) return NULL;

  new_nvti = nvti_new ();

  nvti_set_oid (new_nvti, nvti_oid (n));
  nvti_set_version (new_nvti, nvti_version (n));
  nvti_set_name (new_nvti, nvti_name (n));
  nvti_set_summary (new_nvti, nvti_summary (n));
  nvti_set_copyright (new_nvti, nvti_copyright (n));
  nvti_set_cve (new_nvti, nvti_cve (n));
  nvti_set_bid (new_nvti, nvti_bid (n));
  nvti_set_xref (new_nvti, nvti_xref (n));
  nvti_set_tag (new_nvti, nvti_tag (n));
  nvti_set_cvss_base (new_nvti, nvti_cvss_base (n));
  nvti_set_dependencies (new_nvti, nvti_dependencies (n));
  nvti_set_required_keys (new_nvti, nvti_required_keys (n));
  nvti_set_mandatory_keys (new_nvti, nvti_mandatory_keys (n));
  nvti_set_excluded_keys (new_nvti, nvti_excluded_keys (n));
  nvti_set_required_ports (new_nvti, nvti_required_ports (n));
  nvti_set_required_udp_ports (new_nvti, nvti_required_udp_ports (n));
  nvti_set_src (new_nvti, nvti_src (n));
  nvti_set_timeout (new_nvti, nvti_timeout (n));
  nvti_set_category (new_nvti, nvti_category (n));
  nvti_set_family (new_nvti, nvti_family (n));

  int i;
  for (i = 0; i < nvti_pref_len (n); i++)
    {
      nvtpref_t *np = nvti_pref (n, i);
      nvtpref_t * new_pref = nvtpref_new (nvtpref_name (np),
        nvtpref_type (np), nvtpref_default (np));
      nvti_add_pref (new_nvti, new_pref);
    }

  return (new_nvti);
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
 */
nvtis_t *
nvtis_new ()
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
nvtis_free (nvtis_t * nvtis)
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
nvtis_add (nvtis_t * nvtis, nvti_t * nvti)
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
nvtis_lookup (nvtis_t * nvtis, const char *oid)
{
  return g_hash_table_lookup (nvtis, oid);
}
