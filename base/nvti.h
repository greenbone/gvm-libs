/* openvas-libraries/base
 * $Id$
 * Description: API (structs and protos) for NVT Info datasets
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009, 2011 Greenbone Networks GmbH
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
 * @file nvti.h
 * @brief Protos and data structures for NVT Information data sets.
 *
 * This file contains the protos for \ref nvti.c
 */

#ifndef _NVTI_H
#define _NVTI_H

#include <glib.h>

/**
 * @brief The structure for a preference of a NVT.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct nvtpref
{
  gchar *type;                  ///< Preference type
  gchar *name;                  ///< Name of the preference
  gchar *dflt;                  ///< Default value of the preference
} nvtpref_t;

nvtpref_t *nvtpref_new (gchar *, gchar *, gchar *);
void nvtpref_free (nvtpref_t *);
gchar *nvtpref_name (const nvtpref_t *);
gchar *nvtpref_type (const nvtpref_t *);
gchar *nvtpref_default (const nvtpref_t *);

/**
 * @brief The structure of a information record that corresponds to a NVT.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct nvti
{
  gchar *oid;                /**< @brief Object ID */
  gchar *version;            /**< @brief Version of the NVT */
  gchar *name;               /**< @brief The name */
  gchar *summary;            /**< @brief Summary about the NVT */
  gchar *copyright;          /**< @brief Copyright for the NVT */

  gchar *cve;               /**< @brief List of CVEs, this NVT corresponds to */
  gchar *bid;               /**< @brief List of Bugtraq IDs, this NVT
                                        corresponds to */
  gchar *xref;              /**< @brief List of Cross-references, this NVT
                                        corresponds to */
  gchar *tag;               /**< @brief List of tags attached to this NVT */
  gchar *cvss_base;         /**< @brief CVSS base score for this NVT. */

  gchar *dependencies;      /**< @brief List of dependencies of this NVT */
  gchar *required_keys;     /**< @brief List of required KB keys of this NVT */
  gchar *mandatory_keys;    /**< @brief List of mandatory KB keys of this NVT */
  gchar *excluded_keys;     /**< @brief List of excluded KB keys of this NVT */
  gchar *required_ports;    /**< @brief List of required ports of this NVT */
  gchar *required_udp_ports;/**< @brief List of required UDP ports of this NVT*/

  gchar *src;               /**< @brief the source of the corresponding script,
                                        can be filename or other URI */

  GSList *prefs;            /**< @brief Collection of NVT preferences */

  // The following are not settled yet.
  gint timeout;             /**< @brief Default timeout time for this NVT */
  gint category;            /**< @brief The category, this NVT belongs to */
  gchar *family;            /**< @brief Family the NVT belongs to */
} nvti_t;

nvti_t *nvti_new (void);
void nvti_free (nvti_t *);
void nvti_shrink (nvti_t *);

gchar *nvti_oid (const nvti_t *);
gchar *nvti_version (const nvti_t *);
gchar *nvti_name (const nvti_t *);
gchar *nvti_summary (const nvti_t *);
gchar *nvti_copyright (const nvti_t *);
gchar *nvti_cve (const nvti_t *);
gchar *nvti_bid (const nvti_t *);
gchar *nvti_xref (const nvti_t *);
gchar *nvti_tag (const nvti_t *);
gchar *nvti_cvss_base (const nvti_t *);
gchar *nvti_dependencies (const nvti_t *);
gchar *nvti_required_keys (const nvti_t *);
gchar *nvti_mandatory_keys (const nvti_t *);
gchar *nvti_excluded_keys (const nvti_t *);
gchar *nvti_required_ports (const nvti_t *);
gchar *nvti_required_udp_ports (const nvti_t *);
gchar *nvti_src (const nvti_t *);
gint nvti_timeout (const nvti_t *);
gint nvti_category (const nvti_t *);
gchar *nvti_family (const nvti_t *);
guint nvti_pref_len (const nvti_t *);
nvtpref_t *nvti_pref (const nvti_t *, guint);

int nvti_set_oid (nvti_t *, const gchar *);
int nvti_set_version (nvti_t *, const gchar *);
int nvti_set_name (nvti_t *, const gchar *);
int nvti_set_summary (nvti_t *, const gchar *);
int nvti_set_copyright (nvti_t *, const gchar *);
int nvti_set_cve (nvti_t *, const gchar *);
int nvti_set_bid (nvti_t *, const gchar *);
int nvti_set_xref (nvti_t *, const gchar *);
int nvti_set_tag (nvti_t *, const gchar *);
int nvti_set_cvss_base (nvti_t *, const gchar *);
int nvti_set_dependencies (nvti_t *, const gchar *);
int nvti_set_required_keys (nvti_t *, const gchar *);
int nvti_set_mandatory_keys (nvti_t *, const gchar *);
int nvti_set_excluded_keys (nvti_t *, const gchar *);
int nvti_set_required_ports (nvti_t *, const gchar *);
int nvti_set_required_udp_ports (nvti_t *, const gchar *);
int nvti_set_src (nvti_t *, const gchar *);
int nvti_set_timeout (nvti_t *, const gint);
int nvti_set_category (nvti_t *, const gint);
int nvti_set_family (nvti_t *, const gchar *);

int nvti_add_cve (nvti_t *, const gchar *);
int nvti_add_bid (nvti_t *, const gchar *);
int nvti_add_required_keys (nvti_t *, const gchar *);
int nvti_add_mandatory_keys (nvti_t *, const gchar *);
int nvti_add_excluded_keys (nvti_t *, const gchar *);
int nvti_add_required_ports (nvti_t *, const gchar *);
int nvti_add_required_udp_ports (nvti_t *, const gchar *);
int nvti_add_pref (nvti_t *, nvtpref_t *);

nvti_t *nvti_from_keyfile (const gchar *);
int nvti_to_keyfile (const nvti_t *, const gchar *);

nvti_t * nvti_clone (const nvti_t *);

/* Collections of NVT Infos. */

/**
 * @brief A collection of information records corresponding to NVTs.
 */
typedef GHashTable nvtis_t;

nvtis_t *nvtis_new ();

void nvtis_free (nvtis_t *);

void nvtis_add (nvtis_t *, nvti_t *);

nvti_t *nvtis_lookup (nvtis_t *, const char *);

#define nvtis_find g_hash_table_find

#endif /* not _NVTI_H */
