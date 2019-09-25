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

/* For strptime in time.h. */
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#include "nvti.h"

#include <stdio.h>   // for sscanf
#include <string.h>  // for strcmp
#include <strings.h> // for strcasecmp
#include <time.h>    // for strptime

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  nvti"

/* VT references */

/**
 * @brief The structure for a cross reference of a VT.
 *
 * The elements of this structure should only be accessed by the
 * respective functions.
 */
typedef struct vtref
{
  gchar *type;     ///< Reference type ("cve", "bid", ...)
  gchar *ref_id;   ///< Actual reference ID ("CVE-2018-1234", etc)
  gchar *ref_text; ///< Optional additional text
} vtref_t;

/**
 * @brief Create a new vtref structure filled with the given values.
 *
 * @param type The type to be set.
 *
 * @param ref_id The actual reference to be set.
 *
 * @param ref_text The optional text accompanying a reference.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else a vtref structure which needs to be
 *         released using @ref vtref_free .
 */
vtref_t *
vtref_new (const gchar *type, const gchar *ref_id, const gchar *ref_text)
{
  vtref_t *ref = g_malloc0 (sizeof (vtref_t));

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
 * @param ref The structure to be freed.
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
 * @brief Get the type of a reference.
 *
 * @param r The VT Reference structure of which the type should
 *          be returned.
 *
 * @return The type string. Don't free this.
 */
const gchar *
vtref_type (const vtref_t *r)
{
  return (r ? r->type : NULL);
}

/**
 * @brief Get the id of a reference.
 *
 * @param r The VT Reference structure of which the id should
 *          be returned.
 *
 * @return The id string. Don't free this.
 */
const gchar *
vtref_id (const vtref_t *r)
{
  return (r ? r->ref_id : NULL);
}

/**
 * @brief Get the text of a reference.
 *
 * @param r The VT Reference structure of which the id should
 *          be returned.
 *
 * @return The id string. Don't free this.
 */
const gchar *
vtref_text (const vtref_t *r)
{
  return (r ? r->ref_text : NULL);
}

/* Support function for timestamps */

/**
 * @brief Try convert an NVT tag time string into epoch time
 *        or return 0 upon parse errors.
 *
 * @param[in]   str_time Time stamp as string in one of the forms used in NVTs.
 *
 * @return Time as seconds since the epoch.
 */
static time_t
parse_nvt_timestamp (const gchar *str_time)
{
  time_t epoch_time;
  int offset;
  struct tm tm;

  if ((strcmp ((char *) str_time, "") == 0)
      || (strcmp ((char *) str_time, "$Date: $") == 0)
      || (strcmp ((char *) str_time, "$Date$") == 0)
      || (strcmp ((char *) str_time, "$Date:$") == 0)
      || (strcmp ((char *) str_time, "$Date") == 0)
      || (strcmp ((char *) str_time, "$$") == 0))
    {
      return 0;
    }

  /* Parse the time. */

  /* 2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011) */
  /* $Date: 2012-02-17 16:05:26 +0100 (Fr, 17. Feb 2012) $ */
  /* $Date: Fri, 11 Nov 2011 14:42:28 +0100 $ */
  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char *) str_time, "%F %T %z", &tm) == NULL)
    {
      memset (&tm, 0, sizeof (struct tm));
      if (strptime ((char *) str_time, "$Date: %F %T %z", &tm) == NULL)
        {
          memset (&tm, 0, sizeof (struct tm));
          if (strptime ((char *) str_time, "%a %b %d %T %Y %z", &tm) == NULL)
            {
              memset (&tm, 0, sizeof (struct tm));
              if (strptime ((char *) str_time, "$Date: %a, %d %b %Y %T %z", &tm)
                  == NULL)
                {
                  memset (&tm, 0, sizeof (struct tm));
                  if (strptime ((char *) str_time, "$Date: %a %b %d %T %Y %z",
                                &tm)
                      == NULL)
                    {
                      g_warning ("%s: Failed to parse time: %s", __FUNCTION__,
                                 str_time);
                      return 0;
                    }
                }
            }
        }
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time: %s", __FUNCTION__, str_time);
      return 0;
    }

  /* Get the timezone offset from the str_time. */

  if ((sscanf ((char *) str_time, "%*u-%*u-%*u %*u:%*u:%*u %d%*[^]]", &offset)
       != 1)
      && (sscanf ((char *) str_time, "$Date: %*u-%*u-%*u %*u:%*u:%*u %d%*[^]]",
                  &offset)
          != 1)
      && (sscanf ((char *) str_time, "%*s %*s %*s %*u:%*u:%*u %*u %d%*[^]]",
                  &offset)
          != 1)
      && (sscanf ((char *) str_time,
                  "$Date: %*s %*s %*s %*u %*u:%*u:%*u %d%*[^]]", &offset)
          != 1)
      && (sscanf ((char *) str_time,
                  "$Date: %*s %*s %*s %*u:%*u:%*u %*u %d%*[^]]", &offset)
          != 1))
    {
      g_warning ("%s: Failed to parse timezone offset: %s", __FUNCTION__,
                 str_time);
      return 0;
    }

  /* Use the offset to convert to UTC. */

  if (offset < 0)
    {
      epoch_time += ((-offset) / 100) * 60 * 60;
      epoch_time += ((-offset) % 100) * 60;
    }
  else if (offset > 0)
    {
      epoch_time -= (offset / 100) * 60 * 60;
      epoch_time -= (offset % 100) * 60;
    }

  return epoch_time;
}

/* VT Information */

/**
 * @brief The structure of a information record that corresponds to a NVT.
 */
typedef struct nvti
{
  gchar *oid;  /**< @brief Object ID */
  gchar *name; /**< @brief The name */

  gchar *summary;  /**< @brief The summary */
  gchar *insight;  /**< @brief The insight */
  gchar *affected; /**< @brief Affected systems */
  gchar *impact;   /**< @brief Impact of vulnerability */

  time_t creation_time;     /**< @brief Time of creation, seconds since epoch */
  time_t modification_time; /**< @brief Time of last change, sec. since epoch */

  gchar *solution;      /**< @brief The solution */
  gchar *solution_type; /**< @brief The solution type */

  gchar *tag;       /**< @brief List of tags attached to this NVT */
  gchar *cvss_base; /**< @brief CVSS base score for this NVT. */

  gchar *dependencies;   /**< @brief List of dependencies of this NVT */
  gchar *required_keys;  /**< @brief List of required KB keys of this NVT */
  gchar *mandatory_keys; /**< @brief List of mandatory KB keys of this NVT */
  gchar *excluded_keys;  /**< @brief List of excluded KB keys of this NVT */
  gchar *required_ports; /**< @brief List of required ports of this NVT */
  gchar
    *required_udp_ports; /**< @brief List of required UDP ports of this NVT*/

  gchar *detection; /**< @brief Detection description */
  gchar *qod_type;  /**< @brief Quality of detection type */

  GSList *refs;  /**< @brief Collection of VT references */
  GSList *prefs; /**< @brief Collection of NVT preferences */

  // The following are not settled yet.
  gint timeout;  /**< @brief Default timeout time for this NVT */
  gint category; /**< @brief The category, this NVT belongs to */
  gchar *family; /**< @brief Family the NVT belongs to */
} nvti_t;

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
nvti_add_vtref (nvti_t *vt, vtref_t *ref)
{
  if (!vt)
    return (-1);

  vt->refs = g_slist_append (vt->refs, ref);
  return (0);
}

/* VT preferences */

/**
 * @brief The structure for a preference of a NVT.
 */
typedef struct nvtpref
{
  int id;      ///< Preference ID
  gchar *type; ///< Preference type
  gchar *name; ///< Name of the preference
  gchar *dflt; ///< Default value of the preference
} nvtpref_t;

/**
 * @brief Create a new nvtpref structure filled with the given values.
 *
 * @param id The ID to be set.
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
  g_free (n->summary);
  g_free (n->insight);
  g_free (n->affected);
  g_free (n->impact);
  g_free (n->solution);
  g_free (n->solution_type);
  g_free (n->tag);
  g_free (n->cvss_base);
  g_free (n->dependencies);
  g_free (n->required_keys);
  g_free (n->mandatory_keys);
  g_free (n->excluded_keys);
  g_free (n->required_ports);
  g_free (n->required_udp_ports);
  g_free (n->detection);
  g_free (n->qod_type);
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
 * @brief Get the summary.
 *
 * @param n The NVT Info structure of which the summary should
 *          be returned.
 *
 * @return The summary string. Don't free this.
 */
gchar *
nvti_summary (const nvti_t *n)
{
  return (n ? n->summary : NULL);
}

/**
 * @brief Get the text about insight.
 *
 * @param n The NVT Info structure of which the insight description should
 *          be returned.
 *
 * @return The insight string. Don't free this.
 */
gchar *
nvti_insight (const nvti_t *n)
{
  return (n ? n->insight : NULL);
}

/**
 * @brief Get the text about affected systems.
 *
 * @param n The NVT Info structure of which the affected description should
 *          be returned.
 *
 * @return The affected string. Don't free this.
 */
gchar *
nvti_affected (const nvti_t *n)
{
  return (n ? n->affected : NULL);
}

/**
 * @brief Get the text about impact.
 *
 * @param n The NVT Info structure of which the impact description should
 *          be returned.
 *
 * @return The impact string. Don't free this.
 */
gchar *
nvti_impact (const nvti_t *n)
{
  return (n ? n->impact : NULL);
}

/**
 * @brief Get the creation time.
 *
 * @param n The NVT Info structure of which the creation time should
 *          be returned.
 *
 * @return The creation time in seconds since epoch.
 */
time_t
nvti_creation_time (const nvti_t *n)
{
  return (n ? n->creation_time : 0);
}

/**
 * @brief Get the modification time.
 *
 * @param n The NVT Info structure of which the modification time should
 *          be returned.
 *
 * @return The modification time in seconds since epoch.
 */
time_t
nvti_modification_time (const nvti_t *n)
{
  return (n ? n->modification_time : 0);
}

/**
 * @brief Get the number of references of the NVT.
 *
 * @param n The NVT Info structure.
 *
 * @return The number of references.
 */
guint
nvti_vtref_len (const nvti_t *n)
{
  return (n ? g_slist_length (n->refs) : 0);
}

/**
 * @brief Get the n'th reference of the NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param p The position of the reference to return.
 *
 * @return The reference. NULL on error.
 */
vtref_t *
nvti_vtref (const nvti_t *n, guint p)
{
  return (n ? g_slist_nth_data (n->refs, p) : NULL);
}

/**
 * @brief Get references as string.
 *
 * @param n The NVT Info structure of which the references should
 *          be returned.
 *
 * @param type Optional type to collect. If NULL, all types are collected.
 *
 * @param exclude_types Optional CSC list of types to exclude from collection.
 *                      If NULL, no types are excluded.
 *
 * @param use_types If 0, then a simple comma separated list will be returned.
 *                  If not 0, then for each reference the syntax "type:id" is
 *                  applied.
 *
 * @return The references as string. This needs to be free'd.
 *         The format of the string depends on the "use_types" parameter.
 *         If use_types is 0 it is a comma-separated list "id, id, id"
 *         is returned.
 *         If use_types is not 0 a comma-separated list like
 *         "type:id, type:id, type:id" is returned.
 *         NULL is returned in case n is NULL.
 */
gchar *
nvti_refs (const nvti_t *n, const gchar *type, const gchar *exclude_types,
           guint use_types)
{
  gchar *refs, *refs2, **exclude_item;
  vtref_t *ref;
  guint i, exclude;
  gchar **exclude_split;

  if (!n)
    return (NULL);

  refs = NULL;
  refs2 = NULL;
  exclude = 0;

  if (exclude_types && exclude_types[0])
    exclude_split = g_strsplit (exclude_types, ",", 0);
  else
    exclude_split = NULL;

  for (i = 0; i < g_slist_length (n->refs); i++)
    {
      ref = g_slist_nth_data (n->refs, i);
      if (type && strcasecmp (ref->type, type) != 0)
        continue;

      if (exclude_split)
        {
          exclude = 0;
          for (exclude_item = exclude_split; *exclude_item; exclude_item++)
            {
              if (strcasecmp (g_strstrip (*exclude_item), ref->type) == 0)
                {
                  exclude = 1;
                  break;
                }
            }
        }

      if (!exclude)
        {
          if (use_types)
            {
              if (refs)
                refs2 =
                  g_strdup_printf ("%s, %s:%s", refs, ref->type, ref->ref_id);
              else
                refs2 = g_strdup_printf ("%s:%s", ref->type, ref->ref_id);
            }
          else
            {
              if (refs)
                refs2 = g_strdup_printf ("%s, %s", refs, ref->ref_id);
              else
                refs2 = g_strdup_printf ("%s", ref->ref_id);
            }
          g_free (refs);
          refs = refs2;
        }
    }

  g_strfreev (exclude_split);

  return (refs);
}

/**
 * @brief Get the solution.
 *
 * @param n The NVT Info structure of which the solution should
 *          be returned.
 *
 * @return The solution string. Don't free this.
 */
gchar *
nvti_solution (const nvti_t *n)
{
  return (n ? n->solution : NULL);
}

/**
 * @brief Get the solution type.
 *
 * @param n The NVT Info structure of which the solution type should
 *          be returned.
 *
 * @return The solution type string. Don't free this.
 */
gchar *
nvti_solution_type (const nvti_t *n)
{
  return (n ? n->solution_type : NULL);
}

/**
 * @brief Get the tags.
 *
 * @param n The NVT Info structure of which the tags should
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
 * @brief Get the text about detection.
 *
 * @param n The NVT Info structure of which the detection should
 *          be returned.
 *
 * @return The detection string. Don't free this.
 */
gchar *
nvti_detection (const nvti_t *n)
{
  return (n ? n->detection : NULL);
}

/**
 * @brief Get the QoD type.
 *
 * @param n The NVT Info structure of which the QoD type should
 *          be returned.
 *
 * @return The QoD type as string. Don't free this.
 */
gchar *
nvti_qod_type (const nvti_t *n)
{
  return (n ? n->qod_type : NULL);
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
 * @return The preference. NULL on error.
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
 * @brief Set the summary of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param solution The summary to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_summary (nvti_t *n, const gchar *summary)
{
  if (!n)
    return (-1);

  if (n->summary)
    g_free (n->summary);
  n->summary = g_strdup (summary);
  return (0);
}

/**
 * @brief Set the insight text of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param insight The insight text to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_insight (nvti_t *n, const gchar *insight)
{
  if (!n)
    return (-1);

  if (n->insight)
    g_free (n->insight);
  n->insight = g_strdup (insight);
  return (0);
}

/**
 * @brief Set the affected text of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param affected The affected text to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_affected (nvti_t *n, const gchar *affected)
{
  if (!n)
    return (-1);

  if (n->affected)
    g_free (n->affected);
  n->affected = g_strdup (affected);
  return (0);
}

/**
 * @brief Set the impact text of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param affected The impact text to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_impact (nvti_t *n, const gchar *impact)
{
  if (!n)
    return (-1);

  if (n->impact)
    g_free (n->impact);
  n->impact = g_strdup (impact);
  return (0);
}

/**
 * @brief Set the creation time of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param creation_time The creation time to set.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_creation_time (nvti_t *n, const time_t creation_time)
{
  if (!n)
    return (-1);

  n->creation_time = creation_time;
  return (0);
}

/**
 * @brief Set the modification time of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param modification_time The modification time to set.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_modification_time (nvti_t *n, const time_t modification_time)
{
  if (!n)
    return (-1);

  n->modification_time = modification_time;
  return (0);
}

/**
 * @brief Set the solution of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param solution The solution to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_solution (nvti_t *n, const gchar *solution)
{
  if (!n)
    return (-1);

  if (n->solution)
    g_free (n->solution);
  n->solution = g_strdup (solution);
  return (0);
}

/**
 * @brief Set the solution type of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param solution_type The solution type to set. A copy will be created
 *                      from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_solution_type (nvti_t *n, const gchar *solution_type)
{
  if (!n)
    return (-1);

  if (n->solution_type)
    g_free (n->solution_type);
  n->solution_type = g_strdup (solution_type);
  return (0);
}

/**
 * @brief Add a tag to the NVT tags.
 *        The tag names "last_modification" and "creation_date" are
 *        treated special: The value is expected to be a timestamp
 *        and it is being converted to seconds since epoch before
 *        added as a tag value.
 *        The tag name "cvss_base" will be ignored and not added.
 *
 * @param n     The NVT Info structure.
 *
 * @param name  The tag name. A copy will be created from this.
 *
 * @param value The tag value. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_add_tag (nvti_t *n, const gchar *name, const gchar *value)
{
  gchar *newvalue = NULL;

  if (!n)
    return (-1);

  if (!name || !name[0])
    return (-2);

  if (!value || !value[0])
    return (-3);

  if (!strcmp (name, "last_modification"))
    {
      nvti_set_modification_time (n, parse_nvt_timestamp (value));
      newvalue = g_strdup_printf ("%i", (int) nvti_modification_time (n));
    }
  else if (!strcmp (name, "creation_date"))
    {
      nvti_set_creation_time (n, parse_nvt_timestamp (value));
      newvalue = g_strdup_printf ("%i", (int) nvti_creation_time (n));
    }
  else if (!strcmp (name, "cvss_base"))
    {
      /* Ignore this tag because it is not being used.
       * It is redundant with the tag cvss_base_vector from which
       * it is computed.
       * Once GOS 6 and GVM 11 are retired, all set_tag commands
       * in the NASL scripts can be removed that set "cvss_base".
       * Once this happened this exception can be removed from the code.
       */
      return (0);
    }

  if (n->tag)
    {
      gchar *newtag;

      newtag =
        g_strconcat (n->tag, "|", name, "=", newvalue ? newvalue : value, NULL);
      g_free (n->tag);
      n->tag = newtag;
    }
  else
    n->tag = g_strconcat (name, "=", newvalue ? newvalue : value, NULL);

  if (newvalue)
    g_free (newvalue);

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
 * @brief Set the detection text of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param detection The detection text to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_detection (nvti_t *n, const gchar *detection)
{
  if (!n)
    return (-1);

  if (n->detection)
    g_free (n->detection);
  n->detection = g_strdup (detection);
  return (0);
}

/**
 * @brief Set the QoD type of a NVT.
 *
 * @param n The NVT Info structure.
 *
 * @param qod_type The QoD type to set. A copy will be created from this.
 *                 The string is not checked, any string is accepted as type.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
nvti_set_qod_type (nvti_t *n, const gchar *qod_type)
{
  if (!n)
    return (-1);

  if (n->qod_type)
    g_free (n->qod_type);
  if (qod_type && qod_type[0])
    n->qod_type = g_strdup (qod_type);
  else
    n->qod_type = NULL;
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
 * @brief Add many new vtref from a comma-separated list.
 *
 * @param n The NVTI where to add the references.
 *
 * @param type The type for all references. If NULL, then for ref_ids
 *             a syntax is expected that includes the type like
 *             "type:id,type:id".
 *
 * @param ref_ids A CSV of reference to be added.
 *
 * @param ref_text The optional text accompanying all references.
 *
 * @return 0 for success. 1 if n was NULL, 2 if ref_ids was NULL.
 */
int
nvti_add_refs (nvti_t *n, const gchar *type, const gchar *ref_ids,
               const gchar *ref_text)
{
  gchar **split, **item;

  if (!n)
    return (1);

  if (!ref_ids)
    return (2);

  split = g_strsplit (ref_ids, ",", 0);

  for (item = split; *item; item++)
    {
      gchar *id;

      id = *item;
      g_strstrip (id);

      if (strcmp (id, "") == 0)
        continue;

      if (type)
        {
          nvti_add_vtref (n, vtref_new (type, id, ref_text));
        }
      else
        {
          gchar **split2;

          split2 = g_strsplit (id, ":", 2);
          if (split2[0] && split2[1])
            nvti_add_vtref (n, vtref_new (split2[0], split2[1], ""));
          g_strfreev (split2);
        }
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
