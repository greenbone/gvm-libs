/* OpenVAS-Client
 *
 * Description: Structures and protos for Severity Filters
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
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

#ifndef _UTIL_SEVERITYFILTER_H
#define _UTIL_SEVERITYFILTER_H

#include <glib.h>

/**
 * @brief A severity_filter is a named collection of severity_overrides.
 */
typedef struct severity_filter
{
  gchar *name;        /**< Name for this filter. */
  gchar *filename;    /**< Path to file with which this filter is going to be synced. */
  GSList *overrides;  /**< List of overrides. */
} severity_filter_t;

/* temporary, should be part of the global context */
extern severity_filter_t *global_filter;

/**
 * @brief A severity_override maps a severity of a message under certain
 * @brief conditions to a new severity.
 * 
 * The conditions to be met are:
 *  - OID of script that issued the message.
 *  - Certain host (target).
 *  - Certain port or port "family".
 * 
 * A severity_override furthermore own a name and reason (user-relavant only)
 * and an active-flag (is it en- or disabled?).
 * 
 * severity_overrides are bundled in severity_filters.
 */
typedef struct severity_override
{
  gchar *name;      /**< A name for this override. */
  gchar *host;      /**< An IP (eg. "192.168.1.1") or a name (e.g. "localhost"). */
  gchar *port;      /**< A port number or something like "general/tcp" -
                       whatever is returned by the scan server. */
  gchar *OID;       /**< The OID of the NVT. */
  gchar *reason;    /**< A rationale for this severity override. */
  gchar *severity_from; /**< If this severity occurs ... */
  gchar *severity_to;   /**< ... replace it with this one. */
  gboolean active;  /**< FALSE = this override is not active, TRUE: is active. */
} severity_override_t;


severity_filter_t *severity_filter_new (const gchar *, const gchar *);
void severity_filter_free (severity_filter_t *);
gboolean severity_filter_contains_conflicting_override (const severity_filter_t
                                                        * filter,
                                                        const
                                                        severity_override_t *
                                                        override);
gboolean severity_filter_contains_conflicting (const severity_filter_t * filter,
                                               const gchar * host,
                                               const gchar * port,
                                               const gchar * oid,
                                               const gchar * from);
gboolean severity_filter_add (severity_filter_t *, const severity_override_t *);
const gchar *severity_filter_apply (const gchar *, const gchar *, const gchar *,
                                    const gchar *);
gboolean severity_filter_remove (severity_filter_t * filter,
                                 severity_override_t * override);

const severity_override_t *severity_override_new (const gchar *, const gchar *,
                                                  const gchar *, const gchar *,
                                                  const gchar *, const gchar *,
                                                  const gchar *, gboolean);
const severity_override_t *severity_override_duplicate (const
                                                        severity_override_t *);
void severity_override_free (severity_override_t *);

severity_filter_t *severity_filter_from_xml (const gchar *);

#endif /* _UTIL_SEVERITYFILTER_H */
