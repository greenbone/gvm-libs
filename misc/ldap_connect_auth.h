/* OpenVAS Libraries
 * $Id$
 * Description: Header for LDAP-Connect Authentication module.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
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

#ifndef ENABLE_LDAP_AUTH
// Handle cases where openldap is not available.
#else

#ifndef LDAP_CONNECT_AUTH_H
#define LDAP_CONNECT_AUTH_H

#include <glib.h>
#include <ldap.h>

/** @brief Authentication schema and adress type. */
typedef struct ldap_auth_info *ldap_auth_info_t;

/**
 * @brief Schema (dn) and info to use for a basic ldap authentication.
 *
 * Use like an opaque struct, create with ldap_auth_schema_new, do not modify,
 * free with ldap_auth_schema_free.
 */
struct ldap_auth_info
{
  gchar *ldap_host;             ///< Adress of the ldap server, might include port.
  gchar *auth_dn;               ///< DN to authenticate with.
  /** @brief Attribute to check against \ref role_user_values and
   *  @brief \ref role_admin_values. Empty string if n/a. */
  gchar *role_attribute;
  gchar **role_admin_values;    ///< Attribute values that qualify an admin.
  gchar **role_observer_values; ///< Attribute values that qualify an observer.
  gchar **role_user_values;     ///< Attribute values that qualify a user.
  gchar *ruletype_attribute;    ///< Attribute to hold the ruletype.
  gchar *rule_attribute;        ///< Attribute to hold the rule (hosts) itself.
  gboolean allow_plaintext;     ///< !Whether or not StartTLS is required.
  int (*user_set_role) (const gchar *,
                        const gchar *,
                        const gchar *);  ///< Function to set role of user.
};

ldap_auth_info_t
ldap_auth_info_from_key_file (GKeyFile *, const gchar *);

int ldap_connect_authenticate (const gchar *, const gchar *,
                       /*ldap_auth_info_t */ void *);

void ldap_auth_info_free (ldap_auth_info_t);

ldap_auth_info_t
ldap_auth_info_new (const gchar *, const gchar *, const gchar *, gchar **,
                    gchar **, gchar **, const gchar *, const gchar *, gboolean,
                    gboolean);

gchar*
ldap_auth_info_auth_dn (const ldap_auth_info_t, const gchar*);

LDAP *
ldap_auth_bind (const gchar *, const gchar *, const gchar *, gboolean);

GSList*
ldap_auth_bind_query (const gchar*, const gchar*, const gchar*, const gchar*,
                      const gchar*, const gchar*, const gchar*);

gboolean ldap_auth_dn_is_good (const gchar *);

GSList*
ldap_auth_query (LDAP*, const gchar*, const gchar*, const gchar* attribute);

#endif /* not LDAP_CONNECT_AUTH_H */

#endif /* ENABLE_LDAP_AUTH */
