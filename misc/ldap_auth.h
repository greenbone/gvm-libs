/* OpenVAS Libraries
 * $Id$
 * Description: Header for LDAP Authentication module.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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
#endif

#ifndef LDAP_AUTH_H
#define LDAP_AUTH_H

#include <glib.h>


/**
 * @brief Schema (dn) and info to use for a basic ldap authentication.
 *
 * Use like an opaque struct, create with ldap_auth_schema_new, do not modify,
 * free with ldap_auth_schema_free.
 */
struct ldap_auth_info {
  gchar* ldap_host;         ///< Adress of the ldap server, might include port.
  gchar* auth_dn;                 ///< DN to authenticate with.
  /** @brief Attribute to check against \ref role_user_values and
   *  @brief \ref role_admin_values. Empty string if n/a. */
  gchar* role_attribute;
  gchar** role_admin_values;  ///< Attribute values that qualify an admin.
  gchar** role_user_values;   ///< Attribute values that qualify a user.
  gchar* ruletype_attribute;  ///< Attribute to hold the ruletype.
  gchar* rule_attribute;      ///< Attribute to hold the rule (hosts) itself.
};

/** @brief Authentication schema and adress type. */
typedef struct ldap_auth_info* ldap_auth_info_t;


ldap_auth_info_t
ldap_auth_info_new (const gchar* ldap_host, const gchar* auth_dn,
                    const gchar* role_attribute,
                    gchar** role_user_values,
                    gchar** role_admin_values,
                    const gchar* ruletype_attribute,
                    const gchar* rule_attribute);

void
ldap_auth_info_free (ldap_auth_info_t info);

int
ldap_authenticate (const gchar* username, const gchar* password,
                   /*ldap_auth_info_t*/ void* info);

ldap_auth_info_t
ldap_auth_info_from_key_file (GKeyFile* keyfile, const gchar* group);

#endif /* not LDAP_AUTH_H */
