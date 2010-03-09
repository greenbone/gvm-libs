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
 *
 * @todo auth_dn[before|after]_user should be collapsed. The format might
 *       e.g. become auth_dn="uid=%s,cn=users,o=greenbone,c=net" .
 *       As we would sprintf with that string it has to be checked with great
 *       care.
 */
struct ldap_auth_info {
  gchar* auth_dn_before_user; ///< First part of the DN to authenticate with.
  gchar* auth_dn_after_user;  ///< Last part of the DN to authenticate with.
  gchar* ldap_host;          ///< Adress of the ldap server, might include port.
};

/** @brief Authentication schema and adress type. */
typedef struct ldap_auth_info* ldap_auth_info_t;


ldap_auth_info_t
ldap_auth_info_new (const gchar* _auth_dn_before_user,
                    const gchar* _auth_dn_after_user,
                    const gchar* _ldap_host);

void
ldap_auth_info_free (ldap_auth_info_t info);

int
ldap_authenticate (const gchar* username, const gchar* password, 
                   ldap_auth_info_t info);

ldap_auth_info_t
ldap_auth_info_from_key_file (GKeyFile* keyfile, const gchar* group);

#endif /* not LDAP_AUTH_H */
