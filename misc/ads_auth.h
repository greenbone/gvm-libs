/* OpenVAS Libraries
 * $Id$
 * Description: Header for LDAP/ADS Authentication module.
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

#ifndef ADS_AUTH_H
#define ADS_AUTH_H

#include "ldap_auth.h"

#include <glib.h>

/**
 * @brief Info to use for an authentication against an ADS/LDAP.
 *
 * Use like an opaque struct, create with ads_auth_info_new, do not modify,
 * free with ads_auth_info_free.
 */
struct ads_auth_info
{
  ldap_auth_info_t ldap_auth_conf; ///< Inherit everything from ldap case.
  gchar* domain;  ///< The domain to bind to, in "dot-notation" like domain.org
  gchar* domain_dc; ///< The domain as ldap dc, like "dc=domain,dc=org".
};

/** @brief Authentication schema and adress type. */
typedef struct ads_auth_info *ads_auth_info_t;

ads_auth_info_t
ads_auth_info_from_key_file (GKeyFile * key_file, const gchar * group);

void
ads_auth_info_free (ads_auth_info_t info);

int ads_authenticate (const gchar * username, const gchar * password,
                       /*ads_auth_info_t */ void *info);

#endif /* not ADS_AUTH_H */
