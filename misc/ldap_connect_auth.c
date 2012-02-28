/* OpenVAS Libraries
 * $Id$
 * Description: LDAP-connect Authentication module.
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

#ifdef ENABLE_LDAP_AUTH

#include "ldap_connect_auth.h"

#include "ldap_auth.h"

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <ldap.h>

#include "openvas_auth.h"
#include "openvas_string.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  ldap"

/**
 * @file ldap_connect_auth.c
 * Contains structs and functions to use for basic authentication (unmanaged, meaning that
 * authorization like role management is file-based) against an LDAP directory server.
 */


/**
 * @brief Authenticate against an ldap directory server.
 *
 * @param info      Schema and adress to use.
 * @param username  Username to authenticate.
 * @param password  Password to use.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
ldap_connect_authenticate (const gchar * username, const gchar * password,
                   /*const *//*ldap_auth_info_t */ void *ldap_auth_info)
{
  // TODO this is an incomplete copy of ldap_authenticate.
  ldap_auth_info_t info = (ldap_auth_info_t) ldap_auth_info;
  LDAP *ldap = NULL;
  gchar *dn = NULL;

  if (info == NULL || username == NULL || password == NULL || !info->ldap_host) {
    g_debug("Not attempting ldap_connect: missing parameter.");
    return -1;
  }

  dn = ldap_auth_info_auth_dn (info, username);

  ldap = ldap_auth_bind (info->ldap_host, dn, password, !info->allow_plaintext);

  if (ldap == NULL) {
    g_debug("Could not bind to ldap host %s", info->ldap_host);
    return -1;
  }

  // TODO: ldap_user_exists in ldap_auth.c 
  int user_exists = ldap_user_exists(username, info);

  // TODO do a proper authentication.

  return user_exists;
}

#endif /* ENABLE_LDAP_AUTH */
