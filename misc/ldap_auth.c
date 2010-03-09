/* OpenVAS Libraries
 * $Id$
 * Description: LDAP Authentication module.
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

#include "ldap_auth.h"

#include <stdio.h>

#include "glib.h"

/** @todo Use non-deprecated counterparts of openldap functionality. */
#define LDAP_DEPRECATED 1
#include "ldap.h"

//#define KEY_LDAP_AUTHDN "authdn"
#define KEY_LDAP_DNPRE "dnpre"
#define KEY_LDAP_DNPOST "dnpost"
#define KEY_LDAP_HOST "ldaphost"


/**
 * @file ldap_auth.c
 * Contains structs and functions to use for basic authentication against
 * an LDAP directory server.
 */

/**
 * @brief Create a new ldap authentication schema and info.
 *
 * @param a_auth_dn_before_user Part of the DN before the actual user name,
 *                              e.g. \"uid=\". Might not be NULL, but empty.
 * @param a_auth_dn_after_user  Part of the DN after the actual user name,
 *                              e.g. \",cn=powerusers,o=greenbone,c=net\".
 *                              Might not be NULL, but empty.
 *
 * @return Fresh ldap_auth_info_t, or NULL if one of the given parameters was
 *         NULL. Free with ldap_auth_info_free.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar* _auth_dn_before_user,
                    const gchar* _auth_dn_after_user,
                    const gchar* _ldap_host)
{
  // Parameters might not be NULL.
  if (!_auth_dn_before_user || !_auth_dn_after_user || !_ldap_host)
    return NULL;

  ldap_auth_info_t info = g_malloc0 (sizeof (struct ldap_auth_info));
  info->auth_dn_before_user = g_strdup (_auth_dn_before_user);
  info->auth_dn_after_user = g_strdup (_auth_dn_after_user);
  info->ldap_host = g_strdup (_ldap_host);

  return info;
}


/**
 * @brief Free an ldap_auth_info and all associated memory.
 *
 * @param info ldap_auth_schema_t to free.
 */
void
ldap_auth_info_free (ldap_auth_info_t info)
{
  g_free (info->auth_dn_before_user);
  g_free (info->auth_dn_after_user);
  g_free (info->ldap_host);

  g_free (info);
}


/**
 * @brief Create the dn to authenticate with.
 *
 * @param info     Info and schema to use.
 * @param username Name of the user.
 *
 * @return Freshly allocated dn or NULL if one of the parameters was NULL. Free
 *         with g_free.
 */
static gchar*
ldap_auth_info_create_dn (const ldap_auth_info_t info, const gchar* username)
{
  if (info == NULL || username == NULL)
    return NULL;

  gchar* dn = g_strdup_printf ("%s%s%s", info->auth_dn_before_user, username,
                               info->auth_dn_after_user);
  return dn;
}


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
ldap_authenticate (const gchar* username, const gchar* password,
                   /*const*/ ldap_auth_info_t info)
{
  if (info == NULL || username == NULL || password == NULL || !info->ldap_host)
    return -1;

  LDAP* ldap      = (LDAP*) ldap_open (info->ldap_host, LDAP_PORT);
  gchar* dn       = NULL;
  int ldap_return = 0;

  if (ldap == NULL)
    {
      g_warning ("Could not open LDAP connection for authentication.\n");
      return -1;
    }

  dn = ldap_auth_info_create_dn (info, username);

  ldap_return = ldap_simple_bind_s (ldap, dn, password);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("LDAP authentication failure.");
    }

  /** @todo Administrator/ Access-attributes to be checked here. */

  g_free (dn);
  ldap_unbind (ldap);

  if (ldap_return != LDAP_SUCCESS)
    return 1;
  else
    return 0;
}


/**
 * @brief Reads in a schema and info from key file.
 *
 * @param key_file Key file to read schema and info from.
 * @param group    In \ref key_file , group of interest.
 *
 * @return Fresh ldap_auth_info, or NULL in case of errors.
 */
ldap_auth_info_t
ldap_auth_info_from_key_file (GKeyFile* key_file, const gchar* group)
{
  if (key_file == NULL || group == NULL)
    return NULL;

  /** @todo Errors to be checked here. */
  gchar* dnpre = g_key_file_get_string (key_file, group, KEY_LDAP_DNPRE, NULL);
  gchar* dnpost = g_key_file_get_string (key_file, group, KEY_LDAP_DNPOST, NULL);
  gchar* ldaphost = g_key_file_get_string (key_file, group, KEY_LDAP_HOST, NULL);

  ldap_auth_info_t info = ldap_auth_info_new (dnpre, dnpost, ldaphost);

  g_free (dnpre);
  g_free (dnpost);
  g_free (ldaphost);

  return info;
}
