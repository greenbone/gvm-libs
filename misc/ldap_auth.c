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

#ifdef ENABLE_LDAP_AUTH

#include "ldap_auth.h"

#include <stdio.h>

#include <glib.h>

/** @todo Use non-deprecated counterparts of openldap functionality (see
 *        further TODOS). */
#define LDAP_DEPRECATED 1
#include "ldap.h"

#define KEY_LDAP_HOST "ldaphost"
#define KEY_LDAP_DN_AUTH "authdn"
#define KEY_LDAP_ROLE_ATTRIBUTE "role-attribute"
#define KEY_LDAP_ROLE_USER_VALUES "role-user-values"
#define KEY_LDAP_ROLE_ADMIN_VALUES "role-admin-values"

/**
 * @file ldap_auth.c
 * Contains structs and functions to use for basic authentication against
 * an LDAP directory server.
 */

/**
 * @brief True if parameter contains just one %s and no evil other characters.
 *
 * @param authdn The string to check.
 *
 * @return TRUE if authdn is considered safe enough to be sprintf'ed into.
 */
static gboolean
auth_dn_is_good (const gchar* authdn)
{
  if (authdn == NULL)
    return FALSE;

  // Must contain %s
  if (!strstr (authdn, "%s"))
    return FALSE;

  // Must not contain other %-signs
  char* pos = strchr (authdn, '%');
  pos = strchr (pos + 1, '%');
  if (pos != NULL)
    return FALSE;

  return TRUE;
}


/**
 * @brief Create a new ldap authentication schema and info.
 *
 * @param ldap_host         Host to authenticate against. Might not be NULL,
 *                          but empty.
 * @param auth_dn           DN where the actual user name is to be inserted at
 *                          "%s", e.g. uid=%s,cn=users. Might not be NULL,
 *                          but empty, has to contain a single %s.
 * @param role_attribute    Attribute that qualifies a role. Might not be NULL,
 *                          but empty.
 * @param role_user_values  Comma-separated list of values for
 *                          \ref role_attribute that qualify as a user.
 *                          Might not be NULL, but empty.
 * @param role_admin_values Comma-separated list of values
 *                          for \ref role_attribute that qualify as an admin.
 *                          Might not be NULL, but empty.
 *
 * @return Fresh ldap_auth_info_t, or NULL if one of the given parameters was
 *         NULL. Free with ldap_auth_info_free.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar* ldap_host, const gchar* auth_dn,
                    const gchar* role_attribute,
                    const gchar* role_user_values,
                    const gchar* role_admin_values)
{
  // Parameters might not be NULL.
  if (!ldap_host || !auth_dn || !role_attribute || !role_user_values || !role_admin_values)
    return NULL;

  if (auth_dn_is_good (auth_dn) == FALSE)
    return NULL;

  ldap_auth_info_t info = g_malloc0 (sizeof (struct ldap_auth_info));
  info->ldap_host = g_strdup (ldap_host);
  info->auth_dn = g_strdup (auth_dn);
  info->role_attribute = g_strdup (role_attribute);
  info->role_user_values = g_strdup (role_user_values);
  info->role_admin_values = g_strdup (role_admin_values);

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
  g_free (info->ldap_host);
  g_free (info->auth_dn);
  g_free (info->role_attribute);
  g_free (info->role_admin_values);
  g_free (info->role_user_values);

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

  gchar* dn = g_strdup_printf (info->auth_dn, username);

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

  /** @todo deprecated, use ldap_initialize or ldap_create */
  LDAP* ldap      = (LDAP*) ldap_open (info->ldap_host, LDAP_PORT);
  gchar* dn       = NULL;
  int ldap_return = 0;

  if (ldap == NULL)
    {
      g_warning ("Could not open LDAP connection for authentication.\n");
      return -1;
    }

  dn = ldap_auth_info_create_dn (info, username);

  /** @todo deprecated, use ldap_sasl_bind_s */
  ldap_return = ldap_simple_bind_s (ldap, dn, password);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("LDAP authentication failure.");
    }

  /** @todo If just a role-attribute and a role-mapping is defined in this
   *        configuration, check the attribute value(s) here. */

  /** @todo Administrator/ Access-attributes to be checked here. */

  /** @todo deprecated, use ldap_unbind_ext_s */
  ldap_unbind (ldap);
  g_free (dn);

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

  /** @todo Errors to be checked here, get string lists for the role values. */
  gchar* auth_dn = g_key_file_get_string (key_file, group,
                                          KEY_LDAP_DN_AUTH, NULL);
  gchar* ldap_host = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_HOST, NULL);
  gchar* role_attr = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_ROLE_ATTRIBUTE, NULL);
  gchar* role_usrv = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_ROLE_USER_VALUES, NULL);
  gchar* role_admv = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_ROLE_ADMIN_VALUES, NULL);

  ldap_auth_info_t info = ldap_auth_info_new (ldap_host, auth_dn,
                                              role_attr,
                                              role_usrv,
                                              role_admv);

  g_free (auth_dn);
  g_free (ldap_host);
  g_free (role_attr);
  g_free (role_usrv);
  g_free (role_admv);

  return info;
}


/**
 * @brief Query the role of a user.
 *
 * @return Role of the user, e.g. "admin", "user" or "none".
 */
gchar*
ldap_auth_query_role (const gchar* username, const gchar* password,
                   /*const*/ ldap_auth_info_t info)
{
  return NULL;
}

#endif /* ENABLE_LDAP_AUTH */
