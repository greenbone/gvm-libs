/* OpenVAS Libraries
 * $Id$
 * Description: LDAP/ADS Authentication module.
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

#include "ads_auth.h"
#include "ldap_auth.h"

#include <stdio.h>
#include <stdlib.h> /* for free */

#include <glib.h>

/** @todo Use non-deprecated counterparts of openldap functionality (see
 *        further TODOS). */
#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "openvas_auth.h"
#include "openvas_string.h"

#define KEY_ADS_DOMAIN "domain"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib   ads"

/**
 * @file ads_auth.c
 * Contains structs and functions to use for basic authentication against
 * an ADS (Active Directory Server). Most functionality is provided by the
 * ldap_auth module.
 */

/**
 * @brief From domain.org returns dc=domain,dc=org to be used with ldap
 * @brief queries.
 *
 * @param[in] domain The domain in "dot-notation"
 *
 * @return The domain as ldap dc's to be used with ldap-queries.
 */
static gchar*
domain_to_ldap_dc (const gchar* domain)
{
  gchar ** domain_components = g_strsplit (domain, ".", -1);
  gchar * part = g_strjoinv (",dc=", domain_components);
  g_strfreev (domain_components);
  gchar * result = g_strconcat ("dc=", part, NULL);
  g_free (part);

  return result;
}


/**
 * @brief Creates a ads_auth_info_t struct from Key-file.
 *
 * @param[in] key_file Key-file to read values in from.
 * @param[in] group    Group in key-file.
 *
 * @return Freshly allocated ads_auth_info in case all mandatory values where
 *         found. NULL otherwise.
 */
ads_auth_info_t
ads_auth_info_from_key_file (GKeyFile * key_file, const gchar * group)
{
  if (key_file == NULL || group == NULL)
    return NULL;

  ldap_auth_info_t ldapinfo = ldap_auth_info_from_key_file (key_file, group);
  gchar* ads_domain;

  if (ldapinfo == NULL)
    {
      g_debug ("ldap info of ads not found.");
      return NULL;
    }

  ads_auth_info_t info = g_malloc0 (sizeof (struct ads_auth_info));
  info->ldap_auth_conf = ldapinfo;
  ads_domain = g_key_file_get_string (key_file, group, KEY_ADS_DOMAIN,
                                              NULL);

  if (ads_domain == NULL)
    {
      g_warning ("Domain is not specified in ADS/LDAP Configuration.");
      ads_auth_info_free (info);
      return NULL;
    }

  info->domain = ads_domain;
  info->domain_dc = domain_to_ldap_dc (info->domain);

  return info;
}


/**
 * @brief Frees an ads_auth_info struct.
 *
 * @param[in] info The struct to free, can be NULL.
 */
void
ads_auth_info_free (ads_auth_info_t info)
{
  if (!info)
    return;

  ldap_auth_info_free (info->ldap_auth_conf);

  g_free (info->domain);
  g_free (info->domain_dc);
  g_free (info);
}


/**
 * @brief Queries the DN of an users object.
 *
 * @param[in] ldap     LDAP-Handle to use.
 * @param[in] username Account name to search for.
 * @param[in] domain   Domain for ldap query (e.g. "dc=company,dc=org").
 *
 * @return DN of user object, NULL in case of errors / not found. Caller has
 *         to free.
 */
static char*
ads_query_user_dn (LDAP * ldap, const gchar * username, const gchar * domain)
{
  LDAPMessage *result;
  char* dn = NULL;
  int res = ldap_search_ext_s (ldap, domain /* base */,
                               LDAP_SCOPE_SUBTREE, /* scope */
                              ("(&(objectClass=user)(sAMAccountName=gsmtest))")
                               /* filter */, NULL /*attrs*/, 0 /* attrsonly */,
                               NULL /* serverctrls */ , NULL /* clientctrls */,
                               LDAP_NO_LIMIT,   /* timeout */
                               LDAP_NO_LIMIT,   /* sizelimit */
                               &result);

  // The query failed, handle as error.
  if (res != LDAP_SUCCESS)
    {
      g_debug ("The dn of an ads user could not be found: %s",
               ldap_err2string (res));
      return NULL;
    }

  // No or not a distinct result, handle as error.
  if (ldap_count_entries (ldap, result) != 1)
    {
      g_debug ("The dn of a user could not be found: %d results were "
               "returned.", ldap_count_entries (ldap, result));
      return NULL;
    }

  dn = ldap_get_dn (ldap, result);
  ldap_msgfree (result);

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
ads_authenticate (const gchar * username, const gchar * password,
                   /*const *//*ads_auth_info_t */ void *ads_auth_info)
{
  ldap_auth_info_t info = ((ads_auth_info_t) ads_auth_info)->ldap_auth_conf;
  ads_auth_info_t ads_info = (ads_auth_info_t) ads_auth_info;
  int role = 0;

  if (info == NULL || username == NULL || password == NULL || !info->ldap_host)
    return -1;

  /** @todo deprecated, use ldap_initialize or ldap_create */
  LDAP *ldap = (LDAP *) ldap_open (info->ldap_host, LDAP_PORT);
  gchar *authdn = NULL;
  int ldap_return = 0;
  int ldapv3 = 3;

  if (ldap == NULL)
    {
      g_warning ("Could not open LDAP connection for authentication.");
      return -1;
    }

  /* Fail if server doesnt talk LDAPv3 or StartTLS initialization fails. */
  ldap_return = ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ldapv3);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Could not set ldap protocol version to 3: %s.",
                 ldap_err2string (ldap_return));
      return -1;
    }

  ldap_return = ldap_start_tls_s (ldap, NULL, NULL);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Could not init LDAP StartTLS: %s.",
                 ldap_err2string (ldap_return));

      if (info->allow_plaintext == FALSE)
        return -1;
    }
  else
    g_debug ("LDAP StartTLS initialized.");

  // Create user@domain authentication string.
  authdn = g_strconcat (username, "@", ads_info->domain, NULL);

  /** @todo deprecated, use ldap_sasl_bind_s */
  ldap_return = ldap_simple_bind_s (ldap, authdn, password);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("LDAP authentication failure.");
      return 1;
    }

  // Get the "real" DN by searching for samAccountName=user .
  char* dn = ads_query_user_dn (ldap, username, ads_info->domain_dc);

  // Get the role.
  role = ldap_auth_query_role (ldap, info, dn);

  // Query and save users rules if s/he is at least a "User".
  if (role == 2 || role == 1)
    {
      if (ldap_auth_query_rules (ldap, info, dn, username) == -1)
        g_warning ("Users rules could not be found on ADS/LDAP directory.");
      // If user is admin, mark it so.
      gchar *user_dir_name = g_build_filename (OPENVAS_STATE_DIR,
                                               "users-remote", "ldap",
                                               username, NULL);
      openvas_set_user_role (username, (role == 2) ? "Admin" : "User",
                             user_dir_name);
      g_free (user_dir_name);
    }

  ldap_unbind_ext_s (ldap, NULL, NULL);
  free (dn);

  switch (role)
    {
    case 2:
      g_debug ("User has admin role.");
    case 1:
      g_debug ("User has user role.");
      return 0;
    case -1:
    default:
      g_warning ("User has no role.");
      return 1;
    }
}

#endif /* ENABLE_LDAP_AUTH */
