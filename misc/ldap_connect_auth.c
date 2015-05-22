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

#include "ldap_connect_auth.h"

#ifdef ENABLE_LDAP_AUTH

#include <assert.h>
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

#define KEY_LDAP_HOST "ldaphost"
#define KEY_LDAP_DN_AUTH "authdn"

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

  ldap_unbind_ext_s (ldap, NULL, NULL);

  return 0;
}

/**
 * @brief Create LDAP info from info provided by function.
 *
 * @param get_info  Function to get info.
 *
 * @return Fresh ldap_auth_info, or NULL in case of errors.
 */
ldap_auth_info_t
ldap_auth_info_from_function (int (*get_info) (gchar **, gchar **, int *))
{
  int allow_plaintext;
  gchar *auth_dn, *ldap_host;
  ldap_auth_info_t info;

  assert (get_info);

  if (get_info (&ldap_host, &auth_dn, &allow_plaintext))
    return NULL;

  info = ldap_auth_info_new (ldap_host, auth_dn, allow_plaintext);

  g_free (ldap_host);
  g_free (auth_dn);

  return info;
}

/**
 * @brief Create a new ldap authentication schema and info.
 *
 * @param ldap_host         Host to authenticate against. Might not be NULL,
 *                          but empty.
 * @param auth_dn           DN where the actual user name is to be inserted at
 *                          "%s", e.g. uid=%s,cn=users. Might not be NULL,
 *                          but empty, has to contain a single %s.
 * @param allow_plaintext   If FALSE, require StartTLS initialization to
 *                          succeed.
 *
 * @return Fresh ldap_auth_info_t, or NULL on error.  Free with
 *         ldap_auth_info_free.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar * ldap_host, const gchar * auth_dn,
                    gboolean allow_plaintext)
{
  // Certain parameters might not be NULL.
  if (!ldap_host || !auth_dn)
    return NULL;

  if (ldap_auth_dn_is_good (auth_dn) == FALSE)
    return NULL;

  ldap_auth_info_t info = g_malloc0 (sizeof (struct ldap_auth_info));
  info->ldap_host = g_strdup (ldap_host);
  info->auth_dn = g_strdup (auth_dn);
  info->allow_plaintext = allow_plaintext;

  return info;
}

/**
 * @brief Free an ldap_auth_info and all associated memory.
 *
 * @param info ldap_auth_schema_t to free, can be NULL.
 */
void
ldap_auth_info_free (ldap_auth_info_t info)
{
  if (!info)
    return;

  g_free (info->ldap_host);
  g_free (info->auth_dn);

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
gchar *
ldap_auth_info_auth_dn (const ldap_auth_info_t info, const gchar * username)
{
  if (info == NULL || username == NULL)
    return NULL;

  gchar *dn = g_strdup_printf (info->auth_dn, username);

  return dn;
}

/**
 * @brief Setup and bind to an LDAP.
 *
 * @param[in] host              Host to connect to.
 * @param[in] userdn            DN to authenticate against
 * @param[in] password          Password for userdn.
 * @param[in] force_encryption  Whether or not to abort if connection
 *                              encryption via StartTLS or ldaps failed.
 *
 * @return LDAP Handle or NULL if an error occured, authentication failed etc.
 */
LDAP *
ldap_auth_bind (const gchar * host, const gchar * userdn,
                const gchar * password, gboolean force_encryption)
{
  LDAP *ldap = NULL;
  int ldap_return = 0;
  int ldapv3 = LDAP_VERSION3;
  gchar *ldapuri = NULL;
  struct berval credential;

  if (host == NULL || userdn == NULL || password == NULL)
    return NULL;

  // Prevent empty password, bind against ADS will succeed with
  // empty password by default.
  if (strlen(password) == 0)
    return NULL;

  if (force_encryption == FALSE)
    g_warning ("Allowed plaintext LDAP authentication.");

  ldapuri = g_strconcat ("ldap://", host, NULL);

  ldap_return = ldap_initialize (&ldap, ldapuri);

  if (ldap == NULL || ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Could not open LDAP connection for authentication.");
      g_free (ldapuri);
      return NULL;
    }

  /* Fail if server doesnt talk LDAPv3 or StartTLS initialization fails. */
  ldap_return = ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ldapv3);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Aborting, could not set ldap protocol version to 3: %s.",
                 ldap_err2string (ldap_return));
      g_free (ldapuri);
      return NULL;
    }

  ldap_return = ldap_start_tls_s (ldap, NULL, NULL);
  if (ldap_return != LDAP_SUCCESS)
    {
      // Try ldaps.
      g_warning ("StartTLS failed, trying to establish ldaps connection.");
      g_free (ldapuri);
      ldapuri = g_strconcat ("ldaps://", host, NULL);

      ldap_return = ldap_initialize (&ldap, ldapuri);
      if (ldap == NULL || ldap_return != LDAP_SUCCESS)
        {
          if (force_encryption == TRUE)
            {
              g_warning
                ("Aborting ldap authentication: Could not init LDAP StartTLS nor ldaps: %s.",
                 ldap_err2string (ldap_return));
              g_free (ldapuri);
              return NULL;
            }
          else
            {
              g_warning ("Could not init LDAP StartTLS, nor ldaps: %s.",
                         ldap_err2string (ldap_return));
              g_warning ("Reinit LDAP connection to do plaintext authentication");
              ldap_unbind_ext_s (ldap, NULL, NULL);

              // Note that for connections to default ADS, a failed
              // StartTLS negotiation breaks the future bind, so retry.
              ldap_return = ldap_initialize (&ldap, ldapuri);
              if (ldap == NULL || ldap_return != LDAP_SUCCESS)
                {
                  g_warning ("Could not reopen LDAP connection for authentication.");
                  g_free (ldapuri);
                  return NULL;
                }
            }
        }
    }
  else
    g_debug ("LDAP StartTLS initialized.");

  g_free (ldapuri);

  credential.bv_val = g_strdup (password);
  credential.bv_len = strlen (password);

  ldap_return =
    ldap_sasl_bind_s (ldap, userdn, LDAP_SASL_SIMPLE, &credential, NULL, NULL,
                      NULL);
  g_free (credential.bv_val);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("LDAP authentication failure: %s",
                 ldap_err2string (ldap_return));
      return NULL;
    }

  return ldap;
}

/**
 * @brief True if parameter contains just one %s and no evil other characters.
 *
 * @param authdn The string to check.
 *
 * @return TRUE if authdn is considered safe enough to be sprintf'ed into.
 */
gboolean
ldap_auth_dn_is_good (const gchar * authdn)
{
  gchar *eg;
  LDAPDN dn;
  int ln = 0;

  if (authdn == NULL || authdn[0] == '\0')
    return FALSE;

  // Must contain %s
  if (!strstr (authdn, "%s"))
    return FALSE;

  // Must not contain other %-signs
  char *pos = strchr (authdn, '%');
  pos = strchr (pos + 1, '%');
  if (pos != NULL)
    return FALSE;

  ln = strlen (authdn);

  // As a special exception allow ADS-style domain\user - pairs.
  if (strchr (authdn, '\\') && authdn[ln-2] == '%' && authdn[ln-1] == 's')
    return TRUE;

  // Also allow user@domain - pairs.
  if (authdn[0] == '%' && authdn[1] == 's' && authdn[2] == '@')
    return TRUE;

  /* Validate the DN with the LDAP library. */
  eg = g_strdup_printf (authdn, "example");
  dn = NULL;
  if (ldap_str2dn (eg, &dn, LDAP_DN_FORMAT_LDAPV3))
    {
      g_free (eg);
      return FALSE;
    }
  g_free (eg);
  ldap_memfree (dn);

  return TRUE;
}

#else

/**
 * @brief Dummy function for Manager.
 *
 * @param get_info  Function to get info.
 *
 * @return NULL.
 */
ldap_auth_info_t
ldap_auth_info_from_function (int (*get_info) (gchar **, gchar **, int *))
{
  return NULL;
}

/**
 * @brief Dummy function for Manager.
 *
 * @param info      Schema and adress to use.
 * @param username  Username to authenticate.
 * @param password  Password to use.
 *
 * @return -1.
 */
int
ldap_connect_authenticate (const gchar * username, const gchar * password,
                   /*const *//*ldap_auth_info_t */ void *ldap_auth_info)
{
  return -1;
}

/**
 * @brief Dummy function for Manager.
 *
 * @param info ldap_auth_schema_t to free, can be NULL.
 */
void
ldap_auth_info_free (ldap_auth_info_t info)
{
}

#endif /* ENABLE_LDAP_AUTH */
