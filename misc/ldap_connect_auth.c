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
#define KEY_LDAP_ROLE_ATTRIBUTE "role-attribute"
#define KEY_LDAP_ROLE_USER_VALUES "role-user-values"
#define KEY_LDAP_ROLE_ADMIN_VALUES "role-admin-values"
#define KEY_LDAP_ROLE_OBSERVER_VALUES "role-observer-values"
#define KEY_LDAP_RULE_ATTRIBUTE "rule-attribute"
#define KEY_LDAP_RULETYPE_ATTRIBUTE "ruletype-attribute"

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
 * @brief Reads in a schema and info from key file.
 *
 * @param key_file Key file to read schema and info from.
 * @param group    In \ref key_file , group of interest.
 *
 * @return Fresh ldap_auth_info, or NULL in case of errors.
 */
ldap_auth_info_t
ldap_auth_info_from_key_file (GKeyFile * key_file, const gchar * group)
{
  if (key_file == NULL || group == NULL)
    return NULL;
  gboolean allow_plaintext = FALSE;
  gboolean is_connect = FALSE;

  /** @todo Errors to be checked here, get string lists for the role values. */
  gchar *auth_dn = g_key_file_get_string (key_file, group,
                                          KEY_LDAP_DN_AUTH, NULL);
  gchar *ldap_host = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_HOST, NULL);
  gchar *role_attr = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_ROLE_ATTRIBUTE, NULL);
  gchar **role_usrv = g_key_file_get_string_list (key_file, group,
                                                  KEY_LDAP_ROLE_USER_VALUES,
                                                  NULL, NULL);
  gchar **role_admv = g_key_file_get_string_list (key_file, group,
                                                  KEY_LDAP_ROLE_ADMIN_VALUES,
                                                  NULL, NULL);
  gchar **role_obsv = g_key_file_get_string_list (key_file, group,
                                                  KEY_LDAP_ROLE_OBSERVER_VALUES,
                                                  NULL, NULL);
  gchar *ruletype_attr = g_key_file_get_string (key_file, group,
                                                KEY_LDAP_RULETYPE_ATTRIBUTE,
                                                NULL);
  gchar *rule_attr = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_RULE_ATTRIBUTE, NULL);

  gchar *plaintext_ok = g_key_file_get_value (key_file, group,
                                              "allow-plaintext", NULL);
  if (plaintext_ok && strcmp (plaintext_ok, "true") == 0)
    {
      allow_plaintext = TRUE;
    }
  g_free (plaintext_ok);

  if (strcmp (group, "method:ldap_connect") == 0)
    is_connect = TRUE;

  ldap_auth_info_t info = ldap_auth_info_new (ldap_host, auth_dn,
                                              role_attr,
                                              role_usrv,
                                              role_admv,
                                              role_obsv,
                                              ruletype_attr,
                                              rule_attr,
                                              allow_plaintext,
                                              is_connect);

  g_free (auth_dn);
  g_free (ldap_host);
  g_free (role_attr);
  g_free (role_usrv);
  g_free (role_admv);
  g_free (role_obsv);
  g_free (ruletype_attr);
  g_free (rule_attr);

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
 * @param role_attribute    Attribute that qualifies a role. Might not be NULL,
 *                          but empty.
 * @param role_user_values  Comma-separated list of values for
 *                          \ref role_attribute that qualify as a user.
 *                          Might not be NULL, but empty.
 * @param role_admin_values Comma-separated list of values
 *                          for \ref role_attribute that qualify as an admin.
 *                          Might not be NULL, but empty.
 * @param role_observer_values   Comma-separated list of values
 *                               for \ref role_attribute that qualify as an
 *                               observer.  Might not be NULL, but empty.
 * @param allow_plaintext   If FALSE, require StartTLS initialization to
 *                          succeed.
 * @param is_connect        If TRUE, certain parameters are not needed.
 *
 * @return Fresh ldap_auth_info_t, or NULL if one of the last five parameters
 *         is NULL. Free with ldap_auth_info_free.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar * ldap_host, const gchar * auth_dn,
                    const gchar * role_attribute, gchar ** role_user_values,
                    gchar ** role_admin_values, gchar ** role_observer_values,
                    const gchar * ruletype_attr, const gchar * rule_attr,
                    gboolean allow_plaintext, gboolean is_connect)
{
  // Certain parameters might not be NULL.
  if (!ldap_host || !auth_dn)
    return NULL;

  if (ldap_auth_dn_is_good (auth_dn) == FALSE)
    return NULL;

  if (!is_connect)
    {
      if (!ruletype_attr || !rule_attr)
        return NULL;
    }

  ldap_auth_info_t info = g_malloc0 (sizeof (struct ldap_auth_info));
  info->ldap_host = g_strdup (ldap_host);
  info->auth_dn = g_strdup (auth_dn);
  info->role_attribute = g_strdup (role_attribute);
  info->role_user_values = g_strdupv (role_user_values);
  info->role_admin_values = g_strdupv (role_admin_values);
  info->role_observer_values = g_strdupv (role_observer_values);
  info->ruletype_attribute = g_strdup (ruletype_attr);
  info->rule_attribute = g_strdup (rule_attr);
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
  g_free (info->role_attribute);
  g_strfreev (info->role_admin_values);
  g_strfreev (info->role_observer_values);
  g_strfreev (info->role_user_values);
  g_free (info->rule_attribute);
  g_free (info->ruletype_attribute);

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

  credential.bv_val = strdup (password);
  credential.bv_len = strlen (password);

  ldap_return =
    ldap_sasl_bind_s (ldap, userdn, LDAP_SASL_SIMPLE, &credential, NULL, NULL,
                      NULL);
  free (credential.bv_val);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("LDAP authentication failure: %s",
                 ldap_err2string (ldap_return));
      return NULL;
    }

  return ldap;
}

/**
 * @brief Binds to an LDAP and returns result of query.
 *
 * @param host      The host to connect to.
 * @param userdn_tmpl The DN to authenticate against as template, containing
 *                    single %s.
 * @param username  Username to print into userdn_tmpl.
 * @param password  Password for userdn.
 * @param dn        The dn whose subtree to search.
 * @param filter    Filter for object (e.g. "objectClass=person").
 * @param attribute Attribute to query (e.g. "gender").
 *
 * @return Result of query.
 */
GSList *
ldap_auth_bind_query (const gchar * host, const gchar * userdn_tmpl,
                      const gchar * username, const gchar * password,
                      const gchar * dn, const gchar * filter,
                      const gchar * attribute)
{
  if (ldap_auth_dn_is_good (userdn_tmpl) == FALSE)
    return NULL;

  GSList *attribute_values = NULL;
  gchar *userdn = g_strdup_printf (userdn_tmpl, username);
  LDAP *ldap = ldap_auth_bind (host, userdn, password, FALSE);

  if (!ldap)
    {
      g_warning ("LDAP Connection for query failed.");
    }

  attribute_values = ldap_auth_query (ldap, dn, filter, attribute);

  if (ldap)
    ldap_unbind_ext_s (ldap, NULL, NULL);

  return attribute_values;
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

/**
 * @brief Queries an LDAP directory.
 *
 * @param ldap      The ldap handle to use.
 * @param dn        The dn whose subtree to search.
 * @param filter    Filter for object (e.g. "objectClass=person").
 * @param attribute Attribute to query (e.g. "gender").
 *
 * @return Values of attribute of objects matching filter as a gchar* list.
 *         Caller has to free.
 */
GSList *
ldap_auth_query (LDAP * ldap, const gchar * dn, const gchar * filter,
                 const gchar * attribute)
{
  if (ldap == NULL || dn == NULL || filter == NULL || attribute == NULL)
    return NULL;

  // Keep const correctness.
  char *attr_cpy = strdup (attribute);

  char *attrs[] = {
    attr_cpy,
    NULL
  };

  GSList *value_list = NULL;
  char *attr_it = NULL;
  struct berval **attr_vals = NULL;
  struct berval **attr_vals_it = NULL;
  BerElement *ber = NULL;
  LDAPMessage *result, *result_it;

  int res = ldap_search_ext_s (ldap, dn /* base */ , LDAP_SCOPE_SUBTREE,
                               filter /* filter */ , attrs, 0 /* attrsonly */ ,
                               NULL /* serverctrls */ , NULL /* clientctrls */ ,
                               LDAP_NO_LIMIT,   /* timeout */
                               LDAP_NO_LIMIT,   /* sizelimit */
                               &result);
  free (attr_cpy);
  if (res != LDAP_SUCCESS)
    {
      g_debug ("LDAP Query failed: %s\n", ldap_err2string (res));
      return NULL;
    }
  else
    {
      g_debug ("LDAP Query returned %d results.",
               ldap_count_entries (ldap, result));
    }

  result_it = ldap_first_entry (ldap, result);
  while (result_it != NULL)
    {
      // Iterate through each attribute in the entry.
      attr_it = ldap_first_attribute (ldap, result_it, &ber);
      while (attr_it != NULL)
        {
          /* For each attribute, check its value(s). */
          attr_vals = ldap_get_values_len (ldap, result_it, attr_it);
          if (attr_vals != NULL)
            {
              attr_vals_it = attr_vals;
              while (*attr_vals_it)
                {
                  value_list =
                    g_slist_prepend (value_list,
                                     g_strdup ((*attr_vals_it)->bv_val));
                  attr_vals_it++;
                }
              ldap_value_free_len (attr_vals);
            }
          ldap_memfree (attr_it);
          attr_it = ldap_next_attribute (ldap, result_it, ber);
        }

      if (ber != NULL)
        {
          ber_free (ber, 0);
        }
      result_it = ldap_next_entry (ldap, result_it);
    }

  ldap_msgfree (result);
  return value_list;
}

#endif /* ENABLE_LDAP_AUTH */
