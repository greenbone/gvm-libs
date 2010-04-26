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

#include "openvas_auth.h"
#include "openvas_string.h"

#define KEY_LDAP_HOST "ldaphost"
#define KEY_LDAP_DN_AUTH "authdn"
#define KEY_LDAP_ROLE_ATTRIBUTE "role-attribute"
#define KEY_LDAP_ROLE_USER_VALUES "role-user-values"
#define KEY_LDAP_ROLE_ADMIN_VALUES "role-admin-values"
#define KEY_LDAP_RULE_ATTRIBUTE "rule-attribute"
#define KEY_LDAP_RULETYPE_ATTRIBUTE "ruletype-attribute"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  ldap"

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
                    gchar** role_user_values,
                    gchar** role_admin_values,
                    const gchar* ruletype_attr,
                    const gchar* rule_attr)
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
  info->role_user_values = g_strdupv (role_user_values);
  info->role_admin_values = g_strdupv (role_admin_values);
  info->ruletype_attribute = g_strdup (ruletype_attr);
  info->rule_attribute = g_strdup (rule_attr);

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
  g_strfreev (info->role_admin_values);
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
static gchar*
ldap_auth_info_create_dn (const ldap_auth_info_t info, const gchar* username)
{
  if (info == NULL || username == NULL)
    return NULL;

  gchar* dn = g_strdup_printf (info->auth_dn, username);

  return dn;
}


/**
 * @brief Queries the accessrules of a user and saves them to disc.
 *
 * @param  ldap[in]       The bound ldap session to use.
 * @param  ldap_info[in]  The ldap_auth_info struct to use.
 * @param  dn[in]         The dn to query from.
 * @param  username[in]   The username.
 *
 * @return  0 if successfull,
 *         -1 if failed.
 */
static int
ldap_auth_query_rules (LDAP *ldap, ldap_auth_info_t auth_info, const gchar* dn,
                       const gchar* username)
{
  char *attrs[]    = { auth_info->ruletype_attribute,
                       auth_info->rule_attribute,
                       NULL };
  char *attr_it    = NULL;
  char **attr_vals = NULL;
  BerElement *ber  = NULL;
  gchar *rule      = NULL;
  int ruletype     = -1;
  LDAPMessage *result, *result_it;

  int res = ldap_search_ext_s (ldap, dn /* base */, LDAP_SCOPE_BASE,
                               NULL /* filter */,  attrs, 0 /* attrsonly */,
                               NULL /* serverctrls */, NULL /* clientctrls */,
                               LDAP_NO_LIMIT, /* timeout */
                               LDAP_NO_LIMIT, /* sizelimit */
                               &result);
  if (res != LDAP_SUCCESS)
    {
      g_debug ("The rule/ruletype of an ldap user could not be found: %s\n",
               ldap_err2string (res));
      return -1;
    }

  result_it = ldap_first_entry (ldap, result);
  if (result_it != NULL)
    {
      // Iterate through each attribute in the entry.
      attr_it = ldap_first_attribute (ldap, result_it, &ber);
      while (attr_it != NULL)
        {
          /* For each attribute, print the attribute name and values. */
          attr_vals = ldap_get_values (ldap, result_it, attr_it);
          if (attr_vals != NULL)
            {
              // Found ruletype attribute
              if (strcmp (attr_it, auth_info->ruletype_attribute) == 0)
                {
                  // 3 Ruletypes are possible
                  if (strcmp (attr_vals[0], "allow") == 0)
                    ruletype = 1;
                  else if (strcmp (attr_vals[0], "allow all") == 0)
                    ruletype = 2;
                  else if (strcmp (attr_vals[0], "deny") == 0)
                    ruletype = 0;
                  else
                    g_debug ("unknown rule type"); // (ruletype = -1)
                }
              // Found rule attribute
              else if (strcmp (attr_it, auth_info->rule_attribute) == 0)
                {
                  rule = g_strdup (attr_vals[0]);
                }

              ldap_value_free (attr_vals);
            }
          ldap_memfree (attr_it);
          attr_it = ldap_next_attribute (ldap, result_it, ber);
        }

      // Save the rules
      if (ruletype == -1)
        g_warning ("No ruletype specified!");
      else
        {
          gchar* user_dir = g_build_filename (OPENVAS_STATE_DIR,
                                              "users-remote", "ldap",
                                              username, NULL);
          openvas_auth_store_user_rules (user_dir, rule, ruletype);
          g_free (user_dir);
        }

      g_free (rule);

      if (ber != NULL)
        {
          ber_free (ber, 0);
        }
    }
  else // No such attribute(s)
    {
      g_debug ("User has no rule/ruletype, did not find the attributes.");
    }

  ldap_msgfree (result);

  /** @todo proper returns */
  return 0;
}


/**
 * @brief Queries the role of a user.
 *
 * @param  ldap       The bound ldap session to use.
 * @param  ldap_info  The ldap_auth_info struct to use.
 * @param  dn         The dn to query from.
 *
 * @return -1 if an error occurred,
 *          0 if user is neither "user" nor "admin",
 *         +1 if user is "user",
 *         +2 if user is "admin".
 */
static int
ldap_auth_query_role (LDAP *ldap, ldap_auth_info_t auth_info, gchar* dn)
{
  char *attrs[]    = {auth_info->role_attribute, NULL};
  char *attr_it    = NULL;
  char **attr_vals = NULL;
  BerElement *ber  = NULL;
  LDAPMessage  *result, *result_it;
  int found_role = -1; // error

  int res = ldap_search_ext_s (ldap, dn /* base */, LDAP_SCOPE_BASE,
                               NULL /* filter */,  attrs, 0 /* attrsonly */,
                               NULL /* serverctrls */, NULL /* clientctrls */,
                               LDAP_NO_LIMIT, /* timeout */
                               LDAP_NO_LIMIT, /* sizelimit */
                               &result);
  if (res != LDAP_SUCCESS)
    {
      g_debug ("The role of an ldap user could not be found: %s\n",
               ldap_err2string (res));
      return found_role;
    }

  result_it = ldap_first_entry (ldap, result);
  if (result_it != NULL)
    {
      // Iterate through each attribute in the entry.
      attr_it = ldap_first_attribute (ldap, result_it, &ber);
      while (attr_it != NULL)
        {
          // Get the value of that attribute (we expect to see one attr/value)
          attr_vals = ldap_get_values (ldap, result_it, attr_it);
          if (attr_vals != NULL)
            {
              // We expect exactly one value here, ignore others.
              if (openvas_strv_contains_str (auth_info->role_admin_values,
                                             attr_vals[0]))
                found_role = 2; // is admin
              else if (openvas_strv_contains_str (auth_info->role_user_values,
                                                  attr_vals[0]))
                found_role = 1; // is user
              else
                g_debug ("User is neither in admin nor users group.");

              ldap_value_free (attr_vals);
            }
          ldap_memfree (attr_it);
          attr_it = ldap_next_attribute (ldap, result_it, ber);
        }
      if (ber != NULL)
        {
          ber_free (ber, 0);
        }
    }
  else // No such attribute(s)
    {
      g_debug ("User has no role, did not find role attribute.");
      found_role = -1;
    }

  ldap_msgfree (result);

  return found_role;
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
                   /*const*/ /*ldap_auth_info_t*/ void* ldap_auth_info)
{
  ldap_auth_info_t info = (ldap_auth_info_t) ldap_auth_info;
  int role = 0;

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
      return 1;
    }

  // Get the role.
  role = ldap_auth_query_role (ldap, info, dn);

  // Query and save users rules if s/he is at least a "User".
  if (role == 2 || role == 1)
    {
      if (ldap_auth_query_rules (ldap, info, dn, username) == -1)
        g_warning ("Users rules could not be found on ldap directory.");
      // If user is admin, mark it so.
      gchar* user_dir_name = g_build_filename (OPENVAS_STATE_DIR,
                                              "users-remote", "ldap",
                                               username, NULL);
      openvas_set_user_role (username, (role == 2) ? "Admin" : "User",
                             user_dir_name);
      g_free (user_dir_name);
    }

  /** @todo deprecated, use ldap_unbind_ext_s */
  ldap_unbind (ldap);
  g_free (dn);

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
  gchar** role_usrv = g_key_file_get_string_list (key_file, group,
                                                  KEY_LDAP_ROLE_USER_VALUES,
                                                  NULL, NULL);
  gchar** role_admv = g_key_file_get_string_list (key_file, group,
                                                  KEY_LDAP_ROLE_ADMIN_VALUES,
                                                  NULL, NULL);
  gchar* ruletype_attr = g_key_file_get_string (key_file, group,
                                                KEY_LDAP_RULETYPE_ATTRIBUTE,
                                                NULL);
  gchar* rule_attr = g_key_file_get_string (key_file, group,
                                            KEY_LDAP_RULE_ATTRIBUTE, NULL);

  ldap_auth_info_t info = ldap_auth_info_new (ldap_host, auth_dn,
                                              role_attr,
                                              role_usrv,
                                              role_admv,
                                              ruletype_attr,
                                              rule_attr);

  g_free (auth_dn);
  g_free (ldap_host);
  g_free (role_attr);
  g_free (role_usrv);
  g_free (role_admv);
  g_free (ruletype_attr);
  g_free (rule_attr);

  return info;
}

#endif /* ENABLE_LDAP_AUTH */
