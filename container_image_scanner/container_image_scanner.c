/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Container Image Scanner communication.
 */

#include "container_image_scanner.h"

/**
 * @brief Struct holding target information.
 */
struct container_image_target
{
  GSList *credentials; /** Credentials to use in the scan */
  gchar *hosts;        /** String defining one or many hosts to scan */
};

/**
 * @brief Struct credential information for container image.
 */
struct container_image_credential
{
  gchar *type;           /**< Credential type */
  gchar *service;        /**< Service the credential is for */
  GHashTable *auth_data; /**< Authentication data (username, password, etc.)*/
};

/**
 * @brief Add a credential to the scan json object.
 *
 * @param credentials Credential to add.
 * @param cred_array JSON array to add the credential to.
 */
static void
add_credential_to_scan_json (gpointer credentials, gpointer cred_array)
{
  GHashTableIter auth_data_iter;
  gchar *auth_data_name, *auth_data_value;
  cJSON *cred_obj = NULL;

  container_image_credential_t *cred = credentials;

  cred_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (cred_obj, "service", cred->service);

  cJSON *cred_type_obj = cJSON_CreateObject ();
  g_hash_table_iter_init (&auth_data_iter, cred->auth_data);
  while (g_hash_table_iter_next (&auth_data_iter, (gpointer *) &auth_data_name,
                                 (gpointer *) &auth_data_value))
    cJSON_AddStringToObject (cred_type_obj, auth_data_name, auth_data_value);
  cJSON_AddItemToObject (cred_obj, cred->type, cred_type_obj);

  cJSON_AddItemToArray ((cJSON *) cred_array, cred_obj);
}

/**
 * @brief Add a scan preference to the scan json object.
 *
 * @param key Preference ID.
 * @param val Preference value.
 * @param scan_prefs_array JSON array to add the preference to.
 */
static void
add_scan_preferences_to_scan_json (gpointer key, gpointer val,
                                   gpointer scan_prefs_array)
{
  cJSON *pref_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (pref_obj, "id", key);
  cJSON_AddStringToObject (pref_obj, "value", val);
  cJSON_AddItemToArray (scan_prefs_array, pref_obj);
}

/**
 * @brief Build a json object with data necessary to start a container image
 * scan
 *
 * JSON result consists of hosts (oci image urls), credentials and
 * scan preferences
 *
 * @param target      target
 * @param scan_preferences Scan preferences to be added to the scan config
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
char *
container_image_build_scan_config_json (container_image_target_t *target,
                                        GHashTable *scan_preferences)
{
  cJSON *scan_obj = NULL;
  cJSON *target_obj = NULL;
  cJSON *hosts_array = NULL;
  gchar *json_str = NULL;

  /* Build the message in json format to be published. */
  scan_obj = cJSON_CreateObject ();

  // begin target
  target_obj = cJSON_CreateObject ();

  // hosts
  hosts_array = cJSON_CreateArray ();
  gchar **hosts_list = g_strsplit (target->hosts, ",", 0);
  for (int i = 0; hosts_list[i] != NULL; i++)
    {
      cJSON *host_item = NULL;
      host_item = cJSON_CreateString (hosts_list[i]);
      cJSON_AddItemToArray (hosts_array, host_item);
    }
  g_strfreev (hosts_list);
  cJSON_AddItemToObject (target_obj, "hosts", hosts_array);

  // credentials
  cJSON *credentials = cJSON_CreateArray ();
  g_slist_foreach (target->credentials, add_credential_to_scan_json,
                   credentials);
  cJSON_AddItemToObject (target_obj, "credentials", credentials);

  cJSON_AddItemToObject (scan_obj, "target", target_obj);

  // Begin Scan Preferences
  cJSON *scan_prefs_array = cJSON_CreateArray ();
  g_hash_table_foreach (scan_preferences, add_scan_preferences_to_scan_json,
                        scan_prefs_array);
  cJSON_AddItemToObject (scan_obj, "scan_preferences", scan_prefs_array);

  json_str = cJSON_Print (scan_obj);
  cJSON_Delete (scan_obj);
  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}

/**
 * @brief Create a new container_image target.
 *
 * @param hosts          The hostnames of the target.
 *
 * @return The newly allocated container_image_target_t.
 */
container_image_target_t *
container_image_target_new (const gchar *hosts)
{
  container_image_target_t *new_target;
  new_target = g_malloc0 (sizeof (container_image_target_t));

  new_target->hosts = hosts ? g_strdup (hosts) : NULL;

  return new_target;
}

/**
 * @brief Free a container_image target, including all added credentials.
 *
 * @param target  The container_image target to free.
 */
void
container_image_target_free (container_image_target_t *target)
{
  if (!target)
    return;

  g_slist_free_full (target->credentials,
                     (GDestroyNotify) container_image_credential_free);
  g_free (target->hosts);
  g_free (target);
  target = NULL;
}

/**
 * @brief Allocate and initialize a new container_image credential.
 *
 * @param type      The credential type.
 * @param service   The service the credential is for.
 *
 * @return New container_image credential.
 */
container_image_credential_t *
container_image_credential_new (const gchar *type, const gchar *service)
{
  container_image_credential_t *new_credential;

  new_credential = g_malloc0 (sizeof (container_image_credential_t));

  new_credential->type = type ? g_strdup (type) : NULL;
  new_credential->service = service ? g_strdup (service) : NULL;
  new_credential->auth_data =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_credential;
}

/**
 * @brief Free a container_image credential.
 *
 * @param credential  The credential to free.
 */
void
container_image_credential_free (container_image_credential_t *credential)
{
  if (!credential)
    return;

  g_free (credential->type);
  g_free (credential->service);
  g_hash_table_destroy (credential->auth_data);
  g_free (credential);
}

/**
 * @brief Set authentication data for a container_image credential.
 *
 * @param  credential  The credential to get the data from.
 * @param  name        The name of the data item to get.
 * @param  value       The authentication data or NULL to unset.
 */
void
container_image_credential_set_auth_data (
  container_image_credential_t *credential, const gchar *name,
  const gchar *value)
{
  if (credential == NULL || name == NULL)
    return;

  if (g_regex_match_simple ("^[[:alpha:]][[:alnum:]_]*$", name, 0, 0))
    {
      if (value)
        g_hash_table_replace (credential->auth_data, g_strdup (name),
                              g_strdup (value));
      else
        g_hash_table_remove (credential->auth_data, name);
    }
  else
    {
      g_warning ("%s: Invalid auth data name: %s", __func__, name);
    }
}

/**
 * @brief Add a credential to a container_image target.
 *
 * @param target       The container_image target to add the credential to.
 * @param credential   The credential to add. Will be freed with target.
 */
void
container_image_target_add_credential (container_image_target_t *target,
                                       container_image_credential_t *credential)
{
  if (!target || !credential)
    return;

  target->credentials = g_slist_prepend (target->credentials, credential);
}
