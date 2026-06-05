/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Web Application Scanner Wrapper communication.
 */

#include "web_application_scanner.h"

#include "../base/array.h"
#include "../util/json.h"

#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm was"

/**
 * @brief Struct holding target information.
 */
struct web_application_target
{
  gchar *scan_id;      /**  Scan ID */
  gchar *urls;         /** String defining one or many URLs to scan */
  gchar *exclude_urls; /** String defining one or many URLs to exclude */
  GSList *credentials; /** Credentials to use in the scan */
};

// Scan config builder.

/**
 * @brief Add authentication data key value to a JSON object.
 *
 * @param key       Key string.
 * @param value     Value string.
 * @param json_obj  JSON object to add the key-value pair to.
 */
static void
add_auth_data_key_value_as_json (const char *key, const char *value,
                                 void *json_obj)
{
  if (!key || !value || !json_obj)
    return;
  cJSON_AddStringToObject ((cJSON *) json_obj, key, value);
}

/**
 * @brief Add a credential to the scan json object.
 *
 * @param credentials Credential to add.
 * @param cred_array JSON array to add the credential to.
 */
static void
add_credential_to_scan_json (gpointer credentials, gpointer cred_array)
{
  cJSON *cred_obj = NULL;

  scan_credential_t *cred = credentials;

  const gchar *type = scan_credential_get_type (cred);
  const gchar *service = scan_credential_get_service (cred);
  const gchar *port = scan_credential_get_port (cred);

  cred_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (cred_obj, "service", service ? service : "");

  if (port)
    {
      cJSON_AddNumberToObject (cred_obj, "port", strtol (port, NULL, 10));
    }

  cJSON *cred_type_obj = cJSON_CreateObject ();
  scan_credential_foreach_auth_data (cred, add_auth_data_key_value_as_json,
                                     cred_type_obj);
  cJSON_AddItemToObject (cred_obj, type ? type : "", cred_type_obj);

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
 * @brief Build a json object with data necessary to start a scan
 *
 * @param target      target
 * @param scan_preferences Scan preferences to be added to the scan config
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
char *
web_application_build_scan_config_json (web_application_target_t *target,
                                        GHashTable *scan_preferences)
{
  cJSON *scan_obj = NULL;
  cJSON *target_obj = NULL;
  cJSON *urls_array = NULL;
  cJSON *exclude_urls_array = NULL;
  gchar *json_str = NULL;

  if (!target || !scan_preferences)
    {
      g_warning ("%s: Target and scan preferences cannot be NULL.", __func__);
      return NULL;
    }

  scan_obj = cJSON_CreateObject ();

  if (target->scan_id && target->scan_id[0] != '\0')
    cJSON_AddStringToObject (scan_obj, "scan_id", target->scan_id);

  // begin target
  target_obj = cJSON_CreateObject ();

  // urls
  urls_array = cJSON_CreateArray ();
  gchar **urls_list = g_strsplit (target->urls, ",", 0);
  for (int i = 0; urls_list[i] != NULL; i++)
    {
      cJSON *url_item = NULL;
      url_item = cJSON_CreateString (urls_list[i]);
      cJSON_AddItemToArray (urls_array, url_item);
    }
  g_strfreev (urls_list);
  cJSON_AddItemToObject (target_obj, "urls", urls_array);

  // exclude urls
  if (target->exclude_urls && target->exclude_urls[0] != '\0')
    {
      exclude_urls_array = cJSON_CreateArray ();
      gchar **exclude_urls_list = g_strsplit (target->exclude_urls, ",", 0);
      for (int i = 0; exclude_urls_list[i] != NULL; i++)
        {
          cJSON *exclude_url_item = NULL;
          exclude_url_item = cJSON_CreateString (exclude_urls_list[i]);
          cJSON_AddItemToArray (exclude_urls_array, exclude_url_item);
        }
      g_strfreev (exclude_urls_list);
      cJSON_AddItemToObject (target_obj, "excluded_urls", exclude_urls_array);
    }

  // Credentials
  cJSON *credentials = cJSON_CreateArray ();
  g_slist_foreach (target->credentials, add_credential_to_scan_json,
                   credentials);
  cJSON_AddItemToObject (target_obj, "credentials", credentials);

  cJSON_AddItemToObject (scan_obj, "target", target_obj);

  // Scan Preferences
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
 * @brief Create a new web application target.
 *
 * @param scanid         Scan ID.
 * @param urls           The URLs of the target.
 * @param exclude_urls   The excluded URLs of the target.
 *
 * @return The newly allocated web_application_target_t. Null on error.
 */
web_application_target_t *
web_application_target_new (const gchar *scanid, const gchar *urls,
                            const gchar *exclude_urls)
{
  if (!urls || urls[0] == '\0')
    {
      g_warning ("%s: URLs cannot be NULL or empty.", __func__);
      return NULL;
    }

  web_application_target_t *new_target;
  new_target = g_malloc0 (sizeof (web_application_target_t));

  if (scanid && *scanid)
    new_target->scan_id = g_strdup (scanid);

  new_target->urls = g_strdup (urls);
  new_target->exclude_urls = exclude_urls ? g_strdup (exclude_urls) : NULL;

  return new_target;
}

/**
 * @brief Free a web application target, including all added credentials.
 *
 * @param target  The web application target to free.
 */
void
web_application_target_free (web_application_target_t *target)
{
  if (!target)
    return;

  g_slist_free_full (target->credentials,
                     (GDestroyNotify) scan_credential_free);
  g_free (target->urls);
  g_free (target->exclude_urls);
  g_free (target->scan_id);
  g_free (target);
  target = NULL;
}

/**
 * @brief Add a credential to a web application target.
 *
 * @param target       The web application target to add the credential to.
 * @param credential   The credential to add. Will be freed with target.
 */
void
web_application_target_add_credential (web_application_target_t *target,
                                       scan_credential_t *credential)
{
  if (!target || !credential)
    return;

  target->credentials = g_slist_prepend (target->credentials, credential);
}
