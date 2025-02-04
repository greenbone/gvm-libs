/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "json.h"

/**
 * @brief Escapes a string according to the JSON or JSONPath standard
 *
 * @param[in]  string         The string to escape
 * @param[in]  single_quote   Whether to escape single quotes
 *
 * @return The escaped string
 */
gchar *
gvm_json_string_escape (const char *string, gboolean single_quote)
{
  gchar *point;
  if (string == NULL)
    return NULL;

  GString *escaped = g_string_sized_new (strlen (string));
  for (point = (char *) string; *point != 0; point++)
    {
      unsigned char character = *point;

      if ((character > 31) && (character != '\\')
          && (single_quote ? (character != '\'') : (character != '\"')))
        {
          g_string_append_c (escaped, character);
        }
      else
        {
          g_string_append_c (escaped, '\\');
          switch (*point)
            {
            case '\\':
            case '\'':
            case '\"':
              g_string_append_c (escaped, *point);
              break;
            case '\b':
              g_string_append_c (escaped, 'b');
              break;
            case '\f':
              g_string_append_c (escaped, 'f');
              break;
            case '\n':
              g_string_append_c (escaped, 'n');
              break;
            case '\r':
              g_string_append_c (escaped, 'r');
              break;
            case '\t':
              g_string_append_c (escaped, 't');
              break;
            default:
              g_string_append_printf (escaped, "u%04x", character);
            }
        }
    }
  return g_string_free (escaped, FALSE);
}

/**
 * @brief Get a double field from a JSON object.
 *
 * @param[in]  obj  Object
 * @param[in]  key  Field name.
 *
 * @return A double.
 */
double
gvm_json_obj_double (cJSON *obj, const gchar *key)
{
  cJSON *item;

  item = cJSON_GetObjectItem (obj, key);
  if (item && cJSON_IsNumber (item))
    return item->valuedouble;

  return 0;
}

/**
 * @brief Get an int field from a JSON object.
 *
 * @param[in]  obj  Object
 * @param[in]  key  Field name.
 * @param[out] val  Return location for int if int exists.
 *
 * @return 0 if such an int field exists, else 1.
 */
int
gvm_json_obj_check_int (cJSON *obj, const gchar *key, int *val)
{
  cJSON *item;

  item = cJSON_GetObjectItem (obj, key);
  if (item && cJSON_IsNumber (item)) {
    if (val)
      *val = item->valueint;
    return 0;
  }
  return 1;
}

/**
 * @brief Get an int field from a JSON object.
 *
 * @param[in]  obj  Object
 * @param[in]  key  Field name.
 *
 * @return An int.
 */
int
gvm_json_obj_int (cJSON *obj, const gchar *key)
{
  cJSON *item;

  item = cJSON_GetObjectItem (obj, key);
  if (item && cJSON_IsNumber (item))
    return item->valueint;

  return 0;
}

/**
 * @brief Get a string field from a JSON object.
 *
 * @param[in]  obj  Object
 * @param[in]  key  Field name.
 *
 * @return A string. Will be freed by cJSON_Delete.
 */
gchar *
gvm_json_obj_str (cJSON *obj, const gchar *key)
{
  cJSON *item;

  item = cJSON_GetObjectItem (obj, key);
  if (item && cJSON_IsString (item))
    return item->valuestring;

  return 0;
}
