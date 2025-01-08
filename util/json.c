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
